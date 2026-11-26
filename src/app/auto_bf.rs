//! `autobf` (config, on by default): KAT recovers the key of every capture a brute force can crack
//! without being asked. An undecrypted PSA frame (TEA) gets ProtoPirate's BF1/BF2 search, the same
//! search as the signal menu's "Recover key" and on the same background job: one search runs at a
//! time, the others wait here, oldest first, and a "Recover key" the user asks for goes first.
//! They run beside a long KeeLoq or HiTag2 search (well under a second each), so frames keep
//! showing up while one runs.
//!
//! With `autobf` on, KeeLoq magic-serial and HiTag2 Hell searches also start automatically when a
//! capture without a key appears and the search has enough presses (KeeLoq: two hop codes; HiTag2:
//! a second press of the same remote). They still wait if another long search runs. One remote
//! (same serial / HiTag2 UID) is normally searched once: later captures share the key. If a saved
//! key no longer verifies a new hop (resync), that key is dropped and the search runs again.
//! A frame of PSA's adaptive AM path that the fast path cannot decrypt (`PSA [unchecked]`, see
//! `protocols/psa.rs`) waits here, outside the list, and joins it only if its key is found: a
//! genuine TEA frame decrypts in a fraction of a second, noise never does. A child module of `app`
//! (`mod auto_bf;`), so it can use App's fields.

use std::collections::VecDeque;

use super::App;
use crate::capture::{Capture, CaptureStatus, KeyRecovery};
use crate::protocols::{
    hitag2_key_known, psa_needs_key_search, psa_search_label, PsaBruteForceHit, PsaBruteForceOutcome,
    PSA_SEARCH_LABEL_ALL,
};
use crate::protocols::hitag2_keys;
use crate::protocols::keeloq_bf as bf;
use crate::protocols::keeloq_common::{self, remove_keeloq_keys};

/// A key search waiting for the background job.
pub(super) enum Waiting {
    /// A capture in the list. `asked`: by the "Recover key" action, which goes first and reports
    /// as that action always did.
    Listed { id: u32, asked: bool },
    /// A `PSA [unchecked]` frame, listed only if its key is found.
    Unchecked(Box<Capture>),
    /// KeeLoq magic-serial search (`autobf`).
    Keeloq { id: u32 },
    /// HiTag2 Hell search (`autobf`).
    Hitag2 { id: u32 },
}

/// The searches waiting for the background job (`App::auto_bf`).
#[derive(Default)]
pub(super) struct AutoBf {
    waiting: VecDeque<Waiting>,
}

/// Give a capture the fields of its recovered PSA key: plain PSA, encoder-capable (so it can be
/// exported and transmitted, and counts as vulnerable), marked as recovered by the search.
pub(super) fn apply_psa_hit(c: &mut Capture, hit: &PsaBruteForceHit) {
    c.protocol = Some("PSA".to_string());
    c.serial = Some(hit.fields.serial);
    c.button = Some(hit.fields.button);
    // PSA counters are up to 28 bits; the capture keeps the low 16 like the decoder.
    c.counter = Some(hit.fields.counter as u16);
    c.crc_valid = true;
    c.status = CaptureStatus::EncoderCapable;
    c.key_recovery = Some(KeyRecovery::Recovered(psa_search_label(hit)));
}

impl App {
    /// KeeLoq remote serial of a capture (stored field, else from the 64-bit frame).
    fn keeloq_remote_serial(c: &Capture) -> Option<u32> {
        c.serial.or_else(|| (c.data_count_bit >= 64).then(|| bf::Frame::from_data(c.data).serial()))
    }

    /// Whether any capture of KeeLoq remote `serial` already has a key-search result.
    fn keeloq_remote_has_key_result(&self, serial: u32) -> bool {
        self.captures.iter().any(|c| {
            c.key_recovery.is_some() && Self::keeloq_remote_serial(c) == Some(serial)
        })
    }

    /// Whether a KeeLoq search for `serial` is running or already queued.
    fn keeloq_search_for_serial_planned(&self, serial: u32) -> bool {
        if self.keeloq_bf_job.as_ref().is_some_and(|j| j.serial == serial) {
            return true;
        }
        self.auto_bf.waiting.iter().any(|w| {
            matches!(w, Waiting::Keeloq { id }
                if self.captures.iter().find(|c| c.id == *id)
                    .and_then(Self::keeloq_remote_serial)
                    == Some(serial))
        })
    }

    /// Whether any HiTag2 capture of UID `uid` already has a key-search result.
    fn hitag2_remote_has_key_result(&self, uid: u32) -> bool {
        self.captures.iter().any(|c| {
            c.key_recovery.is_some()
                && super::hitag2_bf::frame_of(c).is_ok_and(|f| f.uid == uid)
        })
    }

    /// Whether a HiTag2 search for UID `uid` is running or already queued.
    fn hitag2_search_for_uid_planned(&self, uid: u32) -> bool {
        if self.hitag2_bf_job.as_ref().is_some_and(|j| j.uid == uid) {
            return true;
        }
        self.auto_bf.waiting.iter().any(|w| {
            matches!(w, Waiting::Hitag2 { id }
                if self.captures.iter().find(|c| c.id == *id)
                    .and_then(|c| super::hitag2_bf::frame_of(c).ok())
                    .is_some_and(|f| f.uid == uid))
        })
    }

    /// Whether a PSA search for this serial is running or queued (same TEA key for the remote).
    fn psa_search_for_serial_planned(&self, serial: Option<u32>) -> bool {
        let Some(serial) = serial else {
            return false;
        };
        if self.psa_recover_job.as_ref().and_then(|j| j.capture_id).is_some_and(|id| {
            self.captures.iter().find(|c| c.id == id).is_some_and(|c| c.serial == Some(serial))
        }) {
            return true;
        }
        self.auto_bf.waiting.iter().any(|w| match w {
            Waiting::Listed { id, .. } => self
                .captures
                .iter()
                .find(|c| c.id == *id)
                .is_some_and(|c| c.serial == Some(serial)),
            Waiting::Unchecked(c) => c.serial == Some(serial),
            _ => false,
        })
    }

    /// Drop a HiTag2 UID key that no longer verifies `capture`'s hop (resync). Clears
    /// `key_recovery` on that remote so autobf may search again. Returns whether a key was dropped.
    fn invalidate_stale_hitag2_key(&mut self, uid: u32, capture: &Capture) -> bool {
        if hitag2_keys::find(uid).and_then(|r| r.key).is_none() {
            return false;
        }
        if hitag2_key_known(capture.protocol_name(), &capture.decoded_signal()) {
            return false;
        }
        if !hitag2_keys::forget_key(uid) {
            return false;
        }
        for c in self.captures.iter_mut() {
            if super::hitag2_bf::frame_of(c).is_ok_and(|f| f.uid == uid) {
                c.key_recovery = None;
            }
        }
        self.hitag2_key_memo.set(None);
        self.hitag2_offer_memo.set(None);
        true
    }

    /// Drop a recovered KeeLoq `BF_<serial>` that no longer decrypts this Unknown frame. Embedded
    /// manufacturer keys stay. Returns whether a BF key was removed.
    fn invalidate_stale_keeloq_bf_key(&mut self, serial: u32) -> bool {
        let name = format!("BF_{serial:07X}");
        if !keeloq_common::keeloq_keystore().iter().any(|e| e.name == name) {
            return false;
        }
        let removed = remove_keeloq_keys(&[name.as_str()]);
        let file_removed =
            crate::keystore::remove_user_keys(self.storage.config_dir(), &[name.as_str()]).unwrap_or(0);
        if removed == 0 && file_removed == 0 {
            return false;
        }
        for c in self.captures.iter_mut() {
            if Self::keeloq_remote_serial(c) == Some(serial) {
                c.key_recovery = None;
            }
        }
        true
    }

    /// Drop queued automatic searches (PSA / KeeLoq / HiTag2 / unchecked). Keeps a "Recover key"
    /// the user asked for (`asked: true`) so turning `autobf` off mid-run does not cancel that.
    pub(super) fn auto_bf_cancel_automatic(&mut self) {
        self.auto_bf
            .waiting
            .retain(|w| matches!(w, Waiting::Listed { asked: true, .. }));
    }

    /// Queue the key search of each listed capture in `ids` that needs one and has no result yet
    /// (`autobf`; nothing when it is off). PSA, KeeLoq and HiTag2. One search per remote unless a
    /// saved key fails to verify a new hop — then that key is forgotten and the search runs again.
    pub(super) fn auto_bf_listed(&mut self, ids: impl IntoIterator<Item = u32>) {
        if !self.storage.config.autobf {
            return;
        }
        for id in ids {
            let Some(c) = self.captures.iter().find(|c| c.id == id).cloned() else { continue };
            if self.key_search_planned(id) {
                continue;
            }
            // v1.22.4: PSA needs `data` as well as `data_extra`.
            if psa_needs_key_search(c.protocol_name(), c.serial, c.data, c.data_extra) {
                if c.key_recovery.is_some() {
                    continue;
                }
                if self.psa_search_for_serial_planned(c.serial) {
                    continue;
                }
                self.auto_bf.waiting.push_back(Waiting::Listed { id, asked: false });
                continue;
            }
            if Self::keeloq_bf_offered(&c) && self.keeloq_autobf_ready(id) {
                let Some(serial) = Self::keeloq_remote_serial(&c) else { continue };
                // Unknown frame but a recovered BF_ key is still on disk/session → resync.
                if self.invalidate_stale_keeloq_bf_key(serial) {
                    self.status_message = Some(format!(
                        "Saved KeeLoq key no longer fits remote {serial:07X} — recovering…"
                    ));
                }
                if self.keeloq_remote_has_key_result(serial)
                    || self.keeloq_search_for_serial_planned(serial)
                {
                    continue;
                }
                self.auto_bf.waiting.push_back(Waiting::Keeloq { id });
                continue;
            }
            if self.hitag2_bf_offered(&c) && self.hitag2_autobf_ready(id) {
                let Ok(frame) = super::hitag2_bf::frame_of(&c) else { continue };
                if self.invalidate_stale_hitag2_key(frame.uid, &c) {
                    self.status_message = Some(format!(
                        "Saved HiTag2 key no longer fits remote {:08X} — recovering…",
                        frame.uid
                    ));
                }
                if self.hitag2_remote_has_key_result(frame.uid)
                    || self.hitag2_search_for_uid_planned(frame.uid)
                {
                    continue;
                }
                self.auto_bf.waiting.push_back(Waiting::Hitag2 { id });
            }
        }
    }

    /// Whether KeeLoq magic-serial has enough hop codes for a search of this capture's remote.
    fn keeloq_autobf_ready(&self, id: u32) -> bool {
        let Some(capture) = self.captures.iter().find(|c| c.id == id) else {
            return false;
        };
        let serial = bf::Frame::from_data(capture.data).serial();
        let frames = self.keeloq_frames_of(serial);
        bf::check_input(&frames, &bf::AUTO_TYPES).is_ok()
    }

    /// Whether HiTag2 Hell has a second press of this remote to pair with.
    fn hitag2_autobf_ready(&self, id: u32) -> bool {
        use super::hitag2_bf::{frame_of, partner_of};
        let Some(capture) = self.captures.iter().find(|c| c.id == id) else {
            return false;
        };
        let Ok(f1) = frame_of(capture) else {
            return false;
        };
        partner_of(&self.captures, capture, &f1).is_some()
    }

    /// Hold a `PSA [unchecked]` frame for its key search; a copy of one already held is dropped.
    pub(super) fn auto_bf_unchecked(&mut self, capture: Capture) {
        let same = |c: &Capture| c.data == capture.data && c.data_extra == capture.data_extra;
        let held = self.auto_bf.waiting.iter().any(|w| matches!(w, Waiting::Unchecked(c) if same(c)))
            || self.psa_recover_job.as_ref().and_then(|j| j.unchecked.as_deref()).is_some_and(same);
        if !held {
            self.auto_bf.waiting.push_back(Waiting::Unchecked(Box::new(capture)));
        }
    }

    /// "Recover key" while another search runs: first in line.
    pub(super) fn queue_asked_key_search(&mut self, id: u32) {
        self.auto_bf.waiting.retain(|w| !matches!(w, Waiting::Listed { id: i, .. } if *i == id));
        self.auto_bf.waiting.push_front(Waiting::Listed { id, asked: true });
    }

    /// Whether capture `id`'s key search waits or runs (the detail panel says so).
    pub fn key_search_planned(&self, id: u32) -> bool {
        self.key_search_runs_for(id)
            || self.auto_bf.waiting.iter().any(|w| match w {
                Waiting::Listed { id: i, .. } | Waiting::Keeloq { id: i } | Waiting::Hitag2 { id: i } => *i == id,
                Waiting::Unchecked(_) => false,
            })
    }

    /// Start the next waiting search once free (every tick). PSA searches may run beside a long
    /// KeeLoq/HiTag2 one; those long ones wait until none is running.
    pub(super) fn auto_bf_tick(&mut self) {
        let mut deferred = VecDeque::new();
        while let Some(next) = self.auto_bf.waiting.pop_front() {
            match next {
                Waiting::Listed { id, asked } => {
                    if self.psa_recover_job.is_some() {
                        deferred.push_back(Waiting::Listed { id, asked });
                        continue;
                    }
                    let Some(c) = self.captures.iter().find(|c| c.id == id) else { continue };
                    if !psa_needs_key_search(c.protocol_name(), c.serial, c.data, c.data_extra) {
                        continue;
                    }
                    let (data, extra) = (c.data, c.data_extra.unwrap_or_default());
                    self.auto_bf.waiting.append(&mut deferred);
                    self.spawn_psa_job(data, extra, Some(id), None, !asked);
                    return;
                }
                Waiting::Unchecked(c) => {
                    if self.psa_recover_job.is_some() {
                        deferred.push_back(Waiting::Unchecked(c));
                        continue;
                    }
                    let (data, extra) = (c.data, c.data_extra.unwrap_or_default());
                    self.auto_bf.waiting.append(&mut deferred);
                    self.spawn_psa_job(data, extra, None, Some(c), true);
                    return;
                }
                Waiting::Keeloq { id } => {
                    if self.long_key_search_runs() || !self.keeloq_autobf_ready(id) {
                        deferred.push_back(Waiting::Keeloq { id });
                        continue;
                    }
                    self.auto_bf.waiting.append(&mut deferred);
                    self.start_keeloq_key_recovery(id, None);
                    return;
                }
                Waiting::Hitag2 { id } => {
                    if self.long_key_search_runs() || !self.hitag2_autobf_ready(id) {
                        deferred.push_back(Waiting::Hitag2 { id });
                        continue;
                    }
                    self.auto_bf.waiting.append(&mut deferred);
                    self.start_hitag2_key_recovery(id);
                    return;
                }
            }
        }
        self.auto_bf.waiting = deferred;
    }

    /// The search of listed capture `id` finished (`auto`: started by `autobf`).
    pub(super) fn psa_search_done(&mut self, id: u32, auto: bool, outcome: std::thread::Result<PsaBruteForceOutcome>) {
        match outcome {
            Ok(PsaBruteForceOutcome::Found(hit)) => {
                if let Some(c) = self.captures.iter_mut().find(|c| c.id == id) {
                    apply_psa_hit(c, &hit);
                    self.status_message = Some(format!(
                        "PSA key recovered for #{id:02} ({}): serial {:06X}, counter {:X}",
                        psa_search_label(&hit),
                        hit.fields.serial,
                        hit.fields.counter
                    ));
                }
            }
            Ok(PsaBruteForceOutcome::NotFound) => {
                if let Some(c) = self.captures.iter_mut().find(|c| c.id == id) {
                    c.key_recovery = Some(KeyRecovery::NotFound(PSA_SEARCH_LABEL_ALL.to_string()));
                }
                let msg = format!("No PSA key found for #{id:02} (BF1 and BF2 searched)");
                if auto {
                    self.status_message = Some(msg);
                } else {
                    self.last_error = Some(msg);
                }
            }
            Ok(PsaBruteForceOutcome::Cancelled) => {
                self.status_message = Some(format!("Key recovery for #{id:02} cancelled"));
            }
            Err(_) => self.last_error = Some("Key recovery thread failed".to_string()),
        }
    }

    /// The search of a `PSA [unchecked]` frame finished: listed with its fields if the key was
    /// found, dropped otherwise (it was noise).
    pub(super) fn unchecked_search_done(&mut self, mut frame: Capture, outcome: std::thread::Result<PsaBruteForceOutcome>) {
        match outcome {
            Ok(PsaBruteForceOutcome::Found(hit)) => {
                apply_psa_hit(&mut frame, &hit);
                if let Some(id) = self.list_received(frame) {
                    self.status_message = Some(format!(
                        "New signal captured: PSA #{id:02}, key recovered ({}): serial {:06X}",
                        psa_search_label(&hit),
                        hit.fields.serial
                    ));
                }
            }
            Ok(_) => tracing::debug!(
                "PSA [unchecked] frame {:016X}/{:X}: no key, dropped",
                frame.data,
                frame.data_extra.unwrap_or_default()
            ),
            Err(_) => self.last_error = Some("Key recovery thread failed".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{PsaBruteForceControl, PsaBruteForceOutcome};

    /// A recovered key makes the capture plain PSA with its fields, encoder-capable and marked as
    /// recovered by BF1 (one of the tester's doctor-firmware key files: serial 0x01124A).
    #[test]
    fn a_recovered_key_fills_the_capture() {
        let mut c = Capture::from_pairs_with_rf(1, 433_920_000, Vec::new(), None);
        c.protocol = Some(crate::protocols::PSA_UNCHECKED_NAME.to_string());
        c.data = 0xF1BA_BAE6_408C_36EE;
        c.data_extra = Some(0x9BA4);
        let PsaBruteForceOutcome::Found(hit) =
            crate::protocols::psa_recover_key(c.data, 0x9BA4, &PsaBruteForceControl::default())
        else {
            panic!("no key");
        };
        apply_psa_hit(&mut c, &hit);
        assert_eq!((c.protocol.as_deref(), c.serial), (Some("PSA"), Some(0x01124A)));
        assert_eq!(c.status, CaptureStatus::EncoderCapable);
        assert_eq!(c.key_recovery, Some(KeyRecovery::Recovered("PSA BF1".to_string())));
        assert!(!psa_needs_key_search(c.protocol_name(), c.serial, c.data, c.data_extra));
    }

    /// Turning `autobf` off drops queued automatic searches but keeps a user "Recover key".
    #[test]
    fn cancel_automatic_keeps_asked_recover_key() {
        let mut bf = AutoBf::default();
        bf.waiting.push_back(Waiting::Keeloq { id: 1 });
        bf.waiting.push_back(Waiting::Listed { id: 2, asked: true });
        bf.waiting.push_back(Waiting::Hitag2 { id: 3 });
        bf.waiting.push_back(Waiting::Unchecked(Box::new(Capture::from_pairs(
            9,
            433_920_000,
            Vec::new(),
        ))));
        bf.waiting
            .retain(|w| matches!(w, Waiting::Listed { asked: true, .. }));
        assert_eq!(bf.waiting.len(), 1);
        assert!(matches!(
            bf.waiting.front(),
            Some(Waiting::Listed { id: 2, asked: true })
        ));
    }
}
