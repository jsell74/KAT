//! Flipper key files in the app (`docs/flipper_key_files.md`).
//!
//! - **Load**: a `.sub` without `RAW_Data` (`:load`, the load browser, the startup import) is a
//!   decoded key. The importer (`app/files.rs`) rebuilds its decode with the protocol's
//!   `from_flipper_key` (`crate::export::flipper::capture_from_key`): a capture with the protocol
//!   and fields, the file's frequency and preset, no raw pairs, and EncoderCapable when the encoder
//!   can transmit it.
//! - **Signal menu**: captures without raw pairs (key files, `.fob` files saved without pairs)
//!   cannot be replayed, exported as RAW `.sub` or timing-analysed, so those actions are hidden
//!   ([`App::adjust_signal_actions`]); TX Lock/Unlock/Trunk/Panic and "Send next code" re-encode
//!   from the fields and work as for any capture. "Export Flipper key" appears for every capture
//!   whose protocol writes key files.
//! - **Export**: [`App::export_flipper_key`] / [`App::complete_flipper_key_export`] write
//!   `<name>_key.sub` (so it does not take the RAW export's name) with the protocol's
//!   `to_flipper_key` (its reference's `serialize`), never over an existing file.
//! - **Push to Flipper**: [`App::push_to_flipper`] writes the key file (or RAW `.sub`) onto the
//!   Flipper's SD card at `/ext/subghz/…` over the USB console. [`App::push_all_visible_to_flipper`]
//!   (`:pushflipper`) does the same for every capture the list shows. Bluetooth file transfer is
//!   not supported on macOS (no CDC serial over BLE); USB is the path KAT already uses.

use anyhow::Result;

use super::{App, ExportFormat, InputMode, RadioDevice, SignalAction};
use super::files::safe_stem;
use super::hitag2_bf::{self, Hitag2KeyReport};
use crate::capture::{Capture, CaptureStatus};
use crate::export::flipper;
use crate::protocols::hitag2_keys;
use crate::protocols::keeloq_common::keeloq_keystore;
use crate::protocols::ProtocolRegistry;
use crate::radio::devices::RadioKind;
use crate::radio::SUBGHZ_DIR;

/// Bytes and SD path for a capture pushed to `/ext/subghz` (key file preferred, else RAW).
fn flipper_push_payload(
    capture: &Capture,
    protocols: &ProtocolRegistry,
) -> Result<(Vec<u8>, String, &'static str), String> {
    let (bytes, kind) = match flipper::capture_flipper_key(capture, protocols) {
        Some(key) => (key.to_text().into_bytes(), "key"),
        None if capture.has_raw_data() => flipper::flipper_sub_text(capture)
            .map(|text| (text.into_bytes(), "RAW"))
            .map_err(|e| format!("Could not build .sub: {e:#}"))?,
        None => {
            return Err(format!(
                "{} has no Flipper key file and no raw pairs to push",
                capture.protocol_name()
            ));
        }
    };
    let stem = if kind == "key" {
        format!("{}_key", App::default_export_filename(capture))
    } else {
        App::default_export_filename(capture)
    };
    // Capture ID keeps each push unique when several remotes share the same name.
    let name = format!("{}_{:02}.sub", safe_stem(&stem), capture.id);
    Ok((bytes, format!("{SUBGHZ_DIR}/{name}"), kind))
}

/// The signal menu for a capture: without raw pairs no Replay, no RAW `.sub` export and no timing
/// analysis (they need the pairs); "Export Flipper key" right after the RAW export's place (or
/// the `.fob` export's) when `key_file` (the protocol writes the capture as a key file).
/// `push_flipper`: a Flipper Zero is plugged in, so "Push to Flipper" is offered when a key or
/// RAW `.sub` can be written.
pub(super) fn fit_signal_actions(
    actions: &mut Vec<SignalAction>,
    has_raw: bool,
    key_file: bool,
    push_flipper: bool,
) {
    if !has_raw {
        actions.retain(|a| !matches!(a, SignalAction::Replay | SignalAction::ExportFlipper | SignalAction::Analyze));
    }
    if key_file {
        let at = actions
            .iter()
            .position(|a| matches!(a, SignalAction::ExportFlipper))
            .or_else(|| actions.iter().position(|a| matches!(a, SignalAction::ExportFob)))
            .map_or(actions.len(), |i| i + 1);
        actions.insert(at, SignalAction::ExportFlipperKey);
    }
    if push_flipper && (key_file || has_raw) {
        // After the last Flipper export action (key file preferred over RAW).
        let at = actions
            .iter()
            .rposition(|a| {
                matches!(
                    a,
                    SignalAction::ExportFlipperKey | SignalAction::ExportFlipper | SignalAction::ExportFob
                )
            })
            .map_or(actions.len(), |i| i + 1);
        actions.insert(at, SignalAction::PushToFlipper);
    }
}

/// Whether the capture's encoder produces a frame from its stored fields (what TX uses).
pub(super) fn encoder_works(registry: &ProtocolRegistry, capture: &Capture) -> bool {
    let d = capture.decoded_signal();
    capture
        .protocol
        .as_deref()
        .and_then(|p| registry.get(p))
        .is_some_and(|p| p.supports_encoding() && p.encode(&d, d.button.unwrap_or(0)).is_some())
}

/// A capture from a `.fob` saved without raw pairs keeps "EncoderCapable" only when its encoder
/// produces a frame from the stored fields (TX needs nothing else); otherwise it is Decoded.
pub(super) fn fit_encoder_status(registry: &ProtocolRegistry, capture: &mut Capture) {
    if !capture.has_raw_data() && capture.status == CaptureStatus::EncoderCapable && !encoder_works(registry, capture) {
        capture.status = CaptureStatus::Decoded;
    }
}

/// Whether the signal menu offers "Show key": protocol known (Decoded / Encode).
pub(super) fn show_key_offered(capture: &Capture) -> bool {
    matches!(
        capture.status,
        CaptureStatus::Decoded | CaptureStatus::EncoderCapable
    ) && capture.protocol.is_some()
}

/// Whether "Delete key" is offered: a HiTag2 UID key in `hitag2_keys`, or a KeeLoq `BF_<serial>`.
pub(super) fn delete_key_offered(capture: &Capture) -> bool {
    if let Ok(frame) = hitag2_bf::frame_of(capture) {
        if hitag2_keys::find(frame.uid).and_then(|r| r.key).is_some() {
            return true;
        }
    }
    if let Some(serial) = capture.serial {
        let name = format!("BF_{serial:07X}");
        if keeloq_keystore().iter().any(|e| e.name == name) {
            return true;
        }
    }
    false
}

/// KeeLoq manufacturer / recovered (`BF_<serial>`) key line, if the keystore has it.
fn keeloq_key_line(capture: &Capture) -> Option<String> {
    if let Some(serial) = capture.serial {
        let name = format!("BF_{serial:07X}");
        if let Some(e) = keeloq_keystore().iter().find(|e| e.name == name) {
            return Some(format!("KeeLoq recovered key {name}: {:016X}", e.key));
        }
    }
    let proto = capture.protocol.as_deref()?;
    let mf = proto.strip_prefix("KeeLoq (")?.strip_suffix(')')?;
    if mf.eq_ignore_ascii_case("Unknown") {
        return None;
    }
    let e = keeloq_keystore().iter().find(|e| e.name == mf)?;
    Some(format!("KeeLoq manufacturer key ({mf}): {:016X}", e.key))
}

/// Flipper `Key:` bytes as spaced hex, when the protocol writes a key file.
fn flipper_key_line(capture: &Capture, protocols: &ProtocolRegistry) -> Option<String> {
    let key = flipper::capture_flipper_key(capture, protocols)?;
    let hex = if key.key_bytes.is_empty() {
        format!("{:016X}", key.key)
    } else {
        key.key_bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
    };
    let mut line = format!("Flipper Key: {hex}");
    if let Some((_, v)) = key.fields.iter().find(|(n, _)| n.eq_ignore_ascii_case("Hitag2 Key")) {
        line.push_str(&format!(" · Hitag2 Key: {v}"));
    }
    if let Some((_, v)) = key.fields.iter().find(|(n, _)| n.eq_ignore_ascii_case("Manufacture")) {
        line.push_str(&format!(" · Manufacture: {v}"));
    }
    Some(line)
}

/// Status-line text for "Show key" (crypto key when known, else frame Key/Data).
pub(super) fn capture_key_status_text(capture: &Capture, protocols: &ProtocolRegistry) -> String {
    let mut parts = Vec::new();
    if let Some(line) = keeloq_key_line(capture) {
        parts.push(line);
    }
    if let Some(shown) = hitag2_keys::shown_key(capture.protocol_name(), &capture.decoded_signal()) {
        parts.push(format!("HiTag2: {}", hitag2_keys::hex(&shown.standard, "")));
        if let Some(fiat) = shown.fiat_order() {
            parts.push(format!("Fiat order: {}", hitag2_keys::hex(&fiat, "")));
        }
    }
    if let Some(line) = flipper_key_line(capture, protocols) {
        parts.push(line);
    }
    if parts.is_empty() {
        if capture.data_count_bit > 0 {
            format!(
                "#{:02} {}: Key/Data 0x{} ({} bits)",
                capture.id,
                capture.protocol_name(),
                capture.data_hex(),
                capture.data_count_bit
            )
        } else {
            format!("#{:02} {}: no key stored on this capture", capture.id, capture.protocol_name())
        }
    } else {
        format!("#{:02} {}: {}", capture.id, capture.protocol_name(), parts.join(" · "))
    }
}

impl App {
    /// Whether the capture's protocol writes it as a Flipper key file.
    pub fn can_export_flipper_key(&self, capture: &Capture) -> bool {
        flipper::capture_flipper_key(capture, &self.protocols).is_some()
    }

    /// Insert "Show key" / "Delete key" just before "Delete signal" when the capture is decoded.
    pub(super) fn insert_key_menu_actions(&self, actions: &mut Vec<SignalAction>) {
        let Some(c) = self.signal_menu_capture() else { return };
        let at = actions
            .iter()
            .position(|a| matches!(a, SignalAction::Delete))
            .unwrap_or(actions.len());
        let mut insert_at = at;
        if show_key_offered(c) && !actions.iter().any(|a| matches!(a, SignalAction::ShowKey)) {
            actions.insert(insert_at, SignalAction::ShowKey);
            insert_at += 1;
        }
        if delete_key_offered(c) && !actions.iter().any(|a| matches!(a, SignalAction::DeleteKey)) {
            actions.insert(insert_at, SignalAction::DeleteKey);
        }
    }

    /// "Show key": Hitag2 opens the key overlay when known; otherwise the status line carries the
    /// manufacturer / Flipper / Key/Data hex.
    pub fn show_capture_key(&mut self, id: u32) {
        let Some(capture) = self.captures.iter().find(|c| c.id == id).cloned() else {
            self.last_error = Some(format!("Capture #{id:02} not found"));
            return;
        };
        if let (Ok(frame), Some(shown)) = (
            hitag2_bf::frame_of(&capture),
            self.hitag2_shown_key(&capture),
        ) {
            self.hitag2_key_report = Some(Hitag2KeyReport {
                uid: frame.uid,
                remote: frame.remote,
                key: shown,
                took: "already known".to_string(),
                saved: "from hitag2_keys / this session".to_string(),
                captures: 1,
            });
            self.overlay_scroll = 0;
            self.input_mode = InputMode::Hitag2Key;
            self.status_message = Some(format!(
                "HiTag2 key of remote {:08X}: {}",
                frame.uid,
                hitag2_keys::hex(&shown.standard, "")
            ));
            return;
        }
        self.status_message = Some(capture_key_status_text(&capture, &self.protocols));
    }

    /// "Delete key": drop the saved HiTag2 / KeeLoq `BF_<serial>` key for this remote (not the
    /// capture row). Embedded manufacturer keys stay.
    pub fn delete_capture_key(&mut self, id: u32) {
        let Some(capture) = self.captures.iter().find(|c| c.id == id).cloned() else {
            self.last_error = Some(format!("Capture #{id:02} not found"));
            return;
        };
        let mut done: Vec<String> = Vec::new();

        if let Ok(frame) = hitag2_bf::frame_of(&capture) {
            if hitag2_keys::forget_key(frame.uid) {
                done.push(format!("HiTag2 UID {:08X}", frame.uid));
                for c in self.captures.iter_mut() {
                    if hitag2_bf::frame_of(c).is_ok_and(|f| f.uid == frame.uid) {
                        c.key_recovery = None;
                    }
                }
                self.hitag2_key_memo.set(None);
                self.hitag2_offer_memo.set(None);
            }
        }

        if let Some(serial) = capture.serial {
            let name = format!("BF_{serial:07X}");
            let removed = crate::protocols::keeloq_common::remove_keeloq_keys(&[name.as_str()]);
            let file_removed = crate::keystore::remove_user_keys(self.storage.config_dir(), &[name.as_str()])
                .unwrap_or(0);
            if removed > 0 || file_removed > 0 {
                done.push(name.clone());
                for c in self.captures.iter_mut() {
                    if c.serial == Some(serial) {
                        c.key_recovery = None;
                    }
                }
            }
        }

        if done.is_empty() {
            self.last_error = Some(
                "No saved key to delete for this signal (only HiTag2 UID keys and KeeLoq BF_<serial> recovered keys)"
                    .to_string(),
            );
        } else {
            self.status_message = Some(format!(
                "Deleted key{}: {} (signal kept — use Delete signal to remove the capture)",
                if done.len() == 1 { "" } else { "s" },
                done.join(", ")
            ));
        }
    }

    /// Fit the signal menu to the selected capture: without raw pairs, no Replay, no RAW `.sub`
    /// export and no Analyze; "Export Flipper key" (after the RAW export's place) when
    /// the protocol writes key files; "Push to Flipper" when a Flipper is available.
    pub(super) fn adjust_signal_actions(&self, actions: &mut Vec<SignalAction>) {
        if let Some(c) = self.signal_menu_capture() {
            let push = self.radios.iter().any(|r| r.kind() == RadioKind::Flipper);
            fit_signal_actions(actions, c.has_raw_data(), self.can_export_flipper_key(c), push);
        }
    }

    /// The Flipper to push files to: the TX radio when it is a Flipper, else the first Flipper.
    fn flipper_for_push(&mut self) -> Option<&mut crate::radio::FlipperController> {
        let prefer = self.tx_radio().filter(|&i| self.radios[i].kind() == RadioKind::Flipper);
        let i = prefer.or_else(|| self.radios.iter().position(|r| r.kind() == RadioKind::Flipper))?;
        match &mut self.radios[i].device {
            RadioDevice::Flipper(f) => Some(f),
            _ => None,
        }
    }

    fn no_flipper_for_push_msg() -> String {
        "No Flipper Zero on USB (close qFlipper, plug it in, then :radios). \
         Bluetooth push is not supported on macOS."
            .to_string()
    }

    /// Write prepared `.sub` bytes to `path` on the Flipper SD card.
    fn write_push_to_flipper(&mut self, path: &str, bytes: &[u8]) -> Result<(), String> {
        let Some(flipper) = self.flipper_for_push() else {
            return Err(Self::no_flipper_for_push_msg());
        };
        flipper.write_sd_file(path, bytes).map_err(|e| format!("Push to Flipper failed: {e:#}"))
    }

    /// Push the capture's Flipper key file (preferred) or RAW `.sub` onto the Flipper's SD card
    /// at `/ext/subghz/<name>_<id>.sub` over USB. Bluetooth is not used (see module docs).
    pub fn push_to_flipper(&mut self, id: u32) {
        let Some(capture) = self.captures.iter().find(|c| c.id == id).cloned() else {
            self.last_error = Some(format!("Capture #{id:02} not found"));
            return;
        };
        let (bytes, path, kind) = match flipper_push_payload(&capture, &self.protocols) {
            Ok(v) => v,
            Err(e) => {
                self.last_error = Some(e);
                return;
            }
        };
        match self.write_push_to_flipper(&path, &bytes) {
            Ok(()) => {
                self.status_message = Some(format!("Pushed {kind} .sub to Flipper {path} (USB)"));
            }
            Err(e) => self.last_error = Some(e),
        }
    }

    /// `:pushflipper`: push every capture the list shows (filter + Unknown setting) to
    /// `/ext/subghz` over USB. Skips ones with neither a key file nor raw pairs; status line
    /// reports how many succeeded and which failed.
    pub fn push_all_visible_to_flipper(&mut self) {
        if self.flipper_for_push().is_none() {
            self.last_error = Some(Self::no_flipper_for_push_msg());
            return;
        }
        let view = self.visible_captures();
        if view.is_empty() {
            self.status_message = Some("No captures to push (the list is empty)".to_string());
            return;
        }
        let jobs: Vec<(u32, Result<(Vec<u8>, String, &'static str), String>)> = view
            .iter()
            .filter_map(|&i| self.captures.get(i).map(|c| (c.id, flipper_push_payload(c, &self.protocols))))
            .collect();
        let skip = jobs.iter().filter(|(_, r)| r.is_err()).count();
        let mut ok = 0usize;
        let mut failed: Vec<String> = Vec::new();
        let total = jobs.len();
        for (n, (id, prepared)) in jobs.into_iter().enumerate() {
            match prepared {
                Err(_) => {
                    // Already counted as skip: no key and no raw.
                }
                Ok((bytes, path, _)) => {
                    self.status_message =
                        Some(format!("Pushing to Flipper… {}/{} (#{id:02})", n + 1, total));
                    match self.write_push_to_flipper(&path, &bytes) {
                        Ok(()) => ok += 1,
                        Err(e) => failed.push(format!("#{id:02}: {e}")),
                    }
                }
            }
        }
        let skipped = skip;
        if ok == 0 && failed.is_empty() {
            self.last_error = Some(format!(
                "Nothing to push: {skipped} visible capture(s) have no Flipper key/RAW"
            ));
            return;
        }
        let mut msg = format!("Pushed {ok} of {total} to Flipper (/ext/subghz)");
        if skipped > 0 {
            msg.push_str(&format!(" · {skipped} skipped (no key/RAW)"));
        }
        if failed.is_empty() {
            self.status_message = Some(msg);
        } else {
            let ids: Vec<&str> = failed.iter().map(|s| s.split(':').next().unwrap_or(s.as_str())).collect();
            msg.push_str(&format!(" · {} failed ({})", failed.len(), ids.join(", ")));
            self.last_error = Some(msg);
            // Keep the first failure detail in the log.
            if let Some(first) = failed.first() {
                tracing::warn!("Push all to Flipper: {first}");
            }
        }
    }

    /// Start a Flipper key file export: ask for the file name (default: the RAW export's with
    /// `_key`, so a capture's two exports do not share a name).
    pub fn export_flipper_key(&mut self, id: u32) -> Result<()> {
        let Some(capture) = self.captures.iter().find(|c| c.id == id) else {
            self.last_error = Some(format!("Capture #{:02} not found", id));
            return Ok(());
        };
        if !self.can_export_flipper_key(capture) {
            self.last_error = Some(format!("{} captures cannot be saved as a Flipper key file", capture.protocol_name()));
            return Ok(());
        }
        self.export_filename = format!("{}_key", Self::default_export_filename(capture));
        self.export_capture_id = Some(id);
        self.export_format = Some(ExportFormat::FlipperKey);
        self.input_mode = InputMode::ExportFilename;
        Ok(())
    }

    /// Write the Flipper key file (called after the file name is confirmed). Never over an
    /// existing file; a failure is reported in the status line (app/files.rs).
    pub fn complete_flipper_key_export(&mut self) -> Result<()> {
        let Some(id) = self.export_capture_id else {
            self.last_error = Some("No capture selected for export".to_string());
            return Ok(());
        };
        let Some(capture) = self.captures.iter().find(|c| c.id == id).cloned() else {
            self.last_error = Some(format!("Capture #{:02} not found", id));
            return Ok(());
        };
        self.export_capture_id = None;
        self.export_format = None;
        match self.export_path(&self.export_filename, "sub") {
            Ok(path) => {
                let result = flipper::export_flipper_key(&capture, &self.protocols, &path);
                self.report_export(&path, result);
            }
            Err(e) => self.last_error = Some(e),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::StoredLevelDuration;

    #[test]
    fn show_key_is_for_decoded_captures_only() {
        let mut c = Capture::from_pairs(1, 433_920_000, Vec::new());
        assert!(!show_key_offered(&c));
        c.protocol = Some("Acme".into());
        c.status = CaptureStatus::Decoded;
        assert!(show_key_offered(&c));
        c.status = CaptureStatus::EncoderCapable;
        assert!(show_key_offered(&c));
        assert!(!delete_key_offered(&c), "no saved HiTag2/BF key");
    }

    #[test]
    fn push_payload_names_include_the_capture_id() {
        let reg = ProtocolRegistry::new();
        let text = "Filetype: Flipper SubGhz Key File\nVersion: 1\nFrequency: 433920000\n\
                    Preset: FuriHalSubGhzPreset2FSKDev476Async\nProtocol: Kia V0\nBit: 61\n\
                    Key: 0F 73 91 67 BD 75 B2 BD\n";
        let key = crate::protocols::FlipperKey::parse(text).unwrap();
        let c = flipper::capture_from_key(&key, &reg, 7).unwrap();
        let (_, path, kind) = flipper_push_payload(&c, &reg).unwrap();
        assert_eq!(kind, "key");
        assert!(path.starts_with("/ext/subghz/"), "{path}");
        assert!(path.ends_with("_07.sub"), "{path}");
        let empty = Capture::from_pairs(3, 433_920_000, Vec::new());
        assert!(flipper_push_payload(&empty, &reg).is_err());
    }

    /// Captures without raw pairs lose Replay, the RAW export and Analyze; the key-file
    /// export sits after the RAW export (or the .fob export when the RAW one is gone).
    #[test]
    fn signal_menu_fits_the_capture() {
        use SignalAction::*;
        let car = SignalAction::ALL.to_vec();
        let mut a = car.clone();
        fit_signal_actions(&mut a, true, false, false);
        assert_eq!(a, car);
        let mut a = car.clone();
        fit_signal_actions(&mut a, true, true, false);
        assert_eq!(a, [Replay, Lock, Unlock, Trunk, Panic, ExportFob, ExportFlipper, ExportFlipperKey, Analyze, Delete]);
        let mut a = car.clone();
        fit_signal_actions(&mut a, false, true, false);
        assert_eq!(a, [Lock, Unlock, Trunk, Panic, ExportFob, ExportFlipperKey, Delete]);
        let gate = vec![Replay, SendNextCode, ExportFob, ExportFlipper, Analyze, Delete];
        let mut a = gate.clone();
        fit_signal_actions(&mut a, false, true, false);
        assert_eq!(a, [SendNextCode, ExportFob, ExportFlipperKey, Delete]);
        let mut a = vec![ExportFob, ExportFlipper, Analyze, Delete];
        fit_signal_actions(&mut a, false, false, false);
        assert_eq!(a, [ExportFob, Delete]);
        let mut a = car.clone();
        fit_signal_actions(&mut a, true, true, true);
        assert_eq!(
            a,
            [
                Replay, Lock, Unlock, Trunk, Panic, ExportFob, ExportFlipper, ExportFlipperKey, PushToFlipper,
                Analyze, Delete
            ]
        );
    }

    /// The default export name never contains a path separator (makes such as "Kia/Hyundai").
    #[test]
    fn default_export_name_is_a_plain_file_name() {
        let mut c = Capture::from_pairs(1, 433_920_000, Vec::new());
        c.protocol = Some("Kia V0".into());
        c.button = Some(2);
        let name = App::default_export_filename(&c);
        assert_eq!(name, "Unknown_Kia-Hyundai_Unknown_Unknown_Unlock");
        c.make = Some("Honda/Acura".into());
        assert!(!App::default_export_filename(&c).contains('/'));
        // What the export form builds from its fields is the same name: an empty field is Unknown.
        assert_eq!(App::export_stem("", "Kia/Hyundai", " ", "", "Unlock"), name);
        assert_eq!(App::export_stem("2015", "Kia", "Sportage SX", "NA", "-"), "2015_Kia_Sportage_SX_NA_Unknown");
        // An unknown capture has nothing to name it by.
        let unknown = Capture::from_pairs(2, 433_920_000, Vec::new());
        assert_eq!(App::default_export_filename(&unknown), "Unknown_Unknown_Unknown_Unknown_Unknown");
    }

    /// A key-file capture saved as `.fob` (no raw pairs) imports EncoderCapable again: its encoder
    /// works from the stored fields. A capture whose encoder cannot transmit does not.
    #[test]
    fn fob_without_pairs_keeps_tx_when_the_encoder_works() {
        let reg = ProtocolRegistry::new();
        let text = "Filetype: Flipper SubGhz Key File\nVersion: 1\nFrequency: 433920000\n\
                    Preset: FuriHalSubGhzPreset2FSKDev476Async\nProtocol: Kia V0\nBit: 61\n\
                    Key: 0F 73 91 67 BD 75 B2 BD\n";
        let key = crate::protocols::FlipperKey::parse(text).unwrap();
        let c = flipper::capture_from_key(&key, &reg, 1).unwrap();
        let path = std::env::temp_dir().join(format!("kat_key_fob_{}.fob", std::process::id()));
        crate::export::fob::export_fob(&c, &path, true, None).unwrap();
        let imported = crate::export::fob::import_fob(&path, 2);
        let _ = std::fs::remove_file(&path);
        let imported = imported.unwrap();
        assert!(imported.raw_pairs.is_empty());
        assert_eq!(imported.status, CaptureStatus::EncoderCapable);
        assert!(encoder_works(&reg, &imported));
        assert_eq!(imported.decoded_signal(), c.decoded_signal());
        assert_eq!(imported.rf_preset, c.rf_preset);

        let mut unknown = Capture::from_pairs(3, 433_920_000, vec![StoredLevelDuration { level: true, duration_us: 1 }]);
        unknown.protocol = Some("No Such Protocol".into());
        assert!(!encoder_works(&reg, &unknown));
    }
}
