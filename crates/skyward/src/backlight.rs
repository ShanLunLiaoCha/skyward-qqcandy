//! Backlight is optional for first boot: do not make Qualcomm-only panel
//! metadata a prerequisite for a MediaTek DRM framebuffer.
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub struct Backlight {
    path: Option<PathBuf>,
    top: u32,
    pub(crate) level: u32,
    needs_write: bool,
    mtk_led: bool,
    cold_init: bool,
}

impl Backlight {
    pub fn open() -> Self {
        match Self::from_root(Path::new("/sys/class/backlight")).or_else(|_| Self::from_leds(Path::new("/sys/class/leds"))) {
            Ok(backlight) => backlight,
            Err(error) => {
                eprintln!("backlight control unavailable; preserving bootloader brightness: {error:#}");
                Self { path: None, top: 1, level: 1, needs_write: false, mtk_led: false, cold_init: false }
            }
        }
    }

    fn from_root(root: &Path) -> Result<Self> {
        let mut dirs: Vec<_> = std::fs::read_dir(root)?.map(|entry| entry.map(|entry| entry.path())).collect::<std::io::Result<_>>()?;
        dirs.sort_by_key(|path| (path.file_name().is_none_or(|name| name != "panel0-backlight"), path.clone()));
        Self::from_dirs(dirs)
    }

    fn from_leds(root: &Path) -> Result<Self> {
        // Do not control an arbitrary status/charging LED. This exact label
        // is confirmed in PGZ110's original MTK device tree.
        Self::from_dirs(vec![root.join("lcd-backlight")])
    }

    fn from_dirs(dirs: Vec<PathBuf>) -> Result<Self> {
        for dir in dirs {
            let read = |name: &str| -> Result<u32> {
                std::fs::read_to_string(dir.join(name))?.trim().parse().with_context(|| format!("parse {name}"))
            };
            let Ok(top) = read("max_brightness") else { continue };
            if top == 0 { continue; }
            let Ok(level) = read("brightness") else { continue };
            // Hardware's advertised range, never guessed Qualcomm DT paths.
            let mtk_led = dir.file_name().is_some_and(|name| name == "lcd-backlight");
            return Ok(Self { path: Some(dir.join("brightness")), top, level, needs_write: true, mtk_led, cold_init: mtk_led });
        }
        anyhow::bail!("no readable backlight with nonzero maximum")
    }

    /// Any modeset can reset panel brightness without changing the LED
    /// class's cached value. Force the next show after hardware reinitialises.
    pub fn invalidate(&mut self) { self.needs_write = true; }

    pub fn show(&mut self, level: Option<f32>) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let raw = level.map_or(0, |value| ((value.clamp(0.0, 1.0) * self.top as f32).round() as u32).max(1));
        if raw != self.level || self.needs_write {
            if self.mtk_led && self.cold_init && self.level == 0 && raw > 0 {
                // If LED cache starts at zero, another zero event is suppressed
                // before the AAL notifier. Prime once, then establish 0->target.
                std::fs::write(path, raw.to_string()).with_context(|| format!("prime first MTK AAL event at {}", path.display()))?;
            }
            if reset_led_before_write(self.mtk_led, self.needs_write || self.cold_init, raw) {
                // MTK LED/AAL state can survive a panel reset independently
                // of our cached brightness. Fresh device logs show the first
                // nonzero request did NOT reach set_hw even when our cached
                // value differed. Establish zero->target after all modesets,
                // rather than requiring a manual Power off/on cycle.
                if let Err(error) = std::fs::write(path, "0") {
                    eprintln!("could not reset stale LED brightness cache at {}: {error}; attempting target brightness", path.display());
                }
            }
            if let Err(error) = std::fs::write(path, raw.to_string()) {
                // A late/unwritable MTK node must not tear down a working UI.
                eprintln!("backlight write failed; disabling control at {}: {error}", path.display());
                self.path = None;
                return Ok(());
            }
            eprintln!("backlight restored/written raw={raw} max={}", self.top);
            self.level = raw;
            self.needs_write = false;
            if raw > 0 { self.cold_init = false; }
        }
        Ok(())
    }
}

fn reset_led_before_write(mtk_led: bool, invalidated: bool, target: u32) -> bool {
    mtk_led && invalidated && target > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(root: &Path, name: &str, max: &str, level: &str) {
        let dir = root.join(name);std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("max_brightness"), max).unwrap();
        std::fs::write(dir.join("brightness"), level).unwrap();
    }
    #[test]
    fn first_mtk_aal_event_is_primed_regardless_of_cached_brightness() {
        // This decision deliberately does not take cached brightness: the
        // AAL enable handshake, not numeric equality, is the actual boundary.
        assert!(reset_led_before_write(true, true, 1607));
        assert!(!reset_led_before_write(true, false, 1607));
        assert!(!reset_led_before_write(true, true, 0));
        assert!(!reset_led_before_write(false, true, 1607));
    }
    #[test]
    fn mtk_node_works_without_any_qcom_sysfs_or_device_tree() {
        let root = tempfile::tempdir().unwrap();node(root.path(), "mtk-leds", "2047\n", "512\n");
        let mut backlight = Backlight::from_root(root.path()).unwrap();
        backlight.show(Some(0.5)).unwrap();
        assert_eq!(std::fs::read_to_string(root.path().join("mtk-leds/brightness")).unwrap(), "1024");
        backlight.show(None).unwrap();
        assert_eq!(std::fs::read_to_string(root.path().join("mtk-leds/brightness")).unwrap(), "0");
    }
    #[test]
    fn exact_mtk_led_label_only_never_notification_led() {
        let root = tempfile::tempdir().unwrap();node(root.path(), "charging", "255", "50");
        assert!(Backlight::from_leds(root.path()).is_err());
        node(root.path(), "lcd-backlight", "255", "50");
        let mut backlight = Backlight::from_leds(root.path()).unwrap();
        backlight.show(Some(0.5)).unwrap();
        assert_eq!(std::fs::read_to_string(root.path().join("charging/brightness")).unwrap(), "50");
        assert_eq!(std::fs::read_to_string(root.path().join("lcd-backlight/brightness")).unwrap(), "128");
    }
    #[test]
    fn completed_modeset_invalidates_same_brightness_cache() {
        let root = tempfile::tempdir().unwrap();node(root.path(), "mtk", "1000", "500");
        let mut backlight = Backlight::from_root(root.path()).unwrap();
        backlight.show(Some(0.5)).unwrap();
        let file = root.path().join("mtk/brightness");
        // Model panel reset after modeset while userspace cache stays 500.
        std::fs::write(&file, "0").unwrap();
        backlight.invalidate();backlight.show(Some(0.5)).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "500");
        assert!(!backlight.needs_write);
    }
    #[test]
    fn malformed_and_zero_nodes_are_skipped() {
        let root = tempfile::tempdir().unwrap();node(root.path(), "a-zero", "0", "0");node(root.path(), "b-bad", "NaN", "4");
        assert!(Backlight::from_root(root.path()).is_err());
        node(root.path(), "c-mtk", "255", "4");assert_eq!(Backlight::from_root(root.path()).unwrap().top, 255);
    }
    #[test]
    fn optional_control_and_late_failure_do_not_abort_ui() {
        let mut absent = Backlight { path: None, top: 1, level: 1, needs_write: false, mtk_led: false, cold_init: false };absent.show(Some(0.4)).unwrap();
        let root = tempfile::tempdir().unwrap();node(root.path(), "mtk", "255", "4");
        let mut backlight = Backlight::from_root(root.path()).unwrap();
        let path = root.path().join("mtk/brightness");std::fs::remove_file(&path).unwrap();std::fs::create_dir(&path).unwrap();
        backlight.show(Some(0.4)).unwrap();assert!(backlight.path.is_none());
    }
}
