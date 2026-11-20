//! The reviewed single-A Virtual A/B restore, started from the ordinary
//! Recovery install page once the user confirms the overwrite.
//!
//! This path never enters maintenance mode, never hands the package to the
//! OEM `update_engine`, and never writes the physical LUNs behind the
//! preloader mappings. Staged images live on the data partition, which the
//! restore does not write.
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Where the two externally supplied logical replacements are looked up.
/// They are not part of the official package, so the phone needs them as
/// ordinary files beside the package or in this folder.
const STAGING: &str = "/sdcard/Skyward";
const COMPANY: &str = "my_company.img";
const PRELOAD: &str = "my_preload.img";

#[cfg(target_os = "android")]
pub fn run(cfg: &skyward_config::DeviceConfig, package: &Path, selected: &Path,
    disable_avb: bool, cancelled: &dyn Fn() -> bool, first_write: &dyn Fn()) -> Result<()> {
    use anyhow::ensure;
    use skyward_config::RecoveryPartition;
    ensure!(cfg.device.codename == "OP5911"
        && cfg.device.recovery_partition == RecoveryPartition::VendorBoot,
        "single-A restore is only supported on PGZ110 vendor_boot Recovery");
    ensure!(disable_avb, "this restore retains Skyward; enable the install page's AVB-off option before confirming");
    let device_state = skyward_sys::prop("ro.boot.vbmeta.device_state");
    let flash_locked = skyward_sys::prop("ro.boot.flash.locked");
    let boot_state = skyward_sys::prop("ro.boot.verifiedbootstate");
    ensure!(unlocked_for_restore(device_state.as_deref(), flash_locked.as_deref(), boot_state.as_deref()),
        "AVB-off restore requires unlocked/orange boot state (device_state={device_state:?}, flash_locked={flash_locked:?}, verifiedbootstate={boot_state:?})");
    let _ = skyward_sys::kmsg("factory restore: confirmed on the install page");
    if cancelled() { anyhow::bail!("restore cancelled before staging; nothing was written"); }
    // Stop before staging about 13 GB when metadata still records an
    // unfinished update. The writer checks the same condition again while
    // holding its own lock.
    skyward_install::factory_preflight::audit_restore_metadata()
        .context("restore needs idle snapshot metadata; nothing was written")?;

    let (company, preload) = replacements(selected)?;
    let _ = skyward_sys::kmsg(&format!("factory restore: replacements {} and {}",
        company.display(), preload.display()));
    let (elf, owned) = crate::repack_donor()?;
    let assets: Vec<_> = owned.iter().map(|(name, bytes)| (*name, bytes.as_slice())).collect();
    let super_path = Path::new(skyward_block::BY_NAME).join("super");
    let actual = skyward_block::size_bytes(&super_path)?;
    let _ = skyward_sys::kmsg(&format!("factory restore: physical super is {actual} bytes"));
    let slot = crate::booted_slot()?;
    let reference = skyward_lp::read(&super_path, slot.number())?;
    let _ = skyward_sys::kmsg("factory restore: read the current LP tables for slot verification");
    let root = Path::new(STAGING);
    std::fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
    let scratch = tempfile::Builder::new().prefix("restore-").tempdir_in(root)
        .context("create a private restore staging directory")?;
    let destination = scratch.path().join("bundle");
    let _ = skyward_sys::kmsg(&format!("factory restore: staging verified images under {}", destination.display()));
    if cancelled() {
        anyhow::bail!("restore cancelled before staging; nothing was written");
    }
    let bundle = skyward_install::factory_bundle::prepare(package,
        None, &reference, actual, &company, &preload, &elf, &assets, true, &destination)?;
    let _ = skyward_sys::kmsg(&format!(
        "factory restore: {} images staged; claiming all A/B targets", bundle.images.len()));
    if cancelled() {
        anyhow::bail!("restore cancelled before any target write");
    }
    let holders = skyward_vab::audit_linear_super_holders(slot)
        .context("cannot identify current super holders; nothing was written")?;
    if !holders.is_empty() {
        // healthd and vndservicemanager run out of /vendor; the release below
        // refuses while their maps are live, so retire them first exactly as
        // the audited LP handoff does.
        let _ = skyward_sys::kmsg("factory restore: retiring installed-system services");
        crate::services::retire_for_lp_handoff()
            .context("installed-system services still use super; nothing was written")?;
        let _ = skyward_sys::kmsg("factory restore: releasing idle current-slot logical mappings");
        skyward_vab::release_linear_handoff(slot)
            .context("super still has active users; nothing was written")?;
    }
    crate::boot_services::execute_factory_ab(cfg, &bundle, cancelled, first_write)?;
    let _ = skyward_sys::kmsg("factory restore: finished; A is the next boot slot");
    Ok(())
}

/// The two replacement images are explicit inputs, not package contents.
fn replacements(package: &Path) -> Result<(PathBuf, PathBuf)> {
    let beside = match package.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from(STAGING),
    };
    replacements_in(&[beside, PathBuf::from(STAGING), PathBuf::from("/skyward")])
        .with_context(|| format!("this Recovery carries no built-in replacements; place {COMPANY} and {PRELOAD} beside the package or in {STAGING}/"))
}

fn replacements_in(directories: &[PathBuf]) -> Option<(PathBuf, PathBuf)> {
    directories.iter().find_map(|dir| {
        let (company, preload) = (dir.join(COMPANY), dir.join(PRELOAD));
        (company.is_file() && preload.is_file()).then_some((company, preload))
    })
}

/// Some stock PGZ110 recoveries omit vbmeta.device_state but publish
/// flash.locked=0. Accept that positive signal only with orange state;
/// reject unknown values or conflicting locked evidence.
fn unlocked_for_restore(device: Option<&str>, flash: Option<&str>, boot: Option<&str>) -> bool {
    let device = device.filter(|value| !value.is_empty());
    let flash = flash.filter(|value| !value.is_empty());
    boot == Some("orange")
        && matches!(device, None | Some("unlocked"))
        && matches!(flash, None | Some("0"))
        && (device == Some("unlocked") || flash == Some("0"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepts_stock_flash_unlock_evidence_without_missing_vbmeta_property() {
        use super::unlocked_for_restore as ready;
        assert!(ready(None, Some("0"), Some("orange")));
        assert!(ready(Some(""), Some("0"), Some("orange")));
        assert!(ready(Some("unlocked"), None, Some("orange")));
        assert!(!ready(Some("locked"), Some("0"), Some("orange")));
        assert!(!ready(Some("unlocked"), Some("1"), Some("orange")));
        assert!(!ready(None, None, Some("orange")));
        assert!(!ready(None, Some("0"), Some("green")));
    }

    use super::*;

    #[test]
    fn replacements_come_from_the_package_folder_before_the_fixed_folder() {
        let scratch = tempfile::tempdir().unwrap();
        let (beside, fixed) = (scratch.path().join("package"), scratch.path().join("fixed"));
        std::fs::create_dir_all(&beside).unwrap();
        std::fs::create_dir_all(&fixed).unwrap();
        let dirs = [beside.clone(), fixed.clone()];
        assert_eq!(replacements_in(&dirs), None, "neither folder has them yet");
        std::fs::write(fixed.join(COMPANY), b"company").unwrap();
        std::fs::write(fixed.join(PRELOAD), b"preload").unwrap();
        assert_eq!(replacements_in(&dirs), Some((fixed.join(COMPANY), fixed.join(PRELOAD))));
        std::fs::write(beside.join(COMPANY), b"company").unwrap();
        std::fs::write(beside.join(PRELOAD), b"preload").unwrap();
        assert_eq!(replacements_in(&dirs), Some((beside.join(COMPANY), beside.join(PRELOAD))));
        std::fs::remove_file(beside.join(PRELOAD)).unwrap();
        assert_eq!(replacements_in(&dirs), Some((fixed.join(COMPANY), fixed.join(PRELOAD))),
            "a half-supplied folder is not used");
    }
}
