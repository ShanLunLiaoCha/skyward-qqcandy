//! Validate a preloader DM mapping against a separately audited range.
//! These read-only checks neither create mappings nor authorize execution.
//! The writer may claim only the pre-existing OEM A/B mappings, never a raw LUN.
use anyhow::{Context, Result, ensure};
use skyward_block::dm::{DeviceStatus, Line};

pub const IMAGE_211_BYTES: u64 = 507_904;
/// `new_partition_info` digest of the authenticated .211 preloader_raw bytes.
pub const IMAGE_211_SHA256: [u8; 32] = [
    0xc5, 0xcf, 0x99, 0xf5, 0x81, 0x38, 0xfb, 0x9c, 0xbd, 0x33, 0xc9, 0x18, 0x79, 0xb7, 0xbd, 0xbd,
    0x1a, 0x5e, 0x19, 0xeb, 0x29, 0x4a, 0x51, 0x2a, 0xe3, 0x3f, 0xdc, 0xf6, 0x31, 0xe0, 0xea, 0x95,
];
const LUN_SECTORS: u64 = 8192;
const RESERVED_SECTORS: u64 = 8;
pub(crate) const MAPPED_BYTES: u64 = (LUN_SECTORS - RESERVED_SECTORS) * 512;

/// Check only that an authenticated partition declaration fits the dedicated
/// mapping. No firmware version, exact length or digest allowlist here.
pub(crate) fn check_image_bounds(bytes: u64, sha256: &[u8; 32]) -> Result<()> {
    ensure!(bytes > 0 && bytes <= MAPPED_BYTES && bytes % 512 == 0 && *sha256 != [0; 32],
        "preloader image must be aligned, hashed and fit the dedicated mapping");
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct ReviewedRange {
    pub backing_device: (u32, u32),
    pub backing_sectors: u64,
    pub backing_start: u64,
    pub mapped_sectors: u64,
}

/// Match the exact boot-LUN extent and a distinct DM device identity. Policy
/// values must come from independent OEM evidence, not from the examined DM
/// table or a partition-size guess. Passing this check only describes a
/// mapping at one instant; a writer would also need claims, stable tables,
/// and verified protected-write semantics.
pub fn check_mapping(status: &DeviceStatus, target_device: (u32, u32), table: &[Line],
    policy: ReviewedRange, image_bytes: u64) -> Result<()> {
    ensure!(!status.suspended && status.active_table && !status.readonly, "preloader mapping is not live and writable");
    ensure!(status.device == target_device && target_device != policy.backing_device,
        "preloader target is not the audited DM device or aliases its backing disk");
    let [line] = table else { anyhow::bail!("expected exactly one preloader mapping segment"); };
    ensure!(line.start == 0 && line.kind == "linear" && line.sectors == policy.mapped_sectors,
        "preloader mapping has the wrong shape or mapped bounds");
    let mut words = line.text.split_ascii_whitespace();
    let (major, minor) = words.next().and_then(|device| device.split_once(':')).context("missing preloader backing device")?;
    let actual = (major.parse::<u32>()?, minor.parse::<u32>()?);
    let start = words.next().context("missing preloader backing offset")?.parse::<u64>()?;
    ensure!(words.next().is_none() && actual == policy.backing_device && start == policy.backing_start,
        "preloader mapping differs from the audited backing device or offset");
    ensure!(line.sectors > 0 && start.checked_add(line.sectors).is_some_and(|end| end <= policy.backing_sectors),
        "preloader extent exceeds its backing device");
    let mapped_bytes = line.sectors.checked_mul(512).context("preloader mapping byte size overflow")?;
    ensure!(image_bytes > 0 && image_bytes % 512 == 0 && image_bytes <= mapped_bytes,
        "preloader image is unaligned or exceeds the audited mapping");
    Ok(())
}

/// Snapshot the exact live identity/table. It can be compared after taking
/// the exclusive block claim and just before/after writes. The claim does not
/// prevent a privileged process from reloading a DM table; a trusted Recovery
/// with no other DM administrators active remains a prerequisite.
#[cfg(target_os = "android")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ObservedMapping {
    pub(crate) node: std::path::PathBuf,
    pub(crate) target: (u32, u32),
    pub(crate) backing: (u32, u32),
    status: DeviceStatus,
    table: Vec<Line>,
}

#[cfg(target_os = "android")]
fn observe(name: &str, link: &str, backing: &str) -> Result<ObservedMapping> {
    use skyward_block::{BY_NAME, devnum, dm, size_bytes};
    use std::{fs, path::Path};
    let path = Path::new(BY_NAME).join(link);
    let node = path.canonicalize()?;
    let dm_node = node.file_name().and_then(|v| v.to_str())
        .and_then(|v| v.strip_prefix("dm-"))
        .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()));
    ensure!(node.parent() == Some(Path::new("/dev/block")) && dm_node,
        "{link} does not resolve to a dedicated kernel DM node");
    ensure!(Path::new(backing).canonicalize()? == Path::new(backing), "OEM backing path changed: {backing}");
    let target = devnum(&node)?;
    let source = devnum(backing)?;
    ensure!(size_bytes(backing)? == LUN_SECTORS * 512, "unexpected size of {backing}");
    let status = dm::device_status(name)?.with_context(|| format!("missing OEM mapping {name}"))?;
    let table = dm::table(name)?;
    check_mapping(&status, target, &table, ReviewedRange { backing_device:source, backing_sectors:LUN_SECTORS,
        backing_start:RESERVED_SECTORS, mapped_sectors:LUN_SECTORS - RESERVED_SECTORS }, IMAGE_211_BYTES)
        .with_context(|| format!("audit {name} / {link}"))?;
    ensure!(size_bytes(&node)? == MAPPED_BYTES, "unexpected mapped size of {link}");
    // Tie the supplied backing name to the only live slave of this DM disk.
    let source_sysfs = Path::new("/sys/dev/block").join(format!("{}:{}", source.0, source.1)).canonicalize()?;
    let source_name = Path::new(backing).file_name().unwrap();
    ensure!(source_sysfs.file_name() == Some(source_name) && !source_sysfs.join("partition").try_exists()?,
        "preloader backing is not the expected whole boot LUN");
    let target_sysfs = Path::new("/sys/dev/block").join(format!("{}:{}", target.0, target.1));
    let mut slaves = fs::read_dir(target_sysfs.join("slaves"))?;
    let slave = slaves.next().context("preloader mapping has no kernel slave")??;
    ensure!(slave.file_name() == source_name && slave.path().canonicalize()? == source_sysfs && slaves.next().is_none(),
        "preloader mapping does not have the expected sole backing LUN");
    ensure!(dm::device_status(name)?.as_ref() == Some(&status) && dm::table(name)? == table
        && path.canonicalize()? == node && devnum(&node)? == target && devnum(backing)? == source,
        "preloader mapping changed during observation");
    Ok(ObservedMapping {node,target,backing:source,status,table})
}

#[cfg(target_os = "android")]
pub(crate) fn observe_a() -> Result<ObservedMapping> {
    observe("pl_a", "preloader_raw_a", "/dev/block/sda")
}

#[cfg(target_os = "android")]
pub(crate) fn observe_b() -> Result<ObservedMapping> {
    observe("pl_b", "preloader_raw_b", "/dev/block/sdb")
}

/// Check both existing PGZ110 UFS preloader mappings without write handles.
#[cfg(target_os = "android")]
pub fn audit_pgz110_211() -> Result<()> {
    let a = observe_a()?;
    let b = observe_b()?;
    ensure!(std::collections::BTreeSet::from([a.target, a.backing, b.target, b.backing]).len() == 4,
        "preloader slot devices alias");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observations() -> (DeviceStatus, Line, ReviewedRange) {
        // Deliberately fictional geometry, not PGZ110 configuration.
        (DeviceStatus {device:(253,11), active_table:true, readonly:false, suspended:false},
            Line {start:0, sectors:1000, kind:"linear".into(), text:"8:96 70".into()},
            ReviewedRange {backing_device:(8,96), backing_sectors:2048, backing_start:70, mapped_sectors:1000})
    }
    #[test]
    fn accepts_only_the_independently_audited_range() {
        let (status,line,rule)=observations();
        assert!(check_mapping(&status,(253,11), std::slice::from_ref(&line),rule,4*512).is_ok());
        for bad in ["8:96 0", "8:96 71", "8:97 70", "8:96 70 extra"] {
            let mut different=line.clone(); different.text=bad.into();
            assert!(check_mapping(&status,(253,11),&[different],rule,4*512).is_err());
        }
        assert!(check_mapping(&status,(253,11),&[line.clone(),line],rule,4*512).is_err());
    }
    #[test]
    fn observed_ufs_geometry_contains_the_211_image_without_sector_zero() {
        let status = DeviceStatus { device:(253,0), readonly:false, suspended:false, active_table:true };
        let policy = ReviewedRange { backing_device:(8,0), backing_sectors:8192, backing_start:8, mapped_sectors:8184 };
        let mut line = Line { start:0, sectors:8184, kind:"linear".into(), text:"8:0 8".into() };
        assert!(check_mapping(&status, status.device, std::slice::from_ref(&line), policy, 507_904).is_ok());
        line.sectors = 8192;
        line.text = "8:0 0".into();
        assert!(check_mapping(&status, status.device, &[line], policy, 507_904).is_err());
    }

    #[test]
    fn rejects_raw_disk_stale_dm_or_out_of_bounds_bytes() {
        let (status,line,rule)=observations();
        let table=[line];
        assert!(check_mapping(&status,rule.backing_device,&table,rule,4*512).is_err());
        assert!(check_mapping(&DeviceStatus {active_table:false,..status.clone()},status.device,&table,rule,4*512).is_err());
        assert!(check_mapping(&DeviceStatus {suspended:true,..status.clone()},status.device,&table,rule,4*512).is_err());
        assert!(check_mapping(&status,status.device,&table,ReviewedRange {backing_sectors:1000,..rule},4*512).is_err());
        for size in [0, 513, 1001*512] {
            assert!(check_mapping(&status,status.device,&table,rule,size).is_err());
        }
        let overflowing=[Line {text:format!("8:96 {}",u64::MAX),..table[0].clone()}];
        assert!(check_mapping(&status,status.device,&overflowing,ReviewedRange {backing_start:u64::MAX,..rule},512).is_err());
    }
}
