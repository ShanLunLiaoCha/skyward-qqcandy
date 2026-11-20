//! Capture bounded, same-filesystem OTA records without following symlinks.
//! This is only one component of the maintenance proof, not a cleanup API.
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, fs::{self, OpenOptions}, io::Read, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::Path};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Records {
    pub(crate) state: Vec<u8>,
    pub(crate) records: BTreeMap<String, Vec<u8>>,
}

fn read_record(path: &Path, device: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let b = file.metadata()?;
    ensure!(b.is_file() && b.dev() == device && b.nlink() == 1 && b.len() <= 4096, "unexpected snapshot object: {}", path.display());
    let mut result = Vec::new();
    (&file).take(4097).read_to_end(&mut result)?;
    let a = file.metadata()?;
    ensure!(result.len() as u64 == b.len() && (a.len(), a.mtime(), a.mtime_nsec(), a.ctime(), a.ctime_nsec())
        == (b.len(), b.mtime(), b.mtime_nsec(), b.ctime(), b.ctime_nsec()), "snapshot record changed");
    Ok(result)
}

pub(crate) fn read_ota_records(metadata: &Path) -> Result<Records> {
    let device = fs::metadata(metadata)?.dev();
    let ota = metadata.join("ota");
    let snapshots = ota.join("snapshots");
    for p in [&ota, &snapshots] {
        let info = fs::symlink_metadata(p)?;
        ensure!(info.is_dir() && info.dev() == device, "unexpected OTA directory: {}", p.display());
    }
    for entry in fs::read_dir(&ota)? {
        let n = entry?.file_name();
        ensure!(n == "state" || n == "snapshots", "additional OTA marker prevents residue repair: {n:?}");
    }
    let state = read_record(&ota.join("state"), device).context("read exact OTA state file")?;
    let mut records = BTreeMap::new();
    for entry in fs::read_dir(&snapshots)? {
        let entry = entry?;
        ensure!(records.len() < 15, "too many snapshot records for this recovery case");
        let name = entry.file_name().into_string().map_err(|_| anyhow::anyhow!("non-UTF8 snapshot record"))?;
        ensure!(records.insert(name, read_record(&entry.path(), device)?).is_none(), "duplicate snapshot record name");
    }
    Ok(Records { state, records })
}

/// Check the specific COW backing directory, not an unmounted placeholder.
/// Each directory component must stay on the expected filesystem.
fn empty_cow_directory(root: &Path, check_mount: impl Fn(&Path) -> Result<()>) -> Result<()> {
    let base = fs::symlink_metadata(root)?;
    ensure!(base.is_dir(), "COW storage root is not a real directory");
    let mut path = root.to_path_buf();
    for name in ["gsi", "ota"] {
        path.push(name);
        check_mount(&path)?;
        let dir = fs::symlink_metadata(&path).with_context(|| format!("inspect {}", path.display()))?;
        ensure!(dir.is_dir() && dir.dev() == base.dev(), "COW directory leaves the verified filesystem");
    }
    ensure!(fs::read_dir(&path)?.next().transpose()?.is_none(), "COW backing storage is not empty: {}", path.display());
    Ok(())
}

#[cfg(target_os = "android")]
fn verify_userdata_device(id: (u32, u32)) -> Result<()> {
    use skyward_block::{BY_NAME, devnum};
    use std::collections::BTreeSet;
    let userdata = devnum(Path::new(BY_NAME).join("userdata"))?;
    let sys = Path::new("/sys/dev/block");
    ensure!(crate::factory_source::dependencies(sys, id)? == BTreeSet::from([userdata, id]),
        "mounted data does not resolve exclusively to userdata");
    if id != userdata {
        let dm = sys.join(format!("{}:{}", id.0, id.1));
        ensure!(fs::read_to_string(dm.join("dm/name"))?.trim() == "userdata", "unexpected userdata DM identity");
        let status = skyward_block::dm::device_status("userdata")?.context("userdata DM disappeared")?;
        ensure!(status.device == id && status.active_table && !status.suspended, "userdata DM is not active");
        let table = skyward_block::dm::table("userdata")?;
        ensure!(matches!(table.as_slice(), [entry] if entry.start == 0 && entry.sectors != 0
            && matches!(entry.kind.as_str(), "default-key" | "crypt")), "userdata DM is not a plain encryption mapping");
    }
    Ok(())
}

/// Optionally mount an already established, independent userdata mapper.
/// Never creates a mapper, loads vendor, unwraps keys, or replays a journal.
#[cfg(target_os = "android")]
pub(crate) fn with_maintenance_userdata<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    use skyward_block::{devnum, dm, mount, probe};
    let data = Path::new("/data");
    if let Some(mounted) = mount::visible(data)? {
        verify_userdata_device(mounted.device)?;
        return operation();
    }
    let status = dm::device_status("userdata")?.context("no existing userdata mapper in maintenance; COW contents cannot be confirmed")?;
    let id = status.device;
    verify_userdata_device(id)?;
    let sys = Path::new("/sys/dev/block").join(format!("{}:{}", id.0, id.1)).canonicalize()?;
    let name = sys.file_name().and_then(|name| name.to_str()).context("invalid userdata kernel node name")?;
    ensure!(name.strip_prefix("dm-").is_some_and(|n| !n.is_empty() && n.bytes().all(|x| x.is_ascii_digit())),
        "expected a kernel DM node for userdata");
    let mapped = Path::new("/dev/block").join(name);
    ensure!(mapped.canonicalize()? == mapped && devnum(&mapped)? == id, "userdata node identity changed");
    let filesystem = probe::filesystem(&mapped)?.context("cannot identify decrypted userdata filesystem")?;
    let no_replay = match filesystem.as_str() { "ext4" => "noload", "f2fs" => "norecovery", _ => anyhow::bail!("unsupported userdata filesystem") };
    ensure!(fs::symlink_metadata(data)?.is_dir() && mount::visible(data)?.is_none(), "unexpected /data mount hierarchy");
    verify_userdata_device(id)?;
    mount::mount(&mapped, data, &filesystem, &["ro".into(), no_replay.into(), "nodev".into(), "nosuid".into(), "noexec".into()])?;
    let result = (|| {
        let mounted = mount::visible(data)?.context("userdata mount disappeared")?;
        ensure!(mounted.device == id && mounted.filesystem == filesystem, "unexpected temporary userdata mount");
        operation()
    })();
    let release = mount::umount(data);
    match (result, release) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(e), Ok(())) | (Ok(_), Err(e)) => Err(e),
        (Err(e), Err(release)) => Err(e.context(format!("temporary userdata unmount also failed: {release:#}"))),
    }
}

/// Diagnostic only. Proof is scoped to the captured PGZ110 legacy COW
/// layout. Failure (including inaccessible userdata) is unknown, not absence.
#[cfg(target_os = "android")]
pub(crate) fn verify_no_live_cow(super_id: (u32, u32)) -> Result<()> {
    use skyward_block::{BY_NAME, devnum, mount};
    use std::collections::BTreeSet;
    let by_name = Path::new(BY_NAME);
    let sys = Path::new("/sys/dev/block");
    let metadata = Path::new("/metadata");
    let data = Path::new("/data");
    let meta = mount::visible(metadata)?.context("metadata is not mounted")?;
    ensure!(meta.filesystem == "ext4" && meta.device == devnum(by_name.join("metadata"))?, "unexpected metadata mount");
    let data_mount = mount::visible(data)?.context("userdata is not mounted; COW state is unknown")?;
    ensure!(matches!(data_mount.filesystem.as_str(), "f2fs" | "ext4"), "unexpected userdata filesystem");
    verify_userdata_device(data_mount.device)?;
    for root in [data, metadata] {
        empty_cow_directory(root, |p| {
            ensure!(mount::visible(p)?.is_none(), "unexpected mount at {}", p.display());
            Ok(())
        })?;
    }
    let a = crate::factory_preloader::observe_a()?.target;
    let b = crate::factory_preloader::observe_b()?.target;
    let allowed = BTreeSet::from([a, b, data_mount.device]);
    for node in fs::read_dir("/sys/class/block")? {
        let node = node?;
        let name = node.file_name();
        let name = name.to_str().context("non-UTF8 kernel block name")?;
        if name.starts_with("dm-") {
            let id = fs::read_to_string(node.path().join("dev"))?;
            let (major, minor) = id.trim().split_once(':').context("invalid kernel device identifier")?;
            ensure!(allowed.contains(&(major.parse()?, minor.parse()?)), "unexpected live DM mapping {name}");
        } else if name.starts_with("loop") {
            let backing = node.path().join("loop/backing_file");
            if backing.try_exists()? {
                let file = fs::read_to_string(&backing)?;
                let file = file.strip_suffix('\n').context("unexpected loop backing path format")?;
                skyward_block::loopdev::verify_apex_tmpfs_backing(&Path::new("/dev/block").join(name), Path::new(file))
                    .with_context(|| format!("active loop {name} is not a verified volatile APEX backing"))?;
            }
        }
    }
    ensure!(crate::factory_preflight::kernel_super_holders(sys, super_id)?.is_empty(), "super still has kernel holders");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cow_absence_requires_real_empty_directory_without_submount() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path();
        assert!(empty_cow_directory(base, |_| Ok(())).is_err());
        let cow = base.join("gsi/ota");
        fs::create_dir_all(&cow).unwrap();
        assert!(empty_cow_directory(base, |_| Ok(())).is_ok());
        assert!(empty_cow_directory(base, |p| {
            ensure!(p != cow, "hidden backing folder");
            Ok(())
        }).is_err());
        fs::write(cow.join("vendor_b-cow.img"), [1]).unwrap();
        assert!(empty_cow_directory(base, |_| Ok(())).is_err());
        fs::rename(&cow, base.join("other")).unwrap();
        std::os::unix::fs::symlink(base.join("other"), &cow).unwrap();
        assert!(empty_cow_directory(base, |_| Ok(())).is_err());
    }

    #[test]
    fn refuses_ota_markers_symlinks_and_large_records() {
        let dir = tempfile::tempdir().unwrap();
        let ota = dir.path().join("ota");
        fs::create_dir_all(ota.join("snapshots")).unwrap();
        fs::write(ota.join("state"), []).unwrap();
        let path = ota.join("snapshots/vendor_b");
        fs::write(&path, [7, 2, 9]).unwrap();
        assert_eq!(read_ota_records(dir.path()).unwrap().records["vendor_b"], [7, 2, 9]);
        fs::write(ota.join("snapshot-boot"), []).unwrap();
        assert!(read_ota_records(dir.path()).is_err());
        fs::remove_file(ota.join("snapshot-boot")).unwrap();
        fs::write(&path, vec![0; 4097]).unwrap();
        assert!(read_ota_records(dir.path()).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(ota.join("state"), &path).unwrap();
        assert!(read_ota_records(dir.path()).is_err());
    }
}
