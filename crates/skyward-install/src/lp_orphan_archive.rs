//! Durable evidence and guarded quarantine for a caller-verified OTA directory.
//! The caller must hold the OTA lock, prove quiescence, and revalidate the
//! snapshot roster, its bytes and absence of COW resources before calling.
use anyhow::{Context, Result, ensure};
use std::{fs::{self, File, OpenOptions}, io::Write, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::{Path, PathBuf}};

pub(crate) const PENDING: &str = "skyward-lp-repair.pending";

/// Create and flush an interlock before mutating snapshots or super. Keep
/// this on any ambiguous or partial failure; normal OTA must not continue.
pub(crate) fn begin(metadata: &Path) -> Result<()> {
    let marker = OpenOptions::new().write(true).create_new(true).open(metadata.join(PENDING))?;
    marker.sync_all()?;
    File::open(metadata)?.sync_all()?;
    Ok(())
}

pub(crate) fn check_idle(metadata: &Path) -> Result<()> {
    match fs::symlink_metadata(metadata.join(PENDING)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("a previous LP maintenance repair is incomplete; do not start OTA"),
        Err(error) => Err(error).context("check LP maintenance interlock"),
    }
}

/// Remove the OTA interlock only after the caller has verified the complete
/// repaired LP prefix and the archived records. Sync the parent directory.
pub(crate) fn finish(metadata: &Path) -> Result<()> {
    fs::remove_file(metadata.join(PENDING))?;
    File::open(metadata)?.sync_all()?;
    Ok(())
}

/// Stage a durable copy of the original LP prefix before changing the one
/// active snapshot namespace. Preserve its directory inode, owner, mode
/// and SELinux label: OEM update_engine expects the directory to exist.
/// The durable interlock must remain in place across all record moves.
pub(crate) fn quarantine(metadata: &Path, prefix: &[u8], mut revalidate: impl FnMut() -> Result<()>) -> Result<PathBuf> {
    let ota = metadata.join("ota");
    let source = ota.join("snapshots");
    let before = fs::symlink_metadata(&source)?;
    ensure!(before.is_dir(), "snapshot path is not a real directory");
    let archive = tempfile::Builder::new().prefix("skyward-ota-lp-archive-").tempdir_in(metadata)?;
    let mut backup = OpenOptions::new().create_new(true).write(true).open(archive.path().join("super-lp-original.bin"))?;
    backup.write_all(prefix)?;
    backup.sync_all()?;
    File::open(archive.path())?.sync_all()?;
    File::open(metadata)?.sync_all()?;
    let archived = archive.path().join("snapshots");
    fs::create_dir(&archived)?;
    let mut records = Vec::new();
    for entry in fs::read_dir(&source)? {
        let entry = entry?;
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(entry.path())?;
        let meta = file.metadata()?;
        ensure!(meta.is_file() && meta.dev() == before.dev() && meta.nlink() == 1, "snapshot record is not a private regular file");
        file.sync_all()?;
        records.push((entry.file_name(), meta.dev(), meta.ino()));
    }
    File::open(&source)?.sync_all()?;
    revalidate().context("verify unchanged orphan evidence immediately before archive")?;
    let again = fs::symlink_metadata(&source)?;
    ensure!(again.is_dir() && (again.dev(), again.ino()) == (before.dev(), before.ino()), "snapshot directory changed");
    // From this point the folder must never auto-delete, even if rename or
    // a later fsync fails. The archived records are not rollback permission.
    let archive = archive.keep();
    let archived = archive.join("snapshots");
    for (name, dev, inode) in records {
        let path = source.join(&name);
        let meta = fs::symlink_metadata(&path)?;
        ensure!(meta.is_file() && (meta.dev(), meta.ino()) == (dev, inode), "snapshot record changed before archival");
        fs::rename(&path, archived.join(&name)).with_context(|| format!("archive snapshot {name:?} at {}", archive.display()))?;
        File::open(&archived)?.sync_all()?;
        File::open(&source)?.sync_all()?;
    }
    ensure!(fs::read_dir(&source)?.next().transpose()?.is_none(), "active snapshots directory is not empty after archival");
    File::open(&ota)?.sync_all()?;
    File::open(&archive)?.sync_all()?;
    File::open(metadata)?.sync_all()?;
    Ok(archive)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn existing_interlock_prevents_reentry_and_ota() {
        let root = tempfile::tempdir().unwrap();
        assert!(check_idle(root.path()).is_ok());
        begin(root.path()).unwrap();
        assert!(begin(root.path()).is_err());
        assert!(check_idle(root.path()).is_err());
        finish(root.path()).unwrap();
        assert!(check_idle(root.path()).is_ok());
    }

    #[test]
    fn failed_recheck_does_not_move_records_and_success_preserves_them() {
        let root = tempfile::tempdir().unwrap();
        let records = root.path().join("ota/snapshots");
        fs::create_dir_all(&records).unwrap();
        fs::write(records.join("vendor_b"), [7, 2, 9]).unwrap();
        assert!(quarantine(root.path(), &[1, 2, 3], || anyhow::bail!("changed")).is_err());
        assert_eq!(fs::read(records.join("vendor_b")).unwrap(), [7, 2, 9]);
        let before = fs::metadata(&records).unwrap();
        let archive = quarantine(root.path(), &[1, 2, 3], || Ok(())).unwrap();
        let after = fs::metadata(&records).unwrap();
        assert_eq!((after.ino(), after.uid(), after.gid(), after.mode()), (before.ino(), before.uid(), before.gid(), before.mode()));
        assert!(fs::read_dir(&records).unwrap().next().is_none());
        fs::write(records.join("new_b"), [4]).unwrap();
        assert_eq!(fs::read(archive.join("snapshots/vendor_b")).unwrap(), [7, 2, 9]);
        assert_eq!(fs::read(archive.join("super-lp-original.bin")).unwrap(), [1, 2, 3]);
    }
}
