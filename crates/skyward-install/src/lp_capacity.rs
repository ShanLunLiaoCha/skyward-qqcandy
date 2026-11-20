//! Ordinary OTA preflight: repair a verified single-super size mismatch only.
use anyhow::{Context, Result, ensure};
use skyward_block::{BY_NAME, mount};
use skyward_lp::capacity;
use std::{fs::{self, File}, io::Write, os::{fd::AsRawFd, unix::fs::FileExt}, path::{Path, PathBuf}};

fn super_path() -> PathBuf { Path::new(BY_NAME).join("super") }

pub(crate) fn needs_repair(slot: skyward_vab::Slot) -> Result<bool> {
    let path = super_path();
    if !path.try_exists()? { return Ok(false); }
    let metadata = skyward_lp::read(&path, slot.number())?;
    let [device] = metadata.block_devices.as_slice() else { return Ok(false); };
    if device.partition_name != "super" { return Ok(false); }
    Ok(device.size != skyward_block::size_bytes(&path)?)
}

fn backup(prefix: &[u8], directory: &Path) -> Result<PathBuf> {
    let mut backup = tempfile::Builder::new().prefix("skyward-super-lp-original-").suffix(".bin").tempfile_in(directory)?;
    backup.write_all(prefix)?;
    backup.as_file().sync_all()?;
    let (_, path) = backup.keep().context("retain the original LP backup")?;
    File::open(directory)?.sync_all()?;
    Ok(path)
}

fn lock_idle_metadata() -> Result<skyward_vab::snapshots::RestoreLock> {
    let metadata = Path::new("/metadata");
    let visible = mount::visible(metadata)?.context("metadata must be mounted to back up the LP tables")?;
    let device = skyward_block::devnum(Path::new(BY_NAME).join("metadata"))?;
    ensure!(visible.device == device && visible.filesystem == "ext4", "unexpected filesystem at /metadata");
    ensure!(skyward_vab::snapshot_state()? == skyward_vab::SnapshotState::None, "snapshot state changed before LP repair");
    skyward_vab::snapshots::Snapshots::lock_for_restore()
}

/// Fail early, without detaching the installed system or hashing a large OTA.
/// This observation cannot authorize later writes: reacquire the lock then.
pub(crate) fn preflight() -> Result<()> {
    let _guard = lock_idle_metadata()?;
    Ok(())
}

/// Independent, no-write checks for a ramdisk-only maintenance boot.
pub fn audit_maintenance(slot: skyward_vab::Slot) -> (Result<bool>, Result<()>, Result<Result<CapacityAudit>>) {
    use sha2::{Digest, Sha256};
    let capacity = needs_repair(slot);
    let snapshots = preflight();
    let exclusive = crate::factory_targets::claim_gpt_partition(crate::factory_execute::Target::Super, false)
        .map(|(fd, _)| {
            let (physical_bytes, prefix) = read_claimed_prefix(&fd)?;
            let patches = skyward_lp::capacity::repair(&prefix, physical_bytes)?;
            Ok(CapacityAudit { physical_bytes, metadata_bytes: prefix.len(), copy_changes: patches.len(),
                metadata_sha256: format!("{:x}", Sha256::digest(&prefix)) })
        });
    (capacity, snapshots, exclusive)
}

/// Read-only corroboration of the captured failed OTA. Does not hold locks
/// after returning, and must never be used as a cached write permit.
pub fn audit_captured_residue(current: skyward_vab::Slot, next: skyward_vab::Slot,
    merge: skyward_vab::MergeStatus) -> Result<()> {
    crate::lp_orphan_evidence::with_maintenance_userdata(|| audit_captured_with_userdata(current, next, merge))
}

fn audit_captured_with_userdata(current: skyward_vab::Slot, next: skyward_vab::Slot,
    merge: skyward_vab::MergeStatus) -> Result<()> {
    use crate::lp_orphan_policy::{Evidence, Presence, classify};
    let (fd, id) = crate::factory_targets::claim_gpt_partition(crate::factory_execute::Target::Super, false)?;
    let (actual, prefix) = read_claimed_prefix(&fd)?;
    ensure!(!capacity::repair(&prefix, actual)?.is_empty(), "no LP capacity correction is needed");
    let metadata = Path::new("/metadata");
    let records = crate::lp_orphan_evidence::read_ota_records(metadata)?;
    crate::lp_orphan_evidence::verify_no_live_cow(id)?;
    ensure!(crate::lp_orphan_evidence::read_ota_records(metadata)? == records
        && read_claimed_prefix(&fd)? == (actual, prefix.clone()), "LP or snapshot evidence changed during audit");
    classify(&Evidence { state: &records.state, current_slot: Some(current), next_slot: Some(next),
        merge_status: Some(merge), b_or_cow_residency: Presence::Absent, live_snapshots: Presence::Absent,
        lp_prefix: &prefix, records: &records.records })
}

#[derive(Debug)]
pub struct CapacityAudit {
    pub physical_bytes: u64,
    pub metadata_bytes: usize,
    pub copy_changes: usize,
    pub metadata_sha256: String,
}

/// Preview the exact incident while the ordinary UI still owns vendor. The
/// maintenance stage must independently take exclusive leases and reprove
/// all conditions; a positive result here only selects the handoff flow.
pub(crate) fn is_captured_handoff_candidate(slot: skyward_vab::Slot, verified_zip: &mut (impl std::io::Read + std::io::Seek)) -> Result<()> {
    // The caller must already have a Signed verdict for this same pinned
    // package. The manifest pin limits this exception to the reviewed .211.
    let (_, digest) = crate::payload_preflight::read_zip_with_digest(verified_zip)?;
    crate::factory_preflight::reviewed_roster(&digest)?;
    ensure!(slot == skyward_vab::Slot::A, "captured incident requires current slot A");
    let fd = File::open(super_path())?;
    let (actual, prefix) = read_claimed_prefix(&fd)?;
    ensure!(actual == 12_348_030_976, "physical super differs from the captured incident");
    let records = crate::lp_orphan_evidence::read_ota_records(Path::new("/metadata"))?;
    crate::lp_orphan_policy::matches_handoff_candidate(&prefix, &records.state, &records.records)
}

fn read_claimed_prefix(fd: &File) -> Result<(u64, Vec<u8>)> {
    let mut actual = 0u64;
    // BLKGETSIZE64 reports the physical capacity of this same pinned FD.
    if unsafe { libc::ioctl(fd.as_raw_fd(), 0x80081272u32 as libc::c_int, &mut actual) } != 0 {
        return Err(std::io::Error::last_os_error()).context("query physical super capacity");
    }
    let mut geometry = [0; 12288];
    fd.read_exact_at(&mut geometry, 0)?;
    let mut prefix = vec![0; capacity::prefix_len(&geometry)?];
    fd.read_exact_at(&mut prefix, 0)?;
    ensure!(prefix.starts_with(&geometry), "LP geometry changed during read");
    Ok((actual, prefix))
}

/// PGZ110 maintenance transaction, not invoked by the ordinary OTA engine.
/// The readiness callback must query the same OEM BootControl service in
/// the isolated session, without trying to claim super a second time.
pub fn repair_captured_residue(current: skyward_vab::Slot, expected_super: (u32, u32),
    boot_state: impl FnMut() -> Result<(skyward_vab::Slot, skyward_vab::MergeStatus)>) -> Result<PathBuf> {
    crate::lp_orphan_evidence::with_maintenance_userdata(|| repair_captured_with_userdata(current, expected_super, boot_state))
}

fn repair_captured_with_userdata(current: skyward_vab::Slot, expected_super: (u32, u32),
    mut boot_state: impl FnMut() -> Result<(skyward_vab::Slot, skyward_vab::MergeStatus)>) -> Result<PathBuf> {
    use crate::{factory_execute::Target, lp_orphan_archive as archive,
        lp_orphan_evidence::{read_ota_records, verify_no_live_cow}, lp_orphan_policy::{Evidence, Presence, classify}};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let metadata = Path::new("/metadata");
    let visible = mount::visible(metadata)?.context("metadata is not mounted")?;
    ensure!(visible.filesystem == "ext4" && visible.device == skyward_block::devnum(Path::new(BY_NAME).join("metadata"))?,
        "unexpected filesystem mounted at /metadata");
    let lock = |path: &Path| -> Result<File> {
        let dir = fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)?;
        ensure!(dir.metadata()?.dev() == fs::metadata(metadata)?.dev(), "OTA directory is on a different filesystem");
        if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("lock {}", path.display()));
        }
        Ok(dir)
    };
    let _metadata = lock(metadata)?;
    let _ota = lock(&metadata.join("ota"))?;
    archive::check_idle(metadata)?;
    let (fd, id) = crate::factory_targets::claim_gpt_partition(Target::Super, true)?;
    ensure!(id == expected_super, "super identity changed between BootControl audit and write claim");
    let (actual, prefix) = read_claimed_prefix(&fd)?;
    ensure!(actual == 12_348_030_976, "physical super differs from the captured failure");
    let writes = capacity::repair(&prefix, actual)?;
    ensure!(writes.len() == 6, "expected six LP copies requiring repair");
    let records = read_ota_records(metadata)?;
    let mut validate = || -> Result<()> {
        let (next, merge) = boot_state()?;
        verify_no_live_cow(id)?;
        ensure!(read_ota_records(metadata)? == records && read_claimed_prefix(&fd)? == (actual, prefix.clone()),
            "LP or snapshot evidence changed");
        classify(&Evidence { state: &records.state, current_slot: Some(current), next_slot: Some(next),
            merge_status: Some(merge), b_or_cow_residency: Presence::Absent, live_snapshots: Presence::Absent,
            lp_prefix: &prefix, records: &records.records })
    };
    validate()?;
    mount::remount_writable(metadata, true).context("open metadata for LP maintenance archive")?;
    let result = (|| -> Result<PathBuf> {
        validate()?;
        archive::begin(metadata)?;
        let directory = archive::quarantine(metadata, &prefix, validate)?;
        let archived = directory.join("snapshots");
        ensure!(fs::read_dir(&archived)?.collect::<std::io::Result<Vec<_>>>()?.len() == records.records.len(), "archived snapshot roster differs");
        for (name, bytes) in &records.records {
            ensure!(fs::read(archived.join(name))? == *bytes, "archived snapshot changed: {name}");
        }
        ensure!(fs::read(directory.join("super-lp-original.bin"))? == prefix, "LP backup bytes differ");
        let mut expected = prefix.clone();
        for (offset, data) in writes {
            let start = usize::try_from(offset)?;
            let end = start.checked_add(data.len()).context("LP patch length overflow")?;
            expected.get_mut(start..end).context("LP patch outside original prefix")?.copy_from_slice(&data);
            fd.write_all_at(&data, offset).with_context(|| format!("write LP copy at {offset}"))?;
            fd.sync_all().with_context(|| format!("sync LP copy at {offset}"))?;
        }
        ensure!(read_claimed_prefix(&fd)? == (actual, expected), "repaired LP prefix differs from the expected bytes");
        archive::finish(metadata)?;
        Ok(directory)
    })();
    let remount = mount::remount_writable(metadata, false);
    match (result, remount) {
        (Ok(directory), Ok(())) => Ok(directory),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("LP repair verified, but metadata could not return to read-only")),
        (Err(error), Err(remount)) => Err(error.context(format!("metadata read-only remount also failed: {remount:#}"))),
    }
}

pub(crate) fn repair_before_ota() -> Result<()> {
    use crate::factory_execute::Target;
    let metadata = Path::new("/metadata");
    let _snapshot = lock_idle_metadata()?;
    let (fd, _) = crate::factory_targets::claim_gpt_partition(Target::Super, true)
        .context("LP repair requires an unmounted, exclusively available super partition")?;
    let (actual, prefix) = read_claimed_prefix(&fd)?;
    let writes = capacity::repair(&prefix, actual)?;
    if writes.is_empty() { return Ok(()); }
    // Recovery mounts metadata read-only for inspection. Restore that mode
    // before writing super; never leave it writable on a backup failure.
    mount::remount_writable(metadata, true).context("open metadata for a durable LP backup")?;
    let saved = backup(&prefix, metadata);
    let remounted = mount::remount_writable(metadata, false);
    let backup = saved?;
    remounted.context("restore read-only metadata after LP backup")?;
    let _ = skyward_sys::kmsg(&format!("install: original super LP tables saved at {}", backup.display()));
    let mut same = vec![0; prefix.len()];
    fd.read_exact_at(&mut same, 0)?;
    ensure!(same == prefix, "LP tables changed after backup");
    for (offset, data) in writes {
        fd.write_all_at(&data, offset).with_context(|| format!("write corrected LP copy at {offset}; backup: {}", backup.display()))?;
        fd.sync_all().with_context(|| format!("sync corrected LP copy at {offset}; backup: {}", backup.display()))?;
    }
    let _ = skyward_sys::kmsg(&format!("install: corrected super LP size to {actual} bytes"));
    Ok(())
}
