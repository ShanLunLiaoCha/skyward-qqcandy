//! Hold the existing update metadata while a full restore owns block targets.
//! This guard does not mount metadata, cancel updates or change merge status.
use anyhow::{Context, Result, ensure};
use skyward_vab::MergeStatus;
use skyward_vab::snapshots::{RestoreLock, Snapshots};

pub fn check_merge_state(status: MergeStatus) -> Result<()> {
    ensure!(status == MergeStatus::None, "BootControl reports an unfinished or unknown snapshot merge: {status:?}");
    Ok(())
}

#[cfg(target_os = "android")]
pub(crate) fn acquire(merge_status: MergeStatus) -> Result<RestoreLock> {
    check_merge_state(merge_status)?;
    lock_metadata()
}

/// Verify the mounted update metadata without guessing the OEM merge state.
/// Full execution must use `acquire` instead.
#[cfg(target_os = "android")]
pub(crate) fn lock_metadata() -> Result<RestoreLock> {
    use std::path::Path;
    let device = skyward_block::devnum(Path::new(skyward_block::BY_NAME).join("metadata"))?;
    let visible = skyward_block::mount::visible(Path::new("/metadata"))?.context("metadata must already be mounted")?;
    ensure!(visible.device == device && visible.filesystem == "ext4", "unexpected filesystem mounted at /metadata");
    let lock = Snapshots::lock_for_restore()?;
    crate::lp_orphan_archive::check_idle(Path::new("/metadata"))?;
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_positive_no_merge_state_is_admitted() {
        assert!(check_merge_state(MergeStatus::None).is_ok());
        for state in [MergeStatus::Unknown, MergeStatus::Snapshotted, MergeStatus::Merging, MergeStatus::Cancelled] {
            assert!(check_merge_state(state).is_err());
        }
    }
}
