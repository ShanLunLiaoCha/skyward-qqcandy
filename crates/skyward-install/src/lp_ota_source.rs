//! File identity across the same-boot LP maintenance handoff.
//! A matching file is not consent or a signature verdict. Callers retain
//! ownership of the read-only file and must reverify the ZIP before resuming.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{fs::{File, Metadata}, os::{fd::AsRawFd, unix::fs::{FileExt, MetadataExt}}};

pub const CAPTURED_OTA_SIZE: u64 = 7_084_996_559;

/// Whole ZIP from the reviewed, signed .211 incident. The exact-byte pin is
/// only for automatic residue repair; other ordinary OTAs do not use it.
pub const CAPTURED_OTA_SHA256: [u8; 32] = [
    0xad, 0x3e, 0xdf, 0x4b, 0xee, 0xe3, 0xee, 0x6e, 0x55, 0x5c, 0x2a, 0x5e, 0x1d, 0xfa, 0x59, 0x07,
    0x70, 0x46, 0xf1, 0xa1, 0xfc, 0xa2, 0x3b, 0x6a, 0x6f, 0xa1, 0x85, 0x09, 0x5b, 0x33, 0x92, 0xda,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStamp {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified: (i64, i64),
    pub changed: (i64, i64),
}

impl FileStamp {
    fn from_metadata(m: &Metadata) -> Result<Self> {
        ensure!(m.is_file() && m.len() > 0, "OTA source is not a nonempty regular file");
        Ok(Self { device: m.dev(), inode: m.ino(), size: m.len(), modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()) })
    }

    pub fn read(file: &File) -> Result<Self> {
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags == -1 { return Err(std::io::Error::last_os_error()).context("inspect OTA file descriptor flags"); }
        ensure!(flags & libc::O_ACCMODE == libc::O_RDONLY && flags & libc::O_PATH == 0,
            "OTA descriptor must be opened read-only for I/O");
        Self::from_metadata(&file.metadata()?)
    }
}

/// Hash the full contents without modifying the shared file offset. Check the
/// same inode and timestamps on both sides of the read; FUSE separately
/// guards against a package changing after it is offered to the engine.
pub fn digest(file: &File, stamp: FileStamp, mut cancelled: impl FnMut() -> bool) -> Result<[u8; 32]> {
    ensure!(FileStamp::read(file)? == stamp, "OTA source changed before hashing");
    let mut hasher = Sha256::new();
    let mut bytes = vec![0; 1 << 20];
    let mut offset = 0;
    while offset < stamp.size {
        ensure!(!cancelled(), "cancelled OTA source verification");
        let n = (stamp.size - offset).min(bytes.len() as u64) as usize;
        file.read_exact_at(&mut bytes[..n], offset)?;
        hasher.update(&bytes[..n]);
        offset += n as u64;
    }
    ensure!(!cancelled() && FileStamp::read(file)? == stamp, "OTA source changed or verification cancelled");
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::{Seek, SeekFrom}};
    #[test]
    fn pinned_file_does_not_follow_a_replaced_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("update.zip");
        fs::write(&path, b"chosen OTA").unwrap();
        let mut pinned = File::open(&path).unwrap();
        pinned.seek(SeekFrom::Start(3)).unwrap();
        let stamp = FileStamp::read(&pinned).unwrap();
        let original = digest(&pinned, stamp, || false).unwrap();
        assert_eq!(pinned.stream_position().unwrap(), 3);
        fs::rename(&path, tmp.path().join("old.zip")).unwrap();
        fs::write(&path, b"foreign OT").unwrap();
        let other = File::open(&path).unwrap();
        assert_ne!(FileStamp::read(&pinned).unwrap().inode, FileStamp::read(&other).unwrap().inode);
        assert_eq!(digest(&pinned, FileStamp::read(&pinned).unwrap(), || false).unwrap(), original);
        assert_ne!(digest(&other, FileStamp::read(&other).unwrap(), || false).unwrap(), original);
    }

    #[test]
    fn rejects_writable_cancelled_and_changed_sources() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        tmp.write_all(b"old").unwrap();
        assert!(FileStamp::read(tmp.as_file()).is_err());
        let source = File::open(tmp.path()).unwrap();
        let stamp = FileStamp::read(&source).unwrap();
        assert!(digest(&source, stamp, || true).is_err());
        tmp.write_all(b"new").unwrap();
        assert!(digest(&source, stamp, || false).is_err());
    }
}
