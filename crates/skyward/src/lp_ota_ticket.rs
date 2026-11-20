//! A sealed same-process continuation across a Recovery exec. Seals stop
//! mutation, not forgery by privileged Recovery code.
use anyhow::{Result, ensure};

const MAGIC: &[u8; 8] = b"SKYLPOT1";
const BOOT_LEN: usize = 36;
const STAMP_LEN: usize = 7 * 8;
const BINDING_LEN: usize = 8 + 1 + 4 + BOOT_LEN + STAMP_LEN;
const TICKET_LEN: usize = BINDING_LEN + 32;

fn binding(stage: &str, pid: u32, boot: &str, stamp: [u8; STAMP_LEN]) -> Result<[u8; BINDING_LEN]> {
    let tag = match stage {
        "run-lp-handoff" => 1,
        "resume-lp-ota" => 2,
        _ => anyhow::bail!("unrecognized OTA maintenance stage"),
    };
    ensure!(pid > 1, "invalid OTA ticket process identity");
    ensure!(boot.len() == BOOT_LEN && boot.bytes().enumerate().all(|(i, b)| {
        if matches!(i, 8 | 13 | 18 | 23) { b == b'-' } else { b.is_ascii_hexdigit() }
    }), "invalid boot identity for OTA ticket");
    let mut bytes = [0; BINDING_LEN];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8] = tag;
    bytes[9..13].copy_from_slice(&pid.to_le_bytes());
    bytes[13..13 + BOOT_LEN].copy_from_slice(boot.as_bytes());
    bytes[13 + BOOT_LEN..].copy_from_slice(&stamp);
    Ok(bytes)
}

fn encode(b: &[u8; BINDING_LEN], digest: &[u8; 32]) -> [u8; TICKET_LEN] {
    let mut bytes = [0; TICKET_LEN];
    bytes[..BINDING_LEN].copy_from_slice(b);
    bytes[BINDING_LEN..].copy_from_slice(digest);
    bytes
}

fn decode(bytes: &[u8], expected: &[u8; BINDING_LEN]) -> Result<[u8; 32]> {
    ensure!(bytes.len() == TICKET_LEN && bytes.starts_with(expected),
        "OTA ticket is malformed or does not match this stage, boot, process or source");
    Ok(bytes[BINDING_LEN..].try_into()?)
}

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use anyhow::Context;
    use skyward_install::lp_ota_source::{CAPTURED_OTA_SIZE, FileStamp};
    use std::{fs::{self, File}, io::Write,
        os::{fd::{AsRawFd, FromRawFd, RawFd}, unix::{fs::FileExt, process::CommandExt}},
        path::Path, process::{self, Command}};

    const SEALS: libc::c_int = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    const PROC_NAME: &str = "/memfd:skyward-lp-ota (deleted)";

    pub(crate) struct Ticket {
        pub file: File,
        pub stamp: FileStamp,
        pub digest: [u8; 32],
    }

    fn current_binding(stage: &str, stamp: FileStamp) -> Result<[u8; BINDING_LEN]> {
        ensure!(unsafe { libc::getuid() == 0 && libc::geteuid() == 0 }, "OTA ticket requires a root Recovery process");
        ensure!(stamp.size == CAPTURED_OTA_SIZE, "OTA ticket requires the approved ZIP length");
        let values = [stamp.device, stamp.inode, stamp.size, stamp.modified.0 as u64,
            stamp.modified.1 as u64, stamp.changed.0 as u64, stamp.changed.1 as u64];
        let mut bytes = [0; STAMP_LEN];
        for (chunk, value) in bytes.chunks_exact_mut(8).zip(values) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").context("read kernel boot identity")?;
        binding(stage, process::id(), boot.trim(), bytes)
    }

    fn fd_flags(fd: RawFd) -> Result<libc::c_int> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1 { return Err(std::io::Error::last_os_error()).context("inspect OTA continuation descriptor"); }
        Ok(flags)
    }

    fn set_flags(fd: RawFd, flags: libc::c_int) -> Result<()> {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } == -1 {
            return Err(std::io::Error::last_os_error()).context("set OTA continuation descriptor flags");
        }
        Ok(())
    }

    pub(crate) fn exec(ticket: Ticket, stage: &str) -> Result<()> {
        let ota_fd = ticket.file.as_raw_fd();
        ensure!(ota_fd > 2 && FileStamp::read(&ticket.file)? == ticket.stamp, "confirmed OTA descriptor changed");
        let bytes = encode(&current_binding(stage, ticket.stamp)?, &ticket.digest);
        let fd = unsafe { libc::memfd_create(c"skyward-lp-ota".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
        if fd < 0 { return Err(std::io::Error::last_os_error()).context("create sealed OTA continuation"); }
        // SAFETY: successful memfd_create returned a fresh owned descriptor.
        let mut token = unsafe { File::from_raw_fd(fd) };
        ensure!(fd > 2, "OTA ticket occupied a standard-stream descriptor");
        token.write_all(&bytes)?;
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) } == -1 {
            return Err(std::io::Error::last_os_error()).context("seal OTA continuation");
        }
        let ota_flags = fd_flags(ota_fd)?;
        let token_flags = fd_flags(fd)?;
        ensure!(ota_flags & libc::FD_CLOEXEC != 0 && token_flags & libc::FD_CLOEXEC != 0,
            "OTA continuation descriptors must begin close-on-exec");
        let result = (|| -> Result<()> {
            set_flags(fd, token_flags & !libc::FD_CLOEXEC)?;
            set_flags(ota_fd, ota_flags & !libc::FD_CLOEXEC)?;
            let error = Command::new("/proc/self/exe").arg0("skyward").arg(stage)
                .arg("--ticket-fd").arg(fd.to_string()).arg("--ota-fd").arg(ota_fd.to_string()).exec();
            Err(error).context("exec OTA continuation stage")
        })();
        // Success never returns. Restore both flag sets on any failure.
        let a = set_flags(fd, token_flags);
        let b = set_flags(ota_fd, ota_flags);
        result.and(a).and(b)
    }

    /// Consume descriptors inherited by exec. Run at internal startup, before
    /// other threads could invalidate the descriptor identity.
    pub(crate) fn take(ticket_fd: RawFd, ota_fd: RawFd, stage: &str) -> Result<Ticket> {
        ensure!(ticket_fd > 2 && ota_fd > 2 && ticket_fd != ota_fd, "invalid OTA continuation descriptor numbers");
        let token_flags = fd_flags(ticket_fd)?;
        let ota_flags = fd_flags(ota_fd)?;
        ensure!((token_flags | ota_flags) & libc::FD_CLOEXEC == 0, "OTA descriptors were not inherited from exec");
        ensure!(fs::read_link(format!("/proc/self/fd/{ticket_fd}"))? == Path::new(PROC_NAME),
            "OTA ticket is not the expected anonymous memfd");
        let seals = unsafe { libc::fcntl(ticket_fd, libc::F_GET_SEALS) };
        if seals == -1 { return Err(std::io::Error::last_os_error()).context("inspect OTA ticket seals"); }
        ensure!(seals & SEALS == SEALS, "OTA continuation memfd is not immutable");
        // SAFETY: distinct valid FDs were checked with F_GETFD in this
        // single-threaded internal entry, and ownership transfers here.
        let (token, file) = unsafe { (File::from_raw_fd(ticket_fd), File::from_raw_fd(ota_fd)) };
        set_flags(ticket_fd, token_flags | libc::FD_CLOEXEC)?;
        set_flags(ota_fd, ota_flags | libc::FD_CLOEXEC)?;
        let meta = token.metadata()?;
        ensure!(meta.is_file() && meta.len() == TICKET_LEN as u64, "invalid sealed OTA ticket size");
        let mut bytes = [0; TICKET_LEN];
        token.read_exact_at(&mut bytes, 0)?;
        drop(token);
        let stamp = FileStamp::read(&file)?;
        let digest = decode(&bytes, &current_binding(stage, stamp)?)?;
        Ok(Ticket { file, stamp, digest })
    }
}

#[cfg(target_os = "android")]
pub(crate) use android::{Ticket, exec, take};

#[cfg(test)]
mod tests {
    use super::*;
    const BOOT: &str = "64110b66-039d-4b67-9e9e-adda44f692cd";

    #[test]
    fn ticket_round_trips_and_rejects_noncanonical_lengths() {
        let expected = binding("run-lp-handoff", 123, BOOT, [0; STAMP_LEN]).unwrap();
        let digest = [7; 32];
        let bytes = encode(&expected, &digest);
        assert_eq!(decode(&bytes, &expected).unwrap(), digest);
        assert!(decode(&bytes[..bytes.len() - 1], &expected).is_err());
        assert!(decode(&[bytes.as_slice(), &[0]].concat(), &expected).is_err());
    }

    #[test]
    fn stage_boot_pid_and_source_are_all_bound() {
        let expected = binding("run-lp-handoff", 123, BOOT, [0; STAMP_LEN]).unwrap();
        let bytes = encode(&expected, &[7; 32]);
        let other_boot = "64110b66-039d-4b67-9e9e-adda44f692ce";
        for (stage, pid, boot, stamp) in [
            ("resume-lp-ota", 123, BOOT, [0; STAMP_LEN]),
            ("run-lp-handoff", 124, BOOT, [0; STAMP_LEN]),
            ("run-lp-handoff", 123, other_boot, [0; STAMP_LEN]),
            ("run-lp-handoff", 123, BOOT, [1; STAMP_LEN]),
        ] {
            assert!(decode(&bytes, &binding(stage, pid, boot, stamp).unwrap()).is_err());
        }
        assert!(binding("recovery", 123, BOOT, [0; STAMP_LEN]).is_err());
        assert!(binding("run-lp-handoff", 1, BOOT, [0; STAMP_LEN]).is_err());
        assert!(binding("run-lp-handoff", 123, "64110b66039d-4b67-9e9e-adda44f692cd", [0; STAMP_LEN]).is_err());
    }
}
