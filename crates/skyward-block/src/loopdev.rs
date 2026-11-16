//! Making a block device out of part of a file, which is how the bundles a
//! phone keeps its shared libraries in are opened.

#[cfg(target_os = "android")]
pub use android::*;

#[cfg(target_os = "android")]
mod android {
    use anyhow::{Context, Result};
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};

    const CONTROL: &str = "/dev/loop-control";

    const GET_FREE: u32 = 0x4C82;
    const CONFIGURE: u32 = 0x4C0A;
    const GET_STATUS64: u32 = 0x4C05;
    const CLEAR_FD: u32 = 0x4C01;

    /// The device only ever reads. It stays pointed at the file until the
    /// recovery ends, which is as long as anything mounted from it lasts.
    const READ_ONLY: u32 = 1;

    /// Every field is a plain number or a run of bytes, so the request is
    /// made by zeroing it and filling in what matters.
    #[repr(C)]
    struct Info {
        device: u64,
        inode: u64,
        rdevice: u64,
        offset: u64,
        size_limit: u64,
        number: u32,
        encrypt_type: u32,
        encrypt_key_size: u32,
        flags: u32,
        file_name: [u8; 64],
        crypt_name: [u8; 64],
        encrypt_key: [u8; 32],
        init: [u64; 2],
    }

    #[repr(C)]
    struct Config {
        fd: u32,
        block_size: u32,
        info: Info,
        reserved: [u64; 8],
    }

    /// Open `file` from `offset` for `length` bytes as a block device, and
    /// give its path. The device goes away once whatever is mounted from it
    /// is unmounted.
    pub fn attach(file: &Path, offset: u64, length: u64) -> Result<PathBuf> {
        let backing = File::open(file).with_context(|| format!("open {}", file.display()))?;
        let control = File::open(CONTROL).with_context(|| format!("open {CONTROL}"))?;
        let number = unsafe { libc::ioctl(control.as_raw_fd(), GET_FREE as libc::Ioctl) };
        if number < 0 {
            return Err(std::io::Error::last_os_error()).context("ask for a free loop device");
        }
        let path = free_device(number as u32)?;
        let device = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        let mut config: Config = unsafe { std::mem::zeroed() };
        config.fd = backing.as_raw_fd() as u32;
        config.info.offset = offset;
        config.info.size_limit = length;
        config.info.flags = READ_ONLY;
        if unsafe { libc::ioctl(device.as_raw_fd(), CONFIGURE as libc::Ioctl, &mut config) } < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("point {} at {}", path.display(), file.display()));
        }
        Ok(path)
    }

    /// Clear a freshly configured, not-mounted loop after its caller's mount
    /// failed. Never use this to tear down an existing APEX. Both the current
    /// backing inode and device must still match the caller-owned file.
    pub fn detach_owned(device: &Path, backing: &Path) -> Result<()> {
        use anyhow::ensure;
        use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
        let name = device.file_name().and_then(|name| name.to_str()).context("loop path has no plain name")?;
        let number = name.strip_prefix("loop").context("cleanup target is not a loop device")?;
        ensure!(!number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()), "cleanup target is not a numbered loop device");
        let source = File::options().read(true).custom_flags(libc::O_NOFOLLOW).open(backing)
            .with_context(|| format!("open owned loop backing {}", backing.display()))?;
        let expected = source.metadata()?;
        ensure!(expected.is_file(), "owned loop backing is not a regular file");
        let loop_file = File::options().read(true).write(true).custom_flags(libc::O_NOFOLLOW).open(device)?;
        let node = loop_file.metadata()?;
        ensure!(node.file_type().is_block_device(), "loop cleanup target is not a block device");
        let devnum = format!("{}:{}", libc::major(node.rdev()), libc::minor(node.rdev()));
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").context("check loop cleanup mount ownership")?;
        ensure!(!mountinfo.lines().any(|line| line.split_whitespace().nth(2) == Some(devnum.as_str())), "refusing cleanup of an already-mounted loop device");
        let mut actual: Info = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(loop_file.as_raw_fd(), GET_STATUS64 as libc::Ioctl, &mut actual) } < 0 {
            return Err(std::io::Error::last_os_error()).context("inspect owned loop backing before cleanup");
        }
        ensure!(actual.device == expected.dev() && actual.inode == expected.ino(), "loop backing changed; refusing unrelated device cleanup");
        if unsafe { libc::ioctl(loop_file.as_raw_fd(), CLEAR_FD as libc::Ioctl) } < 0 {
            return Err(std::io::Error::last_os_error()).context("clear owned unmounted loop backing");
        }
        Ok(())
    }

    /// Where the kernel put the loop device it just handed out: Android
    /// keeps its block devices in their own directory.
    fn free_device(number: u32) -> Result<PathBuf> {
        for dir in ["/dev/block", "/dev"] {
            let path = Path::new(dir).join(format!("loop{number}"));
            if path.exists() {
                return Ok(path);
            }
        }
        anyhow::bail!("the kernel handed out loop device {number}, which is in neither /dev/block nor /dev")
    }
}
