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

    /// Verify that an existing read-only loop uses the exact named, whole-file
    /// APEX payload inode on Recovery's volatile `/tmp` tmpfs. `backing` is a
    /// candidate path, not trusted evidence (even if obtained through sysfs).
    /// This is a read-only observation, not permission to detach the loop;
    /// callers must prevent competing loop and mount changes while using it.
    pub fn verify_apex_tmpfs_backing(device: &Path, backing: &Path) -> Result<()> {
        use anyhow::ensure;
        use std::{ffi::CString, os::{fd::FromRawFd, unix::{ffi::OsStrExt, fs::{FileTypeExt, MetadataExt, OpenOptionsExt}}}};

        const ROOT: &str = "/tmp/skyward-apex-payloads";
        const TMPFS_MAGIC: u64 = 0x0102_1994;
        let name = backing.file_name().context("missing APEX backing filename")?;
        ensure!(Path::new(ROOT).join(name).as_os_str() == backing.as_os_str(),
            "loop backing must be directly inside {ROOT}");
        let name = CString::new(name.as_bytes()).context("invalid APEX backing filename")?;
        let loop_name = device.file_name().and_then(|name| name.to_str()).context("missing loop node name")?;
        ensure!(["/dev/block", "/dev"].into_iter().any(|dir| Path::new(dir).join(loop_name).as_os_str() == device.as_os_str()),
            "expected a kernel loop node under /dev");
        let number = loop_name.strip_prefix("loop").context("expected a loop node")?.parse::<u32>()?;
        ensure!(loop_name == format!("loop{number}"), "expected a numbered kernel loop node");

        let open_at = |parent: &File, path: &std::ffi::CStr, flags: libc::c_int| -> Result<File> {
            // SAFETY: both the parent descriptor and NUL-terminated component
            // live through openat; O_PATH pins the object without opening
            // a possibly substituted special file for I/O.
            let fd = unsafe { libc::openat(parent.as_raw_fd(), path.as_ptr(), flags | libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd < 0 { return Err(std::io::Error::last_os_error()).with_context(|| format!("open {path:?} without following links")); }
            // SAFETY: successful openat returned a new owned descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        };
        let tmp_path = Path::new("/tmp");
        let tmp = File::options().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY).open(tmp_path)?;
        let tmp_meta = tmp.metadata()?;
        let tmp_device = (libc::major(tmp_meta.dev()) as u32, libc::minor(tmp_meta.dev()) as u32);
        let directory = open_at(&tmp, c"skyward-apex-payloads", libc::O_DIRECTORY)?;
        let directory_meta = directory.metadata()?;
        let source = open_at(&directory, &name, 0)?;
        let source_meta = source.metadata()?;
        ensure!(directory_meta.is_dir() && directory_meta.uid() == 0 && directory_meta.mode() & 0o777 == 0o700
            && source_meta.is_file() && source_meta.uid() == 0 && source_meta.mode() & 0o022 == 0
            && source_meta.nlink() == 1 && source_meta.len() > 0,
            "APEX staging directory or payload is not a private regular inode");

        let verify_mount = || -> Result<()> {
            let mounted = crate::mount::visible(tmp_path)?.context("no visible /tmp mount")?;
            ensure!(mounted.filesystem == "tmpfs" && mounted.device == tmp_device && tmp_device.0 == 0,
                "/tmp is not the expected volatile tmpfs mount");
            ensure!(crate::mount::visible(Path::new(ROOT))?.is_none() && crate::mount::visible(backing)?.is_none(),
                "unexpected mount covers the staged APEX payload");
            for file in [&tmp, &directory, &source] {
                let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
                // SAFETY: fstatfs fills the correctly sized buffer on success.
                if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
                    return Err(std::io::Error::last_os_error()).context("verify APEX tmpfs backing filesystem");
                }
                ensure!(unsafe { stat.assume_init() }.f_type as u64 == TMPFS_MAGIC && file.metadata()?.dev() == tmp_meta.dev(),
                    "APEX backing leaves the actual /tmp tmpfs");
            }
            let tmp_now = std::fs::symlink_metadata(tmp_path)?;
            let directory_now = open_at(&tmp, c"skyward-apex-payloads", libc::O_DIRECTORY)?.metadata()?;
            let source_now = open_at(&directory, &name, 0)?.metadata()?;
            ensure!(tmp_now.is_dir() && (tmp_now.dev(), tmp_now.ino()) == (tmp_meta.dev(), tmp_meta.ino())
                && (directory_now.dev(), directory_now.ino(), directory_now.mode(), directory_now.uid())
                == (directory_meta.dev(), directory_meta.ino(), directory_meta.mode(), directory_meta.uid())
                && (source_now.dev(), source_now.ino(), source_now.mode(), source_now.uid(), source_now.nlink(), source_now.len())
                == (source_meta.dev(), source_meta.ino(), source_meta.mode(), source_meta.uid(), source_meta.nlink(), source_meta.len()),
                "APEX staging directory or backing changed during verification");
            Ok(())
        };
        let loop_node = File::options().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW).open(device)?;
        let node = loop_node.metadata()?;
        ensure!(node.file_type().is_block_device() && libc::major(node.rdev()) == 7,
            "loop path does not name a kernel loop device");
        // Linux can reserve multiple minors per loop when max_part is set;
        // use its sysfs name and lo_number, not equality to the minor.
        let sysfs = PathBuf::from(format!("/sys/dev/block/7:{}", libc::minor(node.rdev())));
        ensure!(sysfs.canonicalize()?.file_name() == Some(std::ffi::OsStr::new(loop_name)),
            "loop path differs from the kernel's block-device name");
        // Open only the already identified block inode, read-only for ioctl.
        let loop_file = File::options().read(true).custom_flags(libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{}", loop_node.as_raw_fd()))?;
        let identity = |meta: &std::fs::Metadata| (meta.dev(), meta.ino(), meta.rdev(), meta.mode());
        ensure!(identity(&loop_file.metadata()?) == identity(&node), "opened loop inode differs from pinned node");
        let verify_status = || -> Result<()> {
            let mut actual: Info = unsafe { std::mem::zeroed() };
            if unsafe { libc::ioctl(loop_file.as_raw_fd(), GET_STATUS64 as libc::Ioctl, &mut actual) } < 0 {
                return Err(std::io::Error::last_os_error()).context("inspect active loop backing");
            }
            ensure!(actual.number == number && actual.device == source_meta.dev() && actual.inode == source_meta.ino(),
                "active loop backing differs from the staged APEX inode");
            ensure!(actual.flags & READ_ONLY != 0 && actual.offset == 0 && actual.size_limit == source_meta.len()
                && actual.encrypt_type == 0, "loop is not a read-only mapping of the complete staged APEX payload");
            Ok(())
        };
        verify_status()?;
        verify_mount()?;
        verify_status()?;
        ensure!(identity(&std::fs::symlink_metadata(device)?) == identity(&node), "loop node changed during verification");
        Ok(())
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
