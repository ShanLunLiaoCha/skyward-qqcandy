//! Fail-closed provenance observation for an already-running init service.
//! It does not launch services, change slots, or open any device for I/O.
//! A successful observation is not a sandbox: keep Recovery quiescent and
//! recheck at transaction boundaries. Future opens, IPC, and service behavior
//! are outside the scope of procfs provenance.
use anyhow::{Context, Result, ensure};
use procfs::process::{FDTarget, MMapPath};
use std::{collections::BTreeSet, path::Path};

pub(crate) type DeviceNumber = (u32, u32);

fn check_filesystem(device: DeviceNumber, ramdisk: DeviceNumber, forbidden: &BTreeSet<DeviceNumber>) -> Result<()> {
    ensure!(!forbidden.contains(&device), "filesystem refers to a restore target");
    ensure!(device == ramdisk, "filesystem is not the Recovery ramdisk");
    Ok(())
}

/// True for a file-backed mapping needing inode/path verification. Only
/// recognized, inode-less, device-less kernel pseudo mappings are exempt.
fn check_map(path: &MMapPath, device: DeviceNumber, inode: u64, ramdisk: DeviceNumber,
    forbidden: &BTreeSet<DeviceNumber>) -> Result<bool> {
    match path {
        MMapPath::Path(p) => {
            ensure!(p.is_absolute() && inode != 0, "ambiguous file-backed mapping {p:?}");
            // Binder maps a character node from devtmpfs/binderfs, not a
            // regular installed-system file. Its exact type, dev and inode
            // are checked below; a filename alone is not an exception.
            if is_binder_char(p) || is_property_file(p) || is_selinux_status(p) {
                ensure!(!forbidden.contains(&device), "Android IPC mapping is on a restore target");
            } else {
                check_filesystem(device, ramdisk, forbidden).with_context(|| format!("mapping {p:?}"))?;
            }
            Ok(true)
        }
        MMapPath::Anonymous | MMapPath::Heap | MMapPath::Stack | MMapPath::TStack(_)
        | MMapPath::Vdso | MMapPath::Vvar | MMapPath::Vsyscall => {
            ensure!(device == (0, 0) && inode == 0, "pseudo mapping unexpectedly has file backing");
            Ok(false)
        }
        MMapPath::Other(name) if name.starts_with("anon:") || name == "vvar_vclock" => {
            ensure!(device == (0, 0) && inode == 0, "named anonymous mapping unexpectedly has file backing");
            Ok(false)
        }
        other => anyhow::bail!("unknown or shared-file process mapping {other:?}"),
    }
}

fn is_known_ipc(target: &FDTarget) -> bool {
    match target {
        FDTarget::Socket(_) | FDTarget::Pipe(_) => true,
        // Neither eventfd nor timerfd can retain references to other open
        // files. Named pipes aren't treated as anonymous IPC.
        FDTarget::AnonInode(name) => matches!(name.as_str(), "[eventfd]" | "eventfd" | "[timerfd]" | "timerfd"),
        _ => false,
    }
}

fn epoll_targets(info: &str) -> Result<BTreeSet<u32>> {
    let mut targets = BTreeSet::new();
    for line in info.lines() {
        let Some(entry) = line.trim_start().strip_prefix("tfd:") else { continue; };
        let number = entry.split_whitespace().next().context("missing epoll target number")?.parse::<u32>()?;
        ensure!(targets.len() < 256 && targets.insert(number), "ambiguous or excessive epoll targets");
    }
    Ok(targets)
}

fn is_epoll(target: &FDTarget) -> bool {
    matches!(target, FDTarget::AnonInode(name) if matches!(name.as_str(), "[eventpoll]" | "eventpoll"))
}

fn is_binder_char(path: &Path) -> bool {
    matches!(path.to_str(), Some("/dev/hwbinder" | "/dev/binderfs/hwbinder"))
}

fn is_property_file(path: &Path) -> bool {
    let Some(name) = path.to_str().and_then(|p| p.strip_prefix("/dev/__properties__/")) else { return false; };
    if matches!(name, "property_info" | "properties_serial") { return true; }
    name.strip_prefix("u:object_r:").and_then(|n| n.strip_suffix(":s0"))
        .is_some_and(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}

fn is_selinux_status(path: &Path) -> bool { path.as_os_str() == "/sys/fs/selinux/status" }

fn is_known_char(path: &Path) -> bool {
    is_binder_char(path) || matches!(path.to_str(), Some("/dev/null" | "/dev/binder" | "/dev/vndbinder"
        | "/dev/binderfs/binder" | "/dev/binderfs/vndbinder"))
}

#[cfg(target_os = "android")]
use std::{fs, os::unix::fs::{FileTypeExt, MetadataExt}, path::PathBuf};
#[cfg(target_os = "android")]
use procfs::process::Process;

#[cfg(target_os = "android")]
fn device_number(device: u64) -> DeviceNumber {
    let dev = device as libc::dev_t;
    (libc::major(dev) as u32, libc::minor(dev) as u32)
}

#[cfg(target_os = "android")]
fn check_ramdisk_object(meta: &fs::Metadata, directory: bool, ramdisk: DeviceNumber,
    forbidden: &BTreeSet<DeviceNumber>) -> Result<()> {
    ensure!(if directory { meta.is_dir() } else { meta.is_file() }, "unexpected ramdisk object type");
    check_filesystem(device_number(meta.dev()), ramdisk, forbidden)
}

#[cfg(target_os = "android")]
fn verify_property_file(path: &Path, observed: &fs::Metadata, forbidden: &BTreeSet<DeviceNumber>) -> Result<()> {
    let dev = skyward_block::mount::visible(Path::new("/dev"))?.context("missing /dev mount")?;
    let parent = fs::symlink_metadata("/dev/__properties__")?;
    let file = fs::symlink_metadata(path)?;
    ensure!(dev.filesystem == "tmpfs" && dev.device.0 == 0 && !forbidden.contains(&dev.device)
        && parent.is_dir() && parent.uid() == 0 && parent.mode() & 0o022 == 0
        && device_number(parent.dev()) == dev.device && file.is_file() && file.uid() == 0
        && file.mode() & 0o022 == 0 && file.nlink() == 1 && device_number(file.dev()) == dev.device
        && observed.dev() == file.dev() && observed.ino() == file.ino(),
        "property file does not match the protected Recovery /dev tmpfs inode: {path:?}");
    Ok(())
}

#[cfg(target_os = "android")]
fn verify_selinux_status(path: &Path, observed: &fs::Metadata, forbidden: &BTreeSet<DeviceNumber>) -> Result<()> {
    let dev = skyward_block::mount::visible(Path::new("/sys/fs/selinux"))?.context("missing selinuxfs mount")?;
    let file = fs::symlink_metadata(path)?;
    ensure!(dev.filesystem == "selinuxfs" && dev.device.0 == 0 && !forbidden.contains(&dev.device)
        && file.is_file() && file.uid() == 0 && file.mode() & 0o222 == 0
        && device_number(file.dev()) == dev.device && observed.dev() == file.dev() && observed.ino() == file.ino(),
        "SELinux status is not the read-only kernel status inode");
    Ok(())
}

#[cfg(target_os = "android")]
fn verify_epoll(proc: &Path, pid: i32, index: u32, ramdisk: DeviceNumber,
    forbidden: &BTreeSet<DeviceNumber>) -> Result<()> {
    use std::io::Read;
    // fdinfo's target number alone is not proof: an epoll interest can
    // outlive a closed or reused descriptor number. KCMP_EPOLL_TFD compares
    // the underlying open file description at the target and in epoll.
    #[repr(C)]
    struct Slot { efd: u32, tfd: u32, toff: u32 }
    const KCMP_EPOLL_TFD: libc::c_int = 7;
    let epfd = proc.join("fd").join(index.to_string());
    let check_kind = || -> Result<()> {
        let link = fs::read_link(&epfd)?;
        let kind: FDTarget = link.to_str().context("non-UTF8 epoll link")?.parse()?;
        ensure!(is_epoll(&kind), "epoll descriptor changed");
        Ok(())
    };
    let fdinfo = proc.join("fdinfo").join(index.to_string());
    let read_info = || -> Result<String> {
        let mut text = String::new();
        fs::File::open(&fdinfo)?.take(65537).read_to_string(&mut text)?;
        ensure!(text.len() <= 65536, "epoll fdinfo exceeds the audit limit");
        Ok(text)
    };
    check_kind()?;
    let observed = read_info()?;
    for target in epoll_targets(&observed)? {
        ensure!(target != index, "epoll references itself");
        let magic = proc.join("fd").join(target.to_string());
        let link = fs::read_link(&magic)?;
        let kind: FDTarget = link.to_str().context("non-UTF8 epoll target link")?.parse()?;
        ensure!(is_known_ipc(&kind) || matches!(&kind, FDTarget::Path(path) if is_binder_char(path)),
            "epoll target is not approved Binder or IPC: {kind:?}");
        let same = || -> Result<()> {
            let slot = Slot { efd: index, tfd: target, toff: 0 };
            let result = unsafe { libc::syscall(libc::SYS_kcmp, pid, pid, KCMP_EPOLL_TFD,
                libc::c_ulong::from(target), &slot as *const Slot) };
            if result < 0 { return Err(std::io::Error::last_os_error()).context("verify epoll's retained file via KCMP_EPOLL_TFD"); }
            ensure!(result == 0, "epoll retained a different file than target descriptor {target}");
            Ok(())
        };
        same()?;
        verify_fd(&magic, &kind, ramdisk, forbidden)?;
        same()?;
        ensure!(fs::read_link(&magic)? == link, "epoll target changed during audit");
    }
    ensure!(read_info()? == observed, "epoll interests changed during audit");
    check_kind()
}

#[cfg(target_os = "android")]
fn verify_fd(magic_link: &Path, target: &FDTarget, ramdisk: DeviceNumber,
    forbidden: &BTreeSet<DeviceNumber>) -> Result<()> {
    let link = fs::read_link(magic_link)?;
    let observed: FDTarget = link.to_str().context("non-UTF8 descriptor link")?.parse()?;
    ensure!(&observed == target, "descriptor changed while inspecting process");
    if is_known_ipc(target) {
        ensure!(fs::read_link(magic_link)? == link, "IPC descriptor changed while inspecting process");
        return Ok(());
    }
    let FDTarget::Path(path) = target else { anyhow::bail!("unknown open descriptor {target:?}"); };
    ensure!(path.is_absolute(), "ambiguous open descriptor {path:?}");
    // Stat the magic link's underlying object, not a pathname that may now
    // resolve to a different file after a bind mount or unmount.
    let meta = fs::metadata(magic_link)?;
    let ty = meta.file_type();
    ensure!(!forbidden.contains(&device_number(meta.dev())), "descriptor is on a restore target");
    if ty.is_block_device() {
        // Even an apparently unrelated block descriptor is out of scope for
        // these two ramdisk services. Do not treat st_dev as its rdev.
        anyhow::bail!("open block device {path:?} ({:?})", device_number(meta.rdev()));
    } else if ty.is_char_device() {
        if path.as_os_str() == "/dev/pmsg0" {
            let (major, minor) = device_number(meta.rdev());
            let sysfs = fs::canonicalize(format!("/sys/dev/char/{major}:{minor}"))?;
            ensure!(sysfs == Path::new("/sys/devices/virtual/pmsg/pmsg0") && meta.uid() == 0
                && meta.mode() & 0o111 == 0, "pmsg descriptor is not the kernel logging device");
        } else {
            ensure!(is_known_char(path), "unrecognized character descriptor {path:?}");
        }
        let expected = fs::metadata(path)?;
        ensure!(expected.file_type().is_char_device() && expected.rdev() == meta.rdev()
            && expected.dev() == meta.dev() && expected.ino() == meta.ino(),
            "character descriptor no longer matches the known kernel node");
    } else if is_property_file(path) {
        verify_property_file(path, &meta, forbidden)?;
    } else if is_selinux_status(path) {
        verify_selinux_status(path, &meta, forbidden)?;
    } else {
        check_ramdisk_object(&meta, ty.is_dir(), ramdisk, forbidden)?;
    }
    let after = fs::metadata(magic_link)?;
    ensure!(fs::read_link(magic_link)? == link && (after.dev(), after.ino(), after.mode(), after.rdev())
        == (meta.dev(), meta.ino(), meta.mode(), meta.rdev()), "descriptor changed while inspecting process");
    Ok(())
}

/// Process identity pinned by the init PID property and start time, not just
/// a service name. Rechecking never accepts a replacement PID or process.
#[cfg(target_os = "android")]
#[derive(Debug)]
pub(crate) struct VerifiedService {
    name: String,
    executable: PathBuf,
    pid: u32,
    starttime: u64,
}

#[cfg(target_os = "android")]
fn init_pid(name: &str) -> Result<u32> {
    ensure!(!name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric()
        || matches!(b, b'.' | b'_' | b'-')), "invalid init service name");
    ensure!(skyward_sys::prop(&format!("init.svc.{name}")).as_deref() == Some("running"),
        "init service {name} is not running");
    let pid: u32 = skyward_sys::prop(&format!("init.svc_debug_pid.{name}"))
        .with_context(|| format!("init gives no PID for {name}"))?.parse()?;
    ensure!(pid > 1 && pid <= i32::MAX as u32, "invalid init service PID");
    Ok(pid)
}

#[cfg(target_os = "android")]
pub(crate) fn verify_init_service(name: &str, executable: &Path,
    forbidden_devices: &BTreeSet<DeviceNumber>) -> Result<VerifiedService> {
    ensure!(executable.is_absolute(), "expected an exact absolute executable pathname");
    let pid = init_pid(name)?;
    let stat = Process::new(pid as i32)?.stat()?;
    let service = VerifiedService { name: name.to_owned(), executable: executable.to_owned(), pid, starttime: stat.starttime };
    service.recheck(forbidden_devices)?;
    Ok(service)
}

#[cfg(target_os = "android")]
impl VerifiedService {
    pub(crate) fn pid(&self) -> u32 { self.pid }

    pub(crate) fn recheck(&self, forbidden_devices: &BTreeSet<DeviceNumber>) -> Result<()> {
        let proc = Path::new("/proc").join(self.pid.to_string());
        let process = Process::new(self.pid as i32)?;
        let identity = || -> Result<()> {
            ensure!(init_pid(&self.name)? == self.pid, "init PID changed for {}", self.name);
            let stat = process.stat()?;
            ensure!(stat.ppid == 1 && stat.starttime == self.starttime && process.exe()? == self.executable,
                "service {} is not the original init-owned process with the expected executable", self.name);
            Ok(())
        };
        identity()?;
        let namespace = fs::read_link("/proc/self/ns/mnt")?;
        ensure!(fs::read_link("/proc/1/ns/mnt")? == namespace && fs::read_link(proc.join("ns/mnt"))? == namespace,
            "service and Recovery do not share init's mount namespace");
        let root = fs::metadata("/")?;
        let ramdisk = device_number(root.dev());
        let check_roots = || -> Result<()> {
            for path in [Path::new("/proc/1/root").to_owned(), proc.join("root")] {
                let other = fs::metadata(path)?;
                ensure!(other.is_dir() && (other.dev(), other.ino()) == (root.dev(), root.ino()),
                    "service or init root differs from Recovery root");
            }
            check_ramdisk_object(&fs::metadata(proc.join("cwd"))?, true, ramdisk, forbidden_devices)
                .context("verify service working directory")
        };
        check_roots()?;
        let check_exe = || -> Result<()> {
            let expected = fs::metadata(&self.executable)?;
            let actual = fs::metadata(proc.join("exe"))?;
            check_ramdisk_object(&actual, false, ramdisk, forbidden_devices)?;
            ensure!((actual.dev(), actual.ino()) == (expected.dev(), expected.ino()),
                "service executable differs from the named ramdisk object");
            Ok(())
        };
        check_exe()?;
        let maps = process.maps().context("read service memory mappings")?;
        ensure!(!maps.0.is_empty() && maps.0.len() <= 8192, "unreasonable service mapping count");
        for map in maps.0 {
            let device = (u32::try_from(map.dev.0)?, u32::try_from(map.dev.1)?);
            if check_map(&map.pathname, device, map.inode, ramdisk, forbidden_devices)? {
                let MMapPath::Path(path) = &map.pathname else { unreachable!("file-backed map") };
                let metadata = fs::metadata(path).with_context(|| format!("inspect service mapping {path:?}"))?;
                if is_binder_char(path) {
                    ensure!(metadata.file_type().is_char_device(), "Binder map is not backed by a character node: {path:?}");
                } else if is_property_file(path) {
                    verify_property_file(path, &metadata, forbidden_devices)?;
                } else if is_selinux_status(path) {
                    verify_selinux_status(path, &metadata, forbidden_devices)?;
                } else {
                    check_ramdisk_object(&metadata, false, ramdisk, forbidden_devices)?;
                }
                ensure!(device_number(metadata.dev()) == device && metadata.ino() == map.inode,
                    "service mapping differs from its named ramdisk inode: {path:?}");
            }
        }
        for (index, fd) in process.fd().context("list service descriptors")?.enumerate() {
            ensure!(index < 4096, "unreasonable service descriptor count");
            let fd = fd.context("read service descriptor")?;
            let proof = if is_epoll(&fd.target) {
                verify_epoll(&proc, i32::try_from(self.pid)?, u32::try_from(fd.fd)?, ramdisk, forbidden_devices)
            } else {
                verify_fd(&proc.join("fd").join(fd.fd.to_string()), &fd.target, ramdisk, forbidden_devices)
            };
            proof.with_context(|| format!("verify service descriptor {}", fd.fd))?;
        }
        check_roots()?;
        check_exe()?;
        ensure!(fs::read_link("/proc/self/ns/mnt")? == namespace && fs::read_link(proc.join("ns/mnt"))? == namespace,
            "mount namespace changed while inspecting service");
        identity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_installed_apex_and_ambiguous_backing() {
        let ramdisk = (0, 12);
        let forbidden = BTreeSet::from([(253, 11)]);
        assert!(check_map(&MMapPath::Path("/vendor/bin/boot-hal".into()), ramdisk, 40, ramdisk, &forbidden).unwrap());
        for (name, device, inode) in [
            ("/apex/com.android.runtime/lib64/libc.so", (7, 2), 12),
            ("/vendor/lib64/installed.so", (253, 11), 20),
            ("/system/lib64/unknown.so", ramdisk, 0), ("relative.so", ramdisk, 8),
        ] {
            assert!(check_map(&MMapPath::Path(name.into()), device, inode, ramdisk, &forbidden).is_err());
        }
        let hwbinder = MMapPath::Path("/dev/binderfs/hwbinder".into());
        assert!(check_map(&hwbinder, (0, 40), 51, ramdisk, &forbidden).unwrap());
        assert!(check_map(&hwbinder, (253, 11), 51, ramdisk, &forbidden).is_err());
        assert!(check_map(&MMapPath::Path("/dev/binderfs/hwbinder-other".into()), (0, 40), 51, ramdisk, &forbidden).is_err());
        assert!(check_filesystem(ramdisk, ramdisk, &BTreeSet::from([ramdisk])).is_err());
    }

    #[test]
    fn property_mapping_requires_exact_path_and_cannot_use_restore_devices() {
        let property = MMapPath::Path("/dev/__properties__/u:object_r:property_service_version_prop:s0".into());
        let targets = BTreeSet::from([(253, 11)]);
        assert!(check_map(&property, (0, 16), 223, (0, 1), &targets).unwrap());
        assert!(check_map(&property, (253, 11), 223, (0, 1), &targets).is_err());
        for path in ["/dev/__properties__/../property_info", "/dev/__properties__/property_info (deleted)",
            "/dev/__properties__/u:object_r:p/q:s0", "/mnt/__properties__/property_info"] {
            assert!(!is_property_file(Path::new(path)));
        }
    }

    #[test]
    fn only_kernel_pseudo_and_unbacked_anonymous_maps_are_exempt() {
        let none = BTreeSet::new();
        for path in [MMapPath::Heap, MMapPath::Stack, MMapPath::Vdso, MMapPath::Other("anon:libc malloc".into())] {
            assert!(!check_map(&path, (0, 0), 0, (0, 12), &none).unwrap());
            assert!(check_map(&path, (0, 12), 0, (0, 12), &none).is_err());
            assert!(check_map(&path, (0, 0), 1, (0, 12), &none).is_err());
        }
        assert!(check_map(&MMapPath::Vsys(1), (0, 0), 0, (0, 12), &none).is_err());
        assert!(check_map(&MMapPath::Other("unknown".into()), (0, 0), 0, (0, 12), &none).is_err());
    }

    #[test]
    fn epoll_requires_unambiguous_targets_and_does_not_count_as_simple_ipc() {
        assert_eq!(epoll_targets("pos:\t0\ntfd: 8 events: 19\ntfd: 9 events: 19\n").unwrap(), BTreeSet::from([8, 9]));
        for s in ["tfd:\n", "tfd: -8\n", "tfd: 8\ntfd: 8\n"] { assert!(epoll_targets(s).is_err()); }
        let epoll = "anon_inode:[eventpoll]".parse().unwrap();
        assert!(is_epoll(&epoll));
        assert!(!is_known_ipc(&epoll));
    }

    #[test]
    fn only_exact_character_nodes_and_simple_ipc_are_recognized() {
        assert!(is_known_char(Path::new("/dev/binderfs/hwbinder")));
        for bad in ["/dev/block/by-name/super", "/dev/ufs-bsg0", "/dev/binderfs/hwbinder-old", "/dev/binderfs/x/../hwbinder", "/dev/null (deleted)"] {
            assert!(!is_known_char(Path::new(bad)), "{bad}");
        }
        for text in ["pipe:[10]", "socket:[10]", "anon_inode:[eventfd]"] {
            assert!(is_known_ipc(&text.parse().unwrap()), "{text}");
        }
        assert!(!is_known_ipc(&"anon_inode:[eventpoll]".parse().unwrap()));
        assert!(!is_known_ipc(&FDTarget::Path("/data/ota/file".into())));
    }
}
