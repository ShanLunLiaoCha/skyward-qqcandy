//! Explicit PGZ110 Trustonic startup, not a generic TEE fallback.
//! No reformat, store creation, credential requests, or automatic restart.
use anyhow::{ensure, Context, Result};
use skyward_config::Trustonic;
use std::path::{Path, PathBuf};

const DAEMON: &str = "/vendor/bin/mcDriverDaemon";
const STORE: &str = "/mnt/vendor/persist/mcRegistry/Store_1.tf";
const REQUIRED: [&str; 3] = [
    "/vendor/app/mcRegistry/07170000000000000000000000000000.drbin",
    "/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin",
    "/vendor/app/mcRegistry/07061000000000000000000000000000.tlbin",
];
const ABSTRACT_NAME: &[u8] = b"mcdaemon";

#[derive(Debug, PartialEq, Eq)]
struct Plan {
    args: Vec<String>,
    libraries: Vec<PathBuf>,
}

fn plan(config: &Trustonic, vndk: Option<&Path>) -> Result<Plan> {
    ensure!(config.allow_persistent_writes, "Trustonic FSD may write existing secure storage; explicit opt-in required");
    let mut libraries: Vec<PathBuf> = config.libraries.iter().map(PathBuf::from).collect();
    // Match the stock recovery-first vendor runtime convention; never overwrite libraries.
    if libraries.is_empty() {
        libraries.extend([PathBuf::from("/system/lib64"), PathBuf::from("/vendor/lib64")]);
    }
    if let Some(path) = vndk {
        libraries.push(path.to_path_buf());
    }
    ensure!(libraries.iter().all(|p| p.is_absolute() && p.components().all(|c| matches!(c, std::path::Component::RootDir | std::path::Component::Normal(_)))), "Trustonic library directories must be plain absolute paths");
    Ok(Plan { args: vec!["--P1".into(), "/mnt/vendor/persist/mcRegistry".into()], libraries })
}

/// Check every existing path component without following symlinks. The store
/// must already exist and be nonempty; checking never creates or repairs it.
fn existing_file(path: &Path) -> Result<std::fs::Metadata> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).with_context(|| format!("stat {}", ancestor.display()))?;
        ensure!(!metadata.file_type().is_symlink(), "refusing Trustonic symlink {}", ancestor.display());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(metadata.is_file() && metadata.len() > 0, "{} must be an existing nonempty regular file; no create/reformat", path.display());
    Ok(metadata)
}

/// Only the child returned by this module's spawn is ever owned or signalled.
/// Keeping this guard in recovery's run scope also handles UI/bring-up errors.
#[cfg(any(target_os = "android", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonState { Running, RegistryReady, Exited, Terminated, Forced }

#[cfg(any(target_os = "android", test))]
pub struct DaemonGuard {
    child: std::process::Child,
    state: DaemonState,
}

#[cfg(any(target_os = "android", test))]
impl DaemonGuard {
    fn new(child: std::process::Child) -> Self { Self { child, state: DaemonState::Running } }

    fn check_running(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait().context("inspect owned Trustonic child")? {
            self.state = DaemonState::Exited;
            let _ = skyward_sys::kmsg(&format!("Trustonic owned child {} exited (not restarted): {status}", self.child.id()));
            anyhow::bail!("Trustonic daemon exited: {status}");
        }
        Ok(())
    }

    pub fn check(&mut self) -> Result<()> { self.check_running() }

    /// Partition transactions must observe successful reaping, not only a
    /// best-effort stop log. Keep ownership if inspection fails.
    pub fn stop_checked(&mut self) -> Result<()> {
        self.stop();
        ensure!(self.child.try_wait().context("confirm owned Trustonic child stopped")?.is_some(), "Trustonic child remains alive; refusing partition transaction");
        Ok(())
    }

    fn registry_ready(&mut self) {
        self.state = DaemonState::RegistryReady;
    }

    /// Stop only this owned child before vendor/odm unmount or fastboot.
    /// Calling again is harmless; neither TERM nor forced KILL guarantees flush.
    pub fn stop(&mut self) {
        // Never signal after try_wait fails: child ownership/reaping is unclear.
        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.state = DaemonState::Exited;
                let _ = skyward_sys::kmsg(&format!("Trustonic owned child {} already exited: {status}", self.child.id()));
                return;
            }
            Err(error) => {
                let _ = skyward_sys::kmsg(&format!("Trustonic owned child {} cannot be inspected; not signalling: {error}", self.child.id()));
                return;
            }
            Ok(None) => {}
        }
        // SIGTERM is a best effort grace period, NOT a secure-filesystem flush
        // guarantee. A stuck child is bounded by KILL, then reaped by its owner.
        let pid = self.child.id();
        if let Err(error) = terminate_owned(pid) {
            let _ = skyward_sys::kmsg(&format!("Trustonic owned child {pid} TERM failed: {error}"));
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.state = DaemonState::Terminated;
                    let _ = skyward_sys::kmsg(&format!("Trustonic owned child {pid} stopped after TERM: {status}; flush not guaranteed"));
                    return;
                }
                Err(error) => {
                    let _ = skyward_sys::kmsg(&format!("Trustonic owned child {pid} wait failed; not signalling further: {error}"));
                    return;
                }
                Ok(None) => {}
            }
            if std::time::Instant::now() >= deadline { break; }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let killed = self.child.kill();
        let waited = self.child.wait();
        self.state = DaemonState::Forced;
        let _ = skyward_sys::kmsg(&format!("Trustonic owned child {pid} forced stop, kill={killed:?}, wait={waited:?}; secure-store flush not guaranteed"));
    }
}

#[cfg(any(target_os = "android", test))]
impl Drop for DaemonGuard { fn drop(&mut self) { self.stop(); } }

#[cfg(any(target_os = "android", all(test, unix)))]
fn terminate_owned(pid: u32) -> std::io::Result<()> {
    unsafe extern "C" { fn kill(pid: std::ffi::c_int, signal: std::ffi::c_int) -> std::ffi::c_int; }
    let pid = i32::try_from(pid).map_err(|_| std::io::Error::other("child PID out of range"))?;
    if unsafe { kill(pid, 15) } == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[cfg(all(test, not(unix)))]
fn terminate_owned(_pid: u32) -> std::io::Result<()> { Err(std::io::Error::other("TERM requires Unix")) }

/// Must run AFTER any setuid/setgid operation, which clears PDEATHSIG on Linux.
/// The post-prctl parent check closes death-before-installation's race window.
#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
fn parent_death_signal(expected_parent: i32) -> std::io::Result<()> {
    unsafe extern "C" {
        fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
        fn getppid() -> std::ffi::c_int;
    }
    if unsafe { prctl(1, 15 as std::ffi::c_ulong, 0 as std::ffi::c_ulong, 0 as std::ffi::c_ulong, 0 as std::ffi::c_ulong) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { getppid() } != expected_parent {
        return Err(std::io::Error::other("recovery parent died before Trustonic exec"));
    }
    Ok(())
}

/// Persistent Trustonic mode cannot safely perform automatic partition work.
/// Cancel only that requested work and remain in the menu instead of failing
/// init's critical service repeatedly. Caller records the cancellation and
/// clears its BCB request before starting any daemon.
#[cfg(any(target_os = "android", test))]
pub fn cancel_unsafe_request(request: &mut skyward_sys::bcb::Request) -> Option<String> {
    use skyward_sys::bcb::Work;
    if matches!(request.work, Work::Menu | Work::Exit | Work::Fastboot) { return None; }
    let cancelled = format!("{:?}", request.work);
    request.work = Work::Menu;
    request.shutdown_after = false;
    request.reason = Some("Automatic recovery work cancelled: experimental Trustonic persistent-write mode".into());
    Some(cancelled)
}

fn owned_peer(expected_pid: u32, expected_uid: u32, peer_pid: i32, peer_uid: u32) -> Result<()> {
    ensure!(peer_pid > 0 && peer_pid as u32 == expected_pid && peer_uid == expected_uid,
        "mcdaemon socket belongs to a different process/account; refusing adoption");
    Ok(())
}

#[cfg(target_os = "android")]
pub fn start(config: &Trustonic, vndk: Option<&Path>) -> Result<DaemonGuard> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::process::CommandExt;
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    use skyward_sys::ueventd;

    let plan = plan(config, vndk)?;
    ensure!(!already_running()?, "an existing mcDriverDaemon is running; refusing to duplicate, kill or adopt it");
    let accounts = ueventd::accounts(&ueventd::PASSWD_FILES.iter().chain(&ueventd::GROUP_FILES).copied().collect::<Vec<_>>());
    let system = ueventd::account(&accounts, "system").context("resolve Trustonic system account")?;
    let readable = |metadata: &std::fs::Metadata| {
        if metadata.uid() == system { metadata.mode() & 0o400 != 0 }
        else if metadata.gid() == system { metadata.mode() & 0o040 != 0 }
        else { metadata.mode() & 0o004 != 0 }
    };
    ensure!(skyward_block::mount::is_mount_point(Path::new("/mnt/vendor/persist"))?, "persist must already be mounted at /mnt/vendor/persist; refusing automatic mount/store creation");
    let persist = std::ffi::CString::new("/mnt/vendor/persist").expect("fixed path");
    let mut filesystem: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(unsafe { libc::statvfs(persist.as_ptr(), &mut filesystem) } == 0, "cannot inspect persist mount flags");
    ensure!(filesystem.f_flag & libc::ST_RDONLY == 0, "persist is read-only; refusing Trustonic persistent-write mode");
    let registry = std::fs::symlink_metadata("/mnt/vendor/persist/mcRegistry")?;
    ensure!(registry.is_dir() && registry.uid() == system && registry.mode() & 0o700 == 0o700, "mcRegistry must already be a system-owned accessible/writable directory; refusing repair");
    let store = existing_file(Path::new(STORE))?;
    ensure!(readable(&store), "existing Store_1.tf is not readable by system; refusing automatic chmod/chown");
    // FSD needs existing writable storage in this opt-in mode, not a temporary replacement.
    ensure!(store.uid() == system && store.mode() & 0o200 != 0, "Store_1.tf must already be system-owned/writable; refusing automatic repair");
    for path in REQUIRED {
        let metadata = existing_file(Path::new(path))?;
        ensure!(readable(&metadata), "{path} is not readable by system");
    }
    let daemon = existing_file(Path::new(DAEMON))?;
    ensure!(readable(&daemon) && daemon.mode() & 0o111 != 0, "Trustonic daemon is not executable/readable");
    for path in ["/dev/mobicore", "/dev/mobicore-user"] {
        let metadata = std::fs::symlink_metadata(path).with_context(|| format!("stat {path}"))?;
        ensure!(metadata.file_type().is_char_device(), "{path} must be a character device, not a link");
        ensure!(metadata.uid() == system && metadata.mode() & 0o600 == 0o600, "{path} must already grant system read/write access; apply stock ueventd rules first");
    }
    let library_path = std::env::join_paths(&plan.libraries).context("make Trustonic LD_LIBRARY_PATH")?;
    let mut command = Command::new(DAEMON);
    command.args(&plan.args).current_dir("/").env("LD_LIBRARY_PATH", library_path)
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    // All allocation/account resolution is done before fork. No retained groups
    // or capabilities, and no unbounded crash/restart loop.
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0 { return Err(std::io::Error::last_os_error()); }
            if libc::setresgid(system, system, system) != 0 { return Err(std::io::Error::last_os_error()); }
            if libc::setresuid(system, system, system) != 0 { return Err(std::io::Error::last_os_error()); }
            // Do not inherit an ignored or blocked TERM from recovery. Set
            // this before exec, and install PDEATHSIG after dropping IDs
            // because Linux clears the setting on credential transitions.
            if libc::signal(libc::SIGTERM, libc::SIG_DFL) == libc::SIG_ERR { return Err(std::io::Error::last_os_error()); }
            let mut unblocked: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut unblocked) != 0 || libc::sigaddset(&mut unblocked, libc::SIGTERM) != 0
                || libc::sigprocmask(libc::SIG_UNBLOCK, &unblocked, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Parent death delivers TERM, but cannot promise FSD flush.
            parent_death_signal(parent_pid)
        });
    }
    let child = command.spawn().context("start opt-in Trustonic daemon without reformat/restart")?;
    let mut guard = DaemonGuard::new(child);
    let result = (|| -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            guard.check_running()?;
            let last = match connect_registry() {
                Ok(stream) => {
                    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
                    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
                    let rc = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut peer as *mut libc::ucred).cast(), &mut size) };
                    ensure!(rc == 0 && size as usize == std::mem::size_of::<libc::ucred>(), "get Trustonic socket peer credentials failed");
                    owned_peer(guard.child.id(), system, peer.pid, peer.uid)?;
                    // Never send an unknown protocol message or a credential request.
                    drop(stream);
                    guard.check_running()?;
                    guard.registry_ready();
                    break;
                }
                Err(error) => error.to_string(),
            };
            ensure!(Instant::now() < deadline, "Trustonic mcdaemon socket timeout: {last}");
            std::thread::sleep(Duration::from_millis(100));
        }
        skyward_sys::kmsg("Trustonic registry socket is ready; FSD may write existing secure storage; decryption is NOT yet proven")?;
        Ok(())
    })();
    result?; // Guard owns cleanup on every readiness/logging error.
    Ok(guard)

}

#[cfg(target_os = "android")]
fn connect_registry() -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if raw < 0 { return Err(std::io::Error::last_os_error()); }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (index, byte) in ABSTRACT_NAME.iter().enumerate() {
        address.sun_path[index + 1] = *byte as libc::c_char;
    }
    // sun_path[0] remains NUL; no trailing NUL is part of the name.
    let length = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + ABSTRACT_NAME.len()) as libc::socklen_t;
    let result = unsafe { libc::connect(socket.as_raw_fd(), (&address as *const libc::sockaddr_un).cast(), length) };
    if result != 0 { return Err(std::io::Error::last_os_error()); }
    Ok(std::os::unix::net::UnixStream::from(socket))
}

#[cfg(target_os = "android")]
fn already_running() -> Result<bool> {
    for entry in std::fs::read_dir("/proc").context("list processes before Trustonic startup")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() { continue; }
        match std::fs::read(entry.path().join("cmdline")) {
            Ok(command) => {
                let first = command.split(|byte| *byte == 0).next().unwrap_or_default();
                let name = first.rsplit(|byte| *byte == b'/').next().unwrap_or_default();
                if name == b"mcDriverDaemon" { return Ok(true); }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                anyhow::bail!("cannot inspect process cmdline before Trustonic startup: {error}");
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn sleeper() -> std::process::Child {
        std::process::Command::new("sh").args(["-c", "exec sleep 30"])
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()).spawn().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn raii_stops_and_reaps_only_its_owned_child() {
        let mut unrelated = sleeper();
        let mut guard = DaemonGuard::new(sleeper());
        guard.check().unwrap();
        assert_eq!(guard.state, DaemonState::Running);
        guard.registry_ready();
        assert_eq!(guard.state, DaemonState::RegistryReady);
        let start = std::time::Instant::now();
        guard.stop();
        assert!(matches!(guard.state, DaemonState::Terminated | DaemonState::Forced));
        assert!(guard.child.try_wait().unwrap().is_some());
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
        drop(guard); // Idempotent: already reaped child never signalled again.
        assert!(unrelated.try_wait().unwrap().is_none());
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn owned_child_ignoring_term_is_bounded_and_reaped() {
        use std::io::BufRead;
        let mut child = std::process::Command::new("sh")
            .args(["-c", "trap '' TERM; printf 'ready\\n'; exec sleep 30"])
            .stdout(std::process::Stdio::piped()).spawn().unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        output.read_line(&mut ready).unwrap();
        assert_eq!(ready, "ready\n");
        let mut guard = DaemonGuard::new(child);
        let began = std::time::Instant::now();
        guard.stop();
        assert_eq!(guard.state, DaemonState::Forced);
        assert!(guard.child.try_wait().unwrap().is_some());
        assert!(began.elapsed() < std::time::Duration::from_secs(3));
    }

    #[cfg(unix)]
    #[test]
    fn startup_failure_and_run_scope_exit_drop_the_guard() {
        fn fail_after_spawn(pid: &mut u32) -> Result<()> {
            let guard = DaemonGuard::new(sleeper());
            *pid = guard.child.id();
            anyhow::bail!("simulate keys::start failure");
        }
        let mut pid = 0;
        assert!(fail_after_spawn(&mut pid).is_err());
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        let pid = {
            let guard = DaemonGuard::new(sleeper());
            guard.child.id()
        };
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(unix)]
    #[test]
    fn exited_child_is_recorded_and_never_restarted() {
        let child = std::process::Command::new("sh").args(["-c", "exit 7"]).spawn().unwrap();
        let mut guard = DaemonGuard::new(child);
        guard.child.wait().unwrap();
        assert!(guard.check().is_err());
        assert_eq!(guard.state, DaemonState::Exited);
        guard.stop();
        assert_eq!(guard.state, DaemonState::Exited);
    }

    #[test]
    fn registry_peer_must_be_this_child_and_account_not_just_a_socket() {
        owned_peer(123, 1000, 123, 1000).unwrap();
        for (pid, uid) in [(124, 1000), (123, 0), (0, 1000), (-1, 1000)] {
            assert!(owned_peer(123, 1000, pid, uid).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parent_death_installation_rejects_parent_race() {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new("sh");
        command.args(["-c", "exec sleep 30"]);
        unsafe { command.pre_exec(|| parent_death_signal(0)); }
        assert!(command.spawn().is_err(), "parent mismatch must fail before exec");
    }

    // Invoked as a separate test process to emulate abrupt recovery exit. No
    // vendor program is run, and no Drop is allowed in the fixture's parent.
    #[cfg(target_os = "linux")]
    #[test]
    fn parent_exit_fixture() {
        let Some(path) = std::env::var_os("SKYWARD_TRUSTONIC_PDEATH_FIXTURE") else { return; };
        use std::os::unix::process::CommandExt;
        let parent = std::process::id() as i32;
        let mut command = std::process::Command::new("sh");
        command.args(["-c", "exec sleep 30"]).stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        unsafe { command.pre_exec(move || parent_death_signal(parent)); }
        let child = command.spawn().unwrap();
        std::fs::write(path, child.id().to_string()).unwrap();
        std::process::exit(0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn abrupt_parent_exit_delivers_term_without_a_background_reaper() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pid");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "trustonic::tests::parent_exit_fixture", "--nocapture"])
            .env("SKYWARD_TRUSTONIC_PDEATH_FIXTURE", &path).status().unwrap();
        assert!(status.success());
        let pid = std::fs::read_to_string(path).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Ok(stat) if stat.split_once(") ").is_some_and(|(_, tail)| tail.starts_with('Z')) => break,
                _ => {}
            }
            assert!(std::time::Instant::now() < deadline, "orphan test child {pid} remained running");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    #[test]
    fn unsafe_automatic_requests_are_cancelled_without_shutdown_or_retry() {
        use skyward_sys::bcb::{Request, Work};
        for work in [Work::WipeData { reformat: None }, Work::WipeAb { package_size: 123 },
            Work::Update(Default::default()), Work::Rescue, Work::Sideload { auto_reboot: true },
            Work::UnshareBlocks, Work::SwitchSystem { to: "other".into() }] {
            let mut request = Request { work, shutdown_after: true, ..Default::default() };
            assert!(cancel_unsafe_request(&mut request).is_some());
            assert_eq!(request.work, Work::Menu);
            assert!(!request.shutdown_after);
        }
        for work in [Work::Menu, Work::Fastboot, Work::Exit] {
            let mut request = Request { work: work.clone(), ..Default::default() };
            assert!(cancel_unsafe_request(&mut request).is_none());
            assert_eq!(request.work, work);
        }
    }

    #[test]
    fn explicit_opt_in_and_fixed_safe_args() {
        assert!(plan(&Trustonic { allow_persistent_writes: false, libraries: vec![] }, None).is_err());
        let result = plan(&Trustonic { allow_persistent_writes: true, libraries: vec![] }, Some(Path::new("/apex/com.android.vndk.v31/lib64"))).unwrap();
        assert_eq!(result.args, ["--P1", "/mnt/vendor/persist/mcRegistry"]);
        assert!(!result.args.iter().any(|arg| matches!(arg.as_str(), "--sfs-reformat" | "-l" | "-r" | "-b")));
        assert_eq!(ABSTRACT_NAME, b"mcdaemon");
        assert!(result.libraries.iter().any(|path| path == Path::new("/apex/com.android.vndk.v31/lib64")));
    }
    #[test]
    fn never_create_or_repair_store() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("Store_1.tf");
        assert!(existing_file(&path).is_err());
        assert!(!path.exists());
        std::fs::write(&path, []).unwrap();
        assert!(existing_file(&path).is_err());
        std::fs::write(&path, b"existing encrypted store").unwrap();
        assert!(existing_file(&path).is_ok());
        assert!(existing_file(directory.path()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn refuses_symlink_store_and_parent() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        std::fs::write(&original, b"encrypted").unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&original, &link).unwrap();
        assert!(existing_file(&link).is_err());
        let parent = directory.path().join("dirlink");
        std::os::unix::fs::symlink(directory.path(), &parent).unwrap();
        assert!(existing_file(&parent.join("original")).is_err());
    }
}
