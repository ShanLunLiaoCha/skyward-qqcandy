//! PGZ110 fastboot's stock HIDL/BootControl chain. The normal recovery uses
//! installed services; never allow both owners to compete for hwbinder.
use anyhow::{ensure, Result};
use skyward_config::{DeviceConfig, RecoveryPartition};

#[cfg(any(target_os = "android", test))]
fn stock_service_idle(state: Option<&str>, has_process: bool) -> bool {
    !has_process && matches!(state, None | Some("" | "stopped"))
}

#[cfg(any(target_os = "android", test))]
fn scoped_probe<T>(mut step: impl FnMut(Step) -> Result<()>, probe: impl FnOnce() -> Result<T>) -> Result<T> {
    let mut manager_requested = false;
    let mut boot_requested = false;
    let result = (|| {
        for &action in START {
            step(action)?;
            manager_requested |= action == Step::StartDirectory;
            boot_requested |= action == Step::StartBoot;
        }
        probe()
    })();
    let cleanup = (|| {
        if !manager_requested { return Ok(()); }
        step(Step::CheckFastbootStopped)?;
        if boot_requested {
            step(Step::StopBoot)?;
            step(Step::WaitBootStopped)?;
        }
        step(Step::StopDirectory)?;
        step(Step::WaitDirectoryStopped)
    })();
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.context(format!("OEM probe cleanup also failed: {cleanup:#}"))),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step { RejectInstalled, StartDirectory, WaitDirectory, StartBoot, WaitBoot, CheckFastbootStopped, StopBoot, WaitBootStopped, StopDirectory, WaitDirectoryStopped }
const START: &[Step] = &[Step::RejectInstalled, Step::StartDirectory, Step::WaitDirectory, Step::StartBoot, Step::WaitBoot];
const STOP: &[Step] = &[Step::CheckFastbootStopped, Step::StopBoot, Step::WaitBootStopped, Step::StopDirectory, Step::WaitDirectoryStopped];

fn applies(cfg: &DeviceConfig) -> bool { cfg.device.codename == "OP5911" && cfg.device.recovery_partition == RecoveryPartition::VendorBoot }
fn sequence(steps: &[Step], mut run: impl FnMut(Step) -> Result<()>) -> Result<()> { for &step in steps { run(step)?; } Ok(()) }

#[cfg(target_os = "android")]
mod runtime {
    use super::*;
    use anyhow::Context;
    use std::{path::Path, sync::Mutex, time::{Duration, Instant}};
    const MANAGER: (&str, &str) = ("hwservicemanager", "/system/bin/hwservicemanager");
    const BOOT: (&str, &str) = ("vendor.boot-hal-1-2", "/vendor/bin/hw/android.hardware.boot@1.2-service");
    static OWNED: Mutex<bool> = Mutex::new(false);
    const TIMEOUT: Duration = Duration::from_secs(10);

    /// `audit-restore-boot-control` can run in a different Recovery process;
    /// the in-process fastboot ownership mutex does not serialize that case.
    fn transition_lock() -> Result<std::fs::File> {
        use std::os::{fd::AsRawFd, unix::fs::{MetadataExt, OpenOptionsExt}};
        let file = std::fs::OpenOptions::new().read(true).write(true).create(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open("/dev/.skyward-hidl-transition.lock")?;
        let info = file.metadata()?;
        ensure!(info.is_file() && info.nlink() == 1 && info.uid() == 0 && info.mode() & 0o077 == 0,
            "invalid HIDL transition lock file");
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error()).context("another Recovery HIDL transition is running");
        }
        Ok(file)
    }

    fn pid_of(service: &str) -> Result<u32> {
        skyward_sys::prop(&format!("init.svc_debug_pid.{service}"))
            .with_context(|| format!("init provides no PID for {service}"))?.parse().context("invalid init service PID")
    }
    fn identity(service: (&str, &str)) -> Result<()> {
        let pid = pid_of(service.0)?;
        ensure!(pid > 1, "refusing invalid init service PID");
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).with_context(|| format!("read {service:?} process identity"))?;
        ensure!(exe == Path::new(service.1), "{} PID {pid} executes {}, not the stock {}", service.0, exe.display(), service.1);
        ensure!(pid_of(service.0)? == pid, "init service PID changed during identity check");
        Ok(())
    }
    fn reject_installed() -> Result<()> {
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() { continue; }
            match std::fs::read_link(entry.path().join("exe")) {
                Ok(exe) if exe.file_name().is_some_and(|n| n == "hwservicemanager") && exe != Path::new(MANAGER.1) => {
                    anyhow::bail!("non-stock HIDL manager {} is running; refusing a second hwbinder owner", exe.display())
                }
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => return Err(e).context("inspect HIDL directory owners"),
            }
        }
        Ok(())
    }
    fn start(service: (&str, &str)) -> Result<()> {
        reject_installed()?;
        if skyward_sys::prop(&format!("init.svc.{}", service.0)).as_deref() == Some("running") {
            return identity(service);
        }
        // Existing processes with the stock path but without init ownership
        // must not be silently adopted or duplicated.
        if let Some(pid) = crate::services::running(service.1) {
            ensure!(pid_of(service.0)? == pid, "stock-path process is not owned by this init service");
            identity(service)?;
        }
        skyward_sys::set_prop("ctl.start", service.0)
    }
    fn wait_ready(service: (&str, &str), ready: impl Fn() -> Result<bool>) -> Result<()> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if skyward_sys::prop(&format!("init.svc.{}", service.0)).as_deref() == Some("running") {
                identity(service)?;
                if ready()? { return Ok(()); }
            }
            ensure!(Instant::now() < deadline, "{} failed to become ready for fastboot", service.0);
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn stop(service: (&str, &str)) -> Result<()> {
        match skyward_sys::prop(&format!("init.svc.{}", service.0)).as_deref() {
            Some("stopped") | None => Ok(()),
            _ => { identity(service)?; skyward_sys::set_prop("ctl.stop", service.0) }
        }
    }
    fn stopped(service: (&str, &str)) -> Result<()> {
        if stock_service_idle(skyward_sys::prop(&format!("init.svc.{}", service.0)).as_deref(),
            crate::services::running(service.1).is_some()) { return Ok(()); }
        skyward_sys::wait_prop(&format!("init.svc.{}", service.0), "stopped", TIMEOUT)?;
        ensure!(crate::services::running(service.1).is_none(), "{} still has a stock process after stop", service.0);
        Ok(())
    }
    fn registered(interface: &str) -> Result<bool> {
        let binder = skyward_binder::driver::Binder::hardware()?;
        Ok(skyward_binder::hidl::find(&binder, interface, "default")?.is_some())
    }
    fn run(step: Step) -> Result<()> {
        match step {
            Step::RejectInstalled => reject_installed(),
            Step::StartDirectory => start(MANAGER),
            Step::WaitDirectory => wait_ready(MANAGER, || {
                if skyward_sys::prop("hwservicemanager.ready").as_deref() != Some("true") { return Ok(false); }
                // IBase::interfaceDescriptor is read-only. Looking up a
                // missing BootControl here can trigger lazy init startup and
                // defeat the explicit directory-before-HAL sequencing.
                let binder = skyward_binder::driver::Binder::hardware()?;
                let directory = binder.directory()?;
                let interface = skyward_binder::hidl::describes(&directory)?;
                Ok(matches!(interface.as_str(),
                    "android.hidl.manager@1.0::IServiceManager" |
                    "android.hidl.manager@1.1::IServiceManager" |
                    "android.hidl.manager@1.2::IServiceManager"))
            }),
            Step::StartBoot => start(BOOT),
            Step::WaitBoot => wait_ready(BOOT, || registered("android.hardware.boot@1.0::IBootControl")),
            Step::CheckFastbootStopped => {
                ensure!(matches!(skyward_sys::prop("init.svc.fastbootd").as_deref(), None | Some("stopped")), "fastbootd must stop before HIDL ownership is transferred"); Ok(())
            }
            Step::StopBoot => stop(BOOT), Step::WaitBootStopped => stopped(BOOT),
            Step::StopDirectory => stop(MANAGER),
            Step::WaitDirectoryStopped => { stopped(MANAGER)?; skyward_sys::set_prop("hwservicemanager.ready", "false") }
        }
    }
    pub fn start_for_fastboot(cfg: &DeviceConfig) -> Result<()> {
        if !applies(cfg) { return Ok(()); }
        let _transition = transition_lock()?;
        let mut owned = OWNED.lock().map_err(|_| anyhow::anyhow!("fastboot ownership lock poisoned"))?;
        sequence(START, run)?;
        *owned = true;
        skyward_sys::kmsg("stock HIDL directory and BootControl are ready for userspace fastboot")
    }
    /// Observe an existing OEM stack or explicitly start a short-lived probe.
    /// Hold super read-only and exclusively; never request activation here.
    pub fn audit_for_restore(cfg: &DeviceConfig, start_stock: bool) -> Result<skyward_vab::Slot> {
        let (active, merge) = observe_for_maintenance(cfg, start_stock)?;
        ensure!(merge == skyward_vab::MergeStatus::None, "BootControl reports a pending or unknown merge: {merge:?}");
        Ok(active)
    }

    pub fn observe_for_maintenance(cfg: &DeviceConfig, start_stock: bool) -> Result<(skyward_vab::Slot, skyward_vab::MergeStatus)> {
        ensure!(applies(cfg), "isolated boot audit is for PGZ110 vendor_boot Recovery");
        let _transition = transition_lock()?;
        let owned = OWNED.lock().map_err(|_| anyhow::anyhow!("HIDL ownership lock poisoned"))?;
        run(Step::CheckFastbootStopped)?;
        reject_installed()?;
        skyward_install::with_exclusive_super_for_audit(|super_device| {
            if !start_stock { return audit_running(super_device); }
            ensure!(!*owned, "the fastboot path still owns the HIDL services");
            with_stopped_stock_session(|| audit_running(super_device))
        })
    }

    /// Diagnostic only: no write authorization. Full maps/FD provenance is
    /// still mandatory for any restore. Read-only Binder calls here merely
    /// report the OEM's view; an epoll FD cannot make that a write permit.
    pub fn query_oem_merge_readonly(cfg: &DeviceConfig) -> Result<(skyward_vab::Slot, skyward_vab::MergeStatus)> {
        ensure!(applies(cfg), "OEM merge diagnostic requires PGZ110 vendor_boot Recovery");
        let _transition = transition_lock()?;
        run(Step::CheckFastbootStopped)?;
        skyward_install::with_exclusive_super_for_audit(|_| with_stopped_stock_session(|| {
            let owners = [pid_of(MANAGER.0)?, pid_of(BOOT.0)?];
            identity(MANAGER)?;
            identity(BOOT)?;
            let binder = skyward_binder::driver::Binder::hardware()?;
            let control = skyward_vab::boot::BootControl::open_hidl12(&binder)?;
            let value = (control.active()?, control.merge_status()?);
            identity(MANAGER)?;
            identity(BOOT)?;
            ensure!(owners == [pid_of(MANAGER.0)?, pid_of(BOOT.0)?], "OEM service changed during read-only query");
            Ok(value)
        }))
    }

    /// Repair only the captured failed OTA layout. The real writer takes
    /// its own exclusive super claim. The OEM stack remains the same across
    /// all of its readiness callbacks and is stopped on completion.
    pub fn repair_captured_lp(cfg: &DeviceConfig, slot: skyward_vab::Slot) -> Result<std::path::PathBuf> {
        use crate::restore_service_provenance::verify_init_service;
        use std::collections::BTreeSet;
        ensure!(applies(cfg), "captured repair requires PGZ110 vendor_boot Recovery");
        let _transition = transition_lock()?;
        run(Step::CheckFastbootStopped)?;
        anyhow::ensure!(skyward_block::mount::visible(Path::new("/data"))?.is_some()
            || skyward_block::dm::device_status("userdata")?.is_some(),
            "maintenance needs an existing verified userdata mapper; no COW absence proof without it");
        let super_id = skyward_install::with_exclusive_super_for_audit(Ok)?;
        let forbidden = BTreeSet::from([super_id]);
        with_stopped_stock_session(|| {
            let manager = verify_init_service(MANAGER.0, Path::new(MANAGER.1), &forbidden)?;
            let boot = verify_init_service(BOOT.0, Path::new(BOOT.1), &forbidden)?;
            let binder = skyward_binder::driver::Binder::hardware()?;
            let control = skyward_vab::boot::BootControl::open_hidl12(&binder)?;
            skyward_install::lp_capacity::repair_captured_residue(slot, super_id, || {
                run(Step::CheckFastbootStopped)?;
                manager.recheck(&forbidden)?;
                boot.recheck(&forbidden)?;
                let value = (control.active()?, control.merge_status()?);
                manager.recheck(&forbidden)?;
                boot.recheck(&forbidden)?;
                Ok(value)
            })
        })
    }

    fn with_stopped_stock_session<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
            let root = std::fs::metadata("/")?;
            for (name, executable) in [MANAGER, BOOT] {
                use std::os::unix::fs::MetadataExt;
                ensure!(stock_service_idle(skyward_sys::prop(&format!("init.svc.{name}")).as_deref(),
                    crate::services::running(executable).is_some()), "refusing to adopt or replace running service {name}");
                let meta = std::fs::symlink_metadata(executable)?;
                ensure!(meta.is_file() && meta.dev() == root.dev(), "{executable} does not come from the Recovery ramdisk");
            }
            let mut manager_identity = None;
            let mut boot_identity = None;
            scoped_probe(|step| {
                let process_stamp = |service: (&str, &str)| -> Result<(u32, u64)> {
                    identity(service)?;
                    let pid = pid_of(service.0)?;
                    let stat = procfs::process::Process::new(i32::try_from(pid)?)?.stat()?;
                    ensure!(stat.ppid == 1, "{} is not init owned", service.0);
                    Ok((pid, stat.starttime))
                };
                match step {
                    Step::StartDirectory | Step::StartBoot => {
                        let service = if step == Step::StartDirectory { MANAGER } else { BOOT };
                        ensure!(stock_service_idle(skyward_sys::prop(&format!("init.svc.{}", service.0)).as_deref(),
                            crate::services::running(service.1).is_some()), "another process started {}", service.0);
                        if step == Step::StartDirectory {
                            skyward_sys::set_prop("hwservicemanager.ready", "false")?;
                        }
                        skyward_sys::set_prop("ctl.start", service.0)
                    }
                    Step::WaitDirectory | Step::WaitBoot => {
                        // Record the owner as soon as init publishes a PID,
                        // even if the subsequent Binder readiness test fails.
                        let service = if step == Step::WaitDirectory { MANAGER } else { BOOT };
                        let stamp = if step == Step::WaitDirectory { &mut manager_identity } else { &mut boot_identity };
                        skyward_sys::wait_prop(&format!("init.svc.{}", service.0), "running", TIMEOUT)?;
                        let deadline = Instant::now() + TIMEOUT;
                        loop {
                            match process_stamp(service) {
                                Ok(owner) => { *stamp = Some(owner); break; }
                                Err(error) => {
                                    let pid = pid_of(service.0)?;
                                    let exe = std::fs::read_link(format!("/proc/{pid}/exe"));
                                    let launching = exe.as_deref().is_ok_and(|p| matches!(p.to_str(), Some("/init" | "/system/bin/init")))
                                        && procfs::process::Process::new(i32::try_from(pid)?)?.stat()?.ppid == 1;
                                    if !launching || Instant::now() >= deadline { return Err(error); }
                                    // init publishes the child PID before it execs the service.
                                    std::thread::sleep(Duration::from_millis(25));
                                }
                            }
                        }
                        run(step)
                    }
                    Step::StopDirectory | Step::StopBoot => {
                        let (service, stamp) = if step == Step::StopDirectory { (MANAGER, manager_identity) } else { (BOOT, boot_identity) };
                        if stock_service_idle(skyward_sys::prop(&format!("init.svc.{}", service.0)).as_deref(),
                            crate::services::running(service.1).is_some()) { return Ok(()); }
                        ensure!(stamp.is_some() && Some(process_stamp(service)?) == stamp,
                            "cannot stop {}: the probe's init owner is unproven or was replaced", service.0);
                        run(step)
                    }
                    _ => run(step),
                }
            }, operation)
    }

    /// Standard OTA only. Super may still have the mappings that the old
    /// slot needs; do not use this session for a whole-super replacement.
    pub fn with_stock_ota_boot_control(apply: &mut dyn FnMut() -> Result<i32>) -> Result<i32> {
        let cfg = DeviceConfig::load(Path::new("/").join(skyward_config::ramdisk::CONFIG))?;
        if !applies(&cfg) { return apply(); }
        let _transition = transition_lock()?;
        run(Step::CheckFastbootStopped)?;
        reject_installed()?;
        let mut code = None;
        let result = with_stopped_stock_session(|| {
            let binder = skyward_binder::driver::Binder::hardware()?;
            let boot = skyward_vab::boot::BootControl::open_hidl12(&binder)?;
            boot.active().context("verify OEM BootControl before update_engine")?;
            skyward_sys::kmsg("install: scoped OEM HIDL BootControl ready for update_engine")?;
            let status = apply()?;
            code = Some(status);
            Ok(status)
        });
        match (result, code) {
            (Err(error), Some(status)) => {
                // Do not turn an applied OTA into a reported install failure.
                let _ = skyward_sys::kmsg(&format!("install: OTA engine finished ({status}); OEM service cleanup failed: {error:#}; restart Recovery before retrying"));
                Ok(status)
            }
            (result, _) => result,
        }
    }

    fn audit_running(super_device: (u32, u32)) -> Result<(skyward_vab::Slot, skyward_vab::MergeStatus)> {
            use std::collections::BTreeSet;
            use skyward_vab::boot::BootControl;
            use crate::restore_service_provenance::verify_init_service;
            let forbidden = BTreeSet::from([super_device]);
            let manager = verify_init_service(MANAGER.0, Path::new(MANAGER.1), &forbidden)?;
            let service = verify_init_service(BOOT.0, Path::new(BOOT.1), &forbidden)?;
            let binder = skyward_binder::driver::Binder::hardware()?;
            let directory = binder.directory()?;
            let interface = skyward_binder::hidl::describes(&directory)?;
            ensure!(matches!(interface.as_str(), "android.hidl.manager@1.0::IServiceManager" |
                "android.hidl.manager@1.1::IServiceManager" | "android.hidl.manager@1.2::IServiceManager"),
                "hwbinder directory did not report a HIDL service manager");
            let control = BootControl::open_hidl12(&binder)?;
            let BootControl::Older(handle) = &control else { anyhow::bail!("HIDL-only lookup returned another transport"); };
            ensure!(skyward_binder::hidl::describes(handle)? == skyward_vab::boot::HARDWARE_SERVICE,
                "boot service did not report the expected HIDL 1.2 interface");
            let active = control.active()?;
            let merge = control.merge_status()?;
            manager.recheck(&forbidden)?;
            service.recheck(&forbidden)?;
            run(Step::CheckFastbootStopped)?;
            Ok((active, merge))
    }

    /// Execute only with the same independently verified init-owned HIDL
    /// service on either side of the device backend's exclusive claims.
    pub fn execute_ab_test(cfg: &DeviceConfig, bundle: &skyward_install::factory_bundle::Bundle) -> Result<()> {
        execute_factory_ab(cfg, bundle, &|| false, &|| {})
    }

    pub fn execute_factory_ab(cfg: &DeviceConfig, bundle: &skyward_install::factory_bundle::Bundle,
        cancelled: &dyn Fn() -> bool, first_write: &dyn Fn(),
    ) -> Result<()> {
        ensure!(applies(cfg), "restore is only for PGZ110 vendor_boot Recovery");
        let _transition = transition_lock()?;
        run(Step::CheckFastbootStopped)?;
        reject_installed()?;
        // Release the read-only probe before the backend claims the full set.
        skyward_install::with_exclusive_super_for_audit(|_| Ok(()))?;
        if [MANAGER, BOOT].into_iter().all(|(name, executable)| stock_service_idle(
            skyward_sys::prop(&format!("init.svc.{name}")).as_deref(), crate::services::running(executable).is_some())) {
            with_stopped_stock_session(|| execute_running_factory_ab(bundle, cancelled, first_write))
        } else {
            execute_running_factory_ab(bundle, cancelled, first_write)
        }
    }

    fn execute_running_factory_ab(bundle: &skyward_install::factory_bundle::Bundle,
        cancelled: &dyn Fn() -> bool, first_write: &dyn Fn(),
    ) -> Result<()> {
        use crate::restore_service_provenance::verify_init_service;
        use skyward_vab::{Slot, boot::BootControl};
        use std::collections::BTreeSet;
        let initial = BTreeSet::new();
        let manager = verify_init_service(MANAGER.0, Path::new(MANAGER.1), &initial)?;
        let service = verify_init_service(BOOT.0, Path::new(BOOT.1), &initial)?;
        let binder = skyward_binder::driver::Binder::hardware()?;
        let control = BootControl::open_hidl12(&binder)?;
        let BootControl::Older(handle) = &control else { anyhow::bail!("expected OEM HIDL BootControl"); };
        ensure!(skyward_binder::hidl::describes(handle)? == skyward_vab::boot::HARDWARE_SERVICE,
            "boot service did not report the expected HIDL 1.2 interface");
        bundle.execute_physical_ab(|targets| {
            run(Step::CheckFastbootStopped)?;
            manager.recheck(targets)?;
            service.recheck(targets)?;
            control.active()?;
            control.merge_status()
        }, || control.set_active(Slot::A), cancelled, first_write)
    }

    pub fn release_for_recovery(cfg: &DeviceConfig) -> Result<()> {
        if !applies(cfg) { return Ok(()); }
        let _transition = transition_lock()?;
        let mut owned = OWNED.lock().map_err(|_| anyhow::anyhow!("fastboot ownership lock poisoned"))?;
        if !*owned { return Ok(()); }
        sequence(STOP, run)?;
        *owned = false;
        skyward_sys::kmsg("stock fastboot HIDL owners stopped before installed Recovery services")
    }
}
#[cfg(target_os = "android")]
pub use runtime::{audit_for_restore, execute_ab_test, execute_factory_ab, observe_for_maintenance, query_oem_merge_readonly, repair_captured_lp, start_for_fastboot, release_for_recovery, with_stock_ota_boot_control};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_and_release_have_single_owner_order() {
        let mut seen=Vec::new();sequence(START, |s| {seen.push(s);Ok(())}).unwrap();assert_eq!(seen, START);
        let mut seen=Vec::new();sequence(STOP, |s| {seen.push(s);Ok(())}).unwrap();assert_eq!(seen, STOP);
        assert_eq!(STOP[0], Step::CheckFastbootStopped);
        assert!(STOP.iter().position(|s| *s==Step::WaitBootStopped).unwrap() < STOP.iter().position(|s| *s==Step::StopDirectory).unwrap());
    }
    #[test]
    fn failure_does_not_start_next_owner_or_continue_to_prepare() {
        let mut seen=Vec::new();let result=sequence(START,|s| {seen.push(s);ensure!(s!=Step::WaitDirectory,"not ready");Ok(())});
        assert!(result.is_err());assert!(!seen.contains(&Step::StartBoot));
        let mut seen=Vec::new();let result=sequence(STOP,|s| {seen.push(s);ensure!(s!=Step::WaitBootStopped,"still running");Ok(())});
        assert!(result.is_err());assert!(!seen.contains(&Step::StopDirectory));
    }
    #[test]
    fn unset_init_state_without_a_process_is_idle() {
        for state in [None, Some(""), Some("stopped")] {
            assert!(stock_service_idle(state, false));
            assert!(!stock_service_idle(state, true));
        }
        for state in ["running", "restarting", "stopping", "unexpected"] {
            assert!(!stock_service_idle(Some(state), false));
        }
    }

    #[test]
    fn isolated_probe_always_releases_successfully_requested_services() {
        for failure in [None, Some(Step::WaitDirectory), Some(Step::WaitBoot), Some(Step::StopBoot)] {
            let mut seen = Vec::new();
            let mut queried = false;
            let result = scoped_probe(|step| {
                seen.push(step);
                ensure!(Some(step) != failure, "injected transition failure");
                Ok(())
            }, || { queried = true; Ok(()) });
            assert_eq!(result.is_ok(), failure.is_none());
            match failure {
                Some(Step::WaitDirectory) => {
                    assert!(!queried);
                    assert_eq!(seen, [Step::RejectInstalled, Step::StartDirectory, Step::WaitDirectory,
                        Step::CheckFastbootStopped, Step::StopDirectory, Step::WaitDirectoryStopped]);
                }
                Some(Step::WaitBoot) => {
                    assert!(!queried);
                    assert_eq!(&seen[START.len()..], STOP);
                }
                Some(Step::StopBoot) => {
                    assert!(queried);
                    assert_eq!(seen.last(), Some(&Step::StopBoot));
                }
                None => { assert!(queried); assert_eq!(&seen[START.len()..], STOP); }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn other_devices_and_standalone_recovery_are_unaffected() {
        for text in ["[device]\ncodename='ishtar'\n", "[device]\ncodename='OP5911'\n"] {
            assert!(!applies(&DeviceConfig::parse(text).unwrap()));
        }
        assert!(applies(&DeviceConfig::parse("[device]\ncodename='OP5911'\nrecovery_partition='vendor_boot'\n").unwrap()));
    }
}
