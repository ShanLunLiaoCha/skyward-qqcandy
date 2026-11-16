//! PGZ110 fastboot's stock HIDL/BootControl chain. The normal recovery uses
//! installed services; never allow both owners to compete for hwbinder.
use anyhow::{ensure, Result};
use skyward_config::{DeviceConfig, RecoveryPartition};

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
        let mut owned = OWNED.lock().map_err(|_| anyhow::anyhow!("fastboot ownership lock poisoned"))?;
        sequence(START, run)?;
        *owned = true;
        skyward_sys::kmsg("stock HIDL directory and BootControl are ready for userspace fastboot")
    }
    pub fn release_for_recovery(cfg: &DeviceConfig) -> Result<()> {
        if !applies(cfg) { return Ok(()); }
        let mut owned = OWNED.lock().map_err(|_| anyhow::anyhow!("fastboot ownership lock poisoned"))?;
        if !*owned { return Ok(()); }
        sequence(STOP, run)?;
        *owned = false;
        skyward_sys::kmsg("stock fastboot HIDL owners stopped before installed Recovery services")
    }
}
#[cfg(target_os = "android")]
pub use runtime::{start_for_fastboot, release_for_recovery};

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
    fn other_devices_and_standalone_recovery_are_unaffected() {
        for text in ["[device]\ncodename='ishtar'\n", "[device]\ncodename='OP5911'\n"] {
            assert!(!applies(&DeviceConfig::parse(text).unwrap()));
        }
        assert!(applies(&DeviceConfig::parse("[device]\ncodename='OP5911'\nrecovery_partition='vendor_boot'\n").unwrap()));
    }
}
