//! Same-kernel handoff from an idle Recovery UI. No LP writes, OTA or reboot.
use anyhow::{Context, Result, ensure};
use std::{fs::{self, OpenOptions}, io::{Read, Write}, os::unix::{fs::{MetadataExt, OpenOptionsExt}, process::CommandExt}, path::Path, process::Command};

const REQUEST: &str = "/skyward/run/lp-handoff.request";
const CLAIM: &str = "/skyward/run/lp-handoff.claimed";
const REPORT: &str = "/skyward/run/lp-maintenance.txt";

pub fn applies(cfg: &skyward_config::DeviceConfig) -> bool {
    cfg.device.codename == "OP5911" && cfg.device.recovery_partition == skyward_config::RecoveryPartition::VendorBoot
}

fn token() -> Result<String> {
    let id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let id = id.trim();
    ensure!(id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'), "invalid boot identity");
    Ok(format!("LP handoff {id}\n"))
}

pub fn queue(cfg: &skyward_config::DeviceConfig) -> Result<()> {
    ensure!(applies(cfg) && crate::ramdisk::in_recovery(), "handoff requires PGZ110 Recovery");
    ensure!(!Path::new(CLAIM).try_exists()? && !Path::new(REPORT).try_exists()?, "maintenance already entered; do not request another handoff");
    let mut file = tempfile::Builder::new().prefix("lp-handoff-staged-")
        .tempfile_in(Path::new(REQUEST).parent().context("missing request parent")?)?;
    file.write_all(token()?.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist_noclobber(REQUEST).context("publish the single complete LP handoff request")?;
    Ok(())
}

fn check_token(path: &Path) -> Result<()> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && meta.uid() == 0 && meta.nlink() == 1 && meta.mode() & 0o777 == 0o600,
        "unexpected maintenance request owner or file type");
    let mut bytes = Vec::new();
    file.take(128).read_to_end(&mut bytes)?;
    ensure!(bytes == token()?.as_bytes(), "stale or invalid maintenance request");
    Ok(())
}

pub(crate) fn requested() -> Result<bool> {
    if !Path::new(REQUEST).try_exists()? { return Ok(false); }
    check_token(Path::new(REQUEST))?;
    Ok(true)
}

pub(crate) fn enter(cfg: &skyward_config::DeviceConfig) -> Result<()> {
    ensure!(applies(cfg) && crate::ramdisk::in_recovery(), "not in the eligible Recovery");
    let executable = fs::metadata("/proc/self/exe")?;
    ensure!(executable.is_file() && executable.dev() == fs::metadata("/")?.dev(), "Recovery executable is not on the ramdisk");
    check_token(Path::new(REQUEST))?;
    ensure!(!Path::new(CLAIM).try_exists()?, "maintenance is already claimed");
    fs::rename(REQUEST, CLAIM)?;
    Err(Command::new("/proc/self/exe").arg0("skyward").arg("run-lp-handoff").exec()).context("exec ramdisk maintenance stage")
}

/// The confirmed path does not reuse or publish a diagnostic token. Failure
/// keeps the installation stopped, even if metadata work has already begun.
pub fn run_confirmed(cfg: &skyward_config::DeviceConfig, ticket_fd: i32, ota_fd: i32) -> Result<()> {
    let result = (|| -> Result<()> {
        ensure!(applies(cfg) && crate::ramdisk::in_recovery(), "not in the eligible Recovery");
        let ticket = crate::lp_ota_ticket::take(ticket_fd, ota_fd, "run-lp-handoff")?;
        ensure!(ticket.digest == skyward_install::lp_ota_source::CAPTURED_OTA_SHA256
            && skyward_install::lp_ota_source::digest(&ticket.file, ticket.stamp, || false)? == ticket.digest,
            "confirmed OTA changed before LP repair");
        let slot = crate::booted_slot()?;
        let data = Path::new("/data");
        let before = skyward_block::mount::visible(data)?.context("userdata is not mounted")?;
        let dev = ticket.stamp.device as libc::dev_t;
        ensure!(before.device == (libc::major(dev) as u32, libc::minor(dev) as u32), "confirmed OTA is not on retained userdata");
        ensure!(!skyward_vab::audit_linear_super_holders(slot)?.is_empty(), "handoff requires verified old-system mappings");
        crate::services::retire_for_lp_handoff()?;
        skyward_vab::release_linear_handoff(slot)?;
        let after = skyward_block::mount::visible(data)?.context("userdata disappeared during handoff")?;
        ensure!(before.device == after.device && before.filesystem == after.filesystem, "userdata changed across handoff");
        let archive = crate::boot_services::repair_captured_lp(cfg, slot)?;
        skyward_sys::kmsg(&format!("install: LP repair verified, backup {}, resuming confirmed local OTA", archive.display()))?;
        crate::lp_ota_ticket::exec(ticket, "resume-lp-ota")
    })();
    park_after_error(result, "/skyward/run/lp-auto-repair-failed.txt")
}

pub fn resume(ticket_fd: i32, ota_fd: i32) -> Result<()> {
    use skyward_config::{DeviceConfig, ramdisk};
    let result = (|| -> Result<()> {
        let ticket = crate::lp_ota_ticket::take(ticket_fd, ota_fd, "resume-lp-ota")?;
        let root = Path::new("/");
        let cfg = DeviceConfig::load(root.join(ramdisk::CONFIG))?;
        ensure!(applies(&cfg) && ramdisk::in_recovery(), "not in the eligible Recovery");
        ensure!(skyward_vab::snapshot_state()? == skyward_vab::SnapshotState::None, "snapshot state changed after repair");
        // Mount the installed files required for ordinary preflight, without
        // restarting the retired UI/vendor HAL stack. Fail on any mount error.
        let slot = crate::booted_slot()?;
        ensure!(slot == skyward_vab::Slot::A, "unexpected slot after captured LP repair");
        let mounted = skyward_vab::mount_partitions(slot)?;
        ensure!(mounted.damaged.is_empty() && !mounted.partitions.is_empty(), "installed partitions did not remount cleanly");
        skyward_vab::audit_linear_super_holders(slot)?;
        crate::ui::run_local(&cfg, &cfg.services, crate::runtime::Runtime::default(),
            &root.join(ramdisk::FONT), &root.join(ramdisk::MONO), skyward_sys::bcb::Request::default(),
            skyward_ui::app::Screen::Home, None, Some(ticket))
    })();
    park_after_error(result, "/skyward/run/lp-auto-resume-failed.txt")
}

fn park_after_error(result: Result<()>, path: &str) -> Result<()> {
    let error = match result { Err(error) => format!("{error:#}"), Ok(()) => "unexpected end of LP install stage".into() };
    let _ = skyward_sys::kmsg(&format!("install: {error}"));
    let _ = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW)
        .open(path).and_then(|mut file| writeln!(file, "{error}"));
    loop { std::thread::park(); }
}

pub fn run(cfg: &skyward_config::DeviceConfig) -> Result<()> {
    ensure!(applies(cfg) && crate::ramdisk::in_recovery(), "not in the eligible Recovery");
    check_token(Path::new(CLAIM))?;
    let result = (|| -> Result<String> {
        let data = Path::new("/data");
        let before = skyward_block::mount::visible(data)?.context("userdata is not mounted; refusing to stop services")?;
        let slot = crate::booted_slot()?;
        let holders = skyward_vab::audit_linear_super_holders(slot)?;
        ensure!(!holders.is_empty(), "handoff requires a verified installed-system holder roster");
        crate::services::retire_for_lp_handoff()?;
        skyward_vab::release_linear_handoff(slot)?;
        let after = skyward_block::mount::visible(data)?.context("userdata mount disappeared after handoff")?;
        ensure!(after.device == before.device && after.filesystem == before.filesystem, "userdata identity changed across handoff");
        skyward_install::with_exclusive_super_for_audit(|_| Ok(()))?;
        let (next, merge) = crate::boot_services::query_oem_merge_readonly(cfg)?;
        let residue = skyward_install::lp_capacity::audit_captured_residue(slot, next, merge);
        Ok(format!("userdata preserved: {:?}\nread-only super exclusive: OK\nnext slot: {next:?}; merge: {merge:?}\nresidue corroboration: {residue:#?}", after.device))
    })();
    let (report_path, report) = match result {
        Ok(report) => (REPORT, report),
        Err(error) => ("/skyward/run/lp-handoff-failed.txt", format!("LP handoff failed: {error:#}")),
    };
    let _ = skyward_sys::kmsg(&report);
    // Failed handoff never publishes the maintenance report. A successful
    // report still does not authorize writes: the repair repeats all proofs.
    let published = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(report_path)
        .and_then(|mut file| writeln!(file, "{report}"));
    if let Err(error) = published { let _ = skyward_sys::kmsg(&format!("record LP handoff report: {error}")); }
    // Returning would let init restart ordinary Recovery over a partially
    // released stack. Stay available to ADB for the human's next action.
    loop { std::thread::park(); }
}
