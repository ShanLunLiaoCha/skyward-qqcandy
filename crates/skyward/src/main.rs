use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use skyward_config::{ramdisk, DeviceConfig};
#[cfg(target_os = "android")]
use skyward_programs::secure::Started;
use skyward_sys::{bcb, Power};
use skyward_vab::SnapshotState;
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "android", test))]
mod backlight;
#[cfg(any(target_os = "android", test))]
mod bundle_paths;
#[cfg(any(target_os = "android", test))]
mod apex_backing;
#[cfg(any(target_os = "android", test))]
mod wifi_calibration;
#[cfg(any(target_os = "android", test))]
mod wifi_profiles;
#[cfg(any(target_os = "android", test))]
mod runtime_policy;
#[cfg(any(target_os = "android", test))]
mod declaration_policy;
#[cfg(any(target_os = "android", test))]
mod reset_order;
#[cfg(any(target_os = "android", test))]
mod reset_fstab;
#[cfg(any(target_os = "android", test))]
mod wipe_adb;
#[cfg(any(target_os = "android", test))]
mod led_haptics;
#[cfg(any(target_os = "android", test))]
mod boot_services;
#[cfg(target_os = "android")]
mod lp_handoff;
#[cfg(any(target_os = "android", test))]
mod factory_restore;
#[cfg(any(target_os = "android", test))]
mod lp_ota_ticket;
#[cfg(any(target_os = "android", test))]
mod restore_service_provenance;
#[cfg(any(target_os = "android", test))]
mod phoenix;
#[cfg(target_os = "android")]
mod backup;
#[cfg(target_os = "android")]
mod decrypt;
#[cfg(target_os = "android")]
mod filework;
#[cfg(target_os = "android")]
mod haptics;
#[cfg(target_os = "android")]
mod input;
#[cfg(target_os = "android")]
mod keys;
#[cfg(target_os = "android")]
mod merge;
#[cfg(target_os = "android")]
mod partwork;
#[cfg(target_os = "android")]
mod pty;
#[cfg(target_os = "android")]
mod readings;
#[cfg(target_os = "android")]
mod relabel;
#[cfg(target_os = "android")]
mod secure;
#[cfg(any(target_os = "android", test))]
mod trustonic;
#[cfg(target_os = "android")]
mod services;
#[cfg(target_os = "android")]
mod runtime;
#[cfg(target_os = "android")]
mod settings;
#[cfg(target_os = "android")]
mod systems;
#[cfg(target_os = "android")]
mod ui;
#[cfg(target_os = "android")]
mod updates;
#[cfg(any(target_os = "android", test))]
mod waveform;
#[cfg(target_os = "android")]
mod wipe;
#[cfg(target_os = "android")]
mod wlan;

#[derive(Parser)]
#[command(name = "skyward", version, about = "Skyward recovery")]
struct Cli {
    /// Override the stock libbinder Parcel mark for explicit Android CLI use.
    /// In recovery the device configuration supplies this automatically.
    #[arg(long, global = true, value_parser = ["recovery", "system"])]
    binder_header: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print what the About page shows, plus a partition summary.
    Info {
        /// Device configuration, e.g. devices/nezha.toml.
        #[arg(long)]
        config: String,
    },
    /// Print the suffix of the slot the phone runs from and, where the
    /// phone's boot control runs, what it holds of each slot.
    Slot,
    /// List modules in dependency load order from a source directory.
    Modules {
        #[arg(long, default_value = "/vendor/lib/modules")]
        source: String,
    },
    /// Load kernel modules and their dependencies from the configured
    /// sources; with no names, the configuration's own list.
    Load {
        #[arg(long, default_value = "/skyward/device.toml")]
        config: String,
        names: Vec<String>,
    },
    /// Run as the recovery service (what init starts as /system/bin/recovery).
    Recovery,
    /// Reboot through init: system, recovery, fastboot, bootloader, edl, or
    /// off.
    Reboot { target: String },
    /// Print the bootloader control block in misc.
    Bcb,
    /// Print the logical partition metadata in super.
    Lp {
        /// The super partition, or an image of its start.
        #[arg(long = "super", default_value = "/dev/block/by-name/super")]
        super_dev: PathBuf,
        /// Metadata slot: 0 for _a, 1 for _b. Defaults to the booted slot.
        #[arg(long)]
        slot: Option<u32>,
    },
    /// Tell what a package or image is, the way the installer reads it.
    Identify { file: PathBuf },
    /// Prepare a PGZ110 vendor_boot candidate as a new file, never flash it.
    #[cfg(target_os = "android")]
    PrepareVendorBoot { stock: PathBuf, output: PathBuf },
    /// Check per-slot staged images and the prospective vendor_boot AVB binding.
    /// Uses ordinary files only; never opens a partition or flashes.
    #[cfg(target_os = "android")]
    AuditVendorBoot { package: PathBuf, slot: String, #[arg(long)] staged: Option<PathBuf> },
    /// Prepare .211's A-slot vendor_boot and AVB-off development candidates as ordinary files.
    #[cfg(target_os = "android")]
    PrepareAvbOffA { package: PathBuf, output_directory: PathBuf },
    /// Inspect a payload and replacement images against the physical super size.
    /// Does not write a partition, disable AVB or change the active slot.
    #[cfg(target_os = "android")]
    PreflightOta {
        package: PathBuf,
        #[arg(long)] my_company: PathBuf,
        #[arg(long)] my_preload: PathBuf,
        /// Verify the entire ZIP with Recovery's trusted OTA certificates and compare its reviewed inventory.
        #[arg(long)] verify_official: bool,
    },
    /// Build a Virtual A/B super candidate with only A populated, as a new file.
    #[cfg(target_os = "android")]
    PrepareSuperA {
        package: PathBuf,
        #[arg(long)] my_company: PathBuf,
        #[arg(long)] my_preload: PathBuf,
        #[arg(long)] output: PathBuf,
    },
    /// Observe the two OEM UFS preloader mappings; never write them.
    #[cfg(target_os = "android")]
    AuditPreloaderMaps,
    /// Observe current .211 restore prerequisites without staging images or writing.
    #[cfg(target_os = "android")]
    AuditFactoryAvailability,
    /// Report OEM merge state from the isolated LP maintenance boot only.
    #[cfg(target_os = "android")]
    QueryMaintenanceMerge,
    /// Read live super holder tables without changing mappings or mounts.
    #[cfg(target_os = "android")]
    AuditLpHandoffHolders,
    /// Ask the idle Recovery UI to enter diagnostic maintenance without rebooting.
    #[cfg(target_os = "android")]
    RequestLpHandoff,
    #[cfg(target_os = "android")]
    #[command(hide = true)]
    RunLpHandoff {
        #[arg(long, requires = "ota_fd")] ticket_fd: Option<i32>,
        #[arg(long, requires = "ticket_fd")] ota_fd: Option<i32>,
    },
    #[cfg(target_os = "android")]
    #[command(hide = true)]
    ResumeLpOta {
        #[arg(long)] ticket_fd: i32,
        #[arg(long)] ota_fd: i32,
    },
    /// Repair the one verified PGZ110 .211 incident before a normal OTA.
    #[cfg(target_os = "android")]
    RepairMaintenanceLp {
        /// Confirm persistent snapshot archival and LP metadata writes.
        #[arg(long)] accept_metadata_repair: bool,
    },
    /// Query the OEM HIDL 1.2 boot service while super is exclusively held read-only.
    #[cfg(target_os = "android")]
    AuditRestoreBootControl {
        /// Explicitly start and stop the stock services for this probe only.
        #[arg(long)] start_stock: bool,
    },
    /// Stage the reviewed official .211 restore bundle as ordinary files, without flashing.
    #[cfg(target_os = "android")]
    PrepareFactoryA {
        package: PathBuf,
        #[arg(long)] my_company: PathBuf,
        #[arg(long)] my_preload: PathBuf,
        #[arg(long)] output_directory: PathBuf,
        #[arg(long)] avb_off: bool,
        /// After staging, check the 26 A-only targets with read-only exclusive claims.
        #[arg(long, conflicts_with = "audit_physical_ab")] audit_targets: bool,
        /// After staging, check 51 targets: both physical slots and one A-only super.
        #[arg(long)] audit_physical_ab: bool,
    },
    /// EXPERIMENTAL: restore official .211 physical images to A and B; super contains A only.
    #[cfg(target_os = "android")]
    RestoreFactoryAbTest {
        package: PathBuf,
        #[arg(long)] my_company: PathBuf,
        #[arg(long)] my_preload: PathBuf,
        #[arg(long)] output_directory: PathBuf,
        #[arg(long)] avb_off: bool,
        /// Explicit acknowledgment: both physical slots will be overwritten; B is not a fallback.
        #[arg(long)] accept_both_slots_no_rollback: bool,
    },
    /// Discard all a block device holds and write zeros over its start, as
    /// a factory reset erases the data partition.
    #[cfg(target_os = "android")]
    Discard { device: PathBuf },
    /// Make a filesystem on a block device, f2fs or ext4, as a factory
    /// reset makes /metadata afresh.
    #[cfg(target_os = "android")]
    Mkfs { device: PathBuf, filesystem: String },
    /// Map the booted slot's partitions from super and mount them read-only.
    Mount,
    /// Unmount what `mount` mounted and remove its device-mapper devices.
    Umount,
    /// Print where an update stands: its state, the slot it came from, each
    /// snapshot as libsnapshot keeps it and as the kernel maps it, and the
    /// kernel's snapshot targets.
    Update,
    /// Merge the update into the slot the phone runs from, starting the
    /// merge where it has not begun, and follow it to its end.
    #[cfg(target_os = "android")]
    Merge,
    /// Keep the configuration's programs that this phone runs, and those
    /// its partitions name for its keys, going until stopped.
    #[cfg(target_os = "android")]
    Services {
        #[arg(long, default_value = "/skyward/device.toml")]
        config: String,
    },
    /// Print what the installed system's partitions say to do to use the
    /// phone's keys, in order, and do none of it. A build of the hardware
    /// the phone's init names as the phone starts is named first where it
    /// has no name yet.
    #[cfg(target_os = "android")]
    Keys,
    /// List the display connectors, their modes, CRTCs and planes.
    #[cfg(target_os = "android")]
    Kms {
        #[arg(long, default_value = "/dev/dri/card0")]
        card: String,
    },
    /// Play the vibration motor's click once, or the ticks of the screen
    /// going off by the power key, saying how strongly and for how long.
    #[cfg(target_os = "android")]
    Haptic {
        #[arg(long, default_value = "/skyward/device.toml")]
        config: String,
        /// Where on the strength slider, from 0 at its left end to 1 at its
        /// right.
        #[arg(long, default_value_t = skyward_ui::app::SLIDER_START)]
        position: f32,
        /// Play the ticks of the screen going off instead of the click.
        #[arg(long)]
        ticks: bool,
    },
    /// Save what the panel shows, as raw RGBA files cap-000.rgba onwards.
    #[cfg(target_os = "android")]
    Capture {
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        count: u32,
        /// Pause between captures, in milliseconds.
        #[arg(long, default_value_t = 100)]
        interval: u64,
        #[arg(long, default_value = "/dev/dri/card0")]
        card: String,
    },
    /// Set the system clock from the RTC and the offset Android keeps on
    /// persist, as the recovery does when it starts, and print the time in
    /// China, the first of the time zones the settings offer.
    #[cfg(target_os = "android")]
    Clock,
    /// Say whether a service has registered with the phone's service
    /// directory, such as android.hardware.security.keymint.IKeyMintDevice/default.
    #[cfg(target_os = "android")]
    Service { name: String },
    /// Report the phone's key service and, given a key directory Android
    /// wrote, unwrap the key it holds and say how long it is.
    #[cfg(target_os = "android")]
    Keymint {
        #[arg(long, default_value = "/metadata/vold/metadata_encryption/key")]
        key: PathBuf,
        /// Report instead what the key service keeps under this name, such
        /// as profile_key_name_decrypt_999.
        #[arg(long)]
        alias: Option<String>,
    },
    /// Say what the phone's credential service answers, which takes no
    /// credential and changes nothing.
    #[cfg(target_os = "android")]
    Gatekeeper,
    /// Say what the phone's weaver says of itself, which reads no slot and
    /// changes nothing.
    #[cfg(target_os = "android")]
    Weaver,
    /// Open the data partition with the key the phone keeps for it, check
    /// it and mount it writable as the phone does, and open each user's
    /// files that open; the owner's shared storage then shows at /sdcard.
    #[cfg(target_os = "android")]
    Data {
        /// What a user would type at their screen lock, where one is set.
        /// A wrong one is counted against that user by the phone's secure
        /// world, the same as a wrong try on the screen itself.
        #[arg(long)]
        credential: Option<String>,
        /// Close the data partition instead, as a factory reset does before
        /// it erases it: every other program holding it ends first.
        #[arg(long, conflicts_with = "credential")]
        close: bool,
    },
    /// Drive the panel and touchscreen with the recovery UI.
    #[cfg(target_os = "android")]
    Ui {
        #[arg(long, default_value = "/skyward/device.toml")]
        config: std::path::PathBuf,
        #[arg(long, default_value = "/skyward/MiSansVF.ttf")]
        font: std::path::PathBuf,
        /// The terminal's monospaced typeface.
        #[arg(long, default_value = "/skyward/KirkMono-Regular.ttf")]
        mono: std::path::PathBuf,
        /// Open on the unlock page instead of the home page.
        #[arg(long)]
        unlock: bool,
        /// After each frame, also write it as raw RGBA to this file.
        #[arg(long)]
        dump: Option<std::path::PathBuf>,
    },
}

#[cfg(target_os = "android")]
fn configure_binder(cfg: &DeviceConfig) -> Result<()> {
    let header = match cfg.device.binder_header {
        skyward_config::BinderHeader::Recovery => skyward_binder::parcel::Header::Recovery,
        skyward_config::BinderHeader::System => skyward_binder::parcel::Header::System,
    };
    skyward_binder::parcel::configure_header(header)
}

fn main() -> Result<()> {
    // init starts the recovery service by path with no arguments.
    let started_as = std::env::args_os().next().unwrap_or_default();
    let name = Path::new(&started_as).file_name().unwrap_or_default();
    if name == "recovery" {
        return recovery();
    }
    // Install scripts run the commands linked to this binary by their names.
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if let Some(code) = skyward_install::commands::run(name, &args) {
        std::process::exit(code);
    }
    let cli = Cli::parse();
    #[cfg(target_os = "android")]
    if let Some(header) = cli.binder_header.as_deref() {
        let header = match header {
            "system" => skyward_binder::parcel::Header::System,
            "recovery" => skyward_binder::parcel::Header::Recovery,
            _ => unreachable!("clap validated Binder header"),
        };
        skyward_binder::parcel::configure_header(header)?;
    } else if ramdisk::in_recovery() {
        configure_binder(&DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?)?;
    }
    match cli.cmd {
        Cmd::Info { config } => info(&config),
        Cmd::Slot => slot(),
        Cmd::Modules { source } => modules(&source),
        Cmd::Load { config, names } => {
            let cfg = DeviceConfig::load(&config)?;
            let names = if names.is_empty() { cfg.modules.load.clone() } else { names };
            for path in load_modules(&cfg, &names)? {
                println!("{}", path.display());
            }
            Ok(())
        }
        Cmd::Recovery => recovery(),
        Cmd::Reboot { target } => {
            let p = Power::parse(&target).ok_or_else(|| anyhow!("unknown target {target:?}"))?;
            skyward_sys::power(p)
        }
        Cmd::Bcb => {
            let b = bcb::read(&bcb::misc())?;
            println!("command = {:?}", b.command);
            println!("args    = {:?}", b.args);
            println!("request = {:?}", b.request());
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Discard { device } => skyward_block::erase::discard(&device),
        #[cfg(target_os = "android")]
        Cmd::Mkfs { device, filesystem } => skyward_block::erase::make(&device, &filesystem, &[], false),
        Cmd::Lp { super_dev, slot } => lp(&super_dev, slot),
        Cmd::Update => update(),
        #[cfg(target_os = "android")]
        Cmd::Merge => {
            let slot = booted_slot()?;
            let start = skyward_vab::standing(slot)? == skyward_vab::Standing::Waiting;
            let end = merge::run(slot, start, &mut |m| println!("{m:?}"))?;
            println!("ended {end:?}");
            Ok(())
        }
        Cmd::Identify { file } => identify(&file),
        #[cfg(target_os = "android")]
        Cmd::PrepareVendorBoot { stock, output } => prepare_vendor_boot(&stock, &output),
        #[cfg(target_os = "android")]
        Cmd::AuditVendorBoot { package, staged, slot } => audit_vendor_boot(&package, staged.as_deref(), &slot),
        #[cfg(target_os = "android")]
        Cmd::PrepareAvbOffA { package, output_directory } => prepare_avb_off_a(&package, &output_directory),
        #[cfg(target_os = "android")]
        Cmd::PreflightOta { package, my_company, my_preload, verify_official } => preflight_ota(&package, &my_company, &my_preload, verify_official),
        #[cfg(target_os = "android")]
        Cmd::PrepareSuperA { package, my_company, my_preload, output } => prepare_super_a(&package, &my_company, &my_preload, &output),
        #[cfg(target_os = "android")]
        Cmd::AuditRestoreBootControl { start_stock } => {
            let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
            let active = boot_services::audit_for_restore(&cfg, start_stock)?;
            println!("Read-only OEM HIDL 1.2 audit succeeded with super exclusively held; next slot is {active:?}. Setter was not tested.");
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::RequestLpHandoff => {
            let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
            lp_handoff::queue(&cfg)?;
            println!("Queued read-only LP maintenance handoff; leave Recovery open on its normal menu.");
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::RunLpHandoff { ticket_fd, ota_fd } => {
            let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
            match (ticket_fd, ota_fd) {
                (None, None) => lp_handoff::run(&cfg),
                (Some(ticket), Some(ota)) => lp_handoff::run_confirmed(&cfg, ticket, ota),
                _ => anyhow::bail!("incomplete OTA continuation"),
            }
        }
        #[cfg(target_os = "android")]
        Cmd::ResumeLpOta { ticket_fd, ota_fd } => lp_handoff::resume(ticket_fd, ota_fd),
        #[cfg(target_os = "android")]
        Cmd::AuditLpHandoffHolders => {
            anyhow::ensure!(ramdisk::in_recovery(), "handoff holder audit is only intended for Recovery");
            let slot = booted_slot()?;
            let holders = skyward_vab::audit_linear_super_holders(slot)?;
            for name in &holders { println!("Verified current-slot LP holder: {name}"); }
            println!("{} verified holders; this does not establish that they are safe to release", holders.len());
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::RepairMaintenanceLp { accept_metadata_repair } => {
            anyhow::ensure!(accept_metadata_repair, "explicit metadata repair confirmation is required");
            anyhow::ensure!(ramdisk::in_recovery() && Path::new(skyward_sys::RUN).join("lp-maintenance.txt").is_file(),
                "requires the isolated LP maintenance boot");
            let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
            let archive = boot_services::repair_captured_lp(&cfg, booted_slot()?)?;
            println!("LP capacity repaired and verified; original records and LP tables saved at {}. No OTA run or reboot requested.", archive.display());
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::QueryMaintenanceMerge => {
            anyhow::ensure!(ramdisk::in_recovery() && Path::new(skyward_sys::RUN).join("lp-maintenance.txt").is_file(),
                "requires the isolated LP maintenance boot");
            let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
            let (slot, merge) = boot_services::query_oem_merge_readonly(&cfg)?;
            println!("OEM BootControl next slot: {slot:?}; merge: {merge:?}. Diagnostic only, no write authorization.");
            let residue = skyward_install::lp_capacity::audit_captured_residue(booted_slot()?, slot, merge);
            println!("Captured .211 residue corroboration: {residue:#?}");
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::AuditFactoryAvailability => {
            let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
            anyhow::ensure!(ramdisk::in_recovery() && cfg.device.codename == "OP5911"
                && cfg.device.recovery_partition == skyward_config::RecoveryPartition::VendorBoot,
                "factory availability audit requires PGZ110 Recovery");
            let observed = skyward_install::factory_preflight::observe_restore_availability();
            println!("{observed:#?}\nRead only. OEM merge state, full target claims and boot acceptance are not established here.");
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::AuditPreloaderMaps => {
            let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
            anyhow::ensure!(cfg.device.codename == "OP5911" && cfg.device.recovery_partition == skyward_config::RecoveryPartition::VendorBoot,
                "this UFS mapping audit is only for PGZ110 vendor_boot Recovery");
            skyward_install::factory_preloader::audit_pgz110_211()?;
            println!("OEM preloader mappings match the observed UFS geometry. Read-only audit; no write authorization.");
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::PrepareFactoryA { package, my_company, my_preload, output_directory, avb_off, audit_targets, audit_physical_ab } =>
            prepare_factory_a(&package, &my_company, &my_preload, &output_directory, avb_off, audit_targets, audit_physical_ab),
        #[cfg(target_os = "android")]
        Cmd::RestoreFactoryAbTest { package, my_company, my_preload, output_directory, avb_off, accept_both_slots_no_rollback } =>
            restore_factory_ab_test(&package, &my_company, &my_preload, &output_directory, avb_off, accept_both_slots_no_rollback),
        Cmd::Mount => {
            let mounts = skyward_vab::mount_partitions(booted_slot()?)?;
            for d in &mounts.damaged {
                println!("damaged: {d}");
            }
            for m in &mounts.partitions {
                println!("{:<14} {:<16} {:<18} {}", m.partition, m.device.display(), m.mount_point.display(), m.filesystem);
            }
            Ok(())
        }
        Cmd::Umount => skyward_vab::unmount_partitions(booted_slot()?),
        #[cfg(target_os = "android")]
        Cmd::Services { config } => {
            let slot = booted_slot()?;
            let props = skyward_info::installed_props(slot)?;
            let services: Vec<Started> = DeviceConfig::load(&config)?.services.into_iter().filter(|s| s.runs_on(&props)).map(Started::from).collect();
            let libraries = secure::libraries()?;
            services::start(&services, libraries.as_deref())?;
            keys::start(&keys::found(slot, libraries.as_deref())?.steps?)?;
            loop {
                std::thread::park();
            }
        }
        #[cfg(target_os = "android")]
        Cmd::Keys => {
            for line in keys::describe(&keys::found(booted_slot()?, secure::libraries()?.as_deref())?.steps?) {
                println!("{line}");
            }
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Kms { card } => {
            print!("{}", skyward_ui::surface::kms::report(&card)?);
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Haptic { config, position, ticks } => {
            let haptics = DeviceConfig::load(&config)?.haptics.context("the configuration describes no vibration motor")?;
            haptics::probe(&haptics, position, ticks)
        }
        #[cfg(target_os = "android")]
        Cmd::Capture { out, count, interval, card } => {
            std::fs::create_dir_all(&out).with_context(|| format!("create {}", out.display()))?;
            for i in 0..count {
                let t0 = std::time::Instant::now();
                let c = skyward_ui::surface::kms::capture(&card)?;
                let path = out.join(format!("cap-{i:03}.rgba"));
                std::fs::write(&path, &c.data).with_context(|| format!("write {}", path.display()))?;
                println!("{} {}x{} in {} ms", path.display(), c.w, c.h, t0.elapsed().as_millis());
                std::thread::sleep(std::time::Duration::from_millis(interval));
            }
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Clock => {
            let ms = skyward_sys::clock::set_from_rtc()?;
            println!("{}", skyward_ui::fmt::datetime(skyward_ui::Lang::En, (ms / 1000) as i64, 0));
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Service { name } => {
            let binder = skyward_binder::driver::Binder::open()?;
            let described = if skyward_binder::service::declared(&binder, &name)? { "described" } else { "not described" };
            let running = match skyward_binder::service::find(&binder, &name)? {
                Some(_) => "registered",
                None => "not registered",
            };
            println!("{name} is {described} and {running}");
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Keymint { key, alias } => {
            let binder = skyward_binder::driver::Binder::open()?;
            let service = skyward_crypto::keymint::KeyMint::open(&binder)?;
            let hw = service.hardware()?;
            println!("keymint {} version {} at security level {} by {}", hw.name, hw.version, hw.security_level, hw.author);
            if let Some(alias) = alias {
                let held = skyward_crypto::keystore2::key_blob(Path::new(skyward_crypto::keystore2::DATABASE), &alias)?;
                println!("{alias} is a key of {} bytes", held.len());
                for (tag, value) in service.authorizations(&held, &[])? {
                    println!("  tag {tag} = {value} ({value:#x})");
                }
                match service.usable(&held, &[]) {
                    Ok(()) => println!("the key service unwraps it and will use it"),
                    Err(e) => println!("the key service will not use it: {e:#}"),
                }
                return Ok(());
            }
            let stored = skyward_crypto::keystore::StoredKey::load(&key)?;
            for (tag, value) in stored.authorizations(&service)? {
                println!("  tag {tag} = {value}");
            }
            let raw = stored.unwrap(skyward_crypto::keystore::Unwrap::Hardware(&service))?;
            println!("{} holds a key of {} bytes", key.display(), raw.len());
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Gatekeeper => {
            let (binder, hardware) = (skyward_binder::driver::Binder::open()?, skyward_binder::driver::Binder::hardware()?);
            let gatekeeper = skyward_crypto::gatekeeper::Gatekeeper::open(&binder, &hardware)?;
            println!("the credential service answers for {}", gatekeeper.serves()?);
            match gatekeeper.version() {
                Ok(Some(version)) => println!("it serves version {version} of that interface"),
                Ok(None) => println!("it numbers its version in its own name"),
                Err(e) => println!("it will not say which version it serves: {e:#}"),
            }
            // A credential belonging to no one, which the secure world
            // cannot recognise and counts against nobody. What comes back
            // says whether the service takes a check at all, apart from
            // whether it recognises what it is given.
            match gatekeeper.verify(NOBODY, &[], &[]) {
                Ok(_) => println!("it took a credential belonging to no one"),
                Err(e) => println!("asked about a credential belonging to no one it says: {e:#}"),
            }
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Weaver => {
            let binder = skyward_binder::driver::Binder::open()?;
            let c = skyward_crypto::weaver::Weaver::open(&binder)?.config()?;
            println!("the weaver has {} slots, keeps keys of {} bytes and values of {} bytes", c.slots, c.key_bytes, c.value_bytes);
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Data { close: true, .. } => {
            wipe::release_data()?;
            println!("the data partition is closed");
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Data { credential, close: false } => {
            use skyward_crypto::data;
            let binder = skyward_binder::driver::Binder::open()?;
            let service = skyward_crypto::keymint::KeyMint::open(&binder)?;
            let opening = data::open_without_credential(&service)?;
            match &opening.mounted {
                Some(mounted) => {
                    if let Some(checked) = &mounted.checked {
                        print!("{}", checked.said);
                        println!("the check of {} ended with {}", mounted.mapped.display(), checked.status);
                    }
                    println!("{} holds {} at {}", mounted.mapped.display(), mounted.filesystem, data::MOUNT);
                }
                None => println!("{} is mounted already", data::MOUNT),
            }
            let mut closed = opening.closed;
            let asked = closed.iter().find(|c| !c.made_up).map(|c| c.user);
            if let (Some(credential), Some(user)) = (&credential, asked) {
                closed = data::unlock(&service, &closed, user, credential.as_bytes())?;
            }
            for c in &closed {
                match &c.why {
                    Some(why) => println!("user {}'s own files stay closed: {why}", c.user),
                    None => println!("user {}'s own files stay closed", c.user),
                }
            }
            if closed.is_empty() {
                println!("every user's own files can be read");
            }
            Ok(())
        }
        #[cfg(target_os = "android")]
        Cmd::Ui { config, font, mono, unlock, dump } => {
            let cfg = DeviceConfig::load(&config)?;
            let start = if unlock { skyward_ui::app::Screen::Decrypt } else { skyward_ui::app::Screen::Home };
            // The programs the recovery service started for the phone's
            // keys are read from the partitions again, as it read them;
            // where they do not show, it started none.
            let mut programs = cfg.services.clone();
            match booted_slot().and_then(|slot| keys::found(slot, secure::libraries()?.as_deref())?.steps) {
                Ok(steps) => programs.extend(keys::programs(&steps)),
                Err(e) => eprintln!("the programs of the phone's keys are not known: {e:#}"),
            }
            ui::run(&cfg, &programs, runtime::Runtime::default(), &font, &mono, bcb::Request::default(), start, dump.as_deref())
        }
    }
}

fn booted_slot() -> Result<skyward_vab::Slot> {
    skyward_vab::current_slot()?.context("not an A/B device")
}

fn lp(super_dev: &Path, slot: Option<u32>) -> Result<()> {
    let slot = match slot {
        Some(n) => n,
        None => booted_slot()?.number(),
    };
    let md = skyward_lp::read(super_dev, slot)?;
    let g = md.geometry;
    println!("slot {slot}: version {}.{}, flags {:#x}", md.major_version, md.minor_version, md.header_flags);
    println!(
        "geometry: {} metadata slots of {} bytes, logical block {} bytes",
        g.metadata_slot_count, g.metadata_max_size, g.logical_block_size
    );
    for d in &md.damaged {
        println!("damaged: {d}");
    }
    for d in &md.block_devices {
        println!(
            "device {}: first sector {}, {} bytes, alignment {} offset {}",
            d.partition_name, d.first_logical_sector, d.size, d.alignment, d.alignment_offset
        );
    }
    for gr in &md.groups {
        println!("group {}: max {} bytes", gr.name, gr.maximum_size);
    }
    for p in &md.partitions {
        println!(
            "partition {} group {} attributes {:#x}, {} bytes",
            p.name, md.groups[p.group].name, p.attributes, p.bytes()
        );
        let mut start = 0;
        for e in &p.extents {
            let end = start + e.sectors() - 1;
            match *e {
                skyward_lp::Extent::Linear { device, sector, .. } => {
                    println!("  {start} .. {end} linear {} {sector}", md.block_devices[device].partition_name)
                }
                skyward_lp::Extent::Zero { .. } => println!("  {start} .. {end} zero"),
            }
            start = end + 1;
        }
    }
    Ok(())
}

/// Load `names` from the module sources the configuration lists.
fn load_modules(cfg: &DeviceConfig, names: &[String]) -> Result<Vec<PathBuf>> {
    let dirs = cfg.modules.sources.iter().map(|s| skyward_modules::source_dir(s)).collect::<Result<Vec<_>>>()?;
    skyward_modules::load(&dirs, names)
}

/// Start the recovery's own logd where it needs libraries of the installed
/// system, make the phone's firmware reachable to its drivers, mount the
/// partitions its own programs and drivers use where it mounts them, load
/// the configured kernel modules, hand the files the phone's init hands
/// over as it boots to their accounts, and start the phone's own programs,
/// read from the partitions just mounted: on the 13 Ultra, the touchscreen
/// driver and the touch processing. Of the programs the configuration
/// names, only those this phone's build of the hardware runs are started.
/// The programs that use the phone's keys come after them, as `found`
/// among the phone's partitions: where what the partitions say could not
/// be made out, the phone's devices are up before that is said.
#[cfg(target_os = "android")]
fn bring_up(cfg: &DeviceConfig, slot: skyward_vab::Slot, found: Result<keys::Found>) -> Result<runtime::Runtime> {
    let nodes = skyward_sys::ueventd::apply()?;
    skyward_sys::kmsg(&format!("{nodes} device nodes given the owner their phone describes"))?;
    let props = skyward_info::installed_props(slot)?;
    adopt_installed_version(&props)?;
    // Without logd the phone's own programs still run, and only what they
    // log is lost, so why it did not start goes to the kernel log.
    if let Some(logd) = &cfg.logd
        && let Err(e) = start_logd(logd)
    {
        skyward_sys::kmsg(&format!("logd not started: {e:#}"))?;
    }
    let services: Vec<Started> = cfg.services.iter().filter(|s| s.runs_on(&props)).cloned().map(Started::from).collect();
    // The drivers ask for their firmware by name, and the kernel looks only
    // in folders of its own unless told to pass on what it does not find
    // there to ueventd, which looks in the recovery's firmware folders.
    std::fs::write(FIRMWARE_FALLBACK, "1").with_context(|| format!("write 1 to {FIRMWARE_FALLBACK}"))?;
    if let Some(firmware) = &cfg.firmware {
        mount_firmware(&firmware.partition)?;
    }
    for name in &cfg.partitions.mounted {
        let at = skyward_block::fstab::mount(name)?;
        skyward_sys::kmsg(&format!("{name} is mounted on {}", at.display()))?;
    }
    for path in load_modules(cfg, &cfg.modules.load)? {
        skyward_sys::kmsg(&format!("loaded {}", path.display()))?;
    }
    if !cfg.owners.is_empty() {
        let handed = hand_over(&cfg.owners)?;
        skyward_sys::kmsg(&format!("{handed} of the phone's own files handed to the accounts its init gives them"))?;
    }
    // What the phone describes is known wherever its partitions could be
    // read at all; what they say of its keys may still not be.
    let (described, mut found) = match found {
        Ok(found) => (found.described, found.steps),
        Err(e) => (Vec::new(), Err(e)),
    };
    if cfg.device.hidl_manager_root {
        anyhow::ensure!(cfg.device.codename == "OP5911" && cfg.device.recovery_partition == skyward_config::RecoveryPartition::VendorBoot,
            "HIDL manager root compatibility is restricted to the audited PGZ110 recovery");
        if let Ok(steps) = &mut found {
            for step in steps {
                if let skyward_programs::secure::Step::Start(program) = step {
                    if matches!(program.service.path.as_str(), "/system_ext/bin/hwservicemanager" | "/mnt/system/system/bin/hwservicemanager") {
                        program.service.user = Some("root".to_string());
                        skyward_sys::kmsg("installed HIDL directory uses UID 0, matching stock fastboot's persistent hwbinder context UID")?;
                    }
                }
            }
        }
    }
    // What either service directory has to know of, it has to know before
    // anything registers with it, so both are told of the configuration's
    // programs and of those that use the phone's keys together.
    let key_programs = found.as_deref().map(keys::programs).unwrap_or_default();
    let programs = || services.iter().map(|p| &p.service).chain(&key_programs);
    let mut hardware: Vec<String> = programs().filter_map(|s| s.ready_hardware_service.clone()).collect();
    hardware.extend(cfg.wlan.iter().filter(|w| w.protocol == skyward_config::ServiceProtocol::Hidl).map(|w| w.service.clone()));
    if !hardware.is_empty() {
        secure::prepare_hardware_directory(&hardware)?;
        skyward_sys::kmsg("the directory for the phone's hardware services can run")?;
    }
    // A program that registers with the service directory needs the
    // directory to know the phone describes what it registers, and so does
    // the secure element service where the recovery serves it. The WLAN's
    // supplicant registers whenever the WLAN is turned on, and the
    // directory can no longer start again by then: the key service
    // registers with it below, and nothing would register that again.
    let mut registering: Vec<String> = programs().flat_map(|s| s.ready_service.iter().chain(&s.registers).cloned()).collect();
    if found.as_deref().is_ok_and(keys::serves_elements) {
        registering.push(skyward_omapi::SERVICE.to_string());
    }
    registering.extend(cfg.wlan.iter().filter(|w| w.protocol == skyward_config::ServiceProtocol::Aidl).map(|w| w.service.clone()));
    // A program may register more than the recovery waits for, as the
    // WLAN's supplicant registers its maker's own service beside
    // Android's, and ends where the directory turns one of them away. So
    // the directory is told of all the phone describes, as the phone's
    // own is.
    let mut told = registering.clone();
    told.extend(described.into_iter().filter(|name| !registering.contains(name)));
    if !told.is_empty() {
        secure::publish_descriptions(&told, &registering)?;
        skyward_sys::kmsg(&format!("the service directory is told of {} of the phone's own services", told.len()))?;
    }
    let libraries = secure::libraries()?;
    if let Some(dir) = &libraries {
        skyward_sys::kmsg(&format!("the phone's own libraries are at {}", dir.display()))?;
    }
    let mut runtime = runtime::Runtime::default();
    runtime.services = services::start_managed(&services, libraries.as_deref())?;
    let steps = found.context("make out from the phone's partitions how its keys are used")?;
    runtime.tee = cfg.trustonic.as_ref().map(|config| trustonic::start(config, libraries.as_deref())).transpose()?;
    for line in keys::describe(&steps) {
        skyward_sys::kmsg(&format!("for the phone's keys: {}", line.replace("\n  ", ", ")))?;
    }
    runtime.services.append(keys::start_managed(&steps)?);
    agree_on_the_notes_key(&registering)?;
    if let Some(daemon) = &mut runtime.tee { daemon.check()?; }
    Ok(runtime) // All owned children stop on partial failure or scope exit.
}

/// How long a file handed over may take to be there once the modules are
/// loaded: a driver makes its files as it takes its device up, and ueventd
/// makes the device's node once the kernel has told it of the device,
/// either of which may come after the load of the module returns.
#[cfg(target_os = "android")]
const FILES_MADE: std::time::Duration = std::time::Duration::from_secs(5);

/// Give each file the phone's own init hands over as it boots to the
/// account it names, with the mode it gives, as its chown and chmod lines
/// do. The files are the ones the modules just loaded make, which the
/// phone's own programs open as those accounts; one not there yet is
/// waited for.
#[cfg(target_os = "android")]
fn hand_over(owners: &[skyward_config::Owners]) -> Result<usize> {
    use skyward_sys::ueventd;
    use std::os::unix::fs::PermissionsExt;
    let known = ueventd::accounts(&ueventd::PASSWD_FILES.iter().chain(&ueventd::GROUP_FILES).copied().collect::<Vec<_>>());
    let id = |name: &str| ueventd::account(&known, name).with_context(|| format!("the phone has no account named {name}"));
    let mut handed = 0;
    for run in owners {
        let (uid, gid) = (id(&run.user)?, id(&run.group)?);
        for path in &run.paths {
            skyward_sys::wait_file(Path::new(path), FILES_MADE).context("wait for a file the modules just loaded make")?;
            std::os::unix::fs::chown(path, Some(uid), Some(gid)).with_context(|| format!("give {path} to {}:{}", run.user, run.group))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(run.mode))
                .with_context(|| format!("give {path} the mode {:o}", run.mode))?;
            handed += 1;
        }
    }
    Ok(handed)
}

/// The folder the recovery's own programs load their libraries from.
#[cfg(target_os = "android")]
const RECOVERY_LIBRARIES: &str = "/system/lib64";

/// How long logd may take to say it is ready once started.
#[cfg(target_os = "android")]
const LOGD_READY: std::time::Duration = std::time::Duration::from_secs(5);

/// Give the recovery's own logd the libraries of the installed system it
/// loads, and start it at once rather than on init's next try, so that it
/// keeps what the phone's own programs log from their start. Each library
/// is copied beside the recovery's own under a name of its own and then
/// renamed into place, so a logd an earlier run of the recovery service
/// started keeps the copy it has open.
#[cfg(target_os = "android")]
fn start_logd(logd: &skyward_config::Logd) -> Result<()> {
    for library in &logd.libraries {
        let from = Path::new(library);
        let to = Path::new(RECOVERY_LIBRARIES).join(from.file_name().expect("the configuration names each library's file"));
        let mut part = to.clone().into_os_string();
        part.push(".part");
        std::fs::copy(from, &part).with_context(|| format!("copy {library} to {}", Path::new(&part).display()))?;
        std::fs::rename(&part, &to).with_context(|| format!("put {} in place", to.display()))?;
    }
    skyward_sys::set_prop("ctl.start", "logd")?;
    skyward_sys::wait_prop("logd.ready", "true", LOGD_READY)?;
    skyward_sys::kmsg(&format!("logd runs with {} libraries of the installed system", logd.libraries.len()))
}

/// Have the parts of the secure world that keep keys agree on the key they
/// sign their notes with, where the phone has any that do. Android's key
/// service has them agree as the phone starts; until they have, the
/// credential service cannot write a note the key service will take, and
/// the keys the phone guards behind a screen lock stay unusable.
#[cfg(target_os = "android")]
fn agree_on_the_notes_key(registered: &[String]) -> Result<()> {
    let interface = format!("{}/", skyward_crypto::sharedsecret::INTERFACE);
    let names: Vec<String> = registered.iter().filter(|n| n.starts_with(&interface)).cloned().collect();
    if names.is_empty() {
        return Ok(());
    }
    let binder = skyward_binder::driver::Binder::open()?;
    let agreed = skyward_crypto::sharedsecret::agree(&binder, &names)?;
    skyward_sys::kmsg(&format!("{agreed} of the secure world agreed on the key it signs its notes with"))
}

/// A slot of the credential service that belongs to no user, which the
/// phone numbers its own from nothing upwards.
#[cfg(target_os = "android")]
const NOBODY: u32 = u32::MAX;

/// The switch that has the kernel pass the firmware requests it cannot
/// answer itself on to ueventd.
#[cfg(target_os = "android")]
const FIRMWARE_FALLBACK: &str = "/proc/sys/kernel/firmware_config/force_sysfs_fallback";

/// Where the firmware partition is shown as well: the recovery's own
/// ueventd looks in the image folder inside it.
#[cfg(target_os = "android")]
const FIRMWARE_SHOWN: &str = "/firmware";

/// Mount the partition holding the firmware images where and as the
/// phone's own table mounts it, which is where the loaders of the secure
/// world's apps look for theirs, and show it where the recovery's ueventd
/// looks for the rest. Both stay when the recovery service starts again.
#[cfg(target_os = "android")]
fn mount_firmware(partition: &str) -> Result<()> {
    let shown = Path::new(FIRMWARE_SHOWN);
    if skyward_block::mount::is_mount_point(shown)? {
        return Ok(());
    }
    let at = skyward_block::fstab::mount(partition)?;
    std::fs::create_dir_all(shown).with_context(|| format!("make {}", shown.display()))?;
    skyward_block::mount::bind(&at, shown)?;
    skyward_sys::kmsg(&format!("{partition} is mounted on {}, shown at {}", at.display(), shown.display()))
}

/// What the phone's own secure services read to tell the secure world which
/// build is running: the system's version and patch level, and the vendor
/// partition's patch level. A recovery image carries its own, older build's
/// values; the secure world then sees keys the installed system made as
/// made under a build it does not know, and refuses them. The recovery's
/// property files leave these out so that they can be set here instead.
#[cfg(target_os = "android")]
const BUILD_VERSION: [&str; 3] = ["ro.build.version.release", "ro.build.version.security_patch", "ro.vendor.build.security_patch"];

/// Set each of [`BUILD_VERSION`] to the installed system's value. An earlier
/// run of the recovery service may have set it already, and init sets such
/// a property only once.
#[cfg(target_os = "android")]
fn adopt_installed_version(props: &std::collections::HashMap<String, String>) -> Result<()> {
    for name in BUILD_VERSION {
        let value = props.get(name).with_context(|| format!("the installed system says no {name}"))?;
        if skyward_sys::prop(name).as_ref() != Some(value) {
            skyward_sys::set_prop(name, value)?;
        }
        skyward_sys::kmsg(&format!("{name} is the installed system's {value}"))?;
    }
    Ok(())
}

/// The recovery service. Its own folder is made and its log kept there from
/// the start, and adb comes up first so a failure later on can be
/// inspected, file transfer joining it
/// once the screen starts; then the boot request in misc is read. A
/// request whose work
/// goes on stays in misc until the work is done; any other is cleared at
/// once, so that any reboot from here boots the system. Failures go to the
/// kernel log and still end the process, which init then starts again.
fn recovery() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let run = || -> Result<()> {
        // Open to the programs the recovery runs as other users, the
        // supplicant among them, whatever the umask.
        std::fs::create_dir_all(skyward_sys::RUN).with_context(|| format!("make {}", skyward_sys::RUN))?;
        std::fs::set_permissions(skyward_sys::RUN, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("open {} to the recovery's other users", skyward_sys::RUN))?;
        skyward_sys::keep_log(Path::new(skyward_sys::LOG))?;
        skyward_sys::kmsg("startup stage: recovery entered; log opened")?;
        // A recovery that ended with a function of its own in the port took
        // the port with it; going through "none" takes that function off.
        if skyward_sys::prop("sys.usb.state").is_some_and(|s| s != "adb") {
            skyward_sys::usb::set("none", std::time::Duration::from_secs(5))?;
        }
        skyward_sys::set_prop("sys.usb.config", "adb")?;
        let misc = bcb::misc();
        let message = bcb::read(&misc)?;
        #[cfg(target_os = "android")]
        if lp_audit_requested(&message) {
            return lp_maintenance_boot();
        }
        let request = message.request();
        if !request.work.lasts() {
            bcb::clear(&misc)?;
        }
        let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
        #[cfg(target_os = "android")]
        configure_binder(&cfg)?;
        skyward_sys::kmsg(&format!(
            "{} {} recovery up, misc command {:?} args {:?}, asking for {:?}",
            cfg.device.codename,
            skyward_info::VERSION,
            message.command,
            message.args,
            request.work
        ))?;
        if !request.unknown.is_empty() {
            skyward_sys::kmsg(&format!("misc arguments this recovery does not know: {:?}", request.unknown))?;
        }
        if request.work == bcb::Work::Exit {
            return skyward_sys::power(if request.shutdown_after { Power::Off } else { Power::System });
        }
        // An update the system asked for starts counting its starts in misc,
        // as Android's own recovery counts them, so that one a restart cuts
        // off is taken up again as a retry; one that follows the kernel
        // stopping is not started at all.
        #[cfg(target_os = "android")]
        if let bcb::Work::Update(update) = &request.work
            && update.retry == 0
            && !ui::panicked()
        {
            bcb::write(&misc, &message.with_retry(1))?;
        }
        // The kernel starts the clock from the RTC, days after 1970 on these
        // phones; the screen and the files written still work without the
        // real time, so a failure goes to the kernel log.
        #[cfg(target_os = "android")]
        match skyward_sys::clock::set_from_rtc() {
            Ok(ms) => skyward_sys::kmsg(&format!("clock set to {} ms from the RTC and persist", ms))?,
            Err(e) => skyward_sys::kmsg(&format!("clock not set: {e:#}"))?,
        }
        // The kernel starts every core at its top frequency, and keeps idle
        // ones from powering down, until the phone's own system boots and
        // changes that; left so, the phone drains its battery with the
        // screen off. The recovery works either way, so a failure goes to
        // the kernel log.
        #[cfg(target_os = "android")]
        match skyward_sys::cpu::run_as_system() {
            Ok(done) => skyward_sys::kmsg(&format!("the CPUs run as the system runs them: {}", done.join(", ")))?,
            Err(e) => skyward_sys::kmsg(&format!("the CPUs run as the kernel started them: {e:#}"))?,
        }
        #[cfg(target_os = "android")]
        {
            use skyward_ui::app::Screen;
            // fastbootd rewrites super, which it cannot do while the slot's
            // partitions are mapped and mounted, so fastboot runs without
            // them and without what runs from them. So does work on whole
            // partitions the system asks for, as in Android's own recovery:
            // erasing them, which may take super with them, and undoing
            // shared blocks, which writes to the slot's own.
            if matches!(request.work, bcb::Work::Fastboot) {
                boot_services::start_for_fastboot(&cfg)?;
                // fastboot USB must not depend on fonts/panel initialisation.
                // The interface still starts normally; its existing mode is
                // recognised below rather than toggled a second time.
                skyward_sys::usb::switch("fastboot", std::time::Duration::from_secs(5))?;
            }
            let mut programs = cfg.services.clone();
            // Own the daemon until ui::run returns, including its error paths.
            let mut runtime = runtime::Runtime::default();
            if !matches!(request.work, bcb::Work::Fastboot | bcb::Work::WipeAb { .. } | bcb::Work::UnshareBlocks) {
                skyward_sys::kmsg("startup stage: preparing partitions and services")?;
                let (prepared, daemon) = prepare(&cfg, booted_slot()?)?;
                skyward_sys::kmsg("startup stage: partition/service preparation returned")?;
                programs.extend(prepared);
                runtime = daemon;
            }
            let root = Path::new("/");
            ui::run(&cfg, &programs, runtime, &root.join(ramdisk::FONT), &root.join(ramdisk::MONO), request, Screen::Home, None)
        }
        #[cfg(not(target_os = "android"))]
        {
            anyhow::bail!("the recovery service runs only on Android")
        }
    };
    run().inspect_err(|e| {
        let _ = skyward_sys::kmsg(&format!("recovery failed: {e:#}"));
    })
}

#[cfg(any(target_os = "android", test))]
fn lp_audit_requested(message: &bcb::Bcb) -> bool {
    message.command == "boot-recovery" && matches!(message.args.as_slice(), [arg] if arg == "--skyward-audit-lp")
}

/// A deliberately read-only boot. Never fall back to normal recovery on an
/// audit error, because normal prepare maps vendor and invalidates the probe.
#[cfg(target_os = "android")]
fn lp_maintenance_boot() -> Result<()> {
    use skyward_block::{BY_NAME, mount};
    let report = (|| -> Result<String> {
        // noload prevents ext4 journal replay even on a read-only mount.
        let metadata = Path::new("/metadata");
        if !mount::is_mount_point(metadata)? {
            mount::mount(&Path::new(BY_NAME).join("metadata"), metadata, "ext4",
                &["ro".into(), "noload".into(), "nodev".into(), "nosuid".into(), "noexec".into()])?;
        }
        let (capacity, snapshots, exclusive) = skyward_install::lp_capacity::audit_maintenance(booted_slot()?);
        let boot = if exclusive.is_ok() {
            (|| {
                let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
                configure_binder(&cfg)?;
                boot_services::observe_for_maintenance(&cfg, true)
            })()
        } else {
            Err(anyhow::anyhow!("skipped: super could not be exclusively claimed"))
        };
        Ok(format!("capacity repair needed: {capacity:#?}\nsnapshot preflight: {snapshots:#?}\nread-only exclusive super / LP dry run: {exclusive:#?}\nOEM BootControl (next slot, merge state): {boot:#?}"))
    })();
    let text = match report { Ok(text) => text, Err(error) => format!("maintenance audit failed: {error:#}") };
    eprintln!("{text}");
    let _ = std::fs::write(Path::new(skyward_sys::RUN).join("lp-maintenance.txt"), format!("{text}\n"));
    let _ = skyward_sys::kmsg("LP audit finished; Recovery is holding for ADB without preparing installed partitions");
    // init restarts the normal Recovery service after exit; remain in this
    // explicit diagnostic mode until the human chooses how to exit it.
    loop { std::thread::park(); }
}

#[cfg(test)]
#[test]
fn lp_audit_does_not_take_over_standard_recovery_requests() {
    for (command,args,expected) in [
        ("boot-recovery", vec!["--skyward-audit-lp"], true),
        ("boot-fastboot", vec!["--skyward-audit-lp"], false),
        ("boot-recovery", vec!["--skyward-audit-lp", "--wipe_data"], false),
        ("boot-recovery", vec!["--sideload"], false),
        ("boot-recovery", vec![], false),
    ] {
        let message = bcb::Bcb { command: command.into(), args: args.into_iter().map(str::to_owned).collect() };
        assert_eq!(lp_audit_requested(&message), expected);
    }
}

/// Map and mount the slot's partitions from super, then bring up what runs
/// from them, and give the programs the partitions name for the phone's
/// keys, which the recovery keeps running from then on. Recovery has to
/// stay usable when super cannot be mounted, as after it is wiped, so the
/// reason goes to the kernel log instead.
#[cfg(target_os = "android")]
fn prepare(cfg: &DeviceConfig, slot: skyward_vab::Slot) -> Result<(Vec<skyward_config::Service>, runtime::Runtime)> {
    match skyward_vab::mount_partitions(slot) {
        Ok(mounts) => {
            for d in &mounts.damaged {
                skyward_sys::kmsg(&format!("super: {d}"))?;
            }
            for m in &mounts.partitions {
                skyward_sys::kmsg(&format!("mounted {} on {} ({})", m.partition, m.mount_point.display(), m.filesystem))?;
            }
            let found = secure::libraries().and_then(|libraries| keys::found(slot, libraries.as_deref()));
            let steps = found.as_ref().ok().and_then(|found| found.steps.as_deref().ok());
            let programs = steps.map(keys::programs).unwrap_or_default();
            // Without them the screen still shows and the keys still work,
            // so this reason goes to the kernel log as well.
            let daemon = match bring_up(cfg, slot, found) {
                Ok(daemon) => daemon,
                Err(e) => {
                    skyward_sys::kmsg(&format!("devices not brought up: {e:#}"))?;
                    runtime::Runtime::default()
                }
            };
            Ok((programs, daemon))
        }
        Err(e) => {
            skyward_sys::kmsg(&format!("partitions not mounted: {e:#}"))?;
            Ok((Vec::new(), runtime::Runtime::default()))
        }
    }
}

fn info(config: &str) -> Result<()> {
    let cfg = DeviceConfig::load(config)?;
    let i = skyward_info::collect(&cfg)?;
    println!("model         = {} ({})", i.model, i.codename);
    println!("soc           = {:?}", i.soc);
    println!("cpu           = {} cores, max {:?} kHz", i.cpu.cores, i.cpu.max_khz);
    println!("ram           = {} KiB", i.ram_kib);
    println!("panel         = {:?}", i.panel);
    println!("screen        = {:?} in", i.screen);
    println!("os_version    = {:?}", i.os_version);
    println!("android       = {:?}", i.android);
    println!("patch         = {:?}", i.security_patch);
    println!("kernel        = {}", i.kernel);
    println!("storage       = {} bytes, free {:?}", i.storage.total, i.storage.free);
    println!("battery       = {:?}", i.battery);
    println!("boot          = {:?}", i.boot);
    println!("recovery      = {}", skyward_info::VERSION);
    match i.slot {
        Some(s) => println!("current_slot  = {}", s.suffix()),
        None => println!("current_slot  = (not A/B)"),
    }
    let snap = i.snapshot;
    println!("snapshot      = {snap:?}");
    match snap {
        SnapshotState::None => {}
        SnapshotState::Unknown => println!("  -> /metadata is not mounted; dynamic-partition writes stay refused"),
        _ => println!("  -> dynamic-partition writes are refused while a snapshot is outstanding"),
    }
    let parts = skyward_block::list_by_name(skyward_block::BY_NAME)?;
    println!("partitions    = {} under {}", parts.len(), skyward_block::BY_NAME);
    Ok(())
}

#[cfg(target_os = "android")]
fn open_repack_input(path: &Path, limit: u64) -> Result<(std::fs::File, u64)> {
    use std::os::unix::fs::OpenOptionsExt;
    let before = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(before.is_file() && before.len() <= limit, "need a bounded regular file: {}", path.display());
    let fd = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let opened = fd.metadata()?;
    anyhow::ensure!(opened.is_file() && opened.len() == before.len(), "input changed while opening {}", path.display());
    Ok((fd, opened.len()))
}

#[cfg(target_os = "android")]
fn read_repack_input(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let (file, size) = open_repack_input(path, limit)?;
    let mut bytes = Vec::new();
    file.take(size + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() as u64 == size, "input size changed: {}", path.display());
    Ok(bytes)
}

#[cfg(target_os = "android")]
fn repack_donor() -> Result<(Vec<u8>, Vec<(&'static str, Vec<u8>)>)> {
    let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
    anyhow::ensure!(cfg.device.codename == "OP5911" && cfg.device.recovery_partition == skyward_config::RecoveryPartition::VendorBoot, "this repacker requires a PGZ110 vendor_boot Recovery");
    let elf = read_repack_input(Path::new("/system/bin/recovery"), 32 << 20)?;
    let mut owned = Vec::new();
    for name in ["skyward/device.toml", "skyward/MiSansVF.ttf", "skyward/KirkMono-Regular.ttf", "skyward/KirkMono-OFL.txt", "system/etc/init/skyward-mtp.rc"] {
        owned.push((name, read_repack_input(&Path::new("/").join(name), 32 << 20)?));
    }
    Ok((elf, owned))
}

#[cfg(target_os = "android")]
fn prepare_avb_off_a(package: &Path, output_directory: &Path) -> Result<()> {
    use skyward_install::{factory_preflight, payload_preflight, retention, signature};
    use std::io::{BufReader, Write};

    let (file, size) = open_repack_input(package, 128 << 30)?;
    let mut zip = BufReader::new(file);
    let (manifest, digest) = payload_preflight::read_zip_with_digest(&mut zip)?;
    factory_preflight::reviewed_roster(&digest)?;
    let keys = signature::keys(BufReader::new(open_repack_input(Path::new(signature::CERTIFICATES), 8 << 20)?.0))?;
    anyhow::ensure!(signature::verify(&mut zip, size, &keys, |_, _| true)? == signature::Verdict::Signed,
        "expected an official OTA signed by this Recovery's trusted certificates");
    let (elf, owned) = repack_donor()?;
    let assets: Vec<_> = owned.iter().map(|(name,data)| (*name,data.as_slice())).collect();
    let prepared = retention::SlotTarget::from_payload(&manifest, skyward_vab::Slot::A)?.stage_from_payload(&mut zip, &manifest)?;
    let pair = prepared.prepare_a_avb_off(&elf, &assets)?;
    // A new directory and exclusively created regular files only. The marker
    // is created last, so partial output is not identified as a complete pair.
    std::fs::create_dir(output_directory)?;
    for (name, bytes) in [("vendor_boot_a-UNTESTED.img", pair.vendor_boot.as_slice()), ("vbmeta_a-AVB-OFF-UNTESTED.img", pair.vbmeta.as_slice()),
        ("PAIR-COMPLETE.txt", b"A-slot development candidates only. Modified vbmeta invalidates its OEM signature. Bootloader acceptance untested. No flash performed.\n".as_slice())] {
        let mut out = std::fs::OpenOptions::new().write(true).create_new(true).open(output_directory.join(name))?;
        out.write_all(bytes)?;
        out.sync_all()?;
    }
    println!("Prepared A-slot development pair at {}; no flash or slot change", output_directory.display());
    Ok(())
}

#[cfg(target_os = "android")]
fn audit_vendor_boot(package: &Path, staged: Option<&Path>, selected: &str) -> Result<()> {
    use skyward_install::{payload_preflight, retention, vendor_boot::parent_avb::ParentBinding};
    use skyward_vab::Slot;
    let slot = match selected { "a" => Slot::A, "b" => Slot::B, _ => anyhow::bail!("slot must be a or b") };
    let (mut zip, _) = open_repack_input(package, 128 << 30)?;
    let manifest = payload_preflight::read_zip(&mut zip)?;
    let target = retention::SlotTarget::from_payload(&manifest, slot)?;
    let prepared = if let Some(staged) = staged {
        target.validate_sources(|s, name| open_repack_input(&staged.join(format!("{name}{}.img", s.suffix())), 128 << 20))?
    } else {
        target.stage_from_payload(&mut zip, &manifest)?
    };
    let (elf, owned) = repack_donor()?;
    let assets: Vec<_> = owned.iter().map(|(name,data)| (*name,data.as_slice())).collect();
    match prepared.audit_repack(&elf, &assets)? {
        ParentBinding::MatchesCandidate => println!("slot {} parent descriptor matches candidate; OEM authorization not established", prepared.slot().suffix()),
        ParentBinding::RejectsCandidate => anyhow::bail!("slot {} unchanged parent vbmeta binds the original image, not the repacked candidate", prepared.slot().suffix()),
        ParentBinding::Unproven => anyhow::bail!("slot {} parent AVB binding is unproven", prepared.slot().suffix()),
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn prepare_vendor_boot(stock: &Path, output: &Path) -> Result<()> {
    use std::io::Write;
    let target = read_repack_input(stock, 64 << 20)?;
    let (elf, owned) = repack_donor()?;
    let mut assets: Vec<(&str, &[u8])> = owned.iter().map(|(name, data)| (*name, data.as_slice())).collect();
    // The two replacement images ride inside this image, so the ported
    // Recovery can install without any file lying beside the package.
    let mut embedded: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for name in skyward_install::vendor_boot::REPLACEMENT_ASSETS {
        let path = Path::new("/").join(name);
        match std::fs::read(&path) {
            Ok(data) if !data.is_empty() => embedded.push((name, data)),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        }
    }
    assets.extend(embedded.iter().map(|(name, data)| (*name, data.as_slice())));
    let result = skyward_install::vendor_boot::repack(&target, &elf, &assets)?;
    // This stage emits a new file only. It cannot open an existing device or
    // output path and cannot select a slot, activate it, or write vbmeta.
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    file.write_all(&result)?;
    file.sync_all()?;
    println!("Prepared {} bytes at {} (unverified runtime candidate; not flashed)", result.len(), output.display());
    Ok(())
}

#[cfg(target_os = "android")]
fn preflight_ota(package: &Path, company: &Path, preload: &Path, verify_official: bool) -> Result<()> {
    use skyward_install::{factory_preflight, payload_preflight as ota, signature, super_replacement};
    let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
    anyhow::ensure!(cfg.device.codename == "OP5911" && cfg.device.recovery_partition == skyward_config::RecoveryPartition::VendorBoot, "this preflight is for PGZ110 vendor_boot Recovery");
    let (mut package, package_size) = open_repack_input(package, 128 << 30)?;
    let (manifest, digest) = ota::read_zip_with_digest(&mut package)?;
    let super_path = Path::new(skyward_block::BY_NAME).join("super");
    let bytes = skyward_block::size_bytes(&super_path)?;
    let lp = skyward_lp::read(&super_path, booted_slot()?.number())?;
    let [device] = lp.block_devices.as_slice() else { anyhow::bail!("expected one physical super device"); };
    anyhow::ensure!(lp.damaged.is_empty() && device.partition_name == "super" && bytes == device.size, "physical super disagrees with verified LP metadata");
    let data_start = device.first_logical_sector.checked_mul(skyward_lp::SECTOR_SIZE).context("super sector overflow")?;
    let g = ota::Geometry { device_size: bytes, data_start, alignment: u64::from(device.alignment),
        alignment_offset: u64::from(device.alignment_offset), logical_block: u64::from(lp.geometry.logical_block_size) };
    let company_size = super_replacement::inspect(company)?;
    let preload_size = super_replacement::inspect(preload)?;
    let plan = ota::preview(&manifest, g, company_size, preload_size)?;
    println!("READ-ONLY: no flash, no AVB changes, no slot switch");
    if verify_official {
        let roster = factory_preflight::reviewed_roster(&digest)?;
        let certs = std::io::BufReader::new(open_repack_input(Path::new(signature::CERTIFICATES), 8 << 20)?.0);
        let keys = signature::keys(certs)?;
        let verdict = signature::verify(&mut package, package_size, &keys, |_, _| true)?;
        anyhow::ensure!(verdict == signature::Verdict::Signed, "official OTA signature is not established: {verdict:?}");
        let checked = factory_preflight::check(&manifest, true, &lp, bytes, roster,
            factory_preflight::ReplacementSizes { my_company: company_size, my_preload: preload_size })?;
        println!("Verified official ZIP signature and reviewed .211 inventory: {} images declared, {} A partitions; allocation ends at byte {}",
            checked.original_images.len(), checked.effective_a_sizes.len(), checked.allocated_end);
        println!("External replacements absent from OTA: {:?}; OEM signature does not cover their bytes", checked.replacements_without_original);
        let boot_chain = skyward_install::retention::SlotTarget::from_payload(&manifest, skyward_vab::Slot::A)?
            .stage_from_payload(&mut package, &manifest)?;
        let (elf, owned) = repack_donor()?;
        let assets: Vec<_> = owned.iter().map(|(name, bytes)| (*name, bytes.as_slice())).collect();
        let binding = boot_chain.audit_repack(&elf, &assets)?;
        println!("A-slot candidate binding against untouched parent vbmeta: {binding:?}; not boot authorization");
    }
    println!("Partial OTA: {}; payload snapshots: {}; physical super: {bytes} bytes", plan.partial, plan.snapshot_enabled);
    for item in &plan.only_a.slot[0] { println!("{:<16} {:>12} {:?}", item.name, item.bytes, item.origin); }
    println!("A only: {} bytes including alignment; fits physical={}; target group limit={:?}", plan.only_a.aligned_end, plan.only_a.fits(), plan.group_limit);
    println!("Independent A and B: {} bytes including alignment; fits physical={}", plan.two_copies.aligned_end, plan.two_copies.fits());
    println!("Not in target dynamic group: {:?}", plan.physical_payload_names);
    let device_number = skyward_block::devnum(&super_path)?;
    let kernel_holders = skyward_install::factory_preflight::kernel_super_holders(Path::new("/sys/dev/block"), device_number)?;
    let super_mounts = skyward_block::mount::points_of(device_number)?;
    let snapshot = skyward_vab::snapshot_state()?;
    println!("Whole-super write preconditions (read-only): snapshot={snapshot:?}, direct mounts={super_mounts:?}, kernel holders={kernel_holders:?}");
    if snapshot != skyward_vab::SnapshotState::None || !super_mounts.is_empty() || !kernel_holders.is_empty() {
        println!("Shared super is not clear for full-device replacement.");
    }
    println!("No authorization to write or switch slots: AVB compatibility and completeness of target layout are not established by this preview.");
    Ok(())
}

#[cfg(target_os = "android")]
fn prepare_super_a(package: &Path, company: &Path, preload: &Path, output: &Path) -> Result<()> {
    let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
    anyhow::ensure!(cfg.device.codename == "OP5911" && cfg.device.recovery_partition == skyward_config::RecoveryPartition::VendorBoot,
        "this candidate builder requires PGZ110 vendor_boot Recovery");
    use skyward_install::{factory_preflight, payload_preflight, signature, super_replacement};
    let (file, input_size) = open_repack_input(package, 128 << 30)?;
    let mut input = std::io::BufReader::new(file);
    let (payload, digest) = payload_preflight::read_zip_with_digest(&mut input)?;
    let roster = factory_preflight::reviewed_roster(&digest)?;
    let super_path = Path::new(skyward_block::BY_NAME).join("super");
    let bytes = skyward_block::size_bytes(&super_path)?;
    let metadata = skyward_lp::read(&super_path, booted_slot()?.number())?;
    let replacements = factory_preflight::ReplacementSizes {
        my_company: super_replacement::inspect(company)?, my_preload: super_replacement::inspect(preload)?,
    };
    let certs = std::io::BufReader::new(open_repack_input(Path::new(signature::CERTIFICATES), 8 << 20)?.0);
    let keys = signature::keys(certs)?;
    let verdict = signature::verify(&mut input, input_size, &keys, |_, _| true)?;
    anyhow::ensure!(verdict == signature::Verdict::Signed, "official OTA signature is not established: {verdict:?}");
    let _ = factory_preflight::check(&payload, true, &metadata, bytes, roster, replacements)?;
    let result = skyward_install::super_image::build_a(&mut input, &payload, &metadata, bytes, company, preload, output)?;
    println!("Prepared {} bytes at {} ({} A-slot partitions; allocated through byte {}; partial payload: {}). No flashing, AVB change, or slot switch.",
        result.bytes, output.display(), result.partitions, result.allocated_end, result.partial_payload);
    Ok(())
}

#[cfg(target_os = "android")]
fn prepare_factory_a(package: &Path, company: &Path, preload: &Path, output: &Path, avb_off: bool, audit_targets: bool, audit_physical_ab: bool) -> Result<()> {
    let (elf, owned) = repack_donor()?;
    let assets: Vec<_> = owned.iter().map(|(name, bytes)| (*name, bytes.as_slice())).collect();
    let super_path = Path::new(skyward_block::BY_NAME).join("super");
    let bytes = skyward_block::size_bytes(&super_path)?;
    let metadata = skyward_lp::read(&super_path, booted_slot()?.number())?;
    let bundle = skyward_install::factory_bundle::prepare(package,
        Some(Path::new(skyward_install::signature::CERTIFICATES)), &metadata, bytes,
        company, preload, &elf, &assets, avb_off, output)?;
    println!("Staged {} files at {}; this did not write partitions or switch slots",
        bundle.images.len() + bundle.extra_physical.len(), bundle.directory.display());
    println!("Unstaged: {:?}; staged but without a verified execution mapping: {:?}",
        bundle.remaining_physical, bundle.unmapped_physical);
    if let Err(error) = bundle.execution_plan() {
        println!("Not an executable restore: {error:#}");
    }
    if audit_targets || audit_physical_ab {
        let count = if audit_physical_ab { bundle.audit_targets_ab()? } else { bundle.audit_targets()? };
        println!("Read-only exclusive claims succeeded for {count} targets and were released. No flash or boot authorization.");
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn restore_factory_ab_test(package: &Path, company: &Path, preload: &Path, output: &Path,
    avb_off: bool, accept_both_slots_no_rollback: bool) -> Result<()> {
    anyhow::ensure!(accept_both_slots_no_rollback, "explicit both-slot/no-rollback acknowledgment is required");
    anyhow::ensure!(avb_off, "the .211 Skyward test changes vendor_boot and requires explicit AVB-off selection");
    anyhow::ensure!(skyward_sys::prop("ro.boot.vbmeta.device_state").as_deref() == Some("unlocked")
        && skyward_sys::prop("ro.boot.verifiedbootstate").as_deref() == Some("orange"),
        "the bootloader must explicitly report unlocked/orange; this does not prove AVB-off boot acceptance");
    anyhow::ensure!(skyward_vab::snapshot_state()? == skyward_vab::SnapshotState::None,
        "a pending or unknown snapshot state prevents this test");
    skyward_install::factory_preflight::audit_restore_metadata().context("restore requires idle snapshot metadata before staging")?;
    let cfg = DeviceConfig::load(Path::new("/").join(ramdisk::CONFIG))?;
    let (elf, owned) = repack_donor()?;
    let assets: Vec<_> = owned.iter().map(|(name, bytes)| (*name, bytes.as_slice())).collect();
    let super_path = Path::new(skyward_block::BY_NAME).join("super");
    let bytes = skyward_block::size_bytes(&super_path)?;
    let reference = skyward_lp::read(&super_path, booted_slot()?.number())?;
    // Reject a mounted or held super before spending time materializing
    // the package; the backend still claims all destinations again.
    skyward_install::with_exclusive_super_for_audit(|_| Ok(()))?;
    let bundle = skyward_install::factory_bundle::prepare(package,
        Some(Path::new(skyward_install::signature::CERTIFICATES)), &reference, bytes,
        company, preload, &elf, &assets, avb_off, output)?;
    println!("Staging complete. Experimental restore: both physical slots, one shared super with A only.");
    boot_services::execute_ab_test(&cfg, &bundle)?;
    println!("All scheduled writes synced. OEM BootControl accepted A as the next slot. No reboot requested.");
    Ok(())
}

fn identify(path: &Path) -> Result<()> {
    use skyward_install::package::{self, Package};
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    match package::identify(std::io::BufReader::new(file))? {
        Package::Update(u) => {
            println!("an A/B update to {}", u.version().unwrap_or("an unnamed version"));
            println!("payload.bin at byte {}, {} bytes", u.payload_offset, u.payload_size);
            for key in ["ota-type", "pre-device", "post-build", "post-timestamp", "post-security-patch-level", "pre-build"] {
                if let Some(v) = u.metadata.get(key) {
                    println!("{key:<26} {v}");
                }
            }
            if u.wipes() {
                println!("all user data is erased once it is in, after the user agrees");
            }
        }
        Package::Image(kind) => println!("{kind:?}, for {}", kind.partitions().join(" or ")),
        Package::Script => println!("a zip that installs itself with a script"),
        Package::System(c) => {
            println!("the system {} {} ({}), to install beside the installed one", c.manifest.name, c.manifest.version, c.manifest.id);
            println!("a boot image of {} bytes, a root image of {} bytes ({}), starting {}", c.boot, c.root, c.manifest.filesystem, c.manifest.init);
            println!("its root takes at least {} bytes", c.least());
            if c.init_boot {
                println!("it brings its own init_boot image");
            }
        }
        Package::Unknown => println!("nothing this recovery installs"),
    }
    Ok(())
}

fn slot() -> Result<()> {
    match skyward_vab::current_slot()? {
        Some(s) => println!("{}", s.suffix()),
        None => println!("(not A/B)"),
    }
    #[cfg(target_os = "android")]
    {
        use skyward_vab::boot::BootControl;
        let (binder, hardware) = (skyward_binder::driver::Binder::open()?, skyward_binder::driver::Binder::hardware()?);
        let opened = BootControl::open(&binder, &hardware);
        match opened {
            Ok(control) => {
                let slots = control.slots()?;
                println!("next {}", slots.active.suffix());
                for slot in [skyward_vab::Slot::A, skyward_vab::Slot::B] {
                    let k = slot.number() as usize;
                    println!("{} bootable {} successful {}", slot.suffix(), slots.bootable[k], slots.successful[k]);
                }
                println!("update {:?}", control.merge_status()?);
            }
            Err(e) => println!("{e:#}"),
        }
    }
    Ok(())
}

fn update() -> Result<()> {
    let slot = booted_slot()?;
    println!("standing {:?}", skyward_vab::standing(slot)?);
    for kind in ["snapshot", "snapshot-merge", "user"] {
        println!("target {kind} {:?}", skyward_block::dm::target_version(kind)?);
    }
    let Some(snaps) = skyward_vab::snapshots::Snapshots::lock(false)? else {
        println!("no update was ever applied");
        return Ok(());
    };
    let u = snaps.update()?;
    println!("state {:?} phase {:?} failure {:?}", snaps.state()?, u.merge_phase, u.merge_failure_code);
    println!("snapuserd {} userspace {} allocated {} total {} metadata {}", u.using_snapuserd, u.userspace_snapshots, u.sectors_allocated, u.total_sectors, u.metadata_sectors);
    println!("from {:?}, {:?} for {}, built {:?}", snaps.source()?, snaps.side(slot)?, slot.suffix(), u.source_build_fingerprint);
    println!("needed {}", snaps.needed(slot)?);
    for name in snaps.list()? {
        let s = snaps.status(&name)?;
        println!(
            "{name}: {:?} device {} snapshot {} cow {} + {} allocated {} metadata {} snapuserd {} old {}",
            s.part_state()?,
            s.device_size,
            s.snapshot_size,
            s.cow_partition_size,
            s.cow_file_size,
            s.sectors_allocated,
            s.metadata_sectors,
            s.using_snapuserd,
            s.old_partition_size
        );
        for dev in [name.clone(), format!("{name}-base"), format!("{name}-cow"), format!("{name}-cow-img")] {
            if skyward_block::dm::status(&dev)?.is_some() {
                for line in skyward_block::dm::table_status(&dev)? {
                    println!("  {dev}: {} {}+{} {}", line.kind, line.start, line.sectors, line.text);
                }
            }
        }
    }
    Ok(())
}

fn modules(source: &str) -> Result<()> {
    let graph = skyward_modules::parse_dep(source)?;
    let order = graph.load_order(&[]);
    println!("{} modules in dependency order", order.len());
    for m in &order {
        println!("  {m}");
    }
    Ok(())
}
