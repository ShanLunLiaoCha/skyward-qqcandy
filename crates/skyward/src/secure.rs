//! What the phone's own secure services need before they will run inside a
//! recovery: the libraries their partitions were built against, and a
//! service directory that knows the phone describes them.

use anyhow::{ensure, Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Where a phone keeps the bundles of shared libraries its own partitions
/// were built against.
use crate::bundle_paths::DIRECTORIES as BUNDLE_DIRS;

/// The file inside a bundle that holds its filesystem. It is stored whole,
/// so the bundle can be opened where it lies.
const BUNDLE_IMAGE: &str = "apex_payload.img";

/// Where Android opens its bundles, and the directory of 64-bit libraries
/// inside one.
const BUNDLE_MOUNT: &str = "/apex";
const BUNDLE_LIBS: &str = "lib64";

/// Which build of the vendor interface the phone's own partitions were
/// made for.
const VENDOR_INTERFACE: &str = "ro.vndk.version";

/// The unversioned bundle name, read only when no versioned one exists.
const CURRENT_VNDK: &str = "com.android.vndk.current";

/// Where a recovery looks for the descriptions of the services the running
/// system carries, and the one the recovery writes there of the phone's
/// own.
const RECOVERY_DESCRIPTIONS: &str = "/system/etc/vintf/manifest";
const PHONE_DESCRIPTION: &str = "phone.xml";

/// The name init knows the service directory by, and the program it runs.
const DIRECTORY_SERVICE: &str = "servicemanager";
const DIRECTORY_PROGRAM: &str = "/system/bin/servicemanager";

/// Where init says which process each of its services runs as, one
/// property per service, the service's name following this.
const SERVICE_PIDS: &str = "init.svc_debug_pid.";

/// How long a service init starts again may take to register again.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long init may take to see a service it stopped gone.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// The loader a program built to run before anything is mounted asks for,
/// and where the installed system keeps the one it was built for: in the
/// bundle that carries the rest of its own runtime.
const EARLY_LOADER: &str = "/system/bin/bootstrap/linker64";
const RUNTIME_BUNDLE: &str = "com.android.runtime";
const BUNDLE_LOADER: &str = "bin/linker64";

/// Which programs may register which hardware services, and where the
/// directory for those services looks for that.
const SERVICE_LABELS: &str = "/mnt/system/system/etc/selinux/plat_hwservice_contexts";
const RECOVERY_LABELS: &str = "/system/etc/selinux";

/// The driver the phone's hardware services talk over, as they expect to
/// find it and as a recovery has it.
const HARDWARE_DRIVER: &str = "/dev/hwbinder";
const HARDWARE_DRIVER_NODE: &str = "/dev/binderfs/hwbinder";

/// The directory for those services is itself one of them, and it turns
/// itself off when the running system does not describe it.
const HARDWARE_DIRECTORY: &str = "android.hidl.manager@1.2::IServiceManager/default";

/// What says the directory is off. It is read by the services, and in a
/// recovery there is nothing else to set it.
const DIRECTORY_OFF: &str = "hwservicemanager.disabled";

/// Where a recovery is given the descriptions of the services the running
/// system carries. A recovery has no framework of its own, so this is read
/// as the framework's description of what it offers.
const RECOVERY_MANIFEST: &str = "/system/etc/vintf/manifest.xml";

/// What the directory for the phone's hardware services of the older kind
/// needs before it will run inside a recovery. The program is the installed
/// system's own: it is built to run before any partition is mounted, so it
/// asks for a loader under a name a recovery does not carry; it decides what
/// may register from labels a recovery does not carry either; and it reads
/// the driver under a name that a recovery, which has the driver's own
/// filesystem, does not have.
///
/// `wanted` names the hardware services that will be asked for.
pub fn prepare_hardware_directory(wanted: &[String]) -> Result<()> {
    // A loader and the lowest libraries are built together and agree
    // between them on how a program's own storage is laid out, so the
    // installed system's programs are loaded by the installed system's
    // loader rather than by the older one a recovery carries.
    let loader = Path::new(EARLY_LOADER);
    let from = bundle(RUNTIME_BUNDLE, false)?
        .map(|at| at.join(BUNDLE_LOADER))
        .filter(|p| p.is_file())
        .with_context(|| format!("the installed system carries no {RUNTIME_BUNDLE}, which holds the loader its own programs ask for"))?;
    let dir = loader.parent().expect("the loader is in a directory");
    fs::create_dir_all(dir).with_context(|| format!("make {}", dir.display()))?;
    // Made under the recovery's own umask the folder is root's alone, and
    // the programs that ask for this loader run as the users their init
    // scripts name: as the system's own folder is, it is open to all.
    fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .with_context(|| format!("open {} to every user", dir.display()))?;
    if loader.exists() {
        fs::remove_file(loader).with_context(|| format!("take away {}", loader.display()))?;
    }
    std::os::unix::fs::symlink(&from, loader).with_context(|| format!("point {} at {}", loader.display(), from.display()))?;
    let driver = Path::new(HARDWARE_DRIVER);
    if !driver.exists() {
        std::os::unix::fs::symlink(HARDWARE_DRIVER_NODE, driver)
            .with_context(|| format!("point {HARDWARE_DRIVER} at {HARDWARE_DRIVER_NODE}"))?;
    }
    // The system's own init opens the driver to every program, as it does
    // /dev/binder; a recovery's, which uses none of it, leaves it root's
    // alone, and the directory and the services that register with it run
    // as the users their init scripts name.
    fs::set_permissions(driver, std::os::unix::fs::PermissionsExt::from_mode(0o666))
        .with_context(|| format!("open {HARDWARE_DRIVER} to every program"))?;
    let from = Path::new(SERVICE_LABELS);
    let into = Path::new(RECOVERY_LABELS).join(from.file_name().expect("a named file"));
    fs::create_dir_all(RECOVERY_LABELS).with_context(|| format!("make {RECOVERY_LABELS}"))?;
    // The directory reads both of these as the user its init script names,
    // and what the recovery makes under its own umask is root's alone: they
    // are given the modes the system's own copies have.
    fs::set_permissions(RECOVERY_LABELS, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .with_context(|| format!("open {RECOVERY_LABELS} to every user"))?;
    fs::copy(from, &into).with_context(|| format!("copy {} to {}", from.display(), into.display()))?;
    fs::write(RECOVERY_MANIFEST, describe_hardware(wanted)?).with_context(|| format!("write {RECOVERY_MANIFEST}"))?;
    fs::set_permissions(RECOVERY_MANIFEST, std::os::unix::fs::PermissionsExt::from_mode(0o644))
        .with_context(|| format!("let every user read {RECOVERY_MANIFEST}"))?;
    // The directory turns itself off when it cannot find its own
    // description, and a run of it before this was written may have left
    // that behind.
    skyward_sys::set_prop(DIRECTORY_OFF, "false")?;
    Ok(())
}

/// The description a recovery offers of the hardware services that will be
/// asked for, and of the directory they are asked of. Each is named as the
/// package it is in and the rest of its name, which is how a description
/// holds the two.
fn describe_hardware(wanted: &[String]) -> Result<String> {
    let mut out = String::from("<manifest version=\"1.0\" type=\"framework\">\n");
    for name in std::iter::once(HARDWARE_DIRECTORY).chain(wanted.iter().map(String::as_str)) {
        let (package, rest) = name
            .split_once('@')
            .with_context(|| format!("{name} does not read as a hardware service's name"))?;
        out.push_str("    <hal format=\"hidl\">\n");
        out.push_str(&format!("        <name>{package}</name>\n"));
        out.push_str("        <transport>hwbinder</transport>\n");
        out.push_str(&format!("        <fqname>@{rest}</fqname>\n"));
        out.push_str("    </hal>\n");
    }
    out.push_str("</manifest>\n");
    Ok(out)
}

/// Open the bundle of libraries the phone's own partitions were built
/// against and give the directory they are in. A phone whose partitions
/// need no bundle has none to open.
pub fn libraries() -> Result<Option<PathBuf>> {
    let version = skyward_sys::prop(VENDOR_INTERFACE).filter(|value| !value.is_empty());
    if let Some(version) = version.as_deref() {
        ensure!(version.bytes().all(|b| b.is_ascii_digit()),
            "{VENDOR_INTERFACE} is not a numeric VNDK version");
    }
    // A Recovery ramdisk often has no ro.vndk.version of its own; the phone's
    // own partitions still carry exactly one versioned VNDK bundle.
    // A versioned bundle is always preferred. com.android.vndk.current is
    // only read when no versioned bundle is present at all.
    let name = match version.as_deref() {
        Some(version) => format!("com.android.vndk.v{version}"),
        None => crate::bundle_paths::discover_vndk()
            .unwrap_or_else(|| CURRENT_VNDK.to_owned()),
    };
    Ok(bundle(&name, true)?.map(|at| at.join(BUNDLE_LIBS)))
}

/// Open the bundle of this name where it lies, and give where it is. A
/// bundle the phone does not carry gives nothing; one already open is left
/// as it is.
fn bundle(name: &str, vndk: bool) -> Result<Option<PathBuf>> {
    // Serialize the check/stage/mount operation so callers cannot stack two
    // mounts or allocate two loops for the same already-opening bundle.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().map_err(|_| anyhow::anyhow!("library bundle preparation lock poisoned"))?;
    let at = Path::new(BUNDLE_MOUNT).join(name);
    if skyward_block::mount::is_mount_point(&at)? {
        return Ok(Some(at));
    }
    let selected = if vndk {
        crate::bundle_paths::find_vndk(name)?
    } else {
        crate::bundle_paths::find(name, BUNDLE_DIRS).map(|file| (file, false))
    };
    let Some((file, from_current)) = selected else { return Ok(None) };
    let (offset, length) = image(&file, from_current.then_some(name))?;
    skyward_sys::kmsg(&format!("opening installed library bundle {} from {}", name, file.display()))?;
    // The kernel loop holds its backing file even after every HAL stops.
    // Stage exact payload bytes in tmpfs first so installation can release
    // system_ext (VNDK) and system (runtime) without tearing down their users.
    let backing = crate::apex_backing::stage(&file, offset, length, &crate::apex_backing::volatile_root()?)?;
    skyward_sys::kmsg(&format!("library bundle {name} uses independent volatile backing {} ({length} bytes)", backing.display()))?;
    let device = match skyward_block::loopdev::attach(&backing, 0, length) {
        Ok(device) => device,
        Err(error) => { let _ = fs::remove_file(&backing); return Err(error); }
    };
    let mounted = (|| -> Result<()> {
        fs::create_dir_all(&at).with_context(|| format!("make {}", at.display()))?;
        skyward_block::mount::mount_ro(&device, &at)?;
        Ok(())
    })();
    if let Err(error) = mounted {
        // Only the loop just created from this exact private backing is ours
        // to clear. Never clear another loop or unlink a live backing blindly.
        return Err(match skyward_block::loopdev::detach_owned(&device, &backing) {
            Ok(()) => { let _ = fs::remove_file(&backing); error }
            Err(cleanup) => error.context(format!("owned APEX loop cleanup failed; backing retained: {cleanup:#}")),
        });
    }
    Ok(Some(at))
}

/// Where the filesystem lies inside a bundle.
fn image(file: &Path, expected_manifest_name: Option<&str>) -> Result<(u64, u64)> {
    use std::io::Read;
    let f = fs::File::open(file).with_context(|| format!("open {}", file.display()))?;
    let mut bundle = zip::ZipArchive::new(f).with_context(|| format!("read what is in {}", file.display()))?;
    if let Some(expected) = expected_manifest_name {
        let limit = crate::bundle_paths::MANIFEST_LIMIT as u64;
        let manifest = bundle.by_name("apex_manifest.pb").context("current VNDK has no apex_manifest.pb")?;
        let size = manifest.size();
        ensure!(size <= limit, "current VNDK apex_manifest.pb exceeds {limit} bytes");
        let mut bytes = Vec::with_capacity(size as usize);
        manifest.take(limit + 1).read_to_end(&mut bytes).context("read complete current VNDK apex_manifest.pb")?;
        ensure!(bytes.len() as u64 == size, "current VNDK manifest length does not match its archive entry");
        crate::bundle_paths::verify_manifest_name(&bytes, expected)
            .with_context(|| format!("refusing VNDK fallback {}", file.display()))?;
    }
    let entry = bundle.by_name(BUNDLE_IMAGE).with_context(|| format!("{} holds no {BUNDLE_IMAGE}", file.display()))?;
    if entry.compression() != zip::CompressionMethod::Stored {
        anyhow::bail!("{} keeps its {BUNDLE_IMAGE} packed, which cannot be opened where it lies", file.display());
    }
    let start = entry.data_start().with_context(|| format!("{BUNDLE_IMAGE} in {} says where it is not", file.display()))?;
    Ok((start, entry.size()))
}

/// Tell the phone's service directory of the services in `wanted`, which
/// the phone's own programs register and the recovery itself may serve.
/// The directory turns away a hardware service the running system does
/// not describe, and a recovery starts up describing only the few services
/// of its own. The recovery writes one description of its own for them
/// all: where a phone tells of a service differs from phone to phone, in a
/// description of one program or in the one a whole partition shares, and
/// the directory reads the whole of its description directory at once, so
/// that one file it cannot make sense of leaves it describing nothing.
pub fn publish_descriptions(wanted: &[String], required: &[String]) -> Result<()> {
    let into = Path::new(RECOVERY_DESCRIPTIONS);
    fs::create_dir_all(into).with_context(|| format!("make {}", into.display()))?;
    // Both directories read these as the users their init scripts name,
    // and what the recovery makes under its own umask is root's alone: the
    // folder and the description are given the modes the system's own have.
    fs::set_permissions(into, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .with_context(|| format!("open {} to every user", into.display()))?;
    let to = into.join(PHONE_DESCRIPTION);
    // A service told of twice has the directory take none of what it
    // reads, so what the descriptions the recovery ships with tell of
    // already, as they do of the boot control on some phones, is left out.
    let mut shipped = vec![PathBuf::from(RECOVERY_MANIFEST)];
    for entry in fs::read_dir(into).with_context(|| format!("read {}", into.display()))? {
        shipped.push(entry.with_context(|| format!("read {}", into.display()))?.path());
    }
    let mut told = Vec::new();
    for path in shipped.iter().filter(|p| **p != to && p.extension().is_some_and(|e| e == "xml") && p.is_file()) {
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let services = skyward_programs::description::read(&text).with_context(|| format!("read {}", path.display()))?;
        told.extend(services.iter().map(skyward_programs::description::Described::name));
    }
    let untold: Vec<String> = wanted.iter().filter(|name| !told.contains(name)).cloned().collect();
    let offered = skyward_programs::description::offering(&untold)?;
    let changed = match fs::read_to_string(&to) {
        Ok(previous) => previous != offered,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(error).with_context(|| format!("read previous {}", to.display())),
    };
    fs::write(&to, &offered).with_context(|| format!("write {}", to.display()))?;
    fs::set_permissions(&to, std::os::unix::fs::PermissionsExt::from_mode(0o644)).with_context(|| format!("let every user read {}", to.display()))?;
    let rewritten = say_framework(into)?;
    // The directory reads the descriptions once and keeps to them, so one
    // that read them before these were written has to start again to see
    // these. One an earlier run of the recovery service had start again
    // knows them already, and is left with what has registered with it
    // since.
    let binder = skyward_binder::driver::Binder::open()?;
    // The first it does not know described settles that it starts again.
    let mut unknown = false;
    // isDeclared is access-controlled independently of VINTF. A vendor
    // manifest can contain unrelated services with no Recovery find label.
    // Preserve them in the file, but only probe services we actually require;
    // any refusal for a required service still fails closed.
    for name in crate::declaration_policy::probes(wanted, required)? {
        if !skyward_binder::service::declared(&binder, name).with_context(|| format!("ask the service directory whether it knows {name} described"))? {
            unknown = true;
            break;
        }
    }
    if crate::declaration_policy::reload(changed, unknown, rewritten) {
        // It comes back knowing nothing of what had registered with it,
        // and nothing registers again by itself, so init starts each of
        // those services again, as the installed system's init does
        // whenever its directory restarts.
        let registered = registered()?;
        let was = crate::services::running(DIRECTORY_PROGRAM);
        skyward_sys::set_prop("ctl.restart", DIRECTORY_SERVICE).context("have the service directory start again")?;
        answering_again(was)?;
        register_again(&registered)?;
    }
    Ok(())
}

/// What has registered with the service directory, each with the init
/// service whose process serves it; the directory's own entry is left out.
fn registered() -> Result<Vec<(String, String)>> {
    let Some(directory) = crate::services::running(DIRECTORY_PROGRAM) else { return Ok(Vec::new()) };
    let binder = skyward_binder::driver::Binder::open()?;
    let started = skyward_sys::props(SERVICE_PIDS);
    let mut out = Vec::new();
    for name in skyward_binder::service::names(&binder)? {
        let Some(service) = skyward_binder::service::find(&binder, &name)? else { continue };
        let pid = skyward_binder::service::pid(&service).with_context(|| format!("ask which process serves {name}"))?;
        if pid == directory {
            continue;
        }
        let (prop, _) = started
            .iter()
            .find(|(_, value)| value.parse() == Ok(pid))
            .with_context(|| format!("{name} is served by process {pid}, which init does not run, so nothing would register it again"))?;
        out.push((name, prop[SERVICE_PIDS.len()..].to_string()));
    }
    Ok(out)
}

/// Have init start again the services behind what had registered, and wait
/// until each name is registered once more. A restart through init waits
/// out the pause it keeps between two starts of a service, seconds after
/// the service last started; stopping it and starting it does not.
fn register_again(registered: &[(String, String)]) -> Result<()> {
    let services: BTreeSet<&str> = registered.iter().map(|(_, service)| service.as_str()).collect();
    for service in &services {
        skyward_sys::set_prop("ctl.stop", service).with_context(|| format!("have init stop {service}"))?;
    }
    for service in &services {
        skyward_sys::wait_prop(&format!("init.svc.{service}"), "stopped", STOP_TIMEOUT)?;
        skyward_sys::set_prop("ctl.start", service).with_context(|| format!("have init start {service} again"))?;
    }
    let binder = skyward_binder::driver::Binder::open()?;
    let until = Instant::now() + REGISTER_TIMEOUT;
    for (name, service) in registered {
        while skyward_binder::service::find(&binder, name)?.is_none() {
            ensure!(Instant::now() < until, "{name} has not registered again since init started {service} again");
            std::thread::sleep(Duration::from_millis(50));
        }
        skyward_sys::kmsg(&format!("{name} registered again from {service}"))?;
    }
    Ok(())
}

/// A description of what the running system offers, rather than of what
/// the phone's own partitions carry. A recovery publishes a description
/// into the place both readers take as the framework's, and the newer of
/// the two readers drops the whole set over one description that says it
/// is the phone's.
fn as_framework(text: &str) -> String {
    text.replace("type=\"device\"", "type=\"framework\"").replace("type='device'", "type='framework'")
}

/// Say the same of the descriptions already there, which a recovery ships
/// with, and give how many had to be rewritten.
fn say_framework(dir: &Path) -> Result<usize> {
    let mut rewritten = 0;
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry.with_context(|| format!("read {}", dir.display()))?.path();
        if path.extension().is_none_or(|e| e != "xml") {
            continue;
        }
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let said = as_framework(&text);
        if said != text {
            fs::write(&path, said).with_context(|| format!("rewrite {}", path.display()))?;
            rewritten += 1;
        }
    }
    Ok(rewritten)
}

/// Wait until the service directory is a new process and takes calls
/// again. init is only asked to restart it, so for a moment the one that
/// has not read the new descriptions is still the one answering.
fn answering_again(was: Option<u32>) -> Result<()> {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let now = crate::services::running(DIRECTORY_PROGRAM);
        // Looking the directory up in itself answers nothing, and that it
        // answers at all is the whole question.
        if now.is_some() && now != was && crate::services::reachable() {
            return Ok(());
        }
        if std::time::Instant::now() >= until {
            anyhow::bail!("the service directory did not come back");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
