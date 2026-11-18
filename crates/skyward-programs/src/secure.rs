//! The programs a recovery starts to use the keys the phone keeps in its
//! secure world, found in what the phone's own partitions say: which
//! program serves each service the recovery asks, and how the phone's init
//! starts it.

use crate::description::{Described, Kind};
use crate::phone::{Happens, Phone};
use crate::script::{Program, Socket};
use anyhow::{bail, ensure, Context, Result};
use skyward_config::Service;
use std::{fs, io::{ErrorKind, Read, Seek, SeekFrom}, path::Path};

/// The key service, and the packages whose services it serves besides: it
/// is one program behind them all.
const KEYS: &str = "android.hardware.security.keymint.IKeyMintDevice/default";
const KEY_PACKAGES: [&str; 3] = ["android.hardware.security.keymint", "android.hardware.security.secureclock", "android.hardware.security.sharedsecret"];

/// The credential service and the boot control, each by its package and
/// its interface; a phone has either as a service of the newer kind or of
/// the older.
const CREDENTIALS: (&str, &str) = ("android.hardware.gatekeeper", "IGatekeeper");
const BOOT: (&str, &str) = ("android.hardware.boot", "IBootControl");

/// The weaver, on phones that keep a part of each user's secret in a
/// secure element.
const WEAVER: &str = "android.hardware.weaver.IWeaver/default";

/// The service of one secure element, by its package and its interface,
/// and what the ones built into the phone are named after, as opposed to
/// the SIM cards'.
const ELEMENT: (&str, &str) = ("android.hardware.secure_element", "ISecureElement");
const EMBEDDED: &str = "eSE";

/// Android's secure element service, which in the system an app serves and
/// in a recovery the recovery does.
const ELEMENT_SERVICE: &str = skyward_omapi::SERVICE;

/// Which of a service the recovery asks: the one every phone has.
const INSTANCE: &str = "default";

/// What a weaver reaches its secure element through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Through {
    /// Android's secure element service.
    ElementService,
    /// A service of the secure element's maker's own, by its interface.
    Own(&'static str),
}

/// The makes of weaver, each by what the name of its program ends in, the
/// longer endings first: Thales' and NXP's go through Android's secure
/// element service, and Goodix's, whose program is named after no maker,
/// through Goodix's own.
const WEAVERS: [(&str, Through); 3] = [
    (".thales", Through::ElementService),
    (".nxp-qti", Through::ElementService),
    ("weaver-service", Through::Own("vendor.goodix.hardware.secure_element_aidl.IGdxEse")),
];

/// Qualcomm's programs between Android and the secure world, by the names
/// of their files: the one that registers the listeners the secure world
/// calls back through, with the property it sets once they are registered,
/// and the ones the secure world's apps are opened through.
const LISTENERS: &str = "qseecomd";
const LISTENERS_READY: &str = "vendor.sys.listeners.registered";
const OPENERS: [&str; 2] = ["ssgtzd", "hlosminkdaemon"];

/// The directory for hardware services of the older kind, by the name init
/// knows it under, and the property it sets once it takes calls.
const HARDWARE_DIRECTORY: &str = "hwservicemanager";
const HARDWARE_DIRECTORY_READY: &str = "hwservicemanager.ready";

const LEGACY_DIRECTORY_RC: &str = "etc/init/hwservicemanager.rc";
const LEGACY_DIRECTORY_BIN: &str = "bin/hwservicemanager";

fn hardware_directory(phone: &Phone, system: Option<&Path>) -> Result<Option<Started>> {
    let directories = || phone.programs.iter().filter(|p| p.name == HARDWARE_DIRECTORY && phone.carries(p));
    if let Some(program) = directories().find(|p| p.path == "/system_ext/bin/hwservicemanager").or_else(|| directories().next()) {
        return Ok(Some(started(phone, program, Ready::Property(HARDWARE_DIRECTORY_READY), Vec::new())));
    }
    let Some(system) = system else { return Ok(None) };
    let rc = system.join(LEGACY_DIRECTORY_RC);
    let rc_metadata = match fs::symlink_metadata(&rc) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("stat {}", rc.display())),
    };
    ensure!(rc_metadata.is_file() && rc_metadata.len() <= 8192, "unexpected legacy HIDL directory RC at {}", rc.display());
    let text = fs::read_to_string(&rc).with_context(|| format!("read {}", rc.display()))?;
    let script = crate::script::read(&text).with_context(|| format!("parse {}", rc.display()))?;
    let [program] = script.programs.as_slice() else { bail!("legacy HIDL RC must declare exactly one service") };
    ensure!(script.imports.is_empty() && script.actions.is_empty()
        && program.name == HARDWARE_DIRECTORY && program.path == "/system/bin/hwservicemanager"
        && program.args.is_empty() && program.user.as_deref() == Some("system")
        && program.groups == ["system", "readproc"] && program.capabilities.is_none()
        && program.sockets.is_empty() && program.environment.is_empty() && program.interfaces.is_empty()
        && !program.oneshot && !program.overrides,
        "unexpected service in legacy HIDL directory RC at {}", rc.display());
    let binary = system.join(LEGACY_DIRECTORY_BIN);
    let metadata = fs::symlink_metadata(&binary).with_context(|| format!("stat {}", binary.display()))?;
    ensure!(metadata.is_file(), "legacy HIDL directory executable must be a regular file: {}", binary.display());
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        ensure!(metadata.permissions().mode() & 0o111 != 0, "legacy HIDL directory is not executable: {}", binary.display());
    }
    legacy_interpreter(&mut fs::File::open(&binary)?).with_context(|| format!("check interpreter of {}", binary.display()))?;
    let mut manager = started(phone, program, Ready::Property(HARDWARE_DIRECTORY_READY), Vec::new());
    manager.service.path = binary.to_str().context("legacy HIDL executable path is not UTF-8")?.to_owned();
    Ok(Some(manager))
}

/// Match only the native loaders already provided by the Recovery ramdisk or
/// by prepare_hardware_directory (which mounts runtime and exposes bootstrap).
pub fn legacy_interpreter(file: &mut (impl Read + Seek)) -> Result<&'static str> {
    let mut header = [0; 64];
    file.read_exact(&mut header)?;
    ensure!(&header[..7] == b"\x7fELF\x02\x01\x01" && header[18..20] == 183u16.to_le_bytes(), "expected AArch64 ELF64");
    let phoff = u64::from_le_bytes(header[32..40].try_into()?);
    let entsize = u16::from_le_bytes(header[54..56].try_into()?);
    let count = u16::from_le_bytes(header[56..58].try_into()?);
    ensure!(entsize == 56 && (1..=128).contains(&count), "unexpected ELF program headers");
    let mut selected = None;
    for index in 0..count {
        let at = phoff.checked_add(u64::from(index) * 56).context("program header offset overflow")?;
        file.seek(SeekFrom::Start(at))?;
        let mut ph = [0; 56];
        file.read_exact(&mut ph)?;
        if u32::from_le_bytes(ph[..4].try_into()?) != 3 { continue; }
        ensure!(selected.is_none(), "multiple ELF interpreters");
        let offset = u64::from_le_bytes(ph[8..16].try_into()?);
        let length = u64::from_le_bytes(ph[32..40].try_into()?);
        ensure!((2..=128).contains(&length), "invalid ELF interpreter length");
        file.seek(SeekFrom::Start(offset))?;
        let mut interp = [0; 128];
        file.read_exact(&mut interp[..length as usize])?;
        selected = Some(match &interp[..length as usize] {
            b"/system/bin/linker64\0" => "/system/bin/linker64",
            b"/system/bin/bootstrap/linker64\0" => "/system/bin/bootstrap/linker64",
            b"/apex/com.android.runtime/bin/linker64\0" => "/apex/com.android.runtime/bin/linker64",
            _ => bail!("unsupported legacy HIDL ELF interpreter"),
        });
    }
    selected.context("legacy HIDL executable has no ELF interpreter")
}

/// The folders a program's libraries are looked for in, by the partition
/// the program is on: the recovery's own come before the vendor
/// partition's, which carries its own copies of the lowest of them, and a
/// program loading those would not be understood by the recovery's service
/// directory; with the vendor partition's comes its folder of hardware
/// libraries, where Android has a program on either partition look too.
/// The directory for hardware services is the installed system's own
/// program and runs on its libraries alone.
const VENDOR_LIBRARIES: [&str; 3] = ["/system/lib64", "/vendor/lib64", "/vendor/lib64/hw"];
const ODM_LIBRARIES: [&str; 4] = ["/system/lib64", "/vendor/lib64", "/vendor/lib64/hw", "/odm/lib64"];
const SYSTEM_LIBRARIES: [&str; 3] = ["/mnt/system/system/lib64/bootstrap", "/mnt/system/system/lib64", "/mnt/system_ext/lib64"];

/// The installed system's folders, where a program on the vendor or the
/// odm partition finds the few libraries it asks for that none of its own
/// folders has: the ones Android lets such a program share with the
/// system, which a recovery may not carry.
const SHARED_LIBRARIES: [&str; 2] = ["/mnt/system/system/lib64", "/mnt/system/system/lib64/bootstrap"];

/// The folders the program a script names `path` finds its libraries in,
/// in the order they are looked in: those of its partition, then `bundle`,
/// where a recovery has opened the libraries the phone's partitions were
/// built against, then, for a program on the vendor or the odm partition,
/// the installed system's. The bundle comes before those: the installed
/// system carries libraries under the names of the bundle's, built for its
/// own programs.
pub(crate) fn libraries_of(path: &str, bundle: Option<&Path>) -> Vec<String> {
    let (own, shared): (&[&str], &[&str]) = match path.split('/').nth(1) {
        Some("vendor") => (&VENDOR_LIBRARIES, &SHARED_LIBRARIES),
        Some("odm") => (&ODM_LIBRARIES, &SHARED_LIBRARIES),
        _ => (&SYSTEM_LIBRARIES, &[]),
    };
    let bundle = bundle.map(|dir| dir.to_string_lossy().into_owned());
    own.iter().map(|l| l.to_string()).chain(bundle).chain(shared.iter().map(|l| l.to_string())).collect()
}

/// A program to start, with what init gives it that a recovery has to
/// give it too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    pub service: Service,
    pub sockets: Vec<Socket>,
    pub environment: Vec<(String, String)>,
    /// It holds on to a service the recovery serves itself, which goes
    /// when the recovery's own program ends: one an earlier run of the
    /// recovery left running is ended and started anew.
    pub anew: bool,
}

impl From<Service> for Started {
    /// A program init gives nothing besides what `service` says.
    fn from(service: Service) -> Started {
        Started { service, sockets: Vec::new(), environment: Vec::new(), anew: false }
    }
}

/// One thing to do, in the order they are done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Start a program of the phone's and wait until it is ready.
    Start(Box<Started>),
    /// Serve Android's secure element service, with a reader for each
    /// secure element whose own service has registered by then.
    ServeElements,
}

/// What a program is ready with.
enum Ready {
    Nothing,
    Property(&'static str),
    Service(String),
    HardwareService(String),
}

/// What to do, in order: start the listeners and the openers of the secure
/// world, the key service, the directory for hardware services where the
/// phone has services of the older kind, and the credential service; on a
/// phone with a weaver, start what the weaver reaches its secure element
/// through, serving Android's secure element service where that is what it
/// goes through, and the weaver; and start the boot control.
pub fn steps(phone: &Phone) -> Result<Vec<Step>> {
    steps_with_system(phone, None)
}

/// Optionally inspect one legacy manager declaration under the installed
/// `system` directory. Never add this directory to Phone's init scan.
pub fn steps_with_system(phone: &Phone, system: Option<&Path>) -> Result<Vec<Step>> {
    let mut out = Vec::new();
    let start = |out: &mut Vec<Step>, started: Started| out.push(Step::Start(Box::new(started)));
    if let Some(listeners) = named(phone, LISTENERS)? {
        start(&mut out, started(phone, listeners, Ready::Property(LISTENERS_READY), Vec::new()));
    }
    for opener in OPENERS {
        if let Some(program) = named(phone, opener)? {
            start(&mut out, started(phone, program, Ready::Nothing, Vec::new()));
        }
    }

    ensure!(described(phone, Kind::Aidl, KEYS).is_some(), "the phone describes no {KEYS}");
    let keys = behind(phone, "the key service", KEYS, |file| file.contains("keymint") && !file.contains("strongbox"))?;
    let with_keys = |d: &Described| d.instance == INSTANCE && KEY_PACKAGES.contains(&d.package.as_str());
    start(&mut out, started(phone, keys, Ready::Service(KEYS.into()), besides(phone, keys, KEYS, with_keys)));

    let (credentials, credentials_kind) = offered(phone, CREDENTIALS).context("the phone describes no credential service")?;
    let (boot, boot_kind) = offered(phone, BOOT).context("the phone describes no boot control")?;
    if credentials_kind == Kind::Hidl || boot_kind == Kind::Hidl {
        let directory = hardware_directory(phone, system)?
            .context("the phone has hardware services of the older kind, and no directory for them among the programs its scripts name")?;
        start(&mut out, directory);
    }
    let ready = |name: String, kind: Kind| match kind {
        Kind::Aidl => Ready::Service(name),
        Kind::Hidl => Ready::HardwareService(name),
    };
    let alone = |_: &Described| false;
    let program = behind(phone, "the credential service", &credentials, |file| file.contains("gatekeeper"))?;
    let registers = besides(phone, program, &credentials, alone);
    start(&mut out, started(phone, program, ready(credentials, credentials_kind), registers));

    if described(phone, Kind::Aidl, WEAVER).is_some() {
        out.extend(weaver(phone)?);
    }

    let program = behind(phone, "the boot control", &boot, |file| file.starts_with(BOOT.0))?;
    let registers = besides(phone, program, &boot, alone);
    start(&mut out, started(phone, program, ready(boot, boot_kind), registers));
    Ok(out)
}

/// The description that tells of the service `name`, where it is the one
/// of `program` alone: a description named as the program's script is
/// tells of what that program registers and of nothing else. One named
/// otherwise may tell of what several programs register, as the one a
/// whole partition shares does, or one that tells of an NFC chip's service
/// and of the secure element's in the chip.
fn own_description<'a>(phone: &'a Phone, program: &Program, name: &str) -> Option<&'a str> {
    let told = described(phone, Kind::Aidl, name)?;
    (!program.script.is_empty() && stem(&program.script) == stem(&told.file)).then_some(told.file.as_str())
}

/// What `program`, ready with the service `name`, registers besides it,
/// which the service directory takes only when it is told of them too:
/// every other service of the newer kind its own description tells of, and
/// whichever of all the phone describes `also` takes.
fn besides(phone: &Phone, program: &Program, name: &str, also: impl Fn(&Described) -> bool) -> Vec<String> {
    let own = own_description(phone, program, name);
    let mut out = Vec::new();
    for service in phone.services.iter().filter(|s| s.described.kind == Kind::Aidl) {
        let other = service.described.name();
        if (own == Some(service.file.as_str()) || also(&service.described)) && other != name && !out.contains(&other) {
            out.push(other);
        }
    }
    out
}

/// The programs among `steps`, in order.
pub fn programs(steps: &[Step]) -> Vec<&Started> {
    steps
        .iter()
        .filter_map(|step| match step {
            Step::Start(started) => Some(started.as_ref()),
            Step::ServeElements => None,
        })
        .collect()
}

/// What starting the weaver takes: what it reaches its secure element
/// through, and then the weaver itself.
fn weaver(phone: &Phone) -> Result<Vec<Step>> {
    let mut out = Vec::new();
    let program = behind(phone, "the weaver", WEAVER, |file| file.contains("weaver-service"))?;
    let file = file_name(program);
    let (_, through) = WEAVERS.iter().find(|(ending, _)| file.ends_with(ending)).with_context(|| format!("{} is a weaver of a make the recovery does not know", program.path))?;
    match through {
        Through::Own(interface) => {
            let own = phone
                .services
                .iter()
                .find(|s| s.described.kind == Kind::Aidl && format!("{}.{}", s.described.package, s.described.interface) == *interface)
                .with_context(|| format!("{} goes through {interface}, which the phone does not describe", program.path))?;
            out.push(Step::Start(Box::new(element(phone, &own.described.name())?)));
        }
        Through::ElementService => {
            ensure!(described(phone, Kind::Aidl, ELEMENT_SERVICE).is_some(), "{} goes through {ELEMENT_SERVICE}, which the phone does not describe", program.path);
            let embedded: Vec<String> = phone
                .services
                .iter()
                .map(|s| &s.described)
                .filter(|d| d.kind == Kind::Aidl && (d.package.as_str(), d.interface.as_str()) == ELEMENT && d.instance.starts_with(EMBEDDED))
                .map(Described::name)
                .collect();
            ensure!(!embedded.is_empty(), "{} goes through a secure element built into the phone, and the phone describes the service of none", program.path);
            for name in embedded {
                let started = element(phone, &name)?;
                if !out.iter().any(|step| matches!(step, Step::Start(s) if s.service.path == started.service.path)) {
                    out.push(Step::Start(Box::new(started)));
                }
            }
            out.push(Step::ServeElements);
        }
    }
    let mut weaver = started(phone, program, Ready::Service(WEAVER.into()), besides(phone, program, WEAVER, |_| false));
    weaver.anew = *through == Through::ElementService;
    out.push(Step::Start(Box::new(weaver)));
    Ok(out)
}

/// The program behind the service of a secure element registered as
/// `name`: it is ready with the secure element's own service, which is
/// `name` itself or the one the program's own description tells of beside
/// it.
fn element(phone: &Phone, name: &str) -> Result<Started> {
    let program = behind(phone, "a secure element's service", name, |file| file.contains("secure_element"))?;
    let told = described(phone, Kind::Aidl, name).expect("the service was found among those described");
    let of_an_element = |d: &Described| (d.package.as_str(), d.interface.as_str()) == ELEMENT;
    let own = match of_an_element(&told.described) {
        true => name.to_string(),
        false => {
            let beside = own_description(phone, program, name).and_then(|file| phone.services.iter().find(|s| s.file == file && s.described.kind == Kind::Aidl && of_an_element(&s.described)));
            beside.with_context(|| format!("{} registers {name}, and its description tells of the service of no secure element beside it", program.path))?.described.name()
        }
    };
    let registers = besides(phone, program, &own, |_| false);
    Ok(started(phone, program, Ready::Service(own), registers))
}

/// The description of the service `name` of `kind`, where the phone
/// describes it.
fn described<'a>(phone: &'a Phone, kind: Kind, name: &str) -> Option<&'a crate::phone::Service> {
    phone.services.iter().find(|s| s.described.kind == kind && s.described.name() == name)
}

/// The name the phone has the default service of `interface` under, and
/// its kind: the newer kind where it has it, else the older at the highest
/// version it describes.
fn offered(phone: &Phone, (package, interface): (&str, &str)) -> Option<(String, Kind)> {
    let of = |kind: Kind| phone.services.iter().map(|s| &s.described).filter(move |d| d.kind == kind && d.package == package && d.interface == interface && d.instance == INSTANCE);
    if let Some(newer) = of(Kind::Aidl).next() {
        return Some((newer.name(), Kind::Aidl));
    }
    let version = |d: &&Described| -> Vec<u32> { d.version.iter().flat_map(|v| v.split('.')).filter_map(|n| n.parse().ok()).collect() };
    of(Kind::Hidl).max_by_key(version).map(|older| (older.name(), Kind::Hidl))
}

/// The name of a program's file.
fn file_name(program: &Program) -> &str {
    program.path.rsplit('/').next().unwrap_or(&program.path)
}

/// The name of a file without what follows its last dot, which a script
/// and a description that belong to one program share.
fn stem(path: &str) -> &str {
    let file = path.rsplit('/').next().unwrap_or(path);
    file.rsplit_once('.').map_or(file, |(stem, _)| stem)
}

/// The one program the phone runs whose file is named `file`; none where
/// the phone has none.
fn named<'a>(phone: &'a Phone, file: &str) -> Result<Option<&'a Program>> {
    one(phone, file, phone.programs.iter().filter(|p| file_name(p) == file).collect())
}

/// Whether init starts `program` only when a service its section says it
/// registers is asked for. Nothing can count on such a program for any
/// other service, which would be there only while something else had
/// asked for one of those.
fn on_demand(program: &Program) -> bool {
    program.disabled && !program.interfaces.is_empty()
}

/// The one program the phone runs that serves `name`: one whose script
/// says it registers it; else one whose script is named as the description
/// that tells of the service is; else one whose file `matches`. A program
/// started only on demand is one of the first kind or none.
fn behind<'a>(phone: &'a Phone, what: &str, name: &str, matches: impl Fn(&str) -> bool) -> Result<&'a Program> {
    let saying: Vec<&Program> = phone.programs.iter().filter(|p| p.interfaces.iter().any(|i| i == name)).collect();
    let may: Vec<&Program> = phone.programs.iter().filter(|p| !on_demand(p)).collect();
    let described_with: Vec<&Program> = match phone.services.iter().find(|s| s.described.name() == name) {
        Some(service) => may.iter().copied().filter(|p| !p.script.is_empty() && stem(&p.script) == stem(&service.file)).collect(),
        None => Vec::new(),
    };
    let matching: Vec<&Program> = may.iter().copied().filter(|p| matches(file_name(p))).collect();
    for candidates in [saying, described_with, matching] {
        if let Some(program) = one(phone, what, candidates)? {
            return Ok(program);
        }
    }
    bail!("no script of the phone's runs {what}, which would register {name}")
}

/// The one of `candidates` the phone's init runs: those it runs for
/// certain before those it may run. More than one is refused, as nothing
/// here tells which the phone means.
fn one<'a>(phone: &Phone, what: &str, candidates: Vec<&'a Program>) -> Result<Option<&'a Program>> {
    for wanted in [Happens::Yes, Happens::Maybe] {
        let running: Vec<&Program> = candidates.iter().copied().filter(|p| phone.runs(p) == wanted).collect();
        match running[..] {
            [] => continue,
            [program] => return Ok(Some(program)),
            _ => bail!("the phone runs more than one program for {what}: {}", running.iter().map(|p| p.path.as_str()).collect::<Vec<_>>().join(", ")),
        }
    }
    Ok(None)
}

/// `program` as it is started: from where its partition is mounted, as the
/// user, in the groups and with the capabilities its script gives it, with
/// the libraries of its partition. It is kept running whatever its script
/// says of starting it once: what a recovery starts it for is the service
/// it registers.
fn started(phone: &Phone, program: &Program, ready: Ready, registers: Vec<String>) -> Started {
    let (ready_property, ready_service, ready_hardware_service) = match ready {
        Ready::Nothing => (None, None, None),
        Ready::Property(name) => (Some(name.to_string()), None, None),
        Ready::Service(name) => (None, Some(name), None),
        Ready::HardwareService(name) => (None, None, Some(name)),
    };
    let service = Service {
        path: phone.started_from(&program.path),
        args: program.args.clone(),
        libraries: libraries_of(&program.path, phone.bundle.as_deref()),
        oneshot: false,
        ready_property,
        ready_service,
        registers,
        ready_hardware_service,
        when: None,
        user: program.user.clone(),
        groups: program.groups.clone(),
        capabilities: program.capabilities.clone().unwrap_or_default(),
    };
    Started { service, sockets: program.sockets.clone(), environment: program.environment.clone(), anew: false }
}

#[cfg(all(test, unix))]
mod legacy_tests {
    use super::*;
    use crate::phone::Partition;
    use std::os::unix::fs::PermissionsExt;

    const RC: &str = "service hwservicemanager /system/bin/hwservicemanager\n    user system\n    disabled\n    group system readproc\n    critical\n    onrestart setprop hwservicemanager.ready false\n    onrestart class_restart main\n    onrestart class_restart hal\n    onrestart class_restart early_hal\n    task_profiles ServiceCapacityLow HighPerformance\n    class animation\n    shutdown critical\n";

    fn fixture(root: &Path, interp: &[u8]) {
        let rc = root.join(LEGACY_DIRECTORY_RC);
        fs::create_dir_all(rc.parent().unwrap()).unwrap();
        fs::write(rc, RC).unwrap();
        fs::write(root.join("etc/init/irrelevant.rc"), "this file must never be read\n").unwrap();
        let bin = root.join(LEGACY_DIRECTORY_BIN);
        fs::create_dir_all(bin.parent().unwrap()).unwrap();
        let mut elf = vec![0; 120];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        elf[64..68].copy_from_slice(&3u32.to_le_bytes());
        elf[72..80].copy_from_slice(&120u64.to_le_bytes());
        elf[96..104].copy_from_slice(&(interp.len() as u64).to_le_bytes());
        elf.extend_from_slice(interp);
        fs::write(&bin, elf).unwrap();
        fs::set_permissions(bin, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn reads_only_the_legacy_rc_and_starts_installed_binary() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), b"/system/bin/bootstrap/linker64\0");
        let phone = Phone::read(Vec::new(), Default::default(), None).unwrap();
        assert!(hardware_directory(&phone, None).unwrap().is_none());
        let manager = hardware_directory(&phone, Some(dir.path())).unwrap().unwrap();
        assert_eq!(Path::new(&manager.service.path), dir.path().join(LEGACY_DIRECTORY_BIN));
        assert_eq!(manager.service.ready_property.as_deref(), Some(HARDWARE_DIRECTORY_READY));
        assert_eq!(manager.service.user.as_deref(), Some("system"));
        assert_eq!(manager.service.libraries, SYSTEM_LIBRARIES);
        assert!(phone.programs.is_empty());
    }

    #[test]
    fn prefers_existing_system_ext_directory_without_reading_legacy_rc() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), b"/unsupported/linker64\0");
        fs::write(dir.path().join("etc/init/irrelevant.rc"), "# Empty system_ext fixture\n").unwrap();
        fs::write(dir.path().join(LEGACY_DIRECTORY_RC), RC.replace("/system/bin/", "/system_ext/bin/")).unwrap();
        let phone = Phone::read(vec![Partition::mounted("system_ext", dir.path())], Default::default(), None).unwrap();
        let manager = hardware_directory(&phone, Some(dir.path())).unwrap().unwrap();
        assert_eq!(Path::new(&manager.service.path), dir.path().join(LEGACY_DIRECTORY_BIN));
    }

    #[test]
    fn rejects_unsupported_interpreter_or_additional_service() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), b"/unsupported/linker64\0");
        let phone = Phone::read(Vec::new(), Default::default(), None).unwrap();
        assert!(hardware_directory(&phone, Some(dir.path())).is_err());
        fixture(dir.path(), b"/system/bin/linker64\0");
        fs::write(dir.path().join(LEGACY_DIRECTORY_RC), format!("{RC}service unrelated /system/bin/other\n")).unwrap();
        assert!(hardware_directory(&phone, Some(dir.path())).is_err());
    }
}
