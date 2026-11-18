//! Read-only preflight of a single Android WLAN module tree. The kernel still
//! checks signatures, symbol versions, and ABI at finit_module time.
use anyhow::{anyhow, bail, ensure, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
struct Family {
    kernel: [u32; 3],
    android: u32,
    generation: u32,
}

impl Family {
    fn parse(release: &str) -> Result<Self> {
        let (numbers, suffix) = release.split_once("-android").context("missing Android KMI release")?;
        let (android, tail) = suffix.split_once('-').context("missing Android KMI generation")?;
        let generation = tail.split('-').next().unwrap_or_default();
        let number = |s: &str| -> Result<u32> {
            ensure!(!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()), "invalid kernel/KMI number");
            Ok(s.parse()?)
        };
        let parts: Vec<_> = numbers.split('.').map(number).collect::<Result<_>>()?;
        let kernel = parts.try_into().map_err(|_| anyhow!("expected major.minor.patch kernel release"))?;
        Ok(Self { kernel, android: number(android)?, generation: number(generation)? })
    }
}

struct Selected {
    path: PathBuf,
    file: File,
}

/// Prevalidated modules grouped by the caller's hardware initialization stages.
/// Descriptors keep loading tied to the checked files. Never try another source
/// after any stage has begun loading.
pub struct WlanModulePlan {
    source: PathBuf,
    stages: Vec<Vec<Selected>>,
}

impl WlanModulePlan {
    pub fn source(&self) -> &Path { &self.source }

    pub fn load_stage(&self, index: usize) -> Result<Vec<PathBuf>> {
        let mut loaded = Vec::new();
        for module in self.stages.get(index).context("invalid WLAN module stage")? {
            match super::finit_module(&module.file, "") {
                Ok(()) => loaded.push(module.path.clone()),
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {},
                Err(e) => return Err(e).with_context(|| format!("finit_module {}", module.path.display())),
            }
        }
        Ok(loaded)
    }
}

/// Choose the first source whose complete staged dependency closure matches
/// the running kernel's patch level and Android KMI release/generation. Build
/// suffixes differ between some stock kernels and vendor modules and are not
/// part of the comparison. No modules are loaded until this returns a plan.
pub fn plan_wlan(dirs: &[PathBuf], running_release: &str, stages: &[&[String]]) -> Result<WlanModulePlan> {
    let family = Family::parse(running_release).with_context(|| format!("unsupported WLAN kernel release {running_release:?}"))?;
    let mut required = BTreeMap::new();
    for (stage, names) in stages.iter().enumerate() {
        for name in *names {
            ensure!(!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "invalid WLAN module name {name:?}");
            ensure!(required.insert(format!("{name}.ko"), stage).is_none(), "duplicate WLAN module root {name}");
        }
    }
    ensure!(!required.is_empty(), "no WLAN module roots to select");
    let mut refused = Vec::new();
    for dir in dirs {
        match plan_source(dir, &family, stages, &required) {
            Ok(plan) => return Ok(plan),
            Err(e) => refused.push(format!("{}: {e:#}", dir.display())),
        }
    }
    bail!("no coherent WLAN module tree for {running_release}: {}", refused.join("; "))
}

struct Dependency {
    relative: PathBuf,
    needs: Vec<PathBuf>,
}

fn relative(path: &Path, dir: &Path, canonical: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.strip_prefix(dir).or_else(|_| path.strip_prefix(canonical))
            .with_context(|| format!("dependency path {} leaves module source", path.display()))?
    } else { path };
    ensure!(path.extension().is_some_and(|s| s == "ko") && path.components().all(|c| matches!(c, Component::Normal(_))),
        "unsafe or unsupported module path {}", path.display());
    Ok(path.to_owned())
}

fn plan_source(dir: &Path, family: &Family, stages: &[&[String]], required: &BTreeMap<String, usize>) -> Result<WlanModulePlan> {
    let canonical = dir.canonicalize()?;
    let text = fs::read_to_string(canonical.join("modules.dep")).context("read modules.dep")?;
    // Preserve depmod paths; never recursively search for a similarly named file.
    let mut graph = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (lhs, rhs) = line.split_once(':').context("malformed modules.dep row")?;
        let entry = relative(Path::new(lhs.trim()), dir, &canonical)?;
        let needs = rhs.split_whitespace().map(|p| relative(Path::new(p), dir, &canonical)).collect::<Result<_>>()?;
        let name = basename(&entry)?.to_owned();
        ensure!(graph.insert(name.clone(), Dependency { relative: entry, needs }).is_none(), "ambiguous modules.dep entry for {name}");
    }
    let mut planner = Planner { canonical, family, required, graph, active: BTreeSet::new(), ready: BTreeSet::new() };
    let mut planned = Vec::new();
    for (stage, names) in stages.iter().enumerate() {
        let mut order = Vec::new();
        for name in *names {
            planner.visit(&format!("{name}.ko"), stage, &mut order)?;
        }
        planned.push(order);
    }
    Ok(WlanModulePlan { source: dir.to_owned(), stages: planned })
}

fn basename(path: &Path) -> Result<&str> {
    path.file_name().and_then(|s| s.to_str()).context("missing module filename")
}

struct Planner<'a> {
    canonical: PathBuf,
    family: &'a Family,
    required: &'a BTreeMap<String, usize>,
    graph: BTreeMap<String, Dependency>,
    active: BTreeSet<String>,
    ready: BTreeSet<String>,
}

impl Planner<'_> {
    fn visit(&mut self, name: &str, stage: usize, order: &mut Vec<Selected>) -> Result<()> {
        ensure!(self.required.get(name).is_none_or(|&later| later <= stage), "dependency {name} would run before its WLAN stage");
        if self.ready.contains(name) { return Ok(()); }
        ensure!(self.active.len() < 256, "WLAN dependency depth exceeded");
        ensure!(self.active.insert(name.to_owned()), "circular WLAN dependency at {name}");
        let dep = self.graph.get(name).with_context(|| format!("no modules.dep entry for {name}"))?;
        let path = self.canonical.join(&dep.relative).canonicalize().with_context(|| format!("resolve {name}"))?;
        ensure!(path.starts_with(&self.canonical) && path.is_file(), "module {} does not resolve to a regular file within its source", path.display());
        let mut file = File::open(&path)?;
        ensure!(file.metadata()?.is_file(), "opened module is not a regular file: {}", path.display());
        let info = modinfo(&mut file).with_context(|| format!("inspect {}", path.display()))?;
        if info.split('\0').any(|item| item.starts_with("name=")) {
            let elf_name = field(&info, "name").context("duplicate module name in ELF metadata")?;
            let expected = name.strip_suffix(".ko").unwrap_or(name);
            ensure!(elf_name.replace('-', "_") == expected.replace('-', "_"),
                "module {} unexpectedly declares the name {elf_name}", path.display());
        }
        let vermagic = field(&info, "vermagic").context("missing or duplicate module vermagic")?;
        let release = vermagic.split_ascii_whitespace().next().context("empty module vermagic")?;
        ensure!(Family::parse(release)? == *self.family, "{} has incompatible vermagic {release}", path.display());
        let needs = dep.needs.clone();
        for child in &needs {
            let key = basename(child)?;
            ensure!(self.graph.get(key).is_some_and(|d| d.relative == *child), "{name} references missing or inconsistent dependency {}", child.display());
            self.visit(key, stage, order)?;
        }
        // Detect missing depmod links for declared hard dependencies in this
        // tree. External platform dependencies may already be loaded/built in;
        // those remain subject to the kernel's symbol and modversion checks.
        if info.split('\0').any(|item| item.starts_with("depends=")) {
            let declared = field(&info, "depends").context("duplicate module depends in ELF metadata")?;
            for module in declared.split(',').filter(|name| !name.is_empty()) {
                let normalized = module.replace('-', "_");
                let in_tree = self.graph.keys().find(|file| file.strip_suffix(".ko").unwrap_or(file).replace('-', "_") == normalized);
                if let Some(key) = in_tree {
                    ensure!(self.ready.contains(key), "{name}: declared dependency {module} is not ordered before the module by modules.dep");
                }
            }
        }
        self.active.remove(name);
        self.ready.insert(name.to_owned());
        order.push(Selected { path, file });
        Ok(())
    }
}

fn field<'a>(info: &'a str, key: &str) -> Option<&'a str> {
    let mut values = info.split('\0').filter_map(|item| item.split_once('=')).filter(|(k, _)| *k == key);
    let (_, value) = values.next()?;
    if values.next().is_none() { Some(value) } else { None }
}

fn u16_at(bytes: &[u8], pos: usize) -> u16 { u16::from_le_bytes(bytes[pos..pos+2].try_into().unwrap()) }
fn u32_at(bytes: &[u8], pos: usize) -> u32 { u32::from_le_bytes(bytes[pos..pos+4].try_into().unwrap()) }
fn u64_at(bytes: &[u8], pos: usize) -> u64 { u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()) }

/// Read only real ELF .modinfo (not a vermagic-looking string elsewhere).
fn modinfo(file: &mut File) -> Result<String> {
    let size = file.metadata()?.len();
    let mut header = [0; 64];
    file.read_exact(&mut header)?;
    ensure!(&header[..7] == b"\x7fELF\x02\x01\x01" && u16_at(&header, 16) == 1 && u16_at(&header, 18) == 183,
        "expected uncompressed AArch64 relocatable ELF module");
    let start = u64_at(&header, 40);
    let count = u16_at(&header, 60);
    let names_index = u16_at(&header, 62);
    ensure!(u16_at(&header, 58) == 64 && count > 0 && count <= 4096 && names_index < count,
        "invalid ELF section table");
    let read = |file: &mut File, offset: u64, len: u64| -> Result<Vec<u8>> {
        ensure!(len <= 256 * 1024 && offset.checked_add(len).is_some_and(|end| end <= size), "ELF metadata outside bounded file range");
        let mut buf = vec![0; len as usize];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;
        Ok(buf)
    };
    let sections = read(file, start, u64::from(count) * 64)?;
    let names = &sections[usize::from(names_index) * 64..][..64];
    ensure!(u32_at(names, 4) == 3, "ELF section names are not a string table");
    let strings = read(file, u64_at(names, 24), u64_at(names, 32))?;
    let mut info = None;
    for section in sections.chunks_exact(64) {
        let name = strings.get(u32_at(section, 0) as usize..).and_then(|s| s.split(|b| *b == 0).next());
        if name != Some(b".modinfo") { continue; }
        ensure!(info.is_none() && u32_at(section, 4) == 1, "ambiguous or invalid ELF .modinfo section");
        let bytes = read(file, u64_at(section, 24), u64_at(section, 32))?;
        info = Some(String::from_utf8(bytes).context("module metadata is not UTF-8")?);
    }
    info.context("no ELF .modinfo section")
}

#[cfg(test)]
mod tests {
    use super::*;

    const A16: &str = "5.10.66-android12-9-00001-g83cbf18b7dcd-ab8546841";
    const OLD_MODULE: &str = "5.10.66-android12-9-ge7ba4c04e5e5";
    const NEW: &str = "5.10.236-android12-9-o-g38e2c85bc7af";
    const WRONG: &str = "5.10.226-android12-9-o-g483c392a2d74";

    // Minimal relocatable ELF fixture; only section metadata is used.
    fn module(path: &Path, release: &str, deps: &str) {
        let info = format!("vermagic={release} SMP preempt mod_unload modversions aarch64\0depends={deps}\0");
        let names = b"\0.shstrtab\0.modinfo\0";
        let mut out = vec![0u8; 256];
        out[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        out[16..18].copy_from_slice(&1u16.to_le_bytes());
        out[18..20].copy_from_slice(&183u16.to_le_bytes());
        out[40..48].copy_from_slice(&64u64.to_le_bytes());
        out[58..60].copy_from_slice(&64u16.to_le_bytes());
        out[60..62].copy_from_slice(&3u16.to_le_bytes());
        out[62..64].copy_from_slice(&1u16.to_le_bytes());
        for (start, name, kind, at, len) in [(128, 1u32, 3u32, 256u64, names.len()), (192, 11, 1, 256 + names.len() as u64, info.len())] {
            out[start..start+4].copy_from_slice(&name.to_le_bytes());
            out[start+4..start+8].copy_from_slice(&kind.to_le_bytes());
            out[start+24..start+32].copy_from_slice(&at.to_le_bytes());
            out[start+32..start+40].copy_from_slice(&(len as u64).to_le_bytes());
        }
        out.extend_from_slice(names);
        out.extend_from_slice(info.as_bytes());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, out).unwrap();
    }

    const GRAPH: &str = "conninfra.ko: dep.ko\ndep.ko:\nsub/wlan.ko: conninfra.ko\nbt.ko: conninfra.ko\n";
    fn tree(dir: &Path, release: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("modules.dep"), GRAPH).unwrap();
        for (path, deps) in [("conninfra.ko", "dep"), ("dep.ko", ""), ("sub/wlan.ko", "conninfra"), ("bt.ko", "conninfra")] {
            module(&dir.join(path), release, deps);
        }
    }

    fn plan(dirs: &[PathBuf], release: &str) -> Result<WlanModulePlan> {
        plan_wlan(dirs, release, &[&["conninfra".into()], &["wlan".into()], &["bt".into()]])
    }

    #[test]
    fn chooses_legacy_vendor_and_keeps_stage_barriers() {
        let temp = tempfile::tempdir().unwrap();
        let dirs = [temp.path().join("vendor_boot"), temp.path().join("vendor_dlkm"), temp.path().join("vendor")];
        tree(&dirs[1], WRONG);
        tree(&dirs[2], OLD_MODULE);
        let selected = plan(&dirs, A16).unwrap();
        assert_eq!(selected.source(), dirs[2]);
        let paths: Vec<Vec<&str>> = selected.stages.iter().map(|stage| stage.iter().map(|m| basename(&m.path).unwrap()).collect()).collect();
        assert_eq!(paths, [vec!["dep.ko", "conninfra.ko"], vec!["wlan.ko"], vec!["bt.ko"]]);
    }

    #[test]
    fn prefers_compatible_stock_dlkm_without_picking_a_wrong_patch() {
        let temp = tempfile::tempdir().unwrap();
        let dirs = [temp.path().join("vendor_dlkm"), temp.path().join("vendor")];
        tree(&dirs[0], NEW); tree(&dirs[1], OLD_MODULE);
        assert_eq!(plan(&dirs, NEW).unwrap().source(), dirs[0]);
        assert!(plan(&dirs, WRONG).is_err());
    }

    #[test]
    fn preflights_later_calibration_and_never_mixes_trees() {
        let temp = tempfile::tempdir().unwrap();
        let dirs = [temp.path().join("left"), temp.path().join("right")];
        tree(&dirs[0], OLD_MODULE); tree(&dirs[1], OLD_MODULE);
        fs::remove_file(dirs[0].join("bt.ko")).unwrap();
        assert_eq!(plan(&dirs, A16).unwrap().source(), dirs[1]);
        module(&dirs[1].join("dep.ko"), WRONG, "");
        assert!(plan(&dirs, A16).is_err());
    }

    #[test]
    fn refuses_bad_graph_and_early_calibration() {
        let temp = tempfile::tempdir().unwrap(); let dir = temp.path().join("vendor");
        tree(&dir, OLD_MODULE);
        for graph in [GRAPH.replace("conninfra.ko: dep.ko", "conninfra.ko: bt.ko"),
                      GRAPH.replace("conninfra.ko: dep.ko", "conninfra.ko:"),
                      GRAPH.replace("sub/wlan.ko: conninfra.ko", "../wlan.ko: conninfra.ko"),
                      GRAPH.replace("dep.ko:", "dep.ko: conninfra.ko")] {
            fs::write(dir.join("modules.dep"), graph).unwrap();
            assert!(plan(std::slice::from_ref(&dir), A16).is_err());
        }
    }

    #[test]
    fn validates_real_stock_tree_when_supplied() {
        let Some(dir) = std::env::var_os("SKYWARD_WLAN_STOCK_MODULES") else { return };
        let dir = PathBuf::from(dir);
        // The extracted fixture contains paths as they were on the device;
        // give them a local root in a temporary view, without editing it.
        let temp = tempfile::tempdir().unwrap();
        let dep = fs::read_to_string(dir.join("modules.dep")).unwrap();
        fs::write(temp.path().join("modules.dep"), dep.replace("/vendor_dlkm/lib/modules/", "")).unwrap();
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "ko") {
                fs::copy(path, temp.path().join(entry.file_name())).unwrap();
            }
        }
        let selected = plan_wlan(&[temp.path().to_owned()], NEW,
            &[&["conninfra".into()], &["wmt_chrdev_wifi_connac2".into(), "wlan_drv_gen4m_6895".into()], &["bt_drv_6895".into()]]).unwrap();
        assert_eq!(selected.source(), temp.path());
        assert!(selected.stages[2].iter().any(|file| file.path.ends_with("bt_drv_6895.ko")));
    }

    #[test]
    fn validates_real_modinfo_and_kmi_family() {
        let temp = tempfile::tempdir().unwrap(); let dir = temp.path().join("vendor");
        tree(&dir, OLD_MODULE);
        for release in ["5.10.66-android13-9-gabcdef", "5.10.66-android12-8-gabcdef", "5.10.66", WRONG] {
            module(&dir.join("bt.ko"), release, "conninfra");
            assert!(plan(std::slice::from_ref(&dir), A16).is_err());
        }
        fs::write(dir.join("bt.ko"), format!("not an ELF\0vermagic={OLD_MODULE}\0")).unwrap();
        assert!(plan(&[dir], A16).is_err());
    }
}
