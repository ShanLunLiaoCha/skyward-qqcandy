//! File-only end-to-end restore tests. Simulated activation is a small file,
//! never a property, binder call or block-device operation.
use crate::factory_backend::{Source, open_sources};
use crate::factory_execute::{Backend, Image, Plan, Target, copy_checked, execute};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs::{self, File, OpenOptions}, io::Write, path::{Path, PathBuf}};

pub(crate) fn replay_staged_ab(bundle: &crate::factory_bundle::Bundle, root: &Path) -> Result<()> {
    let plan = bundle.execution_plan_ab()?;
    // Fail on the first fsync to prove the actual staged plan cannot request
    // activation after a write fault, without making another copy of super.
    let failed_path = root.join("failed-targets");
    let mut failed = FileBackend::new(bundle.execution_sources_ab()?, &failed_path, Some(plan.images()[0].target));
    let error = execute(&plan, &mut failed).expect_err("simulated fsync failure");
    assert!(format!("{error:#}").contains("injected last-mile fsync failure"));
    assert!(!failed_path.join("SIMULATED-NEXT-SLOT").exists());
    drop(failed);
    let output = root.join("virtual-targets");
    let mut backend = FileBackend::new(bundle.execution_sources_ab()?, &output, None);
    execute(&plan, &mut backend)?;
    assert_eq!(backend.synced.len(), 51);
    assert_eq!(fs::read(output.join("SIMULATED-NEXT-SLOT"))?, b"A\n");
    Ok(())
}

struct FileBackend<'a> {
    paths: BTreeMap<Target, PathBuf>,
    sources: BTreeMap<Target, Source>,
    output_dir: &'a Path,
    next_slot: Option<Target>,
    targets: BTreeMap<Target, File>,
    synced: BTreeSet<Target>,
    fail_sync: Option<Target>,
    ready: bool,
}

impl<'a> FileBackend<'a> {
    fn new(paths: BTreeMap<Target, PathBuf>, output_dir: &'a Path, fail_sync: Option<Target>) -> Self {
        Self { paths, sources: BTreeMap::new(), output_dir, next_slot: None,
            targets: BTreeMap::new(), synced: BTreeSet::new(), fail_sync, ready: false }
    }
}

impl Backend for FileBackend<'_> {
    fn arm(&mut self, ordered: &[Image]) -> Result<()> {
        ensure!(!self.ready, "file backend already armed");
        self.sources = open_sources(&self.paths, ordered)?;
        // `create_dir` is exclusive; no existing user or device file can
        // become an output, even when the test destination already exists.
        fs::create_dir(self.output_dir)?;
        for image in ordered {
            let name = format!("{}.sim.img", image.target.display_name());
            let file = OpenOptions::new().create_new(true).write(true).open(self.output_dir.join(name))?;
            ensure!(file.metadata()?.is_file(), "nonregular simulation target");
            self.targets.insert(image.target, file);
        }
        self.ready = true;
        Ok(())
    }

    fn cancelled(&self) -> bool { false }

    fn write(&mut self, image: &Image) -> Result<()> {
        ensure!(self.ready && self.next_slot.is_none(), "write before arming or before previous sync");
        let source = self.sources.get_mut(&image.target).context("simulation source absent")?;
        let target = self.targets.get_mut(&image.target).context("simulation target absent")?;
        copy_checked(&mut source.file, target, image)?;
        self.next_slot = Some(image.target);
        Ok(())
    }

    fn sync(&mut self, target: Target) -> Result<()> {
        ensure!(self.next_slot.take() == Some(target), "simulation write/sync order differs");
        ensure!(self.fail_sync != Some(target), "injected last-mile fsync failure");
        self.targets[&target].sync_all()?;
        ensure!(self.synced.insert(target), "duplicate simulation sync");
        Ok(())
    }

    fn activate_a(&mut self) -> Result<()> {
        ensure!(self.ready && self.next_slot.is_none() && self.synced.len() == self.targets.len(), "not all simulated partitions are durable");
        let mut marker = OpenOptions::new().create_new(true).write(true).open(self.output_dir.join("SIMULATED-NEXT-SLOT"))?;
        marker.write_all(b"A\n")?;
        marker.sync_all()?;
        File::open(self.output_dir)?.sync_all()?;
        Ok(())
    }
}

const CORE: [Target; 7] = [Target::BootA, Target::DtboA, Target::VendorBootA, Target::VbmetaSystemA,
    Target::VbmetaVendorA, Target::Super, Target::VbmetaA];

#[test]
fn real_file_sync_failure_does_not_publish_activation() {
    let tmp = tempfile::tempdir().unwrap();
    let data = vec![11; 4096];
    let mut paths = BTreeMap::new();
    let images: Vec<_> = CORE.into_iter().map(|target| {
        let path = tmp.path().join(format!("{}.source", target.display_name()));
        fs::write(&path, &data).unwrap();
        paths.insert(target, path);
        Image { target, bytes: data.len() as u64, sha256: Sha256::digest(&data).into() }
    }).collect();
    let plan = Plan::core(&images).unwrap();
    let failed = tmp.path().join("failed");
    let mut backend = FileBackend::new(paths.clone(), &failed, Some(Target::VbmetaA));
    assert!(execute(&plan, &mut backend).is_err());
    assert_eq!(backend.synced.len(), 6);
    assert!(!failed.join("SIMULATED-NEXT-SLOT").exists());
    let ok = tmp.path().join("ok");
    let mut backend = FileBackend::new(paths, &ok, None);
    execute(&plan, &mut backend).unwrap();
    assert_eq!(fs::read(ok.join("SIMULATED-NEXT-SLOT")).unwrap(), b"A\n");
}

/// The fixture is already checked against the signed OTA by the staging and
/// audit workflows; its text index is input to this test only. No product
/// parser or Android write path trusts an external descriptor list.
#[test]
#[ignore = "requires real .211 fixture and about 13 GB of host scratch disk"]
fn full_211_bundle_exercises_all_26_writes_and_syncs() -> Result<()> {
    replay_full_211(false)
}

#[test]
#[ignore = "requires real .211 fixture and about 14 GB of host scratch disk"]
fn full_211_bundle_exercises_all_51_writes_with_one_a_only_super() -> Result<()> {
    replay_full_211(true)
}

fn replay_full_211(physical_ab: bool) -> Result<()> {
    use crate::{factory_bundle::{Bundle, StagedPhysical}, factory_execute::FirmwarePartition};
    let root = PathBuf::from(std::env::var_os("SKYWARD_TEST_STAGED_211").context("missing real fixture path")?);
    let full = CORE.into_iter().chain(FirmwarePartition::ALL.into_iter().map(Target::Firmware)).chain([Target::PreloaderA]);
    let mut named = BTreeMap::new();
    for target in full {
        let base = match target {
            Target::Firmware(firmware) => firmware.base_name(),
            Target::PreloaderA => "preloader_raw",
            _ => target.display_name(),
        };
        named.insert(format!("{base}.img"), target);
    }
    let report = fs::read_to_string(root.join("FULL-PAYLOAD-STAGED.txt"))?;
    let mut paths = BTreeMap::new();
    let mut images = Vec::new();
    for line in report.lines().filter(|line| line.contains("  ")) {
        let mut fields = line.split("  ");
        let digest = fields.next().context("missing fixture hash")?;
        let name = fields.next().context("missing fixture filename")?;
        let bytes = fields.next().context("missing fixture size")?.parse()?;
        ensure!(fields.next().is_none() && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()), "bad fixture row");
        let mut sha256 = [0; 32];
        for (i, byte) in sha256.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digest[2*i..2*i+2], 16)?;
        }
        let target = *named.get(name).context("unknown fixture target")?;
        ensure!(paths.insert(target, root.join(name)).is_none(), "duplicate fixture row");
        images.push(Image { target, bytes, sha256 });
    }
    let (plan, paths) = if physical_ab {
        let mut bundle = Bundle { directory: root.clone(), paths: BTreeMap::new(), images: Vec::new(),
            extra_physical: BTreeMap::new(), remaining_physical: Vec::new(), unmapped_physical: Vec::new(), avb_off: true };
        for &image in &images {
            let path = paths[&image.target].clone();
            let base = match image.target {
                Target::Firmware(fw) => Some(fw.base_name()),
                Target::PreloaderA => Some("preloader_raw"),
                _ => None,
            };
            if let Some(base) = base {
                bundle.extra_physical.insert(base.to_owned(), StagedPhysical {path, bytes: image.bytes, sha256: image.sha256});
            } else {
                bundle.images.push(image);
                bundle.paths.insert(image.target, path);
            }
        }
        (bundle.execution_plan_ab()?, bundle.execution_sources_ab()?)
    } else {
        (Plan::full(&images)?, paths)
    };
    let scratch = tempfile::tempdir()?;
    let output = scratch.path().join("virtual-partitions");
    let mut backend = FileBackend::new(paths, &output, None);
    execute(&plan, &mut backend)?;
    assert_eq!(backend.synced.len(), if physical_ab {51} else {26});
    assert_eq!(fs::read(output.join("SIMULATED-NEXT-SLOT"))?, b"A\n");
    if physical_ab {
        use crate::factory_execute::Target::*;
        for (a, b) in [(BootA, BootB), (VendorBootA, VendorBootB), (PreloaderA, PreloaderB), (VbmetaA, VbmetaB)] {
            let path = |t: Target| output.join(format!("{}.sim.img", t.display_name()));
            assert_eq!(fs::read(path(a))?, fs::read(path(b))?);
        }
        assert_eq!(backend.synced.iter().filter(|&&target| target == Super).count(), 1);
    }
    for image in images {
        assert_eq!(fs::metadata(output.join(format!("{}.sim.img", image.target.display_name())))?.len(), image.bytes);
    }
    Ok(())
}
