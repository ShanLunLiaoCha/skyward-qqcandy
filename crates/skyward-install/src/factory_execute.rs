//! Order a reviewed single-A restore. Device-specific checks and writes live
//! in the backend; this layer never opens an arbitrary path or probes a phone.
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;

/// Fixed extra firmware destinations from the independently reviewed .211
/// inventory. Boot-chain files handled by [`Target`] and MediaTek's
/// `preloader_raw` are deliberately absent; preloader remains unsupported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum FirmwarePartition {
    Apusys, AudioDsp, Ccu, CdtEngineering, Dpm, Gpueb, Gz, Lk, McfOta,
    Mcupm, Md1img, MvpuAlgo, PiImg, Scp, Spmfw, Sspm, Tee, Vcp,
}

impl FirmwarePartition {
    pub const ALL: [Self; 18] = [
        Self::Apusys, Self::AudioDsp, Self::Ccu, Self::CdtEngineering, Self::Dpm, Self::Gpueb,
        Self::Gz, Self::Lk, Self::McfOta, Self::Mcupm, Self::Md1img, Self::MvpuAlgo, Self::PiImg,
        Self::Scp, Self::Spmfw, Self::Sspm, Self::Tee, Self::Vcp,
    ];

    /// Base name before the A/B suffix, as the payload and kernel label it.
    pub fn base_name(self) -> &'static str {
        match self {
            Self::Apusys => "apusys", Self::AudioDsp => "audio_dsp", Self::Ccu => "ccu",
            Self::CdtEngineering => "cdt_engineering", Self::Dpm => "dpm", Self::Gpueb => "gpueb",
            Self::Gz => "gz", Self::Lk => "lk", Self::McfOta => "mcf_ota", Self::Mcupm => "mcupm",
            Self::Md1img => "md1img", Self::MvpuAlgo => "mvpu_algo", Self::PiImg => "pi_img",
            Self::Scp => "scp", Self::Spmfw => "spmfw", Self::Sspm => "sspm", Self::Tee => "tee",
            Self::Vcp => "vcp",
        }
    }

    /// The only partition this profile may write. Even if a kernel happens to
    /// expose an unsuffixed equivalent, it is not an accepted destination.
    pub fn partition_name(self) -> &'static str {
        match self {
            Self::Apusys => "apusys_a", Self::AudioDsp => "audio_dsp_a", Self::Ccu => "ccu_a",
            Self::CdtEngineering => "cdt_engineering_a", Self::Dpm => "dpm_a", Self::Gpueb => "gpueb_a",
            Self::Gz => "gz_a", Self::Lk => "lk_a", Self::McfOta => "mcf_ota_a", Self::Mcupm => "mcupm_a",
            Self::Md1img => "md1img_a", Self::MvpuAlgo => "mvpu_algo_a", Self::PiImg => "pi_img_a",
            Self::Scp => "scp_a", Self::Spmfw => "spmfw_a", Self::Sspm => "sspm_a", Self::Tee => "tee_a",
            Self::Vcp => "vcp_a",
        }
    }

    /// Fixed B counterpart; the payload cannot provide the destination name.
    pub fn partition_name_b(self) -> &'static str {
        match self {
            Self::Apusys => "apusys_b", Self::AudioDsp => "audio_dsp_b", Self::Ccu => "ccu_b",
            Self::CdtEngineering => "cdt_engineering_b", Self::Dpm => "dpm_b", Self::Gpueb => "gpueb_b",
            Self::Gz => "gz_b", Self::Lk => "lk_b", Self::McfOta => "mcf_ota_b", Self::Mcupm => "mcupm_b",
            Self::Md1img => "md1img_b", Self::MvpuAlgo => "mvpu_algo_b", Self::PiImg => "pi_img_b",
            Self::Scp => "scp_b", Self::Spmfw => "spmfw_b", Self::Sspm => "sspm_b", Self::Tee => "tee_b",
            Self::Vcp => "vcp_b",
        }
    }

    /// An upper bound from the reviewed payload sizes (largest is 69,967,872
    /// bytes), leaving room for the reviewed inventory to change size without
    /// accepting a whole-disk or wrong-device image. Actual capacity and exact
    /// payload hash are checked independently.
    pub fn maximum_image_bytes(self) -> u64 {
        match self {
            Self::Md1img => 96 << 20,
            Self::McfOta => 48 << 20,
            Self::AudioDsp => 16 << 20,
            Self::Gz | Self::Lk => 8 << 20,
            Self::Vcp => 2 << 20,
            Self::Apusys | Self::Ccu | Self::CdtEngineering | Self::Dpm | Self::Scp
            | Self::Spmfw | Self::Sspm | Self::Tee => 4 << 20,
            Self::Gpueb | Self::Mcupm | Self::MvpuAlgo | Self::PiImg => 1 << 20,
        }
    }
}

/// Logical identity only. Never turn a payload name into a free-form path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Target {
    Firmware(FirmwarePartition),
    BootA, DtboA, VendorBootA, VbmetaSystemA, VbmetaVendorA, Super, PreloaderA, VbmetaA,
    FirmwareB(FirmwarePartition),
    BootB, DtboB, VendorBootB, VbmetaSystemB, VbmetaVendorB, PreloaderB, VbmetaB,
}

impl Target {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Firmware(f) => f.partition_name(),
            Self::BootA => "boot_a", Self::DtboA => "dtbo_a", Self::VendorBootA => "vendor_boot_a",
            Self::VbmetaSystemA => "vbmeta_system_a", Self::VbmetaVendorA => "vbmeta_vendor_a",
            Self::Super => "super", Self::PreloaderA => "preloader_raw_a", Self::VbmetaA => "vbmeta_a",
            Self::FirmwareB(f) => f.partition_name_b(),
            Self::BootB => "boot_b", Self::DtboB => "dtbo_b", Self::VendorBootB => "vendor_boot_b",
            Self::VbmetaSystemB => "vbmeta_system_b", Self::VbmetaVendorB => "vbmeta_vendor_b",
            Self::PreloaderB => "preloader_raw_b", Self::VbmetaB => "vbmeta_b",
        }
    }

    pub(crate) fn is_preloader(self) -> bool {
        matches!(self, Self::PreloaderA | Self::PreloaderB)
    }
}

const REQUIRED: [Target; 7] = [Target::BootA, Target::DtboA, Target::VendorBootA,
    Target::VbmetaSystemA, Target::VbmetaVendorA, Target::Super, Target::VbmetaA];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Image {
    pub target: Target,
    pub bytes: u64,
    /// SHA-256 of the final staged bytes, not the pre-modification image.
    pub sha256: [u8; 32],
}

#[derive(Debug)]
pub struct Plan {
    ordered: Vec<Image>,
}

impl Plan {
    pub(crate) fn images(&self) -> &[Image] { &self.ordered }

    /// Validate the supported core boot-chain/super transaction roster. An
    /// independently reviewed firmware inventory is still required; this does
    /// not declare .211's other physical images unnecessary or authorize them.
    pub fn core(images: &[Image]) -> Result<Self> {
        Self::ordered(images, &REQUIRED)
    }

    /// Require every fixed, reviewed non-preloader firmware target as well as
    /// all core images. Firmware is written first; top-level vbmeta and slot
    /// activation retain their last positions. Preloader is not represented.
    pub fn with_firmware(images: &[Image]) -> Result<Self> {
        let order: Vec<_> = FirmwarePartition::ALL.into_iter().map(Target::Firmware)
            .chain(REQUIRED).collect();
        Self::ordered(images, &order)
    }

    /// Full reviewed .211 A-only roster. Preloader is written only after the
    /// other firmware and core images, immediately before top-level vbmeta.
    pub fn full(images: &[Image]) -> Result<Self> {
        let mut order = FirmwarePartition::ALL.into_iter().map(Target::Firmware).chain(REQUIRED).collect::<Vec<_>>();
        order.insert(order.len() - 1, Target::PreloaderA);
        Self::ordered(images, &order)
    }

    /// Both physical slots, but exactly one shared `super` image. This
    /// validates destination order and descriptors, not B bootability: the
    /// separately checked `super` may contain only A's logical partitions.
    /// Stage regular B targets first, then regular A targets and `super`.
    /// Defer both preloaders and top-level vbmeta; A vbmeta is the last write.
    pub fn physical_ab(images: &[Image]) -> Result<Self> {
        use Target::*;
        let order: Vec<_> = FirmwarePartition::ALL.into_iter().map(FirmwareB)
            .chain([BootB, DtboB, VendorBootB, VbmetaSystemB, VbmetaVendorB])
            .chain(FirmwarePartition::ALL.into_iter().map(Firmware))
            .chain([BootA, DtboA, VendorBootA, VbmetaSystemA, VbmetaVendorA,
                Super, PreloaderB, VbmetaB, PreloaderA, VbmetaA])
            .collect();
        Self::ordered(images, &order)
    }

    fn ordered(images: &[Image], order: &[Target]) -> Result<Self> {
        ensure!(images.len() == order.len(), "incomplete or extra restore images");
        let mut used = BTreeSet::new();
        for image in images {
            ensure!(order.contains(&image.target), "target is outside the selected restore roster");
            ensure!(image.bytes > 0 && image.bytes % 512 == 0 && image.sha256 != [0; 32],
                "invalid staged descriptor for {:?}", image.target);
            if let Target::Firmware(f) | Target::FirmwareB(f) = image.target {
                ensure!(image.bytes <= f.maximum_image_bytes(), "firmware {} exceeds its staging bound", f.base_name());
            }
            if image.target.is_preloader() {
                crate::factory_preloader::check_image_bounds(image.bytes, &image.sha256)?;
            }
            ensure!(used.insert(image.target), "duplicate destination {:?}", image.target);
        }
        let ordered = order.iter().map(|target| *images.iter().find(|i| i.target == *target)
            .expect("unique exact selected target roster")).collect();
        Ok(Self { ordered })
    }
}

/// These operations are deliberately separate so the caller cannot treat
/// preparation, partial writes, or enqueueing writes as a successful restore.
/// A real backend must validate the complete external firmware plan and hold
/// stable, exclusively opened target handles from `arm` through activation.
pub trait Backend {
    /// Verify all genuine inputs, selected AVB policy, target sizes/identity,
    /// snapshot/holder absence and activation availability. No writes yet.
    fn arm(&mut self, ordered: &[Image]) -> Result<()>;
    fn cancelled(&self) -> bool;
    /// Write this entire staged image to its exact target, without reading
    /// the block device back. Any input or short-write failure must be fatal.
    fn write(&mut self, image: &Image) -> Result<()>;
    fn sync(&mut self, target: Target) -> Result<()>;
    /// Only set A as the next boot slot. Never mark it boot-successful here.
    fn activate_a(&mut self) -> Result<()>;
}

/// Recheck the final staged byte stream while copying to a destination
/// already selected and locked by the backend. Verify against an independent
/// pre-write staging digest. Never read from the destination. A failure here
/// may leave partial writes; the caller must not activate the slot.
pub(crate) fn copy_checked(source: &mut impl std::io::Read, target: &mut impl std::io::Write, image: &Image) -> Result<()> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    let mut left = image.bytes;
    let mut buffer = vec![0; 256 << 10];
    while left != 0 {
        let n = left.min(buffer.len() as u64) as usize;
        let block = &mut buffer[..n];
        source.read_exact(block).context("read complete staged image")?;
        digest.update(&*block);
        target.write_all(block).context("write complete staged image block")?;
        left -= n as u64;
    }
    ensure!(source.read(&mut [0])? == 0, "staged source grew beyond the authorized length");
    let actual: [u8; 32] = digest.finalize().into();
    ensure!(actual == image.sha256, "staged source changed after preflight");
    Ok(())
}

/// After arming, all data writes and syncs must succeed before activation is
/// attempted. A partial failure is NOT a rollback; shared super is not an
/// atomic A/B transaction and the currently selected A slot is not protected.
pub fn execute(plan: &Plan, backend: &mut impl Backend) -> Result<()> {
    execute_observed(plan, backend, || {})
}

fn skyward_install_progress(step: crate::FactoryStep) { crate::progress::report(step); }

pub(crate) fn execute_observed(plan: &Plan, backend: &mut impl Backend, first_write: impl FnOnce()) -> Result<()> {
    let mut first_write = Some(first_write);
    let _ = skyward_sys::kmsg(&format!("factory restore: preparing {} ordered targets", plan.ordered.len()));
    ensure!(!backend.cancelled(), "restore cancelled before arming");
    backend.arm(&plan.ordered).context("arm restore before any writes")?;
    for (index, image) in plan.ordered.iter().enumerate() {
        ensure!(!backend.cancelled(), "restore cancelled before {:?}; not activating A", image.target);
        let _ = skyward_sys::kmsg(&format!("factory restore: writing {}/{} {} ({} bytes)",
            index + 1,
            plan.ordered.len(), image.target.display_name(), image.bytes));
        skyward_install_progress(crate::FactoryStep::Writing {
            index: index + 1, count: plan.ordered.len(), name: image.target.display_name().to_owned() });
        if let Some(notify) = first_write.take() { notify(); }
        backend.write(image).with_context(|| format!("write {:?}; not activating A", image.target))?;
        let _ = skyward_sys::kmsg(&format!("factory restore: syncing {}", image.target.display_name()));
        skyward_install_progress(crate::FactoryStep::Syncing { name: image.target.display_name().to_owned() });
        backend.sync(image.target).with_context(|| format!("sync {:?}; not activating A", image.target))?;
    }
    ensure!(!backend.cancelled(), "restore cancelled after sync; not activating A");
    let _ = skyward_sys::kmsg("factory restore: all targets synced; requesting A as next boot");
    skyward_install_progress(crate::FactoryStep::Activating);
    backend.activate_a().context("writes synced, but setting A as next boot failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call { Arm, Write(Target), Sync(Target), Activate }
    #[derive(Default)]
    struct Fake {
        calls: Vec<Call>,
        failure: Option<Call>,
        cancel_on_check: Option<usize>,
        checks: Cell<usize>,
    }
    impl Fake {
        fn step(&mut self, call: Call) -> Result<()> {
            self.calls.push(call);
            ensure!(self.failure != Some(call), "injected failure");
            Ok(())
        }
    }
    impl Backend for Fake {
        fn arm(&mut self, ordered: &[Image]) -> Result<()> {
            let targets: Vec<_> = ordered.iter().map(|i| i.target).collect();
            let core: Vec<_> = REQUIRED.into_iter().collect();
            let full: Vec<_> = FirmwarePartition::ALL.into_iter().map(Target::Firmware).chain(REQUIRED).collect();
            let mut with_preloader = full.clone();
            with_preloader.insert(with_preloader.len() - 1, Target::PreloaderA);
            assert!(targets == core || targets == full || targets == with_preloader || targets == ab_order());
            self.step(Call::Arm)
        }
        fn cancelled(&self) -> bool {
            let n = self.checks.get();
            self.checks.set(n + 1);
            self.cancel_on_check == Some(n)
        }
        fn write(&mut self, image: &Image) -> Result<()> { self.step(Call::Write(image.target)) }
        fn sync(&mut self, target: Target) -> Result<()> { self.step(Call::Sync(target)) }
        fn activate_a(&mut self) -> Result<()> { self.step(Call::Activate) }
    }
    fn images() -> Vec<Image> {
        REQUIRED.into_iter().rev().map(|target| Image { target, bytes: 4096, sha256: [1; 32] }).collect()
    }
    fn expected() -> Vec<Call> {
        std::iter::once(Call::Arm).chain(REQUIRED.into_iter().flat_map(|t| [Call::Write(t), Call::Sync(t)]))
            .chain(std::iter::once(Call::Activate)).collect()
    }
    #[test]
    fn canonical_order_puts_top_vbmeta_and_activation_last() {
        let plan = Plan::core(&images()).unwrap();
        let mut fake = Fake::default();
        execute(&plan, &mut fake).unwrap();
        assert_eq!(fake.calls, expected());
    }
    #[test]
    fn every_fault_stops_before_the_next_step() {
        let plan = Plan::core(&images()).unwrap();
        let expected = expected();
        for (index, failure) in expected.iter().copied().enumerate() {
            let mut fake = Fake { failure: Some(failure), ..Fake::default() };
            assert!(execute(&plan, &mut fake).is_err());
            assert_eq!(fake.calls, expected[..=index]);
        }
    }
    #[test]
    fn cancellation_at_every_boundary_never_activates() {
        let plan = Plan::core(&images()).unwrap();
        for check in 0..=REQUIRED.len()+1 {
            let mut fake = Fake { cancel_on_check: Some(check), ..Fake::default() };
            assert!(execute(&plan, &mut fake).is_err());
            assert!(!fake.calls.contains(&Call::Activate));
            if check == 0 { assert!(fake.calls.is_empty()); }
            if check == REQUIRED.len()+1 { assert_eq!(fake.calls.last(), Some(&Call::Sync(Target::VbmetaA))); }
        }
    }
    #[test]
    fn first_write_notice_waits_for_the_first_real_write() {
        let plan = Plan::core(&images()).unwrap();
        let noticed = std::cell::Cell::new(0);
        let mut fake = Fake::default();
        execute_observed(&plan, &mut fake, || noticed.set(noticed.get() + 1)).unwrap();
        assert_eq!(noticed.get(), 1);
        assert_eq!(fake.calls.first(), Some(&Call::Arm));
        assert!(matches!(fake.calls.get(1), Some(Call::Write(_))), "a real target write follows arming");
        let mut fake = Fake { failure: Some(Call::Arm), ..Fake::default() };
        execute_observed(&plan, &mut fake, || noticed.set(noticed.get() + 1)).unwrap_err();
        assert_eq!(noticed.get(), 1, "failed preflight must not claim anything was written");
        let mut fake = Fake { failure: Some(Call::Write(Target::BootA)), ..Fake::default() };
        execute_observed(&plan, &mut fake, || noticed.set(noticed.get() + 1)).unwrap_err();
        assert_eq!(noticed.get(), 2, "the notice precedes the write that may have begun");
        assert!(!fake.calls.contains(&Call::Activate));
    }

    #[test]
    fn staged_stream_enforces_exact_length_hash_and_write_success() {
        use sha2::{Digest, Sha256};
        use std::io::{self, Cursor, Write};
        let data = [0x39; 4096];
        let image = Image { target: Target::BootA, bytes: data.len() as u64, sha256: Sha256::digest(data).into() };
        let mut out = Vec::new();
        copy_checked(&mut Cursor::new(data), &mut out, &image).unwrap();
        assert_eq!(out, data);
        for bad in [&data[..data.len()-1], &[0; 4096], &[0; 4097]] {
            assert!(copy_checked(&mut Cursor::new(bad), &mut io::sink(), &image).is_err());
        }
        struct ShortWriter;
        impl Write for ShortWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> { Ok(0) }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        assert!(copy_checked(&mut Cursor::new(data), &mut ShortWriter, &image).is_err());
    }

    fn firmware_images() -> Vec<Image> {
        FirmwarePartition::ALL.into_iter().rev().map(|f| Image { target: Target::Firmware(f), bytes: 4096, sha256: [2; 32] })
            .chain(images()).collect()
    }

    #[test]
    fn firmware_is_complete_first_and_never_includes_preloader() {
        let plan = Plan::with_firmware(&firmware_images()).unwrap();
        let Fake { calls, .. } = { let mut fake = Fake::default(); execute(&plan, &mut fake).unwrap(); fake };
        let expected: Vec<_> = FirmwarePartition::ALL.into_iter().map(Target::Firmware)
            .chain(REQUIRED).collect();
        assert_eq!(calls.first(), Some(&Call::Arm));
        assert_eq!(calls.last(), Some(&Call::Activate));
        let written: Vec<_> = calls.iter().filter_map(|c| match c { Call::Write(t) => Some(*t), _ => None }).collect();
        assert_eq!(written, expected);
        assert!(!written.iter().any(|t| format!("{t:?}").to_lowercase().contains("preloader")));
        assert_eq!(written[written.len()-4..], [Target::VbmetaSystemA, Target::VbmetaVendorA, Target::Super, Target::VbmetaA]);
    }

    #[test]
    fn firmware_plan_rejects_missing_duplicate_and_oversized_images() {
        let full = firmware_images();
        assert!(Plan::with_firmware(&full[1..]).is_err());
        assert!(Plan::core(&full).is_err(), "firmware images are not a core-only roster");
        let mut duplicate = full.clone();
        duplicate[0] = duplicate[1];
        assert!(Plan::with_firmware(&duplicate).is_err());
        let mut oversized = full;
        oversized[0].bytes = FirmwarePartition::ALL.into_iter().map(|f| f.maximum_image_bytes()).max().unwrap() + 512;
        assert!(Plan::with_firmware(&oversized).is_err());
    }

    #[test]
    fn firmware_failure_before_core_stops_without_activation() {
        let plan = Plan::with_firmware(&firmware_images()).unwrap();
        let first = Call::Write(Target::Firmware(FirmwarePartition::ALL[0]));
        let mut fake = Fake { failure: Some(first), ..Fake::default() };
        assert!(execute(&plan, &mut fake).is_err());
        assert_eq!(fake.calls, [Call::Arm, first]);
        assert!(!fake.calls.contains(&Call::Activate));
    }

    fn full_images() -> Vec<Image> {
        use crate::factory_preloader::{IMAGE_211_BYTES, IMAGE_211_SHA256};
        let mut all = firmware_images();
        all.push(Image {target:Target::PreloaderA, bytes:IMAGE_211_BYTES, sha256:IMAGE_211_SHA256});
        all
    }

    #[test]
    fn full_requires_exact_211_preloader_after_super_and_before_vbmeta() {
        let mut all = full_images();
        assert!(Plan::with_firmware(&all).is_err());
        assert!(Plan::full(&all[..all.len()-1]).is_err());
        let plan = Plan::full(&all).unwrap();
        let mut fake = Fake::default();
        execute(&plan, &mut fake).unwrap();
        assert_eq!(Target::PreloaderA.display_name(), "preloader_raw_a");
        assert_eq!(&fake.calls[fake.calls.len()-6..], &[Call::Sync(Target::Super),
            Call::Write(Target::PreloaderA), Call::Sync(Target::PreloaderA), Call::Write(Target::VbmetaA),
            Call::Sync(Target::VbmetaA), Call::Activate]);
        let preloader = all.last_mut().unwrap();
        preloader.sha256[31] ^= 1;
        preloader.bytes += 512;
        assert!(Plan::full(&all).is_ok());
        all.last_mut().unwrap().bytes = crate::factory_preloader::MAPPED_BYTES + 512;
        assert!(Plan::full(&all).is_err());
    }

    #[test]
    fn preloader_write_or_sync_error_never_writes_parent_vbmeta_or_activates() {
        let plan = Plan::full(&full_images()).unwrap();
        for failure in [Call::Write(Target::PreloaderA), Call::Sync(Target::PreloaderA)] {
            let mut fake = Fake {failure:Some(failure), ..Fake::default()};
            assert!(execute(&plan, &mut fake).is_err());
            assert_eq!(fake.calls.last(), Some(&failure));
            assert!(!fake.calls.contains(&Call::Write(Target::VbmetaA)));
            assert!(!fake.calls.contains(&Call::Activate));
        }
    }

    fn ab_order() -> Vec<Target> {
        use Target::*;
        FirmwarePartition::ALL.into_iter().map(FirmwareB)
            .chain([BootB, DtboB, VendorBootB, VbmetaSystemB, VbmetaVendorB])
            .chain(FirmwarePartition::ALL.into_iter().map(Firmware))
            .chain([BootA, DtboA, VendorBootA, VbmetaSystemA, VbmetaVendorA, Super,
                PreloaderB, VbmetaB, PreloaderA, VbmetaA]).collect()
    }

    #[test]
    fn physical_ab_syncs_every_target_before_activation_and_stops_at_any_fault() {
        let order = ab_order();
        assert_eq!(order.len(), 51);
        assert_eq!(order.iter().filter(|&&target| target == Target::Super).count(), 1);
        let mut images: Vec<_> = order.iter().rev().map(|&target| {
            let (bytes, sha256) = if target.is_preloader() {
                (crate::factory_preloader::IMAGE_211_BYTES, crate::factory_preloader::IMAGE_211_SHA256)
            } else { (4096,[1; 32]) };
            Image { target, bytes, sha256 }
        }).collect();
        let plan = Plan::physical_ab(&images).unwrap();
        let expected: Vec<_> = std::iter::once(Call::Arm)
            .chain(order.into_iter().flat_map(|target| [Call::Write(target), Call::Sync(target)]))
            .chain(std::iter::once(Call::Activate)).collect();
        let mut fake = Fake::default();
        execute(&plan, &mut fake).unwrap();
        assert_eq!(fake.calls, expected);
        for (i, &step) in expected[..expected.len()-1].iter().enumerate() {
            let mut fake = Fake {failure:Some(step), ..Fake::default()};
            assert!(execute(&plan, &mut fake).is_err());
            assert_eq!(fake.calls, expected[..=i]);
        }
        images.iter_mut().find(|i| i.target == Target::PreloaderB).unwrap().bytes = crate::factory_preloader::MAPPED_BYTES + 512;
        assert!(Plan::physical_ab(&images).is_err());
    }

    #[test]
    fn invalid_rosters_do_not_construct_executable_plans() {
        let mut items = images();
        assert!(Plan::core(&items[1..]).is_err());
        items[0].bytes = 4097;
        assert!(Plan::core(&items).is_err());
        items[0] = items[1];
        assert!(Plan::core(&items).is_err());
    }
}
