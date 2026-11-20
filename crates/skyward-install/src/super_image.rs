//! Build a regular-file Virtual A/B super candidate, not a flash operation.
use crate::{payload_plan, super_replacement};
use anyhow::{Context, Result, ensure};
use skyward_lp::{BlockDevice, Geometry, HEADER_FLAG_VIRTUAL_AB_DEVICE};
use std::{collections::BTreeMap, io::{Read, Seek, Write}, path::Path};

#[derive(Debug)]
pub struct ResultImage {
    pub bytes: u64,
    pub allocated_end: u64,
    pub partitions: usize,
    pub partial_payload: bool,
}

/// Materialize one set of payload logical partitions as `_a`, with the two
/// explicitly selected replacement images. The B table has no allocated copy.
/// An image based on a partial payload is still a candidate, not proof that
/// its declared roster and two replacements cover the entire target system.
pub fn build_a<R: Read + Seek>(reader: &mut R, payload: &payload_plan::Plan,
    reference: &skyward_lp::Metadata, actual_bytes: u64, company: &Path,
    preload: &Path, output: &Path) -> Result<ResultImage> {
    build_a_observed(reader, payload, reference, actual_bytes, company, preload, output, &mut |_, _, _| Ok(()))
}

/// Observe logical image boundaries before writing each one to a temporary
/// regular file. An observer error aborts without publishing the image.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_a_observed<R: Read + Seek>(reader: &mut R, payload: &payload_plan::Plan,
    reference: &skyward_lp::Metadata, actual_bytes: u64, company: &Path, preload: &Path,
    output: &Path, progress: &mut impl FnMut(&str, usize, usize) -> Result<()>) -> Result<ResultImage> {
    let [device] = reference.block_devices.as_slice() else { anyhow::bail!("expected one physical super device"); };
    ensure!(reference.damaged.is_empty() && reference.header_flags == HEADER_FLAG_VIRTUAL_AB_DEVICE
        && device.partition_name == "super" && device.size == actual_bytes,
        "physical super or metadata does not match the Virtual A/B reference");
    let replacements = BTreeMap::from([("my_company", company), ("my_preload", preload)]);
    let company_bytes = super_replacement::inspect(company)?;
    let preload_bytes = super_replacement::inspect(preload)?;
    let (limit, sizes) = target_sizes(payload, company_bytes, preload_bytes)?;
    let source: BTreeMap<_, _> = payload.partitions.iter().map(|p| (p.name.as_str(), p)).collect();
    let layout = skyward_lp::single_a::build(reference.geometry, device, limit, &sizes)?;
    write_candidate(reader, payload, reference.geometry, device, &replacements, &sizes, &source, layout, output, progress)
}

pub(crate) fn target_sizes(payload: &payload_plan::Plan, company: u64, preload: u64) -> Result<(u64, BTreeMap<String,u64>)> {
    let dynamic = payload.dynamic.as_ref().context("missing target dynamic partition metadata")?;
    let [group] = dynamic.groups.as_slice() else { anyhow::bail!("expected exactly one target dynamic group"); };
    ensure!(dynamic.snapshot_enabled && group.name == "main", "unrecognized target Virtual A/B layout");
    let limit = group.maximum_size.filter(|&size| size > 0).context("target dynamic group has no explicit limit")?;
    let replacements = BTreeMap::from([("my_company", company), ("my_preload", preload)]);
    let mut source = BTreeMap::new();
    for p in &payload.partitions {
        ensure!(source.insert(p.name.as_str(),p).is_none(), "duplicate target partition {}", p.name);
    }
    let mut sizes = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    for name in &group.partitions {
        ensure!(seen.insert(name), "duplicate logical target {name}");
        if replacements.contains_key(name.as_str()) { continue; }
        let p = source.get(name.as_str()).with_context(|| format!("target is missing image for {name}"))?;
        ensure!(sizes.insert(name.clone(), p.size).is_none(), "duplicate logical target {name}");
    }
    for (name, size) in replacements { sizes.insert(name.to_owned(), size); }
    Ok((limit, sizes))
}

fn write_candidate<R: Read + Seek>(reader: &mut R, payload: &payload_plan::Plan, geometry: Geometry, device: &BlockDevice,
    replacements: &BTreeMap<&str, &Path>, sizes: &BTreeMap<String, u64>, source: &BTreeMap<&str, &payload_plan::Partition>,
    layout: skyward_lp::single_a::Layout, output: &Path,
    progress: &mut impl FnMut(&str, usize, usize) -> Result<()>) -> Result<ResultImage> {
    let actual_bytes = device.size;
    let parent = output.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    ensure!(output.file_name().is_some(), "missing output image filename");
    match std::fs::symlink_metadata(output) {
        Ok(_) => anyhow::bail!("refusing to overwrite {}", output.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e).with_context(|| format!("inspect {}", output.display())),
    }
    let mut stage = tempfile::Builder::new().prefix(".skyward-super-a-").suffix(".partial").tempfile_in(parent)?;
    let file = stage.as_file_mut();
    file.set_len(actual_bytes)?;
    file.write_all(&layout.prefix)?;
    for (index, (name, &offset)) in layout.offsets.iter().enumerate() {
        progress(name, index + 1, layout.offsets.len())?;
        if let Some(path) = replacements.get(name.as_str()) {
            super_replacement::stage_into(path, file, offset, sizes[name])?;
        } else {
            let part = source[name.as_str()];
            crate::payload_stage::stage_into(reader, part, file, offset, actual_bytes)?;
        }
    }
    file.sync_all()?;
    verify_metadata(stage.path(), geometry, device, &layout.offsets, sizes)?;
    stage.persist_noclobber(output).with_context(|| format!("publish {}", output.display()))?;
    Ok(ResultImage {bytes:actual_bytes, allocated_end:layout.used_end, partitions:sizes.len(), partial_payload:payload.partial_update})
}

fn verify_metadata(file: &Path, geometry: Geometry, device: &BlockDevice,
    offsets: &BTreeMap<String,u64>, sizes: &BTreeMap<String,u64>) -> Result<()> {
    for slot in 0..geometry.metadata_slot_count {
        let lp = skyward_lp::read(file, slot)?;
        ensure!(lp.damaged.is_empty() && lp.geometry == geometry && lp.block_devices.as_slice() == [device.clone()]
            && lp.header_flags == HEADER_FLAG_VIRTUAL_AB_DEVICE, "generated super metadata did not round trip");
        let mut a = std::collections::BTreeSet::new();
        let mut b = std::collections::BTreeSet::new();
        for p in &lp.partitions {
            ensure!(p.attributes == skyward_lp::ATTR_READONLY, "unexpected attributes in {}", p.name);
            if let Some(name) = p.name.strip_suffix("_a") {
                ensure!(a.insert(name) && lp.groups.get(p.group).is_some_and(|g| g.name == "main_a"), "duplicate or misgrouped A partition {name}");
                let size = sizes.get(name).context("unexpected A partition in generated super")? / 512;
                let sector = offsets.get(name).context("missing A offset in generated super")? / 512;
                ensure!(p.extents.as_slice() == [skyward_lp::Extent::Linear { sectors:size, device:0, sector }], "wrong A extent for {name}");
            } else {
                let name = p.name.strip_suffix("_b").context("unexpected unslotted partition in generated super")?;
                ensure!(b.insert(name) && sizes.contains_key(name) && lp.groups.get(p.group).is_some_and(|g| g.name == "main_b") && p.extents.is_empty(),
                    "unexpected or allocated B partition {}", p.name);
            }
        }
        ensure!(a.len() == sizes.len() && a == b, "incomplete A layout or B placeholder roster");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload_plan::{Blob, DynamicGroup, DynamicMetadata, Kind, Operation, Partition, Plan};
    use sha2::{Digest, Sha256};
    use std::{fs, io::Cursor, os::unix::fs::FileExt};

    #[test]
    fn single_a_uses_target_roster_and_publishes_only_complete_files() {
        let tmp = tempfile::tempdir().unwrap();
        let company = tmp.path().join("company.img");
        let preload = tmp.path().join("preload.img");
        let mut erofs = vec![0u8; 4096];
        erofs[1024..1028].copy_from_slice(&[0xe2,0xe1,0xf5,0xe0]);
        erofs[1036] = 12;
        erofs[1060..1064].copy_from_slice(&1u32.to_le_bytes());
        fs::write(&company, &erofs).unwrap();
        fs::write(&preload, &erofs).unwrap();
        let bytes = vec![0x73; 4096];
        let digest = Sha256::digest(&bytes).into();
        let p = Plan { block_size:4096, minor_version:7, partial_update:true, dynamic:Some(DynamicMetadata {
            snapshot_enabled:true, vabc_enabled:false, groups:vec![DynamicGroup {
                name:"main".into(), maximum_size:Some(1<<20), partitions:vec!["system".into()],
            }],
        }), partitions:vec![Partition { name:"system".into(), size:4096, sha256:digest, operations:vec![Operation {
            kind:Kind::Replace, data:Some(Blob {range:0..4096, sha256:digest}), targets:vec![0..4096], output_size:4096,
        }]}] };
        let device = BlockDevice { partition_name:"super".into(), first_logical_sector:2048,
            alignment:1<<20, alignment_offset:0, size:8<<20 };
        let reference = skyward_lp::Metadata { geometry:Geometry { metadata_max_size:65536, metadata_slot_count:3, logical_block_size:4096 },
            major_version:10, minor_version:2, header_flags:HEADER_FLAG_VIRTUAL_AB_DEVICE,
            partitions:vec![skyward_lp::Partition {name:"vendor_dlkm_a".into(), attributes:0, group:0, extents:vec![]}],
            groups:vec![], block_devices:vec![device.clone()], damaged:vec![] };
        let image = tmp.path().join("super.img");
        assert!(build_a(&mut Cursor::new(vec![0;4096]), &p, &reference, device.size, &company, &preload, &image).is_err());
        assert!(!image.exists());
        let output = build_a(&mut Cursor::new(&bytes), &p, &reference, device.size, &company, &preload, &image).unwrap();
        assert!(output.partial_payload);
        assert_eq!(output.partitions,3);
        for slot in 0..3 {
            let meta = skyward_lp::read(&image, slot).unwrap();
            assert!(meta.partition("vendor_dlkm_a").is_none());
            assert!(meta.partitions.iter().filter(|p| p.name.ends_with("_b")).all(|p| p.extents.is_empty()));
            let file = fs::File::open(&image).unwrap();
            for (name, expected) in [("system_a", &bytes), ("my_company_a", &erofs), ("my_preload_a", &erofs)] {
                let [skyward_lp::Extent::Linear { sector, .. }] = meta.partition(name).unwrap().extents.as_slice() else { panic!("expected linear extent") };
                let mut actual = vec![0;4096];
                file.read_exact_at(&mut actual, sector * 512).unwrap();
                assert_eq!(&actual, expected);
            }
        }
        assert!(build_a(&mut Cursor::new(&bytes), &p, &reference, device.size, &company, &preload, &image).is_err());
    }
}
