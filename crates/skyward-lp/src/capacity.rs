//! Pure capacity repair for the redundant metadata on a launch-device super.
//! No file or block-device I/O. A caller must separately establish physical
//! identity, absence of snapshots/holders and safe exclusive write access.
use super::*;
use std::collections::BTreeSet;
use std::ops::Range;

const GEOMETRY_PREFIX: usize = (RESERVED_BYTES + 2 * GEOMETRY_SIZE) as usize;
const MAX_STRIDE: u32 = 1024 * 1024;
const MAX_SLOTS: u32 = 4;

fn geometry(prefix: &[u8]) -> Result<Geometry> {
    let start = RESERVED_BYTES as usize;
    let split = start + GEOMETRY_SIZE as usize;
    let primary = prefix.get(start..split).context("short primary LP geometry")?;
    let backup = prefix.get(split..GEOMETRY_PREFIX).context("short backup LP geometry")?;
    let g = Geometry::parse(primary).context("primary LP geometry")?;
    ensure!(g == Geometry::parse(backup).context("backup LP geometry")?, "LP geometry copies differ");
    ensure!((GEOMETRY_SIZE as u32..=MAX_STRIDE).contains(&g.metadata_max_size)
        && u64::from(g.metadata_max_size) % GEOMETRY_SIZE == 0, "unsupported LP repair stride {}", g.metadata_max_size);
    ensure!((1..=MAX_SLOTS).contains(&g.metadata_slot_count), "unsupported LP metadata count {}", g.metadata_slot_count);
    ensure!(g.logical_block_size.is_power_of_two() && (512..=65536).contains(&g.logical_block_size),
        "unsupported logical block size {}", g.logical_block_size);
    Ok(g)
}

/// Number of bytes covering both geometry copies and all LP metadata copies.
/// Requires the first 12 KiB and verifies the two geometry checksums.
pub fn prefix_len(geometry_prefix: &[u8]) -> Result<usize> {
    Ok(geometry(geometry_prefix)?.metadata_region() as usize)
}

struct Copy<'a> {
    header: RawHeader,
    header_size: usize,
    tables: &'a [u8],
}

fn checked_copy<'a>(g: &Geometry, bytes: &'a [u8]) -> Result<Copy<'a>> {
    let mut header = RawHeader::new_zeroed();
    let short = bytes.get(..HEADER_V1_0_SIZE).context("short LP header")?;
    header.as_mut_bytes()[..HEADER_V1_0_SIZE].copy_from_slice(short);
    ensure!(header.magic.get() == HEADER_MAGIC && header.major_version.get() == MAJOR_VERSION
        && header.minor_version.get() <= MINOR_VERSION_MAX, "unsupported LP header");
    let header_size = if header.minor_version.get() < VERSION_FOR_EXPANDED_HEADER { HEADER_V1_0_SIZE } else { size_of::<RawHeader>() };
    ensure!(header.header_size.get() as usize == header_size, "incorrect LP header length");
    header.as_mut_bytes()[..header_size].copy_from_slice(bytes.get(..header_size).context("truncated LP header")?);
    let mut unsummed = header.clone();
    unsummed.header_checksum = [0; 32];
    ensure!(sha256(&unsummed.as_bytes()[..header_size]) == header.header_checksum, "bad LP header checksum");
    let size = header.tables_size.get();
    ensure!(size <= g.metadata_max_size, "LP tables exceed stride");
    let tables = bytes.get(header_size..header_size + size as usize).context("truncated LP tables")?;
    ensure!(sha256(tables) == header.tables_checksum, "bad LP tables checksum");
    let mut ranges = Vec::new();
    for (t, entry_size) in [(&header.partitions, size_of::<RawPartition>()), (&header.extents, size_of::<RawExtent>()),
        (&header.groups, size_of::<RawGroup>()), (&header.block_devices, size_of::<RawBlockDevice>())] {
        // Before interpreting any entry, also prove the capacity field does
        // not alias bytes that belong to another table.
        ensure!(t.entry_size.get() as usize == entry_size && t.fits(size), "invalid LP table definition");
        if t.num_entries.get() != 0 {
            let start = t.offset.get() as usize;
            ranges.push(start..start + t.num_entries.get() as usize * entry_size);
        }
    }
    ranges.sort_unstable_by_key(|r| r.start);
    ensure!(ranges.windows(2).all(|p| p[0].end <= p[1].start), "overlapping LP tables");
    ensure!(header.block_devices.num_entries.get() > 0, "LP metadata has no devices");
    Ok(Copy { header, header_size, tables })
}

impl Copy<'_> {
    fn devices(&self) -> Vec<RawBlockDevice> {
        self.header.block_devices.entries(self.tables)
    }

    fn validate_repair(&self, g: &Geometry, actual: u64) -> Result<()> {
        let h = &self.header;
        ensure!(h.flags.get() & !HEADER_FLAG_VIRTUAL_AB_DEVICE == 0 && h.reserved.iter().all(|&b| b == 0),
            "LP repair does not support overlays or unknown header fields");
        let devices = self.devices();
        ensure!(devices.len() == 1, "LP repair requires one physical super device");
        let dev = &devices[0];
        ensure!(name(&dev.partition_name)? == "super" && dev.flags.get() == 0, "LP repair requires a non-retrofit super device");
        let bound = actual.min(dev.size.get());
        let first = dev.first_logical_sector.get();
        ensure!(bound % SECTOR_SIZE == 0 && first >= g.metadata_region() / SECTOR_SIZE
            && first < bound / SECTOR_SIZE, "invalid LP device data range");
        let groups: Vec<RawGroup> = h.groups.entries(self.tables);
        let partitions: Vec<RawPartition> = h.partitions.entries(self.tables);
        let extents: Vec<RawExtent> = h.extents.entries(self.tables);
        ensure!(!groups.is_empty(), "LP metadata has no groups");
        let mut group_names = Vec::new();
        for group in &groups {
            ensure!(group.flags.get() == 0, "LP repair does not support slot-suffixed or unknown group flags");
            group_names.push(name(&group.name)?);
        }
        ensure!(group_names.iter().collect::<BTreeSet<_>>().len() == groups.len(), "duplicate LP group names");
        let mut names = BTreeSet::new();
        let mut used = vec![false; extents.len()];
        let mut group_bytes = vec![0u64; groups.len()];
        let mut allocations: Vec<Range<u64>> = Vec::new();
        for p in partitions {
            let pname = name(&p.name)?;
            ensure!(!pname.is_empty() && names.insert(pname.clone()), "empty or duplicate LP partition name");
            ensure!(p.attributes.get() & !ATTR_READONLY == 0, "partition {pname} has snapshot, disabled or unknown attributes");
            let group = p.group_index.get() as usize;
            let group_name = group_names.get(group).context("partition group index out of bounds")?;
            ensure!(group_name != "cow" && !pname.ends_with("-cow"), "cannot repair COW LP metadata");
            let begin = p.first_extent_index.get() as usize;
            let end = begin.checked_add(p.num_extents.get() as usize).context("extent index overflow")?;
            let list = extents.get(begin..end).context("partition extent range out of bounds")?;
            for (own, e) in used[begin..end].iter_mut().zip(list) {
                ensure!(!std::mem::replace(own, true), "LP extent belongs to more than one partition");
                let sectors = e.num_sectors.get();
                ensure!(sectors > 0, "zero-length LP extent");
                let bytes = sectors.checked_mul(SECTOR_SIZE).context("LP extent byte count overflow")?;
                group_bytes[group] = group_bytes[group].checked_add(bytes).context("LP group byte count overflow")?;
                match e.target_type.get() {
                    TARGET_LINEAR => {
                        let start = e.target_data.get();
                        let end = start.checked_add(sectors).context("LP extent end overflow")?;
                        ensure!(e.target_source.get() == 0 && start >= first && end <= bound / SECTOR_SIZE,
                            "partition {pname} has a linear extent outside physical super");
                        allocations.push(start..end);
                    }
                    TARGET_ZERO => ensure!(e.target_data.get() == 0 && e.target_source.get() == 0, "invalid zero extent"),
                    other => bail!("unsupported LP extent type {other}"),
                }
            }
        }
        ensure!(used.into_iter().all(|u| u), "unowned LP extent");
        allocations.sort_unstable_by_key(|r| r.start);
        ensure!(allocations.windows(2).all(|p| p[0].end <= p[1].start), "overlapping LP physical extents");
        for (group, bytes) in groups.iter().zip(group_bytes) {
            let cap = group.maximum_size.get();
            ensure!(cap == 0 || bytes <= cap, "allocated LP group exceeds its quota");
        }
        Ok(())
    }
}

/// Generate full-stride replacement bytes (backup first, then primary). Both
/// copies of each slot must be valid and identical. Returns no writes if all
/// capacity declarations already match, without imposing the mutation-only
/// layout restrictions on such an installation. Only the device capacity
/// and containing header/table checksums change; group quotas and logical
/// partition data/placement are not rewritten.
pub fn repair(prefix: &[u8], actual: u64) -> Result<Vec<(u64, Vec<u8>)>> {
    let g = geometry(prefix)?;
    let stride = g.metadata_max_size as usize;
    ensure!(actual > g.metadata_region() && actual % u64::from(g.logical_block_size) == 0,
        "invalid actual capacity for LP geometry");
    let mut slots = Vec::new();
    for slot in 0..g.metadata_slot_count {
        let at = |offset: u64| prefix.get(offset as usize..offset as usize + stride).context("short LP metadata region");
        let primary = at(g.primary_offset(slot))?;
        let backup = at(g.backup_offset(slot))?;
        ensure!(primary == backup, "LP primary and backup differ for metadata slot {slot}");
        let parsed = checked_copy(&g, primary).with_context(|| format!("LP metadata slot {slot}"))?;
        slots.push((slot, primary, parsed));
    }
    if slots.iter().all(|(_, _, c)| c.devices()[0].size.get() == actual) {
        return Ok(Vec::new());
    }
    let mut backups = Vec::new();
    let mut primaries = Vec::new();
    for (slot, raw, copy) in slots {
        copy.validate_repair(&g, actual).with_context(|| format!("cannot repair LP metadata slot {slot}"))?;
        if copy.devices()[0].size.get() == actual { continue; }
        let cap_at = copy.header_size + copy.header.block_devices.offset.get() as usize + std::mem::offset_of!(RawBlockDevice, size);
        let mut patched = raw.to_vec();
        patched[cap_at..cap_at + size_of::<U64>()].copy_from_slice(&actual.to_le_bytes());
        let end = copy.header_size + copy.tables.len();
        let mut refreshed = copy.header;
        refreshed.tables_checksum = sha256(&patched[copy.header_size..end]);
        refreshed.header_checksum = [0; 32];
        refreshed.header_checksum = sha256(&refreshed.as_bytes()[..copy.header_size]);
        patched[..copy.header_size].copy_from_slice(&refreshed.as_bytes()[..copy.header_size]);
        let verified = checked_copy(&g, &patched)?;
        verified.validate_repair(&g, actual)?;
        ensure!(verified.devices()[0].size.get() == actual, "patched capacity was not recorded");
        backups.push((g.backup_offset(slot), patched.clone()));
        primaries.push((g.primary_offset(slot), patched));
    }
    backups.extend(primaries);
    Ok(backups)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let geometry = Geometry { metadata_max_size: 4096, metadata_slot_count: 3, logical_block_size: 4096 };
        let dev = BlockDevice { partition_name: "super".into(), first_logical_sector: 128,
            alignment: 4096, alignment_offset: 0, size: 131072 };
        single_a::build(geometry, &dev, 65536, &[("system".into(), 8192), ("vendor".into(), 8192)].into()).unwrap().prefix
    }

    #[test]
    fn patch_all_copies_preserving_placement_and_padding() {
        let mut bytes = fixture();
        let g = geometry(&bytes).unwrap();
        let stride = g.metadata_max_size as usize;
        assert_eq!(prefix_len(&bytes[..GEOMETRY_PREFIX]).unwrap(), bytes.len());
        for i in 0..g.metadata_slot_count {
            for offset in [g.primary_offset(i), g.backup_offset(i)] {
                bytes[offset as usize + stride - 1] = 0xa5;
            }
        }
        let edits = repair(&bytes, 98304).unwrap();
        assert_eq!(edits.len(), 6);
        assert!(edits[..3].iter().all(|(at, _)| *at >= g.backup_offset(0)));
        for (at, patch) in edits {
            let pos = at as usize;
            let old = &bytes[pos..pos + stride];
            let old_meta = parse_metadata(&g, old, Some(0)).unwrap();
            let new_meta = parse_metadata(&g, &patch, Some(0)).unwrap();
            let mut expected = old_meta;
            expected.block_devices[0].size = 98304;
            assert_eq!(new_meta, expected);
            let details = checked_copy(&g, old).unwrap();
            let capacity = details.header_size + details.header.block_devices.offset.get() as usize + 16;
            for (i, (&before, &after)) in old.iter().zip(&patch).enumerate() {
                if !(12..44).contains(&i) && !(48..80).contains(&i) && !(capacity..capacity+8).contains(&i) {
                    assert_eq!(before, after, "changed preserved byte {i}");
                }
            }
            bytes[pos..pos + stride].copy_from_slice(&patch);
        }
        assert!(repair(&bytes, 98304).unwrap().is_empty());
    }

    #[test]
    fn reject_corrupt_geometry_copy_divergence_and_out_of_bounds() {
        let mut bytes = fixture();
        assert!(prefix_len(&bytes[..GEOMETRY_PREFIX - 1]).is_err());
        assert!(repair(&bytes, 73728).unwrap_err().to_string().contains("cannot repair"));
        let g = geometry(&bytes).unwrap();
        bytes[g.backup_offset(1) as usize + 12] ^= 1;
        assert!(repair(&bytes, 98304).unwrap_err().to_string().contains("differ"));
        bytes[8192 + 8] ^= 1;
        assert!(prefix_len(&bytes).is_err());
    }

    // Mutate a valid pair so corruption is semantic rather than a digest
    // mismatch, and so the safety checks (not pair identity) must reject it.
    fn alter_copy(bytes: &mut [u8], alter: impl FnOnce(&mut RawHeader, &mut [u8])) {
        let g = geometry(bytes).unwrap();
        let at = g.primary_offset(0) as usize;
        let stride = g.metadata_max_size as usize;
        let mut raw = bytes[at..at + stride].to_vec();
        let c = checked_copy(&g, &raw).unwrap();
        let head_len = c.header_size;
        let data_end = head_len + c.tables.len();
        let mut head = c.header;
        alter(&mut head, &mut raw[head_len..data_end]);
        head.tables_checksum = sha256(&raw[head_len..data_end]);
        head.header_checksum = [0; 32];
        head.header_checksum = sha256(&head.as_bytes()[..head_len]);
        raw[..head_len].copy_from_slice(&head.as_bytes()[..head_len]);
        bytes[at..at + stride].copy_from_slice(&raw);
        let backup = g.backup_offset(0) as usize;
        bytes[backup..backup + stride].copy_from_slice(&raw);
    }

    #[test]
    fn reject_checksummed_overlap_overflow_and_pending_snapshot() {
        for kind in 0..4 {
            let mut bytes = fixture();
            alter_copy(&mut bytes, |head, tables| {
                let e = head.extents.offset.get() as usize;
                let data = std::mem::offset_of!(RawExtent, target_data);
                match kind {
                    0 => tables.copy_within(e + data..e + data + 8, e + size_of::<RawExtent>() + data),
                    1 => tables[e + data..e + data + 8].copy_from_slice(&u64::MAX.to_le_bytes()),
                    2 => head.flags = U32::new(HEADER_FLAG_VIRTUAL_AB_DEVICE | HEADER_FLAG_OVERLAYS_ACTIVE),
                    _ => {
                        let attr = head.partitions.offset.get() as usize + std::mem::offset_of!(RawPartition, attributes);
                        tables[attr..attr + 4].copy_from_slice(&(ATTR_READONLY | ATTR_UPDATED).to_le_bytes());
                    }
                }
            });
            let err = repair(&bytes, 98304).unwrap_err();
            let expected = ["overlapping", "overflow", "overlays", "snapshot"][kind];
            assert!(format!("{err:#}").contains(expected));
        }
    }

    #[test]
    fn captured_prefix_if_supplied() -> Result<()> {
        let Some(path) = std::env::var_os("SKYWARD_LP_CAPTURED_PREFIX") else { return Ok(()); };
        let mut bytes = std::fs::read(path)?;
        let actual = 12_348_030_976;
        assert_eq!(prefix_len(&bytes)?, 405_504);
        let edits = repair(&bytes, actual)?;
        assert_eq!(edits.len(), 6);
        for (at, patch) in edits {
            let at = at as usize;
            bytes[at..at + patch.len()].copy_from_slice(&patch);
        }
        assert!(repair(&bytes, actual)?.is_empty());
        Ok(())
    }
}
