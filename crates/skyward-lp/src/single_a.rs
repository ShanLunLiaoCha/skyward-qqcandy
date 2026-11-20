//! Offline builder for the launch Virtual A/B factory layout used by PGZ110.
//! The input sizes must describe the complete target roster, not the current slot.
//! This emits metadata only; it neither populates nor activates a partition.
use super::*;
use std::collections::BTreeMap;

const MAX_METADATA_SIZE: u32 = 1 << 20;
const A_GROUP: u32 = 1;
const B_GROUP: u32 = 2;

#[derive(Debug, PartialEq, Eq)]
pub struct Layout {
    /// Reserved bytes and all primary/backup geometry and metadata copies.
    pub prefix: Vec<u8>,
    /// A-slot extent byte offset by unsuffixed base name (no B allocations).
    pub offsets: BTreeMap<String, u64>,
    /// Exclusive end of the last allocated A extent, including alignment gaps.
    pub used_end: u64,
}

fn field_name(s: &str) -> Result<[u8; NAME_LEN]> {
    ensure!(!s.is_empty() && s.len() <= NAME_LEN
        && s.bytes().all(|ch| ch.is_ascii_alphanumeric() || ch == b'_'), "invalid LP name {s:?}");
    let mut field = [0; NAME_LEN];
    field[..s.len()].copy_from_slice(s.as_bytes());
    Ok(field)
}

fn append<T: IntoBytes + Immutable>(tables: &mut Vec<u8>, entries: &[T]) -> Result<RawTable> {
    let d = RawTable {
        offset: U32::new(tables.len().try_into()?),
        num_entries: U32::new(entries.len().try_into()?),
        entry_size: U32::new(size_of::<T>().try_into()?),
    };
    for item in entries { tables.extend_from_slice(item.as_bytes()); }
    Ok(d)
}

/// Build a single physical `super` prefix with A populated and B empty.
///
/// Metadata slots are not Android boot slots: PGZ110 factory tooling may also
/// reserve a third metadata copy. All slots receive the same initial table,
/// with one readonly linear extent per `_a` row and zero extents per `_b` row.
/// `group_limit == 0` means no explicit group limit, as in the LP format.
/// Only PGZ110's audited zero alignment offset is supported.
pub fn build(geometry: Geometry, device: &BlockDevice, group_limit: u64, sizes: &BTreeMap<String, u64>) -> Result<Layout> {
    let logical = u64::from(geometry.logical_block_size);
    ensure!(matches!(geometry.metadata_slot_count, 2 | 3), "expected two or three LP metadata slots");
    ensure!(geometry.metadata_max_size >= size_of::<RawHeader>() as u32
        && geometry.metadata_max_size <= MAX_METADATA_SIZE
        && u64::from(geometry.metadata_max_size) % SECTOR_SIZE == 0, "invalid metadata slot capacity");
    ensure!(logical >= SECTOR_SIZE && logical.is_power_of_two() && device.size % logical == 0, "invalid logical block or super size");
    ensure!(device.partition_name == "super", "expected a single physical super block device");
    ensure!(device.alignment_offset == 0, "unsupported nonzero super alignment offset");
    let alignment = u64::from(device.alignment).max(logical);
    ensure!(u64::from(device.alignment) % logical == 0, "super alignment is not a multiple of its logical block size");
    let mut cursor = device.first_logical_sector.checked_mul(SECTOR_SIZE).context("first logical sector overflows")?;
    let prefix_size = geometry.metadata_region();
    ensure!(cursor >= prefix_size && cursor < device.size && cursor % logical == 0, "invalid start of logical super space");
    ensure!(!sizes.is_empty(), "empty target partition roster");
    let row_bytes = 2 * size_of::<RawPartition>() + size_of::<RawExtent>();
    let fixed_bytes = size_of::<RawHeader>() + 3 * size_of::<RawGroup>() + size_of::<RawBlockDevice>();
    let required = sizes.len().checked_mul(row_bytes).and_then(|n| n.checked_add(fixed_bytes)).context("LP table size overflow")?;
    ensure!(required <= geometry.metadata_max_size as usize, "LP tables do not fit the metadata slot");

    let mut offsets = BTreeMap::new();
    let mut partitions = Vec::new();
    let mut extents = Vec::new();
    let mut total = 0u64;
    for (base, &bytes) in sizes {
        ensure!(!base.is_empty() && !base.ends_with("_a") && !base.ends_with("_b"), "expected unsuffixed LP name: {base:?}");
        let name_a = field_name(&format!("{base}_a"))?;
        let name_b = field_name(&format!("{base}_b"))?;
        ensure!(bytes > 0 && bytes % logical == 0, "partition {base} has an empty or unaligned payload");
        total = total.checked_add(bytes).context("group length overflows")?;
        ensure!(group_limit == 0 || total <= group_limit, "A slot exceeds its group limit");
        let gap = (alignment - cursor % alignment) % alignment;
        let offset = cursor.checked_add(gap).context("aligned LP start overflows")?;
        cursor = offset.checked_add(bytes).context("LP extent end overflows")?;
        ensure!(cursor <= device.size, "A slot exceeds physical super space at {base}");
        offsets.insert(base.clone(), offset);
        let first_extent_index = U32::new(extents.len().try_into()?);
        extents.push(RawExtent {
            num_sectors: U64::new(bytes / SECTOR_SIZE),
            target_type: U32::new(TARGET_LINEAR),
            target_data: U64::new(offset / SECTOR_SIZE),
            target_source: U32::new(0),
        });
        partitions.push(RawPartition {
            name: name_a, attributes: U32::new(ATTR_READONLY), first_extent_index,
            num_extents: U32::new(1), group_index: U32::new(A_GROUP),
        });
        partitions.push(RawPartition {
            name: name_b, attributes: U32::new(ATTR_READONLY),
            first_extent_index: U32::new(extents.len().try_into()?),
            num_extents: U32::new(0), group_index: U32::new(B_GROUP),
        });
    }
    let groups = [("default", 0), ("main_a", group_limit), ("main_b", group_limit)].map(|(name, limit)| RawGroup {
        name: field_name(name).expect("static LP group names"), flags: U32::new(0), maximum_size: U64::new(limit),
    });
    let storage = RawBlockDevice {
        first_logical_sector: U64::new(device.first_logical_sector), alignment: U32::new(device.alignment),
        alignment_offset: U32::new(device.alignment_offset), size: U64::new(device.size),
        partition_name: field_name(&device.partition_name)?, flags: U32::new(0),
    };
    let mut tables = Vec::new();
    let partitions = append(&mut tables, &partitions)?;
    let extents = append(&mut tables, &extents)?;
    let groups = append(&mut tables, &groups)?;
    let block_devices = append(&mut tables, &[storage])?;
    let mut header = RawHeader {
        magic: U32::new(HEADER_MAGIC), major_version: U16::new(MAJOR_VERSION), minor_version: U16::new(VERSION_FOR_EXPANDED_HEADER),
        header_size: U32::new(size_of::<RawHeader>() as u32), header_checksum: [0; 32],
        tables_size: U32::new(tables.len().try_into()?), tables_checksum: sha256(&tables), partitions, extents, groups, block_devices,
        flags: U32::new(HEADER_FLAG_VIRTUAL_AB_DEVICE), reserved: [0; 124],
    };
    header.header_checksum = sha256(header.as_bytes());
    let mut raw_geometry = RawGeometry {
        magic: U32::new(GEOMETRY_MAGIC), struct_size: U32::new(size_of::<RawGeometry>() as u32), checksum: [0; 32],
        metadata_max_size: U32::new(geometry.metadata_max_size), metadata_slot_count: U32::new(geometry.metadata_slot_count),
        logical_block_size: U32::new(geometry.logical_block_size),
    };
    raw_geometry.checksum = sha256(raw_geometry.as_bytes());
    let mut prefix = vec![0; prefix_size.try_into()?];
    for copy in [RESERVED_BYTES, RESERVED_BYTES + GEOMETRY_SIZE] {
        let at = copy as usize;
        prefix[at..at + size_of::<RawGeometry>()].copy_from_slice(raw_geometry.as_bytes());
    }
    for slot in 0..geometry.metadata_slot_count {
        for copy in [geometry.primary_offset(slot), geometry.backup_offset(slot)] {
            let at = copy as usize;
            let content = at + size_of::<RawHeader>();
            prefix[at..content].copy_from_slice(header.as_bytes());
            prefix[content..content + tables.len()].copy_from_slice(&tables);
        }
    }
    Ok(Layout { prefix, offsets, used_end: cursor })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn fixture(slots: u32) -> (Geometry, BlockDevice, BTreeMap<String, u64>) {
        (Geometry { metadata_max_size: 65_536, metadata_slot_count: slots, logical_block_size: 4096 },
         BlockDevice { partition_name: "super".into(), first_logical_sector: 2048, alignment: 1 << 20, alignment_offset: 0, size: 16 << 20 },
         BTreeMap::from([("my_preload".into(), 8192), ("system".into(), 3 << 20), ("vendor".into(), 4096)]))
    }
    struct Scratch(PathBuf);
    impl Drop for Scratch { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
    fn sparse(layout: &Layout, device_size: u64) -> Scratch {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!("skyward-single-a-{}-{}.img", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let mut file = OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let guard = Scratch(path);
        file.set_len(device_size).unwrap();
        file.write_all(&layout.prefix).unwrap();
        guard
    }

    #[test]
    fn both_primary_and_backup_slots_read_but_b_has_no_extents() {
        for slots in [2, 3] {
            let (g, d, sizes) = fixture(slots);
            let layout = build(g, &d, 8 << 20, &sizes).unwrap();
            assert_eq!(layout, build(g, &d, 8 << 20, &sizes).unwrap());
            assert_eq!(layout.prefix.len() as u64, g.metadata_region());
            assert!(layout.prefix[..RESERVED_BYTES as usize].iter().all(|&n| n == 0));
            assert_eq!(layout.offsets, BTreeMap::from([("my_preload".into(), 1 << 20), ("system".into(), 2 << 20), ("vendor".into(), 5 << 20)]));
            assert_eq!(layout.used_end, (5 << 20) + 4096);
            let file = sparse(&layout, d.size);
            let mut original = Vec::new();
            for slot in 0..slots {
                let md = read(&file.0, slot).unwrap();
                assert!(md.damaged.is_empty());
                assert_eq!(md.geometry, g);
                assert_eq!(md.block_devices, [d.clone()]);
                assert_eq!((md.major_version, md.minor_version, md.header_flags), (10, 2, HEADER_FLAG_VIRTUAL_AB_DEVICE));
                assert_eq!(md.groups.iter().map(|g| (g.name.as_str(), g.maximum_size)).collect::<Vec<_>>(),
                    [("default", 0), ("main_a", 8 << 20), ("main_b", 8 << 20)]);
                for (base, &size) in &sizes {
                    let a = md.partition(&format!("{base}_a")).unwrap();
                    let b = md.partition(&format!("{base}_b")).unwrap();
                    assert_eq!(a.extents, [Extent::Linear { sectors: size / SECTOR_SIZE, device: 0, sector: layout.offsets[base] / SECTOR_SIZE }]);
                    assert_eq!((a.group, b.group), (A_GROUP as usize, B_GROUP as usize));
                    assert_eq!((a.attributes, b.attributes), (ATTR_READONLY, ATTR_READONLY));
                    assert!(b.extents.is_empty());
                }
                assert_eq!(md.partitions.len(), 2 * sizes.len());
                original.push(md);
            }
            assert!(read(&file.0, slots).is_err());
            let fd = OpenOptions::new().write(true).open(&file.0).unwrap();
            fd.write_all_at(&[0], RESERVED_BYTES).unwrap();
            for slot in 0..slots {
                fd.write_all_at(&[0], g.primary_offset(slot)).unwrap();
                let mut fallback = read(&file.0, slot).unwrap();
                assert_eq!(fallback.damaged.len(), 2);
                fallback.damaged.clear();
                assert_eq!(fallback, original[slot as usize]);
            }
        }
    }

    #[test]
    fn rejects_bad_geometry_names_and_group_or_physical_overflow() {
        let (g, mut d, mut sizes) = fixture(2);
        assert!(build(g, &d, 8192, &sizes).is_err());
        d.size = 5 << 20;
        assert!(build(g, &d, 0, &sizes).is_err());
        d.size = 16 << 20;
        sizes.insert("system_b".into(), 4096);
        assert!(build(g, &d, 0, &sizes).is_err());
        sizes.remove("system_b");
        assert!(build(Geometry { metadata_max_size: 512, ..g }, &d, 0, &sizes).is_err());
        assert!(build(Geometry { metadata_slot_count: 1, ..g }, &d, 0, &sizes).is_err());
        d.first_logical_sector = u64::MAX;
        assert!(build(g, &d, 0, &sizes).is_err());
        d.first_logical_sector = 8;
        assert!(build(g, &d, 0, &sizes).is_err());
    }
}
