//! Bounded, read-only CrAU v2 planning for self-contained replacement payloads.
//! This is opt-in: it does not replace update_engine, authenticate a package,
//! decode operation blobs, resolve devices/slots, or perform an installation.
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::ops::Range;

const HEADER: usize = 24;
const MAX_MANIFEST: u64 = 8 << 20;
const MAX_SIGNATURE: u64 = 1 << 20;
const MAX_PAYLOAD: u64 = 128 << 30;
const MAX_PARTITION: u64 = 64 << 30;
const MAX_OP_BYTES: u64 = 128 << 20;
const MAX_PARTITIONS: usize = 256;
const MAX_GROUPS: usize = 128;
const MAX_OPS: usize = 65_536;
const MAX_EXTENTS: usize = 262_144;

#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub block_size: u64,
    pub minor_version: u32,
    pub partial_update: bool,
    pub dynamic: Option<DynamicMetadata>,
    pub partitions: Vec<Partition>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DynamicMetadata {
    pub snapshot_enabled: bool,
    pub vabc_enabled: bool,
    pub groups: Vec<DynamicGroup>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DynamicGroup {
    pub name: String,
    /// A logical group quota, not the size of the super block device.
    pub maximum_size: Option<u64>,
    pub partitions: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Partition {
    pub name: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub operations: Vec<Operation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind { Replace, ReplaceXz, ReplaceBz, Zero }

#[derive(Debug, PartialEq, Eq)]
pub struct Operation {
    pub kind: Kind,
    pub data: Option<Blob>,
    /// Byte ranges relative to the partition, in operation order. Do not
    /// sort these to apply an operation; their order defines its byte stream.
    pub targets: Vec<Range<u64>>,
    pub output_size: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Blob {
    /// Absolute byte offsets in the input reader, not payload-relative.
    pub range: Range<u64>,
    pub sha256: [u8; 32],
}

/// Check SHA-256 of the exact raw 24-byte header and manifest (Android
/// METADATA_HASH domain, excluding the metadata signature), then plan.
/// `expected_metadata_hash` may come from payload properties. It does not
/// establish origin/authenticity when those properties are not trusted.
/// On success no operation blob or signature bytes have been read.
pub fn read<R: Read + Seek>(source: &mut R, payload_offset: u64, payload_size: u64, expected_metadata_hash: &[u8; 32]) -> Result<Plan> {
    let (bytes, data_start, payload_end) = read_manifest(source, payload_offset, payload_size, expected_metadata_hash)?;
    manifest(&bytes, data_start, payload_end).context("validate CrAU replacement plan")
}

/// Read only the flags that determine whether OEM Recovery may use the
/// unsafe partial Virtual A/B fallback. Do not require our image planner to
/// understand every operation in order to identify the package class.
pub(crate) fn is_partial_vab<R: Read + Seek>(source: &mut R, payload_offset: u64,
    payload_size: u64, expected_metadata_hash: &[u8; 32]) -> Result<bool> {
    let (bytes, _, _) = read_manifest(source, payload_offset, payload_size, expected_metadata_hash)?;
    partial_vab_flags(&bytes)
}

fn partial_vab_flags(bytes: &[u8]) -> Result<bool> {
    let mut wire = Wire(bytes);
    let (mut partial, mut snapshot) = (None, None);
    while let Some((key, val)) = wire.field()? {
        match key {
            15 => {
                let mut fields = Wire(val.bytes()?);
                let mut enabled = None;
                while let Some((key, val)) = fields.field()? {
                    if key == 2 { once(&mut enabled, val.boolean()?, "snapshot_enabled")?; }
                }
                once(&mut snapshot, enabled.unwrap_or(false), "dynamic_partition_metadata")?;
            }
            16 => once(&mut partial, val.boolean()?, "partial_update")?,
            _ => (),
        }
    }
    Ok(partial == Some(true) && snapshot == Some(true))
}

fn read_manifest<R: Read + Seek>(source: &mut R, payload_offset: u64, payload_size: u64,
    expected_metadata_hash: &[u8; 32]) -> Result<(Vec<u8>, u64, u64)> {
    ensure!((HEADER as u64..=MAX_PAYLOAD).contains(&payload_size), "payload size exceeds planner limits");
    let payload_end = payload_offset.checked_add(payload_size).context("payload end overflow")?;
    ensure!(payload_end <= source.seek(SeekFrom::End(0))?, "payload extends past input");
    source.seek(SeekFrom::Start(payload_offset))?;
    let mut header = [0u8; HEADER];
    source.read_exact(&mut header).context("read CrAU header")?;
    ensure!(&header[..4] == b"CrAU" && u64::from_be_bytes(header[4..12].try_into()?) == 2, "expected CrAU v2");
    let manifest_len = u64::from_be_bytes(header[12..20].try_into()?);
    let meta_signature_len = u64::from(u32::from_be_bytes(header[20..].try_into()?));
    ensure!((1..=MAX_MANIFEST).contains(&manifest_len) && meta_signature_len <= MAX_SIGNATURE, "CrAU metadata exceeds planner limits");
    let data_offset = HEADER as u64 + manifest_len + meta_signature_len;
    ensure!(data_offset <= payload_size, "CrAU metadata extends past payload");
    let mut bytes = vec![0; manifest_len as usize];
    source.read_exact(&mut bytes).context("read exact CrAU manifest")?;
    let actual: [u8; 32] = Sha256::new().chain_update(header).chain_update(&bytes).finalize().into();
    ensure!(&actual == expected_metadata_hash, "CrAU header/manifest SHA-256 mismatch");
    Ok((bytes, payload_offset + data_offset, payload_end))
}

struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn varint(&mut self) -> Result<u64> {
        let mut out = 0;
        for shift in (0..70).step_by(7) {
            let (&b, rest) = self.0.split_first().context("truncated protobuf varint")?;
            self.0 = rest;
            ensure!(shift != 63 || b <= 1, "protobuf varint overflow");
            out |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                ensure!(shift == 0 || b != 0, "non-minimal protobuf varint");
                return Ok(out);
            }
        }
        bail!("protobuf varint overflow")
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let (data, rest) = self.0.split_at_checked(length).context("truncated protobuf field")?;
        self.0 = rest;
        Ok(data)
    }

    fn field(&mut self) -> Result<Option<(u32, Value<'a>)>> {
        if self.0.is_empty() { return Ok(None); }
        let tag = self.varint()?;
        ensure!((1..=0x1fff_ffff).contains(&(tag >> 3)), "invalid protobuf field number");
        let val = match tag & 7 {
            0 => Value::Int(self.varint()?),
            2 => { let len = usize::try_from(self.varint()?)?; Value::Bytes(self.bytes(len)?) },
            _ => bail!("unsupported protobuf wire type {}", tag & 7),
        };
        Ok(Some(((tag >> 3) as u32, val)))
    }
}

#[derive(Clone, Copy)]
enum Value<'a> { Int(u64), Bytes(&'a [u8]) }

impl<'a> Value<'a> {
    fn int(self) -> Result<u64> {
        match self { Self::Int(n) => Ok(n), _ => bail!("expected a protobuf integer") }
    }
    fn bytes(self) -> Result<&'a [u8]> {
        match self { Self::Bytes(b) => Ok(b), _ => bail!("expected a protobuf byte field") }
    }
    fn boolean(self) -> Result<bool> {
        match self.int()? { 0 => Ok(false), 1 => Ok(true), _ => bail!("non-canonical protobuf bool") }
    }
    fn text(self, max: usize) -> Result<&'a str> {
        let bytes = self.bytes()?;
        ensure!(!bytes.is_empty() && bytes.len() <= max && !bytes.contains(&0), "invalid protobuf text length or NUL");
        std::str::from_utf8(bytes).context("protobuf text is not UTF-8")
    }
    fn name(self) -> Result<String> {
        let name = self.text(64)?;
        let first = name.as_bytes()[0];
        ensure!((first.is_ascii_lowercase() || first.is_ascii_digit())
            && name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'), "invalid partition/group name {name:?}");
        Ok(name.to_owned())
    }
}

fn once<T>(target: &mut Option<T>, value: T, name: &str) -> Result<()> {
    ensure!(target.is_none(), "duplicate protobuf {name}");
    *target = Some(value);
    Ok(())
}

fn manifest(bytes: &[u8], data_start: u64, payload_end: u64) -> Result<Plan> {
    let mut wire = Wire(bytes);
    let (mut block_size, mut minor, mut partial, mut signature_at, mut signature_len, mut timestamp, mut dynamic) = (None, None, None, None, None, None, None);
    let mut messages = Vec::new();
    while let Some((key, val)) = wire.field()? {
        match key {
            3 => once(&mut block_size, val.int()?, "block_size")?,
            4 => once(&mut signature_at, val.int()?, "signatures_offset")?,
            5 => once(&mut signature_len, val.int()?, "signatures_size")?,
            12 => once(&mut minor, u32::try_from(val.int()?)?, "minor_version")?,
            13 => {
                ensure!(messages.len() < MAX_PARTITIONS, "too many payload partitions");
                messages.push(val.bytes()?);
            }
            14 => once(&mut timestamp, val.int()?, "max_timestamp")?,
            15 => once(&mut dynamic, parse_dynamic(val.bytes()?)?, "dynamic_partition_metadata")?,
            16 => once(&mut partial, val.boolean()?, "partial_update")?,
            // Apex hints are not needed to plan partition ranges. They are
            // bounded by the checked manifest length and do not affect writes.
            17 => { val.bytes()?; }
            _ => bail!("manifest field {key} is outside the replacement planner profile"),
        }
    }
    let block_size = block_size.unwrap_or(4096);
    ensure!((512..=65536).contains(&block_size) && block_size.is_power_of_two(), "unsupported payload block size");
    let minor_version = minor.unwrap_or(0);
    ensure!(minor_version <= 9, "unreviewed payload minor version {minor_version}");
    ensure!(!messages.is_empty(), "payload contains no partitions");
    let data_end = match (signature_at, signature_len) {
        (None, None) => payload_end,
        (Some(offset), Some(length)) => {
            ensure!((1..=MAX_SIGNATURE).contains(&length), "invalid payload signature length");
            let at = data_start.checked_add(offset).context("payload signature offset overflow")?;
            ensure!(at.checked_add(length) == Some(payload_end), "payload signature is not exactly at payload end");
            at
        }
        _ => bail!("incomplete payload signature geometry"),
    };
    let mut bounds = Bounds { block: block_size, data_start, data_end, operations: 0, extents: 0 };
    let mut partitions = Vec::with_capacity(messages.len());
    let mut sizes = BTreeMap::new();
    for msg in messages {
        let p = partition(msg, &mut bounds)?;
        ensure!(sizes.insert(p.name.clone(), p.size).is_none(), "duplicate payload partition {}", p.name);
        partitions.push(p);
    }
    let mut blobs: Vec<_> = partitions.iter().flat_map(|p| &p.operations).filter_map(|op| op.data.as_ref().map(|b| &b.range)).collect();
    blobs.sort_unstable_by_key(|range| range.start);
    let mut end = data_start;
    for range in blobs {
        ensure!(range.start >= end, "overlapping payload operation blobs");
        end = range.end;
    }
    let partial_update = partial.unwrap_or(false);
    if let Some(meta) = &dynamic {
        for group in &meta.groups {
            let mut included = 0u64;
            for member in &group.partitions {
                match sizes.get(member) {
                    Some(size) => included = included.checked_add(*size).context("dynamic group size overflow")?,
                    None => ensure!(partial_update, "full payload omits dynamic group member {member}"),
                }
            }
            if let Some(max) = group.maximum_size.filter(|n| *n != 0) {
                ensure!(included <= max, "declared images exceed dynamic group quota for {}", group.name);
            }
        }
    }
    Ok(Plan { block_size, minor_version, partial_update, dynamic, partitions })
}

fn parse_dynamic(bytes: &[u8]) -> Result<DynamicMetadata> {
    let mut wire = Wire(bytes);
    let mut groups = Vec::new();
    let mut names = BTreeSet::new();
    let mut members = BTreeSet::new();
    let (mut snapshot, mut vabc, mut compression, mut cow_version) = (None, None, None, None);
    while let Some((key, val)) = wire.field()? {
        match key {
            1 => {
                ensure!(groups.len() < MAX_GROUPS, "too many dynamic groups");
                let group = parse_group(val.bytes()?)?;
                ensure!(names.insert(group.name.clone()), "duplicate dynamic group {}", group.name);
                for p in &group.partitions {
                    ensure!(members.len() < MAX_PARTITIONS && members.insert(p.clone()), "duplicate or excessive dynamic membership: {p}");
                }
                groups.push(group);
            }
            2 => once(&mut snapshot, val.boolean()?, "snapshot_enabled")?,
            3 => once(&mut vabc, val.boolean()?, "vabc_enabled")?,
            4 => once(&mut compression, val.text(64)?, "vabc_compression_param")?,
            5 => once(&mut cow_version, u32::try_from(val.int()?)?, "cow_version")?,
            _ => bail!("unreviewed dynamic metadata field {key}"),
        }
    }
    Ok(DynamicMetadata { snapshot_enabled: snapshot.unwrap_or(false), vabc_enabled: vabc.unwrap_or(false), groups })
}

fn parse_group(bytes: &[u8]) -> Result<DynamicGroup> {
    let mut wire = Wire(bytes);
    let (mut name, mut maximum_size) = (None, None);
    let mut partitions = Vec::new();
    while let Some((key, val)) = wire.field()? {
        match key {
            1 => once(&mut name, val.name()?, "dynamic group name")?,
            2 => once(&mut maximum_size, val.int()?, "dynamic group maximum size")?,
            3 => {
                ensure!(partitions.len() < MAX_PARTITIONS, "too many dynamic group members");
                partitions.push(val.name()?);
            }
            _ => bail!("unknown dynamic group field {key}"),
        }
    }
    Ok(DynamicGroup { name: name.context("missing dynamic group name")?, maximum_size, partitions })
}

struct Bounds {
    block: u64,
    data_start: u64,
    data_end: u64,
    operations: usize,
    extents: usize,
}

fn partition(bytes: &[u8], bounds: &mut Bounds) -> Result<Partition> {
    let mut wire = Wire(bytes);
    let (mut name, mut info, mut version) = (None, None, None);
    let mut operations = Vec::new();
    while let Some((key, val)) = wire.field()? {
        match key {
            1 => once(&mut name, val.name()?, "partition_name")?,
            6 => bail!("old_partition_info is outside the no-source profile"),
            7 => once(&mut info, new_info(val.bytes()?)?, "new_partition_info")?,
            8 => operations.push(operation(val.bytes()?, bounds)?),
            17 => once(&mut version, val.text(128)?, "partition version")?,
            // This planner does not execute postinstall hooks, generate
            // verity/FEC blocks, or plan source-backed COW merge operations.
            _ => bail!("partition field {key} is outside the replacement planner profile"),
        }
    }
    let name = name.context("missing payload partition name")?;
    let (size, sha256) = info.context("missing new_partition_info")?;
    ensure!(size >= bounds.block && size <= MAX_PARTITION && size % bounds.block == 0, "invalid target size for {name}");
    ensure!(!operations.is_empty(), "no operations for {name}");
    let mut targets: Vec<_> = operations.iter().flat_map(|op| &op.targets).collect();
    targets.sort_unstable_by_key(|range| range.start);
    let mut cursor = 0;
    for range in targets {
        ensure!(range.start == cursor && range.end <= size, "gap, overlap or out-of-bounds target extent in {name} at byte {cursor}");
        cursor = range.end;
    }
    ensure!(cursor == size, "incomplete target coverage for {name}");
    Ok(Partition { name, size, sha256, operations })
}

fn new_info(bytes: &[u8]) -> Result<(u64, [u8; 32])> {
    let mut wire = Wire(bytes);
    let (mut size, mut digest) = (None, None);
    while let Some((key, val)) = wire.field()? {
        match key {
            1 => once(&mut size, val.int()?, "target size")?,
            2 => once(&mut digest, val.bytes()?.try_into().context("target SHA-256 must have 32 bytes")?, "target hash")?,
            _ => bail!("unknown partition info field {key}"),
        }
    }
    Ok((size.context("missing target size")?, digest.context("missing target SHA-256")?))
}

fn operation(bytes: &[u8], bounds: &mut Bounds) -> Result<Operation> {
    ensure!(bounds.operations < MAX_OPS, "too many payload operations");
    bounds.operations += 1;
    let mut wire = Wire(bytes);
    let (mut kind, mut offset, mut length, mut output_len, mut digest) = (None, None, None, None, None);
    let mut targets = Vec::new();
    let mut output_size = 0u64;
    while let Some((key, val)) = wire.field()? {
        match key {
            1 => {
                let k = match val.int()? {
                    0 => Kind::Replace, 1 => Kind::ReplaceBz, 8 => Kind::ReplaceXz, 6 => Kind::Zero,
                    other => bail!("operation type {other} is outside the no-source replacement profile"),
                };
                once(&mut kind, k, "operation type")?;
            }
            2 => once(&mut offset, val.int()?, "data_offset")?,
            3 => once(&mut length, val.int()?, "data_length")?,
            4 | 5 | 9 => bail!("operation carries a source-dependent field {key}"),
            6 => {
                ensure!(bounds.extents < MAX_EXTENTS, "too many target extents");
                bounds.extents += 1;
                let target = extent(val.bytes()?, bounds.block)?;
                output_size = output_size.checked_add(target.end - target.start).context("operation output size overflow")?;
                ensure!(output_size <= MAX_OP_BYTES, "operation output exceeds planner limit");
                targets.push(target);
            }
            7 => once(&mut output_len, val.int()?, "dst_length")?,
            8 => once(&mut digest, val.bytes()?, "operation SHA-256")?,
            _ => bail!("unknown operation field {key}"),
        }
    }
    let kind = kind.context("missing operation type")?;
    ensure!(output_size > 0 && output_len.is_none_or(|n| n == output_size), "empty or inconsistent operation output");
    let data = if kind == Kind::Zero {
        ensure!(offset.unwrap_or(0) == 0 && length.unwrap_or(0) == 0 && digest.is_none_or(<[u8]>::is_empty), "ZERO operation unexpectedly has a data blob");
        None
    } else {
        let len = length.context("replacement operation lacks data_length")?;
        ensure!((1..=MAX_OP_BYTES).contains(&len), "invalid replacement data size");
        if kind == Kind::Replace { ensure!(len == output_size, "uncompressed REPLACE size differs from target extents"); }
        let start = bounds.data_start.checked_add(offset.context("replacement operation lacks data_offset")?).context("operation offset overflow")?;
        let end = start.checked_add(len).context("operation end overflow")?;
        ensure!(end <= bounds.data_end, "operation data extends past payload blob area");
        let sha256 = digest.context("replacement operation lacks data SHA-256")?.try_into().context("operation SHA-256 must have 32 bytes")?;
        Some(Blob { range: start..end, sha256 })
    };
    Ok(Operation { kind, data, targets, output_size })
}

fn extent(bytes: &[u8], block: u64) -> Result<Range<u64>> {
    let mut wire = Wire(bytes);
    let (mut start, mut count) = (None, None);
    while let Some((key, val)) = wire.field()? {
        match key {
            1 => once(&mut start, val.int()?, "extent start_block")?,
            2 => once(&mut count, val.int()?, "extent num_blocks")?,
            _ => bail!("unknown extent field {key}"),
        }
    }
    let start = start.context("missing extent start")?;
    let count = count.context("missing extent block count")?;
    ensure!(count > 0, "zero-length target extent");
    let end = start.checked_add(count).and_then(|n| n.checked_mul(block)).context("target extent overflow")?;
    ensure!(end <= MAX_PARTITION, "target extent exceeds planner limit");
    Ok(start.checked_mul(block).context("target extent offset overflow")?..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn v(mut n: u64) -> Vec<u8> {
        let mut b = Vec::new();
        while n >= 128 { b.push((n as u8) | 0x80); n >>= 7; }
        b.push(n as u8);
        b
    }
    fn i(field: u64, n: u64) -> Vec<u8> { [v(field * 8), v(n)].concat() }
    fn b(field: u64, bytes: &[u8]) -> Vec<u8> { [v(field * 8 + 2), v(bytes.len() as u64), bytes.to_vec()].concat() }
    fn target(start: u64, count: u64) -> Vec<u8> { b(6, &[i(1, start), i(2, count)].concat()) }
    fn op(kind: u64, offset: u64, len: u64, targets: &[(u64, u64)]) -> Vec<u8> {
        let mut out = i(1, kind);
        if len != 0 { out.extend([i(2, offset), i(3, len), b(8, &[7; 32])].concat()); }
        for &(start, n) in targets { out.extend(target(start, n)); }
        out
    }
    fn part(name: &[u8], blocks: u64, ops: &[Vec<u8>]) -> Vec<u8> {
        let mut p = [b(1, name), b(7, &[i(1, 4096 * blocks), b(2, &[9; 32])].concat())].concat();
        for op in ops { p.extend(b(8, op)); }
        b(13, &p)
    }
    fn fixture(body: &[u8], data_len: u64) -> (Cursor<Vec<u8>>, u64, u64, [u8; 32]) {
        let header = [b"CrAU".as_slice(), &2u64.to_be_bytes(), &(body.len() as u64).to_be_bytes(), &17u32.to_be_bytes()].concat();
        let digest = Sha256::new().chain_update(&header).chain_update(body).finalize().into();
        let mut data = vec![3; 19];
        data.extend(header);
        data.extend(body);
        data.resize(data.len() + 17 + data_len as usize, 5);
        let size = data.len() as u64 - 19;
        data.extend([6; 13]);
        (Cursor::new(data), 19, size, digest)
    }
    fn plan(bytes: &[u8], data_len: u64) -> Result<Plan> {
        let (mut input, offset, size, digest) = fixture(bytes, data_len);
        read(&mut input, offset, size, &digest)
    }

    #[test]
    fn ota_211_style_partial_plans_all_four_kinds() {
        let group = [b(1, b"main"), i(2, 65536), b(3, b"vendor"), b(3, b"untouched")].concat();
        let meta = [b(1, &group), i(2, 1)].concat();
        let vendor = part(b"vendor", 5, &[op(0, 0, 8192, &[(4, 1), (0, 1)]), op(8, 8192, 9, &[(1, 1)]), op(1, 8201, 10, &[(2, 1)]), op(6, 0, 0, &[(3, 1)])]);
        let bytes = [i(12, 7), i(16, 1), i(4, 8211), i(5, 3), b(15, &meta), vendor].concat();
        let p = plan(&bytes, 8214).unwrap();
        assert_eq!(p.minor_version, 7);
        assert!(p.partial_update);
        let dynamic = p.dynamic.unwrap();
        assert!(dynamic.snapshot_enabled);
        assert_eq!(dynamic.groups[0].partitions, ["vendor", "untouched"]);
        let ops = &p.partitions[0].operations;
        assert_eq!(ops.iter().map(|o| o.kind).collect::<Vec<_>>(), [Kind::Replace, Kind::ReplaceXz, Kind::ReplaceBz, Kind::Zero]);
        assert_eq!(ops[0].targets, [16384..20480, 0..4096]);
        let start = (19 + HEADER + bytes.len() + 17) as u64;
        assert_eq!(ops[0].data.as_ref().unwrap().range, start..start + 8192);
        assert_eq!(ops[3].data, None);
    }

    #[test]
    fn malformed_or_modified_manifest_and_wrong_payload_span_refused() {
        let bytes = part(b"vendor", 1, &[op(6, 0, 0, &[(0, 1)])]);
        let (mut input, off, len, sha) = fixture(&bytes, 0);
        assert!(read(&mut input, off, len, &[42; 32]).is_err());
        assert!(read(&mut input, off, len + 14, &sha).is_err());
        assert!(read(&mut input, off, len - 1, &sha).is_err());
        let (mut input, off, len, sha) = fixture(&bytes, 0);
        input.get_mut()[(off as usize) + HEADER + 3] ^= 1;
        assert!(read(&mut input, off, len, &sha).is_err());
        for bad in [vec![0x18, 0x80], vec![0x18, 0x80, 0], [vec![0x18], vec![0xff; 10]].concat(), i(0, 1)] {
            assert!(plan(&bad, 0).is_err());
        }
    }

    #[test]
    fn refuses_source_ops_and_sparse_gaps_or_overlapping_targets() {
        let source_field = [op(0, 0, 4096, &[(0, 1)]), b(4, &i(1, 0))].concat();
        for ops in [
            vec![op(4, 0, 0, &[(0, 1)])],
            vec![source_field],
            vec![op(6, 0, 0, &[(1, 1)])],
            vec![op(6, 0, 0, &[(0, 2), (1, 1)])],
            vec![op(6, 0, 0, &[(u64::MAX, 2)])],
        ] { assert!(plan(&part(b"vendor", 2, &ops), 4096).is_err()); }
    }

    #[test]
    fn refuses_overlapping_blobs_out_of_bounds_and_signature_reads() {
        let p1 = part(b"system", 1, &[op(0, 0, 4096, &[(0, 1)])]);
        let p2 = part(b"vendor", 1, &[op(8, 4000, 128, &[(0, 1)])]);
        assert!(plan(&[p1.clone(), p2].concat(), 5000).is_err());
        assert!(plan(&p1, 4095).is_err());
        assert!(plan(&[p1, i(4, 4095), i(5, 5)].concat(), 4100).is_err());
    }

    /// Pass a metadata-only fixture obtained from the public .211 ZIP range.
    /// The test reader refuses to hand out a single signature or blob byte.
    #[test]
    fn public_ota_211_metadata_only_fixture() {
        let Some(path) = std::env::var_os("SKYWARD_OTA211_PAYLOAD_HEADER") else { return; };
        const METADATA_END: usize = 263_356;
        const FILE_SIZE: u64 = 7_084_991_019;
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(bytes.len(), 263_623);
        struct HeadOnly(Cursor<Vec<u8>>);
        impl Read for HeadOnly {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                assert!(self.0.position() + b.len() as u64 <= METADATA_END as u64);
                self.0.read(b)
            }
        }
        impl Seek for HeadOnly {
            fn seek(&mut self, s: SeekFrom) -> std::io::Result<u64> {
                match s { SeekFrom::End(0) => Ok(FILE_SIZE), other => self.0.seek(other) }
            }
        }
        let expected = [0xd3, 0x02, 0x07, 0xea, 0x42, 0x53, 0x44, 0xab, 0x79, 0xa8, 0xea, 0x19, 0xec, 0xc7, 0xff, 0xf4,
                        0xe7, 0x6e, 0x64, 0x61, 0x36, 0x04, 0x96, 0x44, 0xa0, 0xc9, 0x50, 0x11, 0xd1, 0xd9, 0xc5, 0x03];
        assert!(is_partial_vab(&mut HeadOnly(Cursor::new(bytes.clone())), 0, FILE_SIZE, &expected).unwrap());
        let plan = read(&mut HeadOnly(Cursor::new(bytes)), 0, FILE_SIZE, &expected).unwrap();
        let compatible = crate::factory_preflight::compatible_pgz_roster(&plan).unwrap();
        assert_eq!(compatible.physical.len(), 25);
        assert!(plan.partial_update);
        let preview = crate::payload_preflight::preview(&plan, crate::payload_preflight::Geometry {
            device_size: 12_348_030_976, data_start: 1 << 20, alignment: 1 << 20,
            alignment_offset: 0, logical_block: 4096,
        }, 335_872, 2_076_672).unwrap();
        assert_eq!(preview.only_a.partition_bytes, [9_380_515_840, 0]);
        assert!(preview.only_a.fits());
        assert!(!preview.two_copies.fits());
        assert!(preview.only_a.slot[0].iter().any(|entry| entry.name == "vendor_dlkm"));
        if let (Some(stock_meta), Some(company), Some(preload)) = (std::env::var_os("SKYWARD_A09_SUPER_META"),
            std::env::var_os("SKYWARD_MY_COMPANY"), std::env::var_os("SKYWARD_MY_PRELOAD")) {
            use std::{io::Write, path::Path};
            let reference = skyward_lp::read_image(Path::new(&stock_meta)).unwrap();
            let [device] = reference.block_devices.as_slice() else { panic!("one OEM super device expected") };
            assert_eq!(device.size, 12_348_030_976);
            assert!(reference.partition("vendor_dlkm_a").is_none());
            let (limit, sizes) = crate::super_image::target_sizes(&plan,
                crate::super_replacement::inspect(Path::new(&company)).unwrap(),
                crate::super_replacement::inspect(Path::new(&preload)).unwrap()).unwrap();
            let layout = skyward_lp::single_a::build(reference.geometry, device, limit, &sizes).unwrap();
            // Independent list from the audited .211 target inventory plus
            // the two explicitly supplied logical images. The fixture uses
            // a simulated signature verdict; it does not authenticate OEM keys.
            let roster = crate::factory_preflight::compatible_pgz_roster(&plan).unwrap();
            assert!(crate::factory_preflight::reviewed_roster(&[0;32]).is_err());
            let replacements = crate::factory_preflight::ReplacementSizes { my_company: 335_872, my_preload: 2_076_672 };
            let check = |authenticated| crate::factory_preflight::check(&plan, authenticated, &reference, device.size, roster, replacements);
            assert!(check(false).is_ok(), "structure alone admits the real package when the caller skips signatures");
            let prepared = check(true).unwrap();
            assert!(prepared.partial_update);
            assert_eq!(prepared.replacements_without_original,
                ["my_company".to_owned(), "my_preload".to_owned()].into_iter().collect());
            assert_eq!(prepared.effective_a_sizes, sizes);
            assert_eq!(prepared.allocated_end, layout.used_end);
            assert_eq!(sizes.values().sum::<u64>(), 9_380_515_840);
            assert!(layout.used_end <= device.size);
            let mut metadata_file = tempfile::NamedTempFile::new().unwrap();
            metadata_file.write_all(&layout.prefix).unwrap();
            for slot in 0..reference.geometry.metadata_slot_count {
                let composed = skyward_lp::read(metadata_file.path(), slot).unwrap();
                assert!(composed.damaged.is_empty());
                assert_eq!(composed.block_devices, reference.block_devices);
                assert!(composed.partition("vendor_dlkm_a").is_some_and(|p| p.bytes() == 52_838_400));
                assert!(composed.partitions.iter().filter(|p| p.name.ends_with("_b")).all(|p| p.bytes() == 0));
                assert_eq!(composed.partitions.len(), 2 * sizes.len());
            }
        }
        let dynamic = plan.dynamic.unwrap();
        assert!(dynamic.snapshot_enabled);
        assert_eq!(dynamic.groups[0].maximum_size, Some(12_343_836_672));
        assert_eq!(dynamic.groups[0].partitions.len(), 15);
        assert_eq!(plan.partitions.len(), 40);
        assert_eq!(plan.partitions.iter().map(|p| p.operations.len()).sum::<usize>(), 4622);
        assert_eq!(plan.partitions.iter().find(|p| p.name == "vendor_boot").unwrap().size, 67_108_864);
        let preloader = plan.partitions.iter().find(|p| p.name == "preloader_raw").unwrap();
        crate::factory_preloader::check_image_bounds(preloader.size, &preloader.sha256).unwrap();
        assert_eq!(preloader.sha256, crate::factory_preloader::IMAGE_211_SHA256);
    }

    #[test]
    fn names_duplicates_and_group_quotas_checked() {
        let zero = op(6, 0, 0, &[(0, 1)]);
        let p1 = part(b"vendor", 1, &[zero.clone()]);
        assert!(plan(&[p1.clone(), p1.clone()].concat(), 0).is_err());
        assert!(plan(&part(b"../boot", 1, &[zero.clone()]), 0).is_err());
        let group = [b(1, b"main"), i(2, 4095), b(3, b"vendor")].concat();
        assert!(plan(&[p1.clone(), b(15, &b(1, &group))].concat(), 0).is_err());
        let duplicate = [b(1, b"main"), b(3, b"vendor"), b(3, b"vendor")].concat();
        assert!(plan(&[p1, b(15, &b(1, &duplicate))].concat(), 0).is_err());
    }
}
