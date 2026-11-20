//! Bounded newc/crc archive operations. Unchanged records retain exact bytes.
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

const DIR: u32 = 0o040000;
const REG: u32 = 0o100000;
const TYPE: u32 = 0o170000;
const TRAILER: &str = "TRAILER!!!";
const MAX_FILES: usize = 12_000;
const MAX_NAME: usize = 4096;

fn aligned(n: usize) -> usize { (n + 3) & !3 }
fn canonical(mut name: &str) -> Result<&str> {
    while let Some(rest) = name.strip_prefix("./") { name = rest; }
    if name == "." { return Ok(""); }
    ensure!(!name.contains(['\\', ':']) && name.split('/').all(|s| !s.is_empty() && s != "." && s != ".."), "unsafe CPIO path {name:?}");
    Ok(name)
}

struct Entry<'a> {
    name: &'a str,
    key: &'a str,
    data: &'a [u8],
    raw: &'a [u8],
    fields: [u32; 13],
    crc: bool,
}

impl Entry<'_> {
    fn mode(&self) -> u32 { self.fields[1] }
    fn inode(&self) -> (u32, u32, u32) { (self.fields[0], self.fields[7], self.fields[8]) }
}

pub(super) struct Archive<'a> {
    entries: Vec<Entry<'a>>,
    paths: BTreeMap<&'a str, usize>,
    trailer: &'a [u8],
    new_inode: u32,
    aliased: BTreeSet<(u32,u32,u32)>,
}

impl<'a> Archive<'a> {
    pub(super) fn parse(mut input: &'a [u8]) -> Result<Self> {
        let mut entries = Vec::new();
        let mut paths = BTreeMap::new();
        let mut new_inode = 0;
        let mut inodes = BTreeSet::new();
        let mut aliased = BTreeSet::new();
        let trailer = loop {
            let header = input.get(..110).context("truncated CPIO header")?;
            let crc = match &header[..6] {
                b"070701" => false,
                b"070702" => true,
                _ => anyhow::bail!("unrecognized CPIO format"),
            };
            let mut fields = [0; 13];
            for (i, data) in header[6..].chunks_exact(8).enumerate() {
                ensure!(data.iter().all(u8::is_ascii_hexdigit), "invalid CPIO numeric field");
                fields[i] = u32::from_str_radix(std::str::from_utf8(data)?, 16)?;
            }
            let namesize = fields[11] as usize;
            ensure!((1..=MAX_NAME).contains(&namesize), "invalid CPIO filename length");
            let name_end = 110 + namesize;
            let bytes = input.get(110..name_end).context("truncated CPIO name")?;
            let bytes = bytes.strip_suffix(&[0]).context("missing CPIO NUL terminator")?;
            ensure!(!bytes.contains(&0), "embedded CPIO NUL");
            let name = std::str::from_utf8(bytes).context("non-UTF8 CPIO name")?;
            let data_start = aligned(name_end);
            let end = data_start.checked_add(fields[6] as usize).context("CPIO overflow")?;
            let data = input.get(data_start..end).context("truncated CPIO contents")?;
            let raw = input.get(..aligned(end)).context("truncated CPIO padding")?;
            if crc { ensure!(checksum(data) == fields[12], "CPIO checksum mismatch at {name}"); }
            if name == TRAILER {
                ensure!(data.is_empty() && input[raw.len()..].iter().all(|v| *v == 0), "extra CPIO archive or invalid trailer");
                break input;
            }
            let key = canonical(name)?;
            ensure!(entries.len() < MAX_FILES, "too many ramdisk entries");
            ensure!(paths.insert(key, entries.len()).is_none(), "duplicate CPIO path {name}");
            let entry = Entry { name, key, data, raw, fields, crc };
            if entry.mode() & TYPE == REG && !inodes.insert(entry.inode()) { aliased.insert(entry.inode()); }
            new_inode = new_inode.max(fields[0]);
            entries.push(entry);
            input = &input[raw.len()..];
        };
        let this = Self { entries, paths, trailer, new_inode, aliased };
        if let Some(entry) = this.entry("") { ensure!(entry.mode() & TYPE == DIR, "CPIO root is not a directory"); }
        for entry in &this.entries {
            let mut path = entry.key;
            while let Some((parent, _)) = path.rsplit_once('/') {
                if let Some(p) = this.entry(parent) { ensure!(p.mode() & TYPE == DIR, "CPIO parent {parent} is not a directory"); }
                path = parent;
            }
        }
        Ok(this)
    }

    fn entry(&self, name: &str) -> Option<&Entry<'a>> { self.paths.get(name).map(|i| &self.entries[*i]) }

    pub(super) fn contains(&self, name: &str) -> bool { self.paths.contains_key(name) }

    pub(super) fn regular(&self, name: &str) -> Result<&'a [u8]> {
        let e = self.entry(name).with_context(|| format!("missing stock {name}"))?;
        ensure!(e.mode() & TYPE == REG && e.fields[4] == 1 && !self.aliased.contains(&e.inode()), "{name} is not a single-link stock file");
        Ok(e.data)
    }

    pub(super) fn names(&self) -> impl Iterator<Item = &'a str> + '_ { self.entries.iter().map(|e| e.key) }

    pub(super) fn rebuild(&self, edits: &BTreeMap<&str, Vec<u8>>) -> Result<Vec<u8>> {
        self.rebuild_without(edits, &BTreeSet::new())
    }

    /// Rebuild, leaving out `dropped` stock records entirely: a duplicate
    /// asset may be removed to make room for the Recovery program.
    pub(super) fn rebuild_without(&self, edits: &BTreeMap<&str, Vec<u8>>, dropped: &BTreeSet<&str>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for e in &self.entries {
            if dropped.contains(e.key) { continue; }
            if let Some(data) = edits.get(e.key) {
                self.regular(e.key)?;
                write(&mut out, e.name, data, e.fields, e.crc)?;
            } else {
                out.extend_from_slice(e.raw);
            }
        }
        let mut created = BTreeSet::new();
        let mut inode = self.new_inode;
        for (&name, data) in edits {
            ensure!(canonical(name)? == name && !name.is_empty() && name != TRAILER, "invalid replacement path");
            if self.contains(name) { continue; }
            let mut dirs = Vec::new();
            let mut path = name;
            while let Some((parent, _)) = path.rsplit_once('/') { dirs.push(parent); path = parent; }
            for parent in dirs.into_iter().rev() {
                if let Some(e) = self.entry(parent) {
                    ensure!(e.mode() & TYPE == DIR, "replacement parent is not a directory");
                } else if created.insert(parent) {
                    inode = inode.checked_add(1).context("CPIO inode overflow")?;
                    write(&mut out, parent, &[], fresh(inode, DIR | 0o755), false)?;
                }
            }
            ensure!(created.insert(name), "replacement path collides with a replacement parent");
            inode = inode.checked_add(1).context("CPIO inode overflow")?;
            write(&mut out, name, data, fresh(inode, REG | 0o644), false)?;
        }
        out.extend_from_slice(self.trailer);
        Ok(out)
    }

    pub(super) fn verify(&self, rebuilt: &Archive<'_>, edits: &BTreeMap<&str, Vec<u8>>) -> Result<()> {
        self.verify_without(rebuilt, edits, &BTreeSet::new())
    }

    pub(super) fn verify_without(&self, rebuilt: &Archive<'_>, edits: &BTreeMap<&str, Vec<u8>>, dropped: &BTreeSet<&str>) -> Result<()> {
        for e in &self.entries {
            if dropped.contains(e.key) { ensure!(rebuilt.entry(e.key).is_none(), "dropped record is still present: {}", e.key); continue; }
            if !edits.contains_key(e.key) {
                ensure!(rebuilt.entry(e.key).is_some_and(|after| after.raw == e.raw), "stock CPIO record changed: {}", e.key);
            }
        }
        for (name, expected) in edits { ensure!(rebuilt.regular(name)? == *expected, "CPIO verification failed for {name}"); }
        Ok(())
    }
}

fn checksum(data: &[u8]) -> u32 { data.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte))) }
fn fresh(inode: u32, mode: u32) -> [u32; 13] { [inode, mode, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0] }
fn write(out: &mut Vec<u8>, name: &str, data: &[u8], mut fields: [u32; 13], crc: bool) -> Result<()> {
    fields[6] = data.len().try_into()?;
    fields[11] = (name.len() + 1).try_into()?;
    fields[12] = if crc { checksum(data) } else { 0 };
    out.extend_from_slice(if crc { b"070702" } else { b"070701" });
    for field in fields { out.extend_from_slice(format!("{field:08x}").as_bytes()); }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.resize(aligned(out.len()), 0);
    out.extend_from_slice(data);
    out.resize(aligned(out.len()), 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stock_records_are_preserved_and_changed_crc_is_valid() {
        let mut input = vec![];
        write(&mut input, "system", &[], fresh(1, DIR | 0o755), false).unwrap();
        write(&mut input, "system/original", b"old", fresh(2, REG | 0o755), true).unwrap();
        write(&mut input, "stock", &[1,2,3], fresh(3, REG | 0o600), false).unwrap();
        write(&mut input, TRAILER, &[], fresh(4, 0), false).unwrap();
        let stock = Archive::parse(&input).unwrap();
        let edits = BTreeMap::from([("system/original", b"test".to_vec()), ("new/added", b"asset".to_vec())]);
        let raw = stock.rebuild(&edits).unwrap();
        let output = Archive::parse(&raw).unwrap();
        stock.verify(&output, &edits).unwrap();
        assert_eq!(output.entry("system/original").unwrap().mode(), REG | 0o755);
        assert!(stock.rebuild(&BTreeMap::from([("stock/unsafe", vec![])])).is_err());
    }
}
