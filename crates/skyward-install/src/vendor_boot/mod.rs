//! Pure Rust PGZ110 vendor_boot repacker. This module never writes a device.
//! It only produces a locally integrity-checked image; signing and activation
//! are different operations and are not performed here.
mod avb;
mod cpio;
mod init;
mod lz4;
pub mod parent_avb;

use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

const CAPACITY: usize = 64 * 1024 * 1024;
const PAGE: usize = 4096;
const MAIN_INIT: &str = "system/etc/init/hw/init.rc";
const PROGRAM: &str = "system/bin/recovery";
const MTP_RC: &str = "system/etc/init/skyward-mtp.rc";
const ASSETS: [&str; 5] = ["skyward/device.toml", "skyward/MiSansVF.ttf", "skyward/KirkMono-Regular.ttf", "skyward/KirkMono-OFL.txt", MTP_RC];

struct Layout {
    ramdisk: Range<usize>,
    dtb: Range<usize>,
    table: Range<usize>,
    bootconfig: Range<usize>,
    end: usize,
}

fn word(b: &[u8], at: usize) -> Result<usize> {
    Ok(u32::from_le_bytes(b.get(at..at+4).context("short vendor_boot field")?.try_into()?) as usize)
}
fn set_word(b: &mut [u8], at: usize, n: usize) -> Result<()> {
    b[at..at+4].copy_from_slice(&u32::try_from(n)?.to_le_bytes());
    Ok(())
}
fn align(n: usize) -> usize { (n + PAGE - 1) & !(PAGE - 1) }

impl Layout {
    fn parse(image: &[u8]) -> Result<Self> {
        ensure!(image.len() == CAPACITY && image.starts_with(b"VNDRBOOT"), "expected the PGZ110 64 MiB vendor_boot image");
        ensure!(word(image, 8)? == 4 && word(image, 12)? == PAGE && word(image, 2096)? == 2128, "expected audited v4 vendor_boot header");
        let ramdisk = word(image, 24)?;
        let dtb = word(image, 2100)?;
        let tab = word(image, 2112)?;
        let bootconfig = word(image, 2124)?;
        ensure!(ramdisk >= 8 && dtb >= 40 && tab == 108 && word(image, 2116)? == 1 && word(image, 2120)? == 108, "expected one v4 ramdisk table entry");
        // Check each section before aligning to avoid trusting attacker sizes.
        let mut cursor = PAGE;
        let mut section = |len: usize| -> Result<Range<usize>> {
            ensure!(len <= CAPACITY && cursor + align(len) <= CAPACITY - PAGE * 2, "vendor_boot sections exceed partition capacity");
            let range = cursor..cursor+len;
            cursor += align(len);
            Ok(range)
        };
        let layout = Self { ramdisk: section(ramdisk)?, dtb: section(dtb)?, table: section(tab)?, bootconfig: section(bootconfig)?, end: cursor };
        let entry = &image[layout.table.clone()];
        ensure!(word(entry, 0)? == ramdisk && word(entry, 4)? == 0 && matches!(word(entry, 8)?, 1 | 2), "not a full single PLATFORM/RECOVERY fragment");
        let dtb = &image[layout.dtb.clone()];
        let be = |at: usize| u32::from_be_bytes(dtb[at..at+4].try_into().expect("checked DTB layout")) as usize;
        ensure!(dtb.len() >= 64 + 40 && be(0) == 0xd7b7ab1e && be(4) == dtb.len() && be(8) == 32
            && be(12) == 32 && be(16) == 1 && be(20) == 32 && be(24) == 2048 && be(28) == 0
            && be(32) == dtb.len()-64 && be(36) == 64 && be(64) == 0xd00dfeed
            && be(68) == dtb.len()-64, "unrecognized PGZ110 Android DTB table or embedded FDT geometry");
        Ok(layout)
    }

    fn rebuild(&self, stock: &[u8], compressed: &[u8]) -> Result<Vec<u8>> {
        let ramdisk_fill = &stock[self.ramdisk.end..self.dtb.start];
        let new_pad = align(compressed.len()) - compressed.len();
        let mut result = Vec::with_capacity(self.end - align(self.ramdisk.len()) + align(compressed.len()));
        result.extend_from_slice(&stock[..PAGE]);
        set_word(&mut result, 24, compressed.len())?;
        result.extend_from_slice(compressed);
        if ramdisk_fill.len() == new_pad {
            result.extend_from_slice(ramdisk_fill);
        } else {
            ensure!(ramdisk_fill.iter().all(|&v| v == 0), "cannot resize ramdisk with nonzero padding");
            result.resize(result.len() + new_pad, 0);
        }
        let tail = result.len();
        result.extend_from_slice(&stock[self.dtb.start..self.end]);
        set_word(&mut result, tail + self.table.start - self.dtb.start, compressed.len())?;
        let image = avb::attach(result, stock.len(), PAGE)?;
        let out = Self::parse(&image)?;
        ensure!(image[..24] == stock[..24] && image[28..PAGE] == stock[28..PAGE]
            && image[out.dtb.start..out.table.start] == stock[self.dtb.start..self.table.start]
            && image[out.table.start+4..out.end] == stock[self.table.start+4..self.end]
            && image[out.bootconfig.clone()] == stock[self.bootconfig.clone()],
            "rebuilt vendor_boot differs outside its ramdisk and length fields");
        Ok(image)
    }
}

fn elf(program: &[u8]) -> Result<()> {
    ensure!(program.len() >= 64 && program.len() <= 48 * 1024 * 1024 && program.starts_with(b"\x7fELF\x02\x01\x01")
        && matches!(&program[16..18], [2, 0] | [3, 0]) && program[18..20] == [183, 0]
        && word(program, 20)? == 1, "recovery is not an AArch64 ELF executable");
    let half = |at: usize| u16::from_le_bytes(program[at..at+2].try_into().expect("known ELF header"));
    let quad = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at+8].try_into().expect("known ELF header"));
    ensure!(half(52) == 64 && half(54) == 56 && (1..=256).contains(&half(56)), "bad ELF program header layout");
    let offset = usize::try_from(quad(program, 32))?;
    let count = usize::from(half(56));
    ensure!(offset >= 64 && offset <= program.len() && count * 56 <= program.len() - offset, "invalid ELF program header bounds");
    let entry = quad(program, 24);
    let mut executable = false;
    for segment in program[offset..offset + count * 56].chunks_exact(56) {
        if word(segment, 0)? != 1 { continue; }
        let (off, addr, filesize, memsize, alignment) = (quad(segment, 8), quad(segment, 16), quad(segment, 32), quad(segment, 40), quad(segment, 48));
        ensure!(filesize <= memsize && off.checked_add(filesize).is_some_and(|end| end <= program.len() as u64), "invalid ELF load segment bounds");
        ensure!(alignment <= 1 || (alignment.is_power_of_two() && off % alignment == addr % alignment), "invalid ELF load alignment");
        let end = addr.checked_add(filesize).context("overflowing ELF address")?;
        executable |= word(segment, 4)? & 1 != 0 && entry >= addr && entry < end;
    }
    ensure!(executable, "ELF entry point is not in an executable load segment");
    Ok(())
}

fn clean_properties(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for line in std::str::from_utf8(bytes).context("non-UTF8 ramdisk properties")?.lines() {
        let key = line.split_once('=').map_or(line, |(key, _)| key).trim();
        if key.starts_with("ro.") && ["build.version.release", "build.version.release_or_codename", "build.version.security_patch", "build.security_patch"].iter().any(|suffix| key.ends_with(suffix)) { continue; }
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

/// Construct a full partition image from clean, audited stock vendor_boot.
/// Changes only the recovery executable, the audited init program policy,
/// pinned OS/SPL properties, and the five supplied Recovery resources. The
/// caller is responsible for establishing actual stock provenance, matching
/// the slot's boot/dtbo, and deciding whether device AVB will accept the result.
pub fn repack(stock: &[u8], recovery: &[u8], assets: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    repack_with(stock, recovery, assets, encoder())
}

/// Stock vendor_boot images leave little room for a larger recovery program.
/// Prefer the high-compression encoder wherever it is compiled in.
fn encoder() -> fn(&[u8], usize) -> Result<Vec<u8>> {
    #[cfg(feature = "lz4-sys")]
    { lz4::encode_hc }
    #[cfg(not(feature = "lz4-sys"))]
    { lz4::encode }
}

/// The mobile porter uses LZ4 HC level 12 on space-constrained stock images.
/// Every structural and independent round-trip check is shared with repack.
#[cfg(feature = "lz4-sys")]
pub fn repack_hc(stock: &[u8], recovery: &[u8], assets: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    repack_with(stock, recovery, assets, lz4::encode_hc)
}

fn repack_with(stock: &[u8], recovery: &[u8], assets: &[(&str, &[u8])],
    encode: fn(&[u8], usize) -> Result<Vec<u8>>) -> Result<Vec<u8>> {
    let layout = Layout::parse(stock)?;
    avb::verify(stock, layout.end, true).context("verify original vendor_boot AVB data")?;
    elf(recovery)?;
    let decoded = lz4::decode(&stock[layout.ramdisk.clone()])?;
    let archive = cpio::Archive::parse(&decoded)?;
    elf(archive.regular(PROGRAM)?).context("invalid stock recovery program")?;
    ensure!(!archive.names().any(|name| name == "skyward" || name.starts_with("skyward/") || name == MTP_RC
        || name.starts_with("system/bin/skyward-")), "vendor_boot contains a prior Skyward customization");
    let mut edits = BTreeMap::from([(PROGRAM, recovery.to_vec())]);
    ensure!(assets.len() == ASSETS.len(), "incomplete native repack assets");
    for &(name, bytes) in assets {
        ensure!(ASSETS.contains(&name) && !bytes.is_empty() && bytes.len() <= 32 * 1024 * 1024, "unknown or invalid native repack asset {name}");
        ensure!(edits.insert(name, bytes.to_vec()).is_none(), "repeated native repack asset {name}");
    }
    archive.regular(MAIN_INIT)?;
    let mut scripts = BTreeMap::new();
    for name in archive.names().filter(|path| path.ends_with(".rc")) {
        let script = archive.regular(name)?;
        ensure!(script.len() <= 1024 * 1024, "oversized stock rc {name}");
        scripts.insert(name.to_owned(), script.to_vec());
    }
    edits.insert(MAIN_INIT, init::adapt_init(&scripts)?);
    for name in ["prop.default", "system/build.prop", "vendor/build.prop"] {
        if archive.contains(name) {
            let before = archive.regular(name)?;
            let after = clean_properties(before)?;
            if after != before { edits.insert(name, after); }
        }
    }
    let max_compressed = stock.len() - (layout.end - align(layout.ramdisk.len())) - PAGE * 2;
    // Stock images of some firmware generations leave no room for the
    // Recovery program. The stock Chinese fallback font is a duplicate of
    // what the program itself carries, so it goes first; nothing else is
    // dropped, and a second failure is reported as it came.
    let compressed = match attempt(&archive, &edits, &BTreeSet::new(), max_compressed, encode) {
        Ok(image) => image,
        Err(error) => {
            ensure!(archive.contains(DUPLICATE_CJK_FONT),
                "compressed ramdisk does not fit the target image and it carries no duplicate font to drop: {error:#}");
            attempt(&archive, &edits, &BTreeSet::from([DUPLICATE_CJK_FONT]), max_compressed, encode)
                .with_context(|| format!("compressed ramdisk does not fit the target image: {error:#}"))?
        }
    };
    layout.rebuild(stock, &compressed)
}

/// The stock Chinese fallback font: the Recovery program brings its own.
const DUPLICATE_CJK_FONT: &str = "res/OplusOS/ttf/DroidSansFallback.ttf";

fn attempt(archive: &cpio::Archive<'_>, edits: &BTreeMap<&str, Vec<u8>>, dropped: &BTreeSet<&str>,
    max_compressed: usize, encode: fn(&[u8], usize) -> Result<Vec<u8>>) -> Result<Vec<u8>> {
    let raw = archive.rebuild_without(edits, dropped)?;
    let compressed = encode(&raw, max_compressed)?;
    let roundtrip = lz4::decode(&compressed)?;
    ensure!(roundtrip == raw, "repacked LZ4 bytes failed independent decoder roundtrip");
    archive.verify_without(&cpio::Archive::parse(&roundtrip)?, edits, dropped)?;
    Ok(compressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_and_spl_properties_only() {
        assert_eq!(clean_properties(b"ro.build.version.release=12\nro.vendor.build.security_patch=2022-09-05\nro.build.version.sdk=31\nro.adb.secure=1\n").unwrap(),
            b"ro.build.version.sdk=31\nro.adb.secure=1\n");
    }

    // Optional local fixture exercise: never embeds a proprietary image.
    #[test]
    fn real_native_repack() {
        let (Ok(stock), Ok(program), Ok(assets)) = (std::env::var("SKYWARD_STOCK_VENDOR_BOOT"), std::env::var("SKYWARD_REPACK_ELF"), std::env::var("SKYWARD_REPACK_ASSETS")) else { return; };
        let assets = std::path::Path::new(&assets);
        let owned = ASSETS.map(|path| std::fs::read(assets.join(path)).unwrap());
        let supplied: Vec<_> = ASSETS.into_iter().zip(owned.iter().map(Vec::as_slice)).collect();
        let image = repack(&std::fs::read(stock).unwrap(), &std::fs::read(program).unwrap(), &supplied).unwrap();
        if let Ok(path) = std::env::var("SKYWARD_REPACK_OUTPUT") {
            use std::io::Write;
            std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap().write_all(&image).unwrap();
        }
    }
}
