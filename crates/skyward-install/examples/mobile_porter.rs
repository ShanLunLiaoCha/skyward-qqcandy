//! Regular-file-only helper for the Android porter. No Root or block writes.
use anyhow::{Context, Result, ensure};
use skyward_install::vendor_boot::{self, parent_avb::{assess, ParentBinding}};
use std::{fs::{File, OpenOptions}, io::{Read, Write}, path::Path};

fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && meta.len() <= limit, "expected bounded regular input");
    let mut data = Vec::new();
    file.take(limit + 1).read_to_end(&mut data)?;
    ensure!(data.len() as u64 == meta.len(), "input length changed");
    Ok(data)
}

fn put(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[path = "mobile_porter_helper/block_write.rs"]
mod block_write;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--flash") {
        return block_write::flash(&args[1..]);
    }
    let [stock, parent, donor, out, avb] = &args[..] else {
        anyhow::bail!("usage: mobile_porter STOCK VBMETA DONOR_DIR NEW_VENDOR_BOOT NEW_VBMETA");
    };
    let donor = Path::new(donor);
    let stock = read(Path::new(stock), 64 << 20)?;
    let mut parent = read(Path::new(parent), 8 << 20)?;
    ensure!(stock.len() == 64 << 20 && parent.len() == 8 << 20, "unsupported partition sizes");
    let elf = read(&donor.join("system/bin/recovery"), 32 << 20)?;
    let names = ["skyward/device.toml", "skyward/MiSansVF.ttf", "skyward/KirkMono-Regular.ttf",
        "skyward/KirkMono-OFL.txt", "system/etc/init/skyward-mtp.rc"];
    let contents = names.iter().map(|name| read(&donor.join(name), 32 << 20)).collect::<Result<Vec<_>>>()?;
    let assets: Vec<_> = names.into_iter().zip(contents.iter().map(Vec::as_slice)).collect();
    let image = vendor_boot::repack_hc(&stock, &elf, &assets)?;
    // The physical backup includes padding beyond the supported AVB header.
    let compact = parent.get(..1 << 20).context("vbmeta prefix")?;
    ensure!(parent[1 << 20..].iter().all(|&b| b == 0), "nonzero trailing vbmeta data");
    ensure!(assess(compact, &stock, &image)? == ParentBinding::RejectsCandidate,
        "top-level stock vbmeta does not directly bind this original vendor_boot");
    let flags = parent.get_mut(120..124).context("missing AVB flags")?;
    ensure!(flags == [0; 4], "expected stock vbmeta flags");
    flags.copy_from_slice(&3u32.to_be_bytes());
    put(Path::new(out), &image)?;
    put(Path::new(avb), &parent)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_is_never_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("image");
        put(&path, b"old").unwrap();
        assert!(put(&path, b"new").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"old");
    }
}
