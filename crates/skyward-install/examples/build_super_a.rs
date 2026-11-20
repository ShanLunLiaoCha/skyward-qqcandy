//! Host acceptance exercise of the Recovery single-A super builder.
//! Only ordinary input/output files; never opens a phone or block device.
use anyhow::{Context, Result, ensure};
use skyward_install::{factory_preflight, payload_preflight, signature, super_image, super_replacement};
use std::{fs::{File, OpenOptions}, io::BufReader, os::unix::fs::OpenOptionsExt, path::Path};

fn regular(path: &Path, cap: u64) -> Result<(File,u64)> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && (1..=cap).contains(&meta.len()), "need a bounded regular file: {}", path.display());
    Ok((file, meta.len()))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [package, certs, reference, company, preload, output] = &args[..] else {
        anyhow::bail!("usage: build_super_a OTA.zip TRUSTED_otacerts.zip OEM_super_meta.raw MY_COMPANY.img MY_PRELOAD.img NEW_SUPER.img");
    };
    let (file, zip_size) = regular(Path::new(package), 128 << 30)?;
    let mut package = BufReader::new(file);
    let (plan, hash) = payload_preflight::read_zip_with_digest(&mut package)?;
    let roster = factory_preflight::reviewed_roster(&hash)?;
    let reference = Path::new(reference);
    regular(reference, 8 << 20)?;
    let lp = skyward_lp::read_image(reference)?;
    let [device] = lp.block_devices.as_slice() else { anyhow::bail!("need one physical super device") };
    let (company, preload) = (Path::new(company), Path::new(preload));
    let replacements = factory_preflight::ReplacementSizes { my_company:super_replacement::inspect(company)?,
        my_preload:super_replacement::inspect(preload)? };
    let keys = signature::keys(BufReader::new(regular(Path::new(certs), 8 << 20)?.0))?;
    let verdict = signature::verify(&mut package, zip_size, &keys, |_, _| true)?;
    println!("Whole-ZIP signature: {verdict:?}");
    let checked = factory_preflight::check(&plan, verdict, &lp, device.size, roster, replacements)?;
    println!("Reviewed declarations={}; allocated_end={}; external replacements absent from signed payload={:?}",
        checked.original_images.len(), checked.allocated_end, checked.replacements_without_original);
    let out = super_image::build_a(&mut package, &plan, &lp, device.size, company, preload, Path::new(output))?;
    println!("Generated {out:?}; candidate only, no AVB authorization, no device writes");
    Ok(())
}
