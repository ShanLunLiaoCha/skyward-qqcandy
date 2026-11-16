//! Audited MTK wlan_assistant RAM-buffer protocol, without creating, rewriting
//! or synthesising calibration files and without custom MAC overlays.
use anyhow::{ensure, Context, Result};
const HEADER: &[u8; 12] = b"WR-BUF:NVRAM";
const MAX_PAYLOAD: usize = 8192;
#[cfg(target_os="android")]
static LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os="android")]
pub fn loaded() -> bool { LOADED.load(std::sync::atomic::Ordering::Acquire) }

pub fn leaf(value: &str) -> Result<&str> {
    let value=value.trim();
    ensure!(!value.is_empty() && value.len()<=128 && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b,b'_'|b'-'|b'.')) && value!="." && value!="..", "invalid existing Wi-Fi calibration filename selector");
    Ok(value)
}

pub fn command(raw: &[u8]) -> Result<Vec<u8>> {
    // Same official assistant reads file_size-2 bytes starting at offset zero.
    // The final two bytes' meaning is not guessed; preserve source unchanged.
    let size=raw.len().checked_sub(2).context("Wi-Fi calibration file too short")?;
    ensure!(size>0 && size<=MAX_PAYLOAD && size%256==0, "existing Wi-Fi calibration length is unsupported; refusing defaults");
    let mut out=Vec::with_capacity(HEADER.len()+size);out.extend_from_slice(HEADER);out.extend_from_slice(&raw[..size]);Ok(out)
}

#[cfg(target_os="android")]
pub fn load(cfg: &skyward_config::WlanNvram) -> Result<()> {
    use std::path::{Path,PathBuf};
    use std::os::unix::fs::{FileTypeExt,OpenOptionsExt};
    use std::io::{Read,Write};
    use skyward_block::mount;
    ensure!(cfg.partition=="nvdata" && cfg.device=="/dev/wmtWifi", "unrecognised calibration partition or device");
    let directory=Path::new(&cfg.directory);
    ensure!(!directory.is_absolute() && directory.components().all(|part| matches!(part,std::path::Component::Normal(_))), "invalid calibration relative directory");
    let mut selected=cfg.file.clone();
    if let Some(selector)=&cfg.selector {
        match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(selector) {
            Ok(file)=> {
                ensure!(file.metadata()?.is_file(),"calibration filename selector is not regular");
                let mut value=String::new();file.take(1025).read_to_string(&mut value)?;
                ensure!(value.len()<=1024,"calibration filename selector too long");
                selected=leaf(&value)?.to_string();
            }
            Err(error) if error.kind()==std::io::ErrorKind::NotFound=>{},
            Err(error)=>return Err(error).context("read existing Wi-Fi calibration filename selector"),
        }
    }
    let selected=leaf(&selected)?;
    let existing=PathBuf::from(format!("/mnt/vendor/{}",cfg.partition));
    let temporary=PathBuf::from("/skyward/wlan-calibration");
    let already=mount::is_mount_point(&existing)?;
    let root=if already {existing} else {
        ensure!(cfg.partition=="nvdata", "only the audited nvdata calibration partition is supported");
        std::fs::create_dir_all(&temporary)?;
        // No journal replay, no fsck, no repair/write to calibration storage.
        mount::mount(&Path::new(skyward_block::BY_NAME).join(&cfg.partition),&temporary,"ext4",&["ro".into(),"noload".into(),"nosuid".into(),"nodev".into()])?;
        temporary.clone()
    };
    let reading=(||->Result<Vec<u8>> {
        let path=root.join(directory).join(selected);
        for ancestor in path.ancestors() {
            if ancestor==root { break; }
            ensure!(!std::fs::symlink_metadata(ancestor)?.file_type().is_symlink(),"calibration source contains a symlink");
        }
        let file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path).context("open existing Wi-Fi calibration (read-only)")?;
        ensure!(file.metadata()?.is_file(),"calibration source is not a regular file");
        let size=file.metadata()?.len();ensure!(size<=MAX_PAYLOAD as u64+2,"calibration source exceeds audited maximum");
        let mut raw=Vec::new();file.take((MAX_PAYLOAD+3) as u64).read_to_end(&mut raw)?;
        command(&raw)
    })();
    let unmounted=if already {Ok(())} else {mount::umount(&temporary)};
    let bytes=reading?;unmounted?;
    let node=Path::new(&cfg.device);
    ensure!(std::fs::symlink_metadata(node)?.file_type().is_char_device(),"calibration target is not the audited character device");
    let mut device=std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW).open(node)?;
    // Exactly one write is required: a short write is not retried as a second
    // malformed driver command. Never log payload, MAC or calibration bytes.
    let written=device.write(&bytes).context("load existing Wi-Fi calibration into driver RAM")?;
    ensure!(written==bytes.len(),"short calibration driver write; refusing power-on");
    LOADED.store(true,std::sync::atomic::Ordering::Release);
    skyward_sys::kmsg(&format!("existing Wi-Fi calibration accepted by driver RAM ({} bytes); source not modified",bytes.len()-HEADER.len()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
 use super::*;
 #[test] fn exact_driver_command_drops_only_audited_trailer() {
  let mut raw=vec![0x42;256];raw.extend_from_slice(&[0xaa,0xbb]);let cmd=command(&raw).unwrap();
  assert_eq!(&cmd[..12],b"WR-BUF:NVRAM");assert_eq!(&cmd[12..],&raw[..256]);assert_eq!(raw[256..],[0xaa,0xbb]);
 }
 #[test] fn no_default_calibration_or_invalid_sizes() {
  for size in [0,1,2,257,259,8195] {assert!(command(&vec![0;size]).is_err(),"{size}");}
  assert_eq!(command(&vec![1;8194]).unwrap().len(),8204);
 }
 #[test] fn selectors_are_basename_only() {
  assert_eq!(leaf("WIFI\n").unwrap(),"WIFI");
  for name in ["","..","../WIFI","/WIFI","WIFI/foo","WIFI\0"] {assert!(leaf(name).is_err());}
 }
}
