//! Stage only a stored APEX filesystem payload into volatile RAM before
//! attaching its loop device. A loop backed by system/system_ext would hold
//! the very partition an installer must release, even after HALs stop.
use anyhow::{ensure,Context,Result};
use std::fs::{self,OpenOptions};
use std::io::{Read,Seek,SeekFrom,Write};
use std::os::unix::fs::{DirBuilderExt,MetadataExt,OpenOptionsExt};
use std::path::{Path,PathBuf};
use std::sync::atomic::{AtomicU64,Ordering};
const LIMIT:u64=512*1024*1024;
static NEXT:AtomicU64=AtomicU64::new(0);

pub fn stage(source:&Path,offset:u64,length:u64,root:&Path)->Result<PathBuf>{
    ensure!(length>0 && length<=LIMIT,"APEX payload exceeds bounded RAM staging limit");
    let mut input=OpenOptions::new().read(true).custom_flags(0x20000).open(source).context("open installed APEX read-only")?;
    let meta=input.metadata()?;
    ensure!(meta.is_file() && offset.checked_add(length).is_some_and(|end|end<=meta.len()),"APEX payload range is outside source file");
    match fs::DirBuilder::new().mode(0o700).create(root){Ok(())=>{},Err(error) if error.kind()==std::io::ErrorKind::AlreadyExists=>{},Err(error)=>return Err(error.into())}
    let directory=fs::symlink_metadata(root)?;
    ensure!(directory.is_dir() && !directory.file_type().is_symlink() && directory.mode()&0o777==0o700 && directory.uid()==meta_uid(),"unsafe APEX staging directory");
    let space=skyward_block::mount::space(root)?;
    ensure!(space.available>=length,"volatile APEX backing has insufficient free space (need {length} bytes, available {})",space.available);
    let path=root.join(format!("payload-{}-{}.img",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
    let mut output=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(0x20000).open(&path)?;
    let result=(||->Result<()>{
        input.seek(SeekFrom::Start(offset))?;
        let written=std::io::copy(&mut input.take(length),&mut output).context("copy APEX payload into volatile RAM backing")?;
        ensure!(written==length,"APEX payload source ended early; refusing loop attachment");
        output.flush()?;output.sync_all()?;
        ensure!(output.metadata()?.len()==length,"staged APEX payload length mismatch");
        Ok(())
    })();
    drop(output);
    if let Err(error)=result {let _=fs::remove_file(&path);return Err(error);}
    Ok(path)
}
fn meta_uid()->u32 {
    // Android Recovery is root; host regressions use their own temporary dir.
    #[cfg(target_os="android")] {0}
    #[cfg(not(target_os="android"))] {fs::metadata("/proc/self").map(|m|m.uid()).unwrap_or(u32::MAX)}
}
#[cfg(target_os="android")]
pub fn volatile_root()->Result<PathBuf>{
    use std::ffi::CString;
    // /tmp is an init-created tmpfs. Refuse persistent/data/vendor backing.
    let path=CString::new("/tmp")?;
    let mut stat:libc::statfs=unsafe{std::mem::zeroed()};
    ensure!(unsafe{libc::statfs(path.as_ptr(),&mut stat)}==0,"cannot identify volatile /tmp filesystem");
    ensure!(stat.f_type as u64==0x01021994,"APEX staging requires init tmpfs /tmp");
    Ok(PathBuf::from("/tmp/skyward-apex-payloads"))
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn copies_exact_payload_range_without_source_dependency(){
  let d=tempfile::tempdir().unwrap();let source=d.path().join("source.apex");fs::write(&source,b"PREFIXpayloadTAIL").unwrap();
  let staged=stage(&source,6,7,&d.path().join("ram")).unwrap();assert_eq!(fs::read(&staged).unwrap(),b"payload");
  fs::write(&source,b"changed source").unwrap();assert_eq!(fs::read(&staged).unwrap(),b"payload");assert_eq!(fs::metadata(&staged).unwrap().mode()&0o777,0o600);
 }
 #[test]fn invalid_ranges_create_no_payload(){let d=tempfile::tempdir().unwrap();let s=d.path().join("s");fs::write(&s,b"abc").unwrap();for (o,n) in [(0,0),(1,3),(u64::MAX,1),(0,LIMIT+1)]{assert!(stage(&s,o,n,&d.path().join("ram")).is_err());}}
 #[test]fn never_replaces_existing_backing_or_follows_source_symlinks(){use std::os::unix::fs::symlink;let d=tempfile::tempdir().unwrap();let s=d.path().join("s");fs::write(&s,b"abc").unwrap();let root=d.path().join("ram");let a=stage(&s,0,3,&root).unwrap();let b=stage(&s,0,3,&root).unwrap();assert_ne!(a,b);symlink(&s,d.path().join("link")).unwrap();assert!(stage(&d.path().join("link"),0,3,&root).is_err());}
}
