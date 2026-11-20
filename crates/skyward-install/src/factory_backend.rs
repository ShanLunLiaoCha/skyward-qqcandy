//! Bind the tested core ordering to stable staged files and Android claims.
//! Not wired to UI yet: complete firmware inventory, quiescence and trusted
//! activation/AVB policy must be supplied by the caller, never inferred here.
use crate::factory_execute::{Image, Target};
#[cfg(target_os = "android")]
use crate::factory_execute::Backend;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::{File, OpenOptions}, io::{Read, Seek, SeekFrom}, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::PathBuf};

pub(crate) struct Source { pub(crate) file: File, image: Image, stamp: (u64,i64,i64,i64,i64) }
fn stamp(file: &File) -> Result<(u64,i64,i64,i64,i64)> {
    let m=file.metadata()?;
    Ok((m.len(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec()))
}
pub(crate) fn open_sources(paths: &BTreeMap<Target,PathBuf>, images: &[Image]) -> Result<BTreeMap<Target,Source>> {
    ensure!(paths.len()==images.len(), "staged target roster differs from execution plan");
    let mut sources=BTreeMap::new();
    for (index, &image) in images.iter().enumerate() {
        #[cfg(target_os = "android")]
        let _ = skyward_sys::kmsg(&format!("factory restore: verifying input {}/{} {} ({} bytes)",
            index + 1, images.len(), image.target.display_name(), image.bytes));
        #[cfg(not(target_os = "android"))]
        let _ = index;
        let path=paths.get(&image.target).context("missing staged source")?;
        let mut file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(path)?;
        let meta=file.metadata()?;
        ensure!(meta.is_file() && meta.len()==image.bytes, "invalid staged image at {}",path.display());
        let before=stamp(&file)?;
        let mut h=Sha256::new();
        let mut buffer=vec![0;256<<10];
        let mut left=image.bytes;
        while left!=0 {
            let take=left.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..take])?;
            h.update(&buffer[..take]);left-=take as u64;
        }
        ensure!(file.read(&mut [0])?==0,"staged image grew during validation");
        ensure!(stamp(&file)?==before && h.finalize().as_slice()==image.sha256, "staged image changed or hash differs");
        file.seek(SeekFrom::Start(0))?;
        ensure!(sources.insert(image.target,Source{file,image,stamp:before}).is_none(), "duplicate staged target");
    }
    Ok(sources)
}

#[cfg(target_os="android")]
fn verify_independent_sources(sources: &BTreeMap<Target, Source>, claims: &crate::factory_targets::Claims) -> Result<()> {
    use std::{collections::BTreeSet, path::Path};
    let targets = claims.identities();
    let mut checked = BTreeSet::new();
    for source in sources.values() {
        let dev = source.file.metadata()?.dev() as libc::dev_t;
        let id = (libc::major(dev) as u32, libc::minor(dev) as u32);
        if checked.insert(id) {
            let dependencies = crate::factory_source::dependencies(Path::new("/sys/dev/block"), id)?;
            crate::factory_source::excludes_targets(&dependencies, &targets)?;
        }
    }
    Ok(())
}

/// Use the same input validation as the writer while holding only read-only
/// exclusive block handles. Does not authorize execution or query OEM state.
#[cfg(target_os="android")]
pub(crate) fn audit_staged_io(paths: &BTreeMap<Target, PathBuf>, images: &[Image]) -> Result<usize> {
    let sources = open_sources(paths, images)?;
    let claims = crate::factory_targets::Claims::claim_set(images, false)?;
    verify_independent_sources(&sources, &claims)?;
    Ok(images.len())
}

#[cfg(target_os="android")]
pub(crate) struct DeviceBackend<C,R,A> {
    paths:BTreeMap<Target,PathBuf>, sources:BTreeMap<Target,Source>,
    claims:Option<crate::factory_targets::Claims>, snapshot:Option<skyward_vab::snapshots::RestoreLock>,
    cancelled:C, ready:R, activate:A,
}
#[cfg(target_os="android")]
impl<C:Fn()->bool,R:FnMut(&std::collections::BTreeSet<(u32,u32)>)->Result<skyward_vab::MergeStatus>,A:FnMut()->Result<()>> DeviceBackend<C,R,A> {
    /// `ready` must actively check the same, independently available boot
    /// service used for activation. A previously cached merge state is not
    /// sufficient after image staging or after claiming super.
    pub(crate) fn new(paths:BTreeMap<Target,PathBuf>,cancelled:C,ready:R,activate:A)->Self {
        Self{paths,sources:BTreeMap::new(),claims:None,snapshot:None,cancelled,ready,activate}
    }
}
#[cfg(target_os="android")]
impl<C:Fn()->bool,R:FnMut(&std::collections::BTreeSet<(u32,u32)>)->Result<skyward_vab::MergeStatus>,A:FnMut()->Result<()>> Backend for DeviceBackend<C,R,A> {
    fn arm(&mut self,images:&[Image])->Result<()> {
        ensure!(self.claims.is_none(), "restore backend already armed");
        ensure!(!(self.cancelled)(),"restore cancelled before source validation");
        self.sources=open_sources(&self.paths,images)?;
        ensure!(!(self.cancelled)(),"restore cancelled after source validation");
        let snapshot=crate::factory_snapshot::acquire((self.ready)(&Default::default()).context("query boot service before target claims")?)?;
        ensure!(!(self.cancelled)(),"restore cancelled before target claims");
        let claims=crate::factory_targets::Claims::acquire(images)?;
        let targets=claims.identities();
        verify_independent_sources(&self.sources, &claims)?;
        crate::factory_snapshot::check_merge_state((self.ready)(&targets).context("query boot service while holding all target claims")?)?;
        self.snapshot=Some(snapshot);self.claims=Some(claims);Ok(())
    }
    fn cancelled(&self)->bool {(self.cancelled)()}
    fn write(&mut self,image:&Image)->Result<()> {
        let source=self.sources.get_mut(&image.target).context("staged source not verified")?;
        ensure!(source.image==*image && stamp(&source.file)?==source.stamp,"staged source changed since arming");
        source.file.seek(SeekFrom::Start(0))?;
        self.claims.as_mut().context("targets not claimed")?.copy(image,&mut source.file)?;
        ensure!(stamp(&source.file)?==source.stamp,"staged source changed during write");Ok(())
    }
    fn sync(&mut self,target:Target)->Result<()> {self.claims.as_ref().context("targets not claimed")?.sync(target)}
    fn activate_a(&mut self)->Result<()> {
        let claims = self.claims.as_ref().context("restore targets are not armed")?;
        ensure!(self.snapshot.is_some(), "restore snapshot lock is missing");
        crate::factory_snapshot::check_merge_state((self.ready)(&claims.identities()).context("query boot service before activating A")?)?;
        (self.activate)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stage_is_verified_before_any_device_claim() {
        let dir=tempfile::tempdir().unwrap();let p=dir.path().join("boot.img");std::fs::write(&p,[5;4096]).unwrap();
        let image=Image{target:Target::BootA,bytes:4096,sha256:Sha256::digest([5;4096]).into()};
        let paths=BTreeMap::from([(Target::BootA,p.clone())]);
        let sources=open_sources(&paths,&[image]).unwrap();assert_eq!(sources.len(),1);
        std::fs::write(&p,[6;4096]).unwrap();assert!(open_sources(&paths,&[image]).is_err());
        let link=dir.path().join("link.img");std::os::unix::fs::symlink(&p,&link).unwrap();
        assert!(open_sources(&BTreeMap::from([(Target::BootA,link)]),&[image]).is_err());
        assert!(open_sources(&BTreeMap::new(),&[image]).is_err());
    }
}
