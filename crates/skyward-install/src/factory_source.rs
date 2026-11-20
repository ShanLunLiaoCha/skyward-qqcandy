//! Determine whether a staging filesystem can depend on a restore target.
//! A missing sysfs node is unknown, never evidence of independence.
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, path::Path};

fn parse_device(text: &str) -> Result<(u32,u32)> {
    let (major,minor)=text.trim().split_once(':').context("bad sysfs device number")?;
    Ok((major.parse()?,minor.parse()?))
}

/// Walk kernel slave relationships, including a filesystem's underlying DM
/// layers. Reject loopback devices: their data can be a regular file on a
/// target filesystem not represented in `slaves`. Filesystem origin and
/// ancestry still need to be established independently by the caller.
pub(crate) fn dependencies(sys_dev_block:&Path, source:(u32,u32))->Result<BTreeSet<(u32,u32)>> {
    let mut seen=BTreeSet::new();let mut pending=vec![source];
    while let Some(id)=pending.pop() {
        if !seen.insert(id) {continue}
        ensure!(seen.len()<=256,"excessive staging block dependency graph");
        let root=sys_dev_block.join(format!("{}:{}",id.0,id.1));
        let dev=std::fs::read_to_string(root.join("dev")).with_context(||format!("read {}",root.display()))?;
        ensure!(parse_device(&dev)?==id,"sysfs dependency number differs");
        match std::fs::symlink_metadata(root.join("loop")) {
            Ok(_) => anyhow::bail!("loop-backed staging filesystem is unsupported"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error).context("inspect staging loop backing"),
        }
        let mut children = 0;
        let slaves = root.join("slaves");
        let entries = match std::fs::read_dir(&slaves) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
                && std::fs::symlink_metadata(root.join("partition"))?.is_file() => None,
            Err(error) => return Err(error).with_context(|| format!("enumerate {}", slaves.display())),
        };
        for child in entries.into_iter().flatten() {
            let child=child?;
            let child_dev=std::fs::read_to_string(child.path().join("dev"))?;
            pending.push(parse_device(&child_dev)?);
            children += 1;
            ensure!(pending.len() <= 256, "excessive staging block dependency graph");
        }
        if children == 0 {
            // A filesystem placed on a whole disk would overlap its child
            // partitions without sharing their device number.
            let uevent = std::fs::read_to_string(root.join("uevent"))?;
            let mut types = uevent.lines().filter_map(|line| line.strip_prefix("DEVTYPE="));
            ensure!(types.next() == Some("partition") && types.next().is_none(),
                "staging block dependency is not a verified partition");
        }
    }
    Ok(seen)
}

pub(crate) fn excludes_targets(dependencies:&BTreeSet<(u32,u32)>, targets:&BTreeSet<(u32,u32)>)->Result<()> {
    ensure!(dependencies.is_disjoint(targets),"staging filesystem depends on a partition scheduled for overwrite");Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traces_dm_dependencies_and_refuses_missing_or_overwritten_sources() {
        let tmp=tempfile::tempdir().unwrap();let sys=tmp.path();
        for (name,dev) in [("253:19","253:19"),("8:12","8:12"),("8:79","8:79")] {
            let root=sys.join(name);std::fs::create_dir_all(root.join("slaves")).unwrap();std::fs::write(root.join("dev"),dev).unwrap();
            std::fs::write(root.join("uevent"),"DEVTYPE=partition\n").unwrap();
        }
        std::os::unix::fs::symlink(sys.join("8:12"),sys.join("253:19/slaves/sdc12")).unwrap();
        let deps=dependencies(sys,(253,19)).unwrap();
        assert_eq!(deps,BTreeSet::from([(253,19),(8,12)]));
        assert!(excludes_targets(&deps,&BTreeSet::from([(8,79)])).is_ok());
        assert!(excludes_targets(&deps,&BTreeSet::from([(8,12)])).is_err());
        assert!(dependencies(sys,(253,20)).is_err());
        std::fs::create_dir(sys.join("8:12/loop")).unwrap();
        assert!(dependencies(sys,(253,19)).unwrap_err().to_string().contains("loop-backed"));
        std::fs::remove_dir(sys.join("8:12/loop")).unwrap();
        std::fs::remove_dir(sys.join("8:12/slaves")).unwrap();
        assert!(dependencies(sys,(253,19)).is_err());
        std::fs::write(sys.join("8:12/partition"),"12\n").unwrap();
        assert_eq!(dependencies(sys,(253,19)).unwrap(), deps);
        std::fs::write(sys.join("8:12/uevent"),"DEVTYPE=disk\n").unwrap();
        assert!(dependencies(sys,(253,19)).unwrap_err().to_string().contains("not a verified partition"));
        std::fs::write(sys.join("8:12/dev"),"8:13").unwrap();assert!(dependencies(sys,(253,19)).is_err());
    }
}
