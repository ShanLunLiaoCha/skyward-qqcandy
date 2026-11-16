//! Offline discovery against the exact extracted PGZ110 official partitions.
//! Run explicitly with SKYWARD_PGZ110_STOCK_ROOT; no vendor binary is executed.
use skyward_programs::{phone::{Partition, Phone}, secure::{self, Step}};
use std::{collections::HashMap, path::PathBuf};

#[test]
#[ignore = "requires locally extracted official PGZ110 vendor/odm/system_ext"]
fn official_pgz110_key_programs_are_discovered() {
    let root = PathBuf::from(std::env::var_os("SKYWARD_PGZ110_STOCK_ROOT").expect("set extracted OTA root"));
    let mut props = HashMap::new();
    // Read the extracted build property files, not another phone's defaults.
    for relative in ["system-root/system/build.prop", "system_ext-root/etc/build.prop", "vendor-root/default.prop", "vendor-root/build.prop", "odm-root/build.prop"] {
        let path = root.join(relative);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("{}: {error}", path.display()),
        };
        for line in text.lines().map(str::trim).filter(|line| !line.starts_with('#')) {
            if let Some((name, value)) = line.split_once('=') { props.insert(name.trim().into(), value.trim().into()); }
        }
    }
    // This bootloader property is not contained in build.prop; the mt6895
    // platform value is confirmed by the stock recovery init filename/fstab.
    props.insert("ro.boot.hardware".into(), "mt6895".into());
    let partitions = ["system_ext", "vendor", "odm"].into_iter().map(|name| Partition {
        name: name.into(), mounted: if name == "system_ext" { "/mnt/system_ext".into() } else { format!("/{name}").into() },
        at: root.join(format!("{name}-root")),
    }).collect();
    let phone = Phone::read(partitions, props, None).expect("read the official init and VINTF files");
    let steps = secure::steps(&phone).expect("resolve the official secure service startup chain");
    let paths: Vec<_> = steps.iter().filter_map(|step| match step { Step::Start(started) => Some(started.service.path.as_str()), _ => None }).collect();
    println!("Programs found: {paths:#?}");
    assert!(paths.contains(&"/vendor/bin/hw/android.hardware.security.keymint-service.trustonic"));
    assert!(paths.contains(&"/vendor/bin/hw/android.hardware.gatekeeper@1.0-service"));
    assert!(paths.iter().any(|path| path.contains("android.hardware.boot@1.2-service")));
    assert!(!paths.iter().any(|path| path.contains("qseecomd")));
}
