//! Narrow PGZ110 stock Android init rewrite. The caller verifies the ramdisk
//! layout, hardware, and inputs separately. This module never opens an import.
use anyhow::{Context, Result, bail, ensure};
use std::collections::{BTreeMap, BTreeSet};

const MAIN: &str = "system/etc/init/hw/init.rc";
const MAX_RC: usize = 2 * 1024 * 1024;
const MANAGED: &[(&str, &str)] = &[
    ("hwservicemanager", "/system/bin/hwservicemanager"),
    ("vendor.boot-hal-1-2", "/vendor/bin/hw/android.hardware.boot@1.2-service"),
    ("vendor.gatekeeper-1-0", "/vendor/bin/hw/android.hardware.gatekeeper@1.0-service"),
    ("gatekeeperd", "/system/bin/gatekeeperd"),
    ("hal_cryptoeng_oppo", "/system/bin/hw/vendor.oplus.hardware.cryptoeng@1.0-service"),
    ("keymaster-4-0", "/system/bin/android.hardware.keymaster@4.0-service.trustonic"),
    ("keymaster-4-1", "/system/bin/android.hardware.keymaster@4.1-service.trustonic"),
    ("mobicore", "/vendor/bin/mcDriverDaemon"),
    ("wmt_loader", "/vendor/bin/wmt_loader"),
    ("wmt_launcher", "/vendor/bin/wmt_launcher"),
    ("conninfra_loader", "/vendor/bin/conninfra_loader"),
    ("wlan_assistant", "/vendor/bin/wlan_assistant"),
    ("wpa_supplicant", "/vendor/bin/hw/wpa_supplicant"),
    ("netd", "/system/bin/netd"),
];
const CORE: &[(&str, &str)] = &[
    ("recovery", "/system/bin/recovery"),
    ("servicemanager", "/system/bin/servicemanager"),
    ("vndservicemanager", "/vendor/bin/vndservicemanager"),
];
const CONNECTIVITY: &[&str] = &[
    "conninfra.ko", "connfem.ko", "bt_drv.ko", "bt_drv_6895.ko",
    "wmt_chrdev_wifi.ko", "wmt_chrdev_wifi_connac2.ko", "wlan_drv_gen4m.ko", "wlan_drv_gen4m_6895.ko",
];

fn expected(name: &str, identities: &[(&'static str, &'static str)]) -> Option<&'static str> {
    identities.iter().find_map(|&(n, executable)| (n == name).then_some(executable))
}
fn managed(name: &str) -> bool { expected(name, MANAGED).is_some() }
fn basename(path: &str) -> &str { path.rsplit('/').next().unwrap_or(path) }
fn owned_executable(path: &str) -> bool {
    MANAGED.iter().chain(CORE).any(|&(_, known)| basename(known) == basename(path))
}
fn valid_path(path: &str) -> bool {
    !path.as_bytes().iter().any(|b| b.is_ascii_control() || matches!(b, b'\\' | b':'))
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

struct Record {
    start: usize,
    end: usize,
    words: Vec<String>,
    /// Index of the containing service/action record, not a guessed class.
    owner: Option<usize>,
}
struct Script<'a> { lines: Vec<&'a str>, records: Vec<Record> }

fn tokens(line: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_quote = false;
    let mut started = false;
    for ch in line.chars() {
        match ch {
            '"' => { in_quote = !in_quote; started = true; }
            '#' if !in_quote && !started => break,
            ' ' | '\t' if !in_quote => {
                if started { words.push(std::mem::take(&mut word)); started = false; }
            }
            '\\' | '\'' => bail!("unreviewed init escape or quoting"),
            c if c.is_control() && c != '\t' => bail!("control character in init statement"),
            c => { word.push(c); started = true; }
        }
    }
    ensure!(!in_quote, "unterminated init quote");
    if started { words.push(word); }
    Ok(words)
}

fn parse<'a>(path: &str, bytes: &'a [u8]) -> Result<Script<'a>> {
    ensure!(bytes.len() <= MAX_RC && !bytes.contains(&0), "oversized or binary init file {path}");
    let text = std::str::from_utf8(bytes).with_context(|| format!("invalid UTF-8 in {path}"))?;
    let lines: Vec<_> = text.split_inclusive('\n').collect();
    ensure!(lines.len() <= 50000, "too many init lines in {path}");
    let mut records = Vec::new();
    let mut owner = None;
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        let first = lines[i];
        let trimmed = first.trim_start_matches([' ', '\t']);
        if trimmed.trim_end_matches(['\n', '\r']).is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let mut joined = String::new();
        loop {
            let line = lines[i].strip_suffix('\n').unwrap_or(lines[i]);
            let line = line.strip_suffix('\r').unwrap_or(line);
            i += 1;
            if let Some(piece) = line.strip_suffix('\\') {
                ensure!(i < lines.len(), "{path}:{}: unfinished line continuation", start + 1);
                // Do not invent a separator in a continued service name or
                // executable. Whitespace supplied by the file is retained.
                joined.push_str(piece);
            } else {
                joined.push_str(line);
                break;
            }
        }
        let words = tokens(&joined).with_context(|| format!("{path}:{}", start + 1))?;
        if words.is_empty() { continue; }
        let section = matches!(words[0].as_str(), "service" | "on" | "import");
        ensure!(section == (first.len() == trimmed.len()), "{path}:{}: ambiguous section indentation", start + 1);
        let record_owner = if section {
            match words[0].as_str() {
                "service" => {
                    ensure!(words.len() >= 3 && !words[1].is_empty() && words[1].bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')),
                        "{path}:{}: malformed service", start + 1);
                    owner = Some(records.len());
                }
                "on" => {
                    ensure!(words.len() >= 2, "{path}:{}: empty action trigger", start + 1);
                    owner = Some(records.len());
                }
                "import" => {
                    ensure!(words.len() == 2, "{path}:{}: malformed import", start + 1);
                    owner = None;
                }
                _ => unreachable!(),
            }
            None
        } else {
            ensure!(owner.is_some(), "{path}:{}: command outside a section", start + 1);
            owner
        };
        records.push(Record { start, end: i, words, owner: record_owner });
    }
    Ok(Script { lines, records })
}

fn known_interface(name: &str, interface: &str) -> bool {
    match name {
        "vendor.boot-hal-1-2" => matches!(interface,
            "android.hardware.boot@1.0::IBootControl" | "android.hardware.boot@1.1::IBootControl" | "android.hardware.boot@1.2::IBootControl"),
        "vendor.gatekeeper-1-0" => interface == "android.hardware.gatekeeper@1.0::IGatekeeper",
        "wpa_supplicant" => matches!(interface,
            "android.hardware.wifi.supplicant@1.0::ISupplicant" | "android.hardware.wifi.supplicant@1.1::ISupplicant"
            | "android.hardware.wifi.supplicant@1.2::ISupplicant" | "android.hardware.wifi.supplicant@1.3::ISupplicant"
            | "android.hardware.wifi.supplicant@1.4::ISupplicant" | "vendor.oplus.hardware.wifi.supplicant@2.0::IOplusSupplicant"),
        _ => false,
    }
}

/// Read all supplied ramdisk RC files, reject ambiguous management and return
/// just the patched main RC. Preserve definitions, ordinary OEM actions and
/// unrelated services; do not disable whole classes or drop imports.
pub fn adapt_init(paths: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    ensure!(paths.contains_key(MAIN), "missing PGZ110 main init RC");
    let mut parsed = BTreeMap::new();
    let mut total = 0usize;
    for (path, raw) in paths {
        ensure!(valid_path(path), "noncanonical init archive path: {path}");
        // ueventd's device rules are not Android init statements.
        if !path.ends_with(".rc") || basename(path).starts_with("ueventd") { continue; }
        total = total.checked_add(raw.len()).context("init scan length overflow")?;
        ensure!(parsed.len() < 256 && total <= MAX_RC * 4, "init scan exceeds limits");
        parsed.insert(path.as_str(), parse(path, raw)?);
    }
    let mut seen = BTreeSet::new();
    for (&path, script) in &parsed {
        for r in &script.records {
            let w = &r.words;
            if r.owner.is_some() { continue; }
            if w[0] == "import" {
                let target = w[1].strip_prefix('/').context("init import is not absolute")?;
                ensure!(valid_path(target) && target.ends_with(".rc") && !target.contains(['*', '?', '[', ']']) && !basename(target).starts_with("ueventd"),
                    "{path}: unbounded or unsafe init import");
                if target == "init.recovery.${ro.board.platform}.rc" {
                    ensure!(path == MAIN && parsed.contains_key("init.recovery.mt6895.rc"), "unreviewed MT6895 platform import");
                } else {
                    ensure!(!target.contains('$'), "{path}: unreviewed property-expanded import");
                    // This exact optional OEM hook is absent from sampled
                    // stock images; init can only follow it if the target
                    // supplies it, in which case it is scanned like any RC.
                    ensure!(parsed.contains_key(target) || (path == "init.recovery.mt6895.rc" && target == "init.recovery.project.rc"),
                        "{path}: unresolved init import /{target}");
                }
            } else if w[0] == "service" {
                let (name, executable) = (w[1].as_str(), w[2].as_str());
                ensure!(seen.insert(name), "duplicate init service {name}");
                if let Some(wanted) = expected(name, MANAGED).or_else(|| expected(name, CORE)) {
                    ensure!(path == MAIN && executable == wanted, "{path}: unreviewed declaration of {name}");
                    if matches!(name, "hwservicemanager" | "vendor.boot-hal-1-2" | "recovery") {
                        ensure!(w.len() == 3, "{path}: unreviewed arguments for {name}");
                    }
                } else {
                    ensure!(!owned_executable(executable) && !executable.contains('$'), "{path}: unreviewed service alias for {name}");
                }
            }
        }
    }
    for name in ["recovery", "hwservicemanager", "vendor.boot-hal-1-2"] {
        ensure!(seen.contains(name), "missing required service {name}");
    }
    let mut remove = BTreeSet::new();
    let mut add = BTreeSet::new();
    for (&path, script) in &parsed {
        let mut disabled = BTreeSet::new();
        let mut user = BTreeSet::new();
        for r in &script.records {
            let Some(index) = r.owner else { continue };
            let owner = &script.records[index].words;
            let service = owner[0] == "service";
            let name = &owner[1];
            let t = &r.words;
            if service && managed(name) {
                match t[0].as_str() {
                    "user" if matches!(name.as_str(), "hwservicemanager" | "vendor.boot-hal-1-2") => {
                        ensure!(t.as_slice() == ["user", "root"] && user.insert(index), "{path}: stock {name} must retain UID 0");
                    }
                    "disabled" => {
                        ensure!(t.len() == 1 && disabled.insert(index), "{path}: malformed or duplicate disabled for {name}");
                    }
                    "interface" => {
                        ensure!(t.len() == 3 && t[2] == "default" && known_interface(name, &t[1]), "{path}: unknown lazy interface on {name}");
                        remove.extend(r.start..r.end);
                    }
                    _ => (),
                }
            } else if service && t[0] == "interface" && t.len() >= 2 {
                ensure!(!["vendor.boot-hal-1-2", "vendor.gatekeeper-1-0", "wpa_supplicant"].iter().any(|n| known_interface(n, &t[1])) && !t[1].contains('$'),
                    "{path}: unexpected owner of managed interface");
            }
            let command = if service && t[0] == "onrestart" { &t[1..] } else { t };
            let Some(verb) = command.first().map(String::as_str) else { continue };
            match verb {
                "start" | "restart" | "stop" | "enable" | "exec_start" => {
                    ensure!(command.len() == 2 && !command[1].contains('$'), "{path}: ambiguous service control");
                    let target = &command[1];
                    let fbe_stop = !service && owner[1..].iter().any(|token| token == "property:enable.fbe.service=0");
                    ensure!(!fbe_stop || managed(target) || matches!(target.as_str(), "servicemanager" | "vndservicemanager"),
                        "{path}: unreviewed legacy FBE control of {target}");
                    ensure!(verb != "stop" || !managed(target) || fbe_stop, "{path}: unreviewed stop of {target}");
                    if (managed(target) && verb != "stop") || (fbe_stop && verb == "stop") {
                        ensure!(path == MAIN, "{path}: managed control outside main RC");
                        remove.extend(r.start..r.end);
                    }
                }
                "interface_start" | "interface_stop" | "interface_restart" => {
                    bail!("{path}: unreviewed direct interface control");
                }
                "setprop" if command.get(1).is_some_and(|p| p.starts_with("ctl.") || p.contains('$')) => {
                    bail!("{path}: ambiguous property-based service control");
                }
                "exec" | "exec_background" => {
                    ensure!(!command[1..].iter().any(|p| owned_executable(p)), "{path}: direct exec of managed executable");
                    let program = command.iter().position(|x| x == "--").map_or(1, |n| n + 1);
                    ensure!(command.get(program).is_some_and(|p| !p.contains('$')), "{path}: ambiguous exec path");
                }
                "insmod" if command.get(1).is_some_and(|p| CONNECTIVITY.contains(&basename(p)) || p.contains('$')) => {
                    let reviewed_trigger = !service && owner.len() == 2 && matches!(name.as_str(), "boot" | "property:vendor.connsys.driver.ready=yes");
                    ensure!(path == MAIN && reviewed_trigger && command.len() == 2
                        && CONNECTIVITY.iter().any(|m| command[1].strip_prefix("/vendor/lib/modules/") == Some(*m)),
                        "{path}: unreviewed connectivity insmod");
                    remove.extend(r.start..r.end);
                }
                _ => (),
            }
        }
        if path == MAIN {
            for (index, r) in script.records.iter().enumerate() {
                if r.owner.is_none() && r.words[0] == "service" && managed(&r.words[1]) && !disabled.contains(&index) {
                    add.insert(r.end);
                }
            }
        }
    }
    let script = &parsed[MAIN];
    let newline = if script.lines.iter().any(|line| line.ends_with("\r\n")) { "\r\n" } else { "\n" };
    let mut result = String::new();
    for i in 0..=script.lines.len() {
        if add.contains(&i) {
            if !result.ends_with('\n') { result.push_str(newline); }
            result.push_str("    disabled");
            result.push_str(newline);
        }
        if let Some(line) = script.lines.get(i) {
            if !remove.contains(&i) { result.push_str(line); }
        }
    }
    Ok(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    const STOCK: &str = "on boot\n    start vendor.boot-hal-1-2\n    start phoenix_recovery\n    insmod /vendor/lib/modules/conninfra.ko\n    insmod /vendor/lib/modules/cpu.ko\nservice recovery /system/bin/recovery\n    seclabel u:r:recovery:s0\nservice hwservicemanager /system/bin/hwservicemanager\n    onrestart setprop hwservicemanager.ready false\nservice vendor.boot-hal-1-2 /vendor/bin/hw/android.hardware.boot@1.2-service\n    interface android.hardware.boot@1.2::IBootControl default\nservice fastbootd /system/bin/fastbootd\n    disabled\n";
    fn scripts(main: &str) -> BTreeMap<String, Vec<u8>> { BTreeMap::from([(MAIN.into(), main.as_bytes().to_vec())]) }
    fn patch(main: &str) -> Result<String> { Ok(String::from_utf8(adapt_init(&scripts(main))?)?) }

    #[test]
    fn rewrites_only_audited_owners_and_retains_unrelated_behavior() {
        let input = format!("{STOCK}on property:enable.fbe.service=0\n    stop servicemanager\nservice mobicore /vendor/bin/mcDriverDaemon \\\n    --P1 /mnt/vendor/persist/mcRegistry\n");
        let output = patch(&input).unwrap();
        for keep in ["start phoenix_recovery", "insmod /vendor/lib/modules/cpu.ko", "service fastbootd", "--P1 /mnt/vendor/persist/mcRegistry\n    disabled", "hwservicemanager\n    disabled\n    onrestart", "android.hardware.boot@1.2-service\n    disabled"] {
            assert!(output.contains(keep), "missing {keep}: {output}");
        }
        for remove in ["start vendor.boot-hal-1-2", "conninfra.ko", "interface android.hardware.boot", "stop servicemanager"] {
            assert!(!output.contains(remove), "not removed: {remove}");
        }
        assert_eq!(output, patch(&output).unwrap());
    }

    #[test]
    fn refuses_unknown_service_controls_interfaces_and_syntax() {
        for extra in ["on boot\n    start ${service}\n", "on boot\n    stop mobicore\n", "on boot\n    setprop ctl.start mobicore\n",
            "on boot\n    insmod /other/conninfra.ko\n", "service fake /other/hwservicemanager\n",
            "service unknown /system/bin/other\n    interface android.hardware.boot@1.2::IBootControl default\n",
            "on boot\n    exec -- /vendor/bin/mcDriverDaemon\n", "    service surprise /bin/x\n", "on boot\n    start \"unterminated\n"] {
            assert!(patch(&format!("{STOCK}{extra}")).is_err(), "accepted {extra:?}");
        }
        assert!(patch(&STOCK.replace("    onrestart", "    user system\n    onrestart")).is_err());
    }

    #[test]
    fn scans_all_other_init_files_but_not_ueventd_rules() {
        let mut all = scripts(&format!("import /init.recovery.${{ro.board.platform}}.rc\n{STOCK}"));
        let platform = "init.recovery.mt6895.rc".to_string();
        all.insert(platform.clone(), b"import /init.recovery.project.rc\non init\n    start unrelated\n".to_vec());
        all.insert("ueventd.rc".into(), b"/dev/foo 0660 root system\n".to_vec());
        assert!(adapt_init(&all).is_ok());
        all.insert(platform.clone(), b"on init\n    start hwservicemanager\n".to_vec());
        assert!(adapt_init(&all).is_err());
        all.insert(platform, b"service fastbootd /other\n".to_vec());
        assert!(adapt_init(&all).is_err());
        assert!(patch(&format!("import /unseen.rc\n{STOCK}")).is_err());
    }

    #[test]
    fn disabled_insertion_handles_unterminated_last_line() {
        let r = patch(&format!("{STOCK}service mobicore /vendor/bin/mcDriverDaemon")).unwrap();
        assert!(r.ends_with("mcDriverDaemon\n    disabled\n"));
    }
}
