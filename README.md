![Skyward](assets/hero.jpg)

# Skyward for OnePlus Ace Racing Edition · qqcandy

English | [简体中文](README.zh-CN.md)

An **unofficial device port** of [Skyward](https://github.com/kirklin/skyward), a recovery written in Rust. This repository (`skyward-qqcandy`) holds the modified source, PGZ110 configurations, image-building tools and the Android porting helper for the OnePlus Ace Racing Edition. It is not an official OnePlus or upstream Skyward release.

## Device

| Item | Value |
| --- | --- |
| Device | OnePlus Ace Racing Edition / 一加 Ace 竞速版 |
| Model | PGZ110 |
| Device codename | `qqcandy` (public name used by this port) |
| Internal configuration identifier | `OP5911` — kept for existing runtime and tooling safety checks |
| SoC | MediaTek Dimensity 8100-MAX |
| Recovery location | A/B `vendor_boot`, **not a standalone `recovery` partition** |
| Upstream source baseline | [`c5e09f6`](https://github.com/kirklin/skyward/commit/c5e09f6eb644e75e051b309f98d6745ccbc97d81) |

Known firmware baselines:

| Firmware | Android | Stock kernel |
| --- | --- | --- |
| ColorOS 12.1 A.16 | 12 | `5.10.66` |
| ColorOS 13.1 | 13 | not recorded in this repository |
| ColorOS 15 `PGZ110_15.0.0.1600(CN01)` | 15 | `5.10.236` |

## What this port adds

- **Official full-package install.** The recovery can install a full official PGZ110 OTA package: it verifies the package's official signature, plans the single-A payload and `super`, and stages every physical partition before writing.
- **Network install.** The Install page browses a built-in catalogue by model and ColorOS generation and downloads the official full OTA over HTTPS from the phone itself, with resume and length checking; the downloaded package installs from internal storage.
- **Automatic Skyward porting into the target system version.** While a full official package is installed, the target's own stock `vendor_boot` is taken from the package and repacked with the running Skyward program, so Skyward ends up inside the system version being installed instead of being lost. The DTB, bootconfig, original modules and firmware are kept from the target image.
- **Automatic AVB-off.** That same path writes the hashtree/verification disable flags into the current slot's top-level `vbmeta`, and the install page exposes a **Disable AVB** switch; retaining Skyward locks it on. Ordinary OTAs ignore it.
- **Android porter (`Skyward-Porter`).** `tools/mobile-porter` builds an on-device helper that repacks the phone's own `vendor_boot` with a donor Skyward program, after saving full-partition backups of `vendor_boot` and top-level `vbmeta`, and writes back only after explicit confirmation.

Everything above is PGZ110-specific, needs an unlocked bootloader, and fails closed when the audited layout, capacities or AVB descriptors do not match.

## Status and limits

Compilation and host tests were reported during development, and earlier work recorded on-device data decryption and manual Wi-Fi connectivity. This repository does not contain those raw logs, and the current tree has **not** been rebuilt or re-verified on a phone by whoever maintained this documentation.

Not established for this device: OTA-upgrade compatibility across arbitrary firmware, dual boot, full feature coverage, and whether every bundled tool behaves identically on A.16, 13.1 and 1600. The porter tool has not been installed, granted root or used to flash a phone.

## Safety

- Unlocking, flashing, repacking `vendor_boot` and disabling AVB can permanently brick the phone or lose data. Keep full-partition backups and a working rescue path before starting.
- Do not reuse `fastboot flash recovery` instructions from Xiaomi models. Recovery lives in `vendor_boot`; confirm the firmware, slot and partition layout first. No universal flashing command is provided here.
- Writing the top-level `vbmeta` invalidates the original signature; an unlocked bootloader does not guarantee the bootloader accepts the result.
- `vendor_boot` and `vbmeta` are written one after the other, not atomically; a failure or power loss can leave a partial write. Do not simply reboot after such an error.
- Stock init, filesystem checks and Trustonic services may write to persistent storage. Recovery and diagnostic modes are **not** read-only.
- "All data" closes data, then formats metadata and data, and leaves the PGZ110 shared OEM cache/RBR partition (`oplusreserve2`) alone. Formatting metadata destroys encryption keys and cannot be undone.
- `userdebug` images and the debug tooling can enable root/debug ADB or carry a preauthorized ADB public key. Do not treat them as production builds, and do not publish a personal key or raw device logs.

## Repository layout

```text
crates/              Skyward workspace, device-port changes and source tests
 devices/            Upstream definitions plus OP5911 configurations
 tools/              PGZ110 packing, OTA extraction and userdebug tools
 tools/mobile-porter/ On-device porter: Java app, native helper and APK build scripts
 resources/          Font resources and their individual license notices
 assets/, slides/    Upstream artwork and feature illustrations
```

Main configuration: [`devices/OP5911.toml`](devices/OP5911.toml). `devices/OP5911-decrypt.experimental.toml` and `devices/OP5911-boot.toml` are alternative experimental profiles, not interchangeable stable ones. Do not globally rename `OP5911`; existing checks depend on it.

## Building from source

Use Linux or WSL2 with the checkout and NDK on the Linux filesystem: the Rust version in [`rust-toolchain.toml`](rust-toolchain.toml) (currently `1.100.0`), `aarch64-linux-android`, Android NDK r29, Python 3. Packaging also needs `lz4`, AOSP `avbtool`, a matching stock `vendor_boot.img` and the bundled fonts. This is not an offline, dependency-free build bundle.

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk-r29
export SKYWARD_SOURCE="$PWD"
sh tools/build_android.sh
```

The helper builds `skyward` for Android API 30 and runs selected host library tests; it does not flash anything. Host tests alone:

```sh
cargo test --locked -p skyward-config -p skyward-crypto -p skyward-install -p skyward-systems --lib
```

Do not run device tests blindly: some of them format filesystems, mount partitions or move encryption keys.

### Packaging `vendor_boot`

```sh
python3 tools/vendor_boot.py build --help

python3 tools/vendor_boot.py build \
  --stock /path/to/matching/vendor_boot.img \
  --binary target/aarch64-linux-android/release/skyward \
  --config devices/OP5911.toml \
  --font resources/fonts/MiSansVF.ttf \
  --mono resources/fonts/KirkMono-Regular.ttf \
  --mono-license resources/fonts/KirkMono-OFL.txt \
  --avbtool /path/to/avbtool.py \
  --ack-experimental --ack-stock-init-writes \
  --allow-unified-platform-fragment \
  --out out/skyward-qqcandy-vendor_boot.img
```

Packaging example only, not a flashing guide or a release guarantee. `--allow-unified-platform-fragment` applies only to the audited layout. Output carries an unsigned AVB hash footer (`algorithm NONE`), not an OEM signature.

### Building the Android porter

[`tools/mobile-porter/README.zh-CN.md`](tools/mobile-porter/README.zh-CN.md) describes the APK build (`tools/mobile-porter/build_apk.ps1` and `build_native.sh`) and the donor extraction step. The APK is development tooling, not a store-ready app.

## Upstream, modifications and licensing

Skyward is by [kirklin and upstream contributors](https://github.com/kirklin/skyward/graphs/contributors). Original names, copyright notices, Git history and the unmodified [`LICENSE`](LICENSE) are retained. The workspace declares **GPL-3.0-or-later** and this port is distributed under it, without implying upstream endorsement.

See [`NOTICE.md`](NOTICE.md) for dated modification notices and distribution requirements. Third-party libraries and fonts keep their own licenses. The interface uses Xiaomi MiSans, kept unchanged as a Skyward resource under its [separate agreement](resources/fonts/MiSans-LICENSE.txt); Kirk Mono keeps its OFL notice. The porter APK bundles a GPL Skyward binary, MiSans and the Kirk Mono font, with license texts inside the APK assets.

Before distributing compiled binaries or images, supply the complete corresponding source for that exact build, the build scripts and all required third-party notices. A lockfile is not a substitute. Stock firmware, proprietary runtime files and a redistribution grant for them are not supplied here.

## Issues

Include the model, firmware build, source revision, configuration and a minimal reproduction. Redact serial numbers, keys, Wi-Fi details and personal data. Do not perform destructive operations just to file a report.
