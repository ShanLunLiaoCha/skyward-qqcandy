![Skyward](assets/hero.jpg)

# Skyward for OnePlus Ace Racing Edition · qqcandy

English | [简体中文](README.zh-CN.md)

An **unofficial, experimental device port** of [Skyward](https://github.com/kirklin/skyward), a recovery written in Rust. This repository is named **skyward-qqcandy** and contains the modified source, device configuration and image-building tools for the OnePlus Ace Racing Edition. It is not an official OnePlus or upstream Skyward release.

## Device and status

| Item | Value |
| --- | --- |
| Device | OnePlus Ace Racing Edition / 一加 Ace 竞速版 |
| Model | PGZ110 |
| Device codename | `qqcandy` (provided by the port maintainer) |
| Internal configuration identifier | `OP5911` — retained for existing runtime/tool safety checks |
| SoC | MediaTek Dimensity 8100-MAX |
| Firmware baseline | ColorOS 15 / Android 15 — `PGZ110_15.0.0.1600(CN01)` |
| Stock kernel baseline | Official stock kernel `5.10.236` |
| Recovery image partition | `vendor_boot` (A/B); **not a standalone `recovery` partition** |
| Upstream source baseline | [`c5e09f6`](https://github.com/kirklin/skyward/commit/c5e09f6eb644e75e051b309f98d6745ccbc97d81) |

The port includes changes for MediaTek/Trustonic decryption services, display resume and backlight, touch/keys, LED-class haptics, Wi-Fi calibration/bootstrap, USB/MTP, startup and partition/wipe policies. These are source-level adaptations, **not a claim that every feature works on the phone**.

Existing handover notes report successful compilation and host tests, and earlier device observations of data decryption and manual Wi-Fi connectivity. The raw logs are deliberately not part of this public tree; these reports have not been independently reproduced during repository cleanup. OTA installation, APEX RAM backing, reuse of existing device-mapper mappings, dual boot, and general ROM compatibility are **not established** for this device. Other device files are inherited upstream references, not additional support claims by this port.

## Safety

- Unlocking, flashing, decryption and formatting can cause permanent data loss or an unbootable device. Keep independent backups and the matching stock firmware/recovery path.
- Do not use upstream Xiaomi `fastboot flash recovery` instructions on this phone. No generic flashing command is supplied here: verify the firmware, partition layout, slot and recovery method first.
- Stock init, filesystem checks and Trustonic services may write to persistent storage. Recovery and diagnostic modes are **not read-only**.
- “All data” follows the port's close-data → format-metadata → format-data policy. Formatting metadata destroys encryption keys and cannot be undone.
- Debug image tools enable root/debug services and use an explicitly supplied ADB public key. Do not ship a personal key, raw device logs, Wi-Fi credentials or a debug image as a secure production build.
- Xiaomi-specific online update behavior inherited from upstream is not a supported update channel for this OnePlus port.

## Repository layout

```text
crates/          Skyward workspace and device-port changes; source tests retained
 devices/        Upstream device definitions and OP5911 configurations
 tools/          PGZ110 vendor_boot packaging and supporting scripts
 resources/      Font resources and their individual license notices
 assets/, slides/  Upstream artwork and feature illustrations
```

Use [`devices/OP5911.toml`](devices/OP5911.toml) for the main configuration. [`devices/OP5911-decrypt.experimental.toml`](devices/OP5911-decrypt.experimental.toml) and [`devices/OP5911-boot.toml`](devices/OP5911-boot.toml) are alternative experimental configurations, not interchangeable stable profiles. `qqcandy` is the public device/repository name; do not globally rename `OP5911`, which existing safety checks rely on.

## Building from source

Use Linux or WSL2 with the checkout and NDK on the Linux filesystem. Requirements: the Rust version in [`rust-toolchain.toml`](rust-toolchain.toml) (currently `1.100.0`), `aarch64-linux-android`, Android NDK r29, and Python 3. Image packaging also requires `lz4`, AOSP `avbtool`, a matching stock `vendor_boot.img`, and the bundled font resources under their individual licenses. This is **not an offline, dependency-free build bundle**.

From the repository root:

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk-r29
export SKYWARD_SOURCE="$PWD"
sh tools/build_android.sh
```

The helper builds `skyward` for Android API 30 and runs selected host-side library tests. It does not flash a phone. Dependencies must be obtainable using [`Cargo.lock`](Cargo.lock). A build log or host test pass does not establish on-device safety. To run only those selected tests:

```sh
cargo test --locked -p skyward-config -p skyward-crypto -p skyward-install -p skyward-systems --lib
```

Do not blindly run device tests: some tests format filesystems, mount partitions or manipulate encryption keys.

### Packaging vendor_boot

[`tools/vendor_boot.py`](tools/vendor_boot.py) rebuilds the matching stock image while checking its structure and preserving the DTB, ramdisk layout and stock components. It rejects unknown init templates; do not remove those checks to force support for another firmware.

```sh
python3 tools/vendor_boot.py build --help
python3 tools/vendor_boot.py inspect --stock /path/to/matching/vendor_boot.img

mkdir -p out
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

This is a packaging example, **not a flashing guide or a tested-release guarantee**. `--allow-unified-platform-fragment` is specific to the audited layout; use it only for a matching image. If the stock image lacks an AVB footer, the tool also requires the verified partition size. Output uses an unsigned AVB hash footer (`algorithm NONE`), not an OEM signature. The script never flashes a device.

Optional userdebug, OTA extraction and Wi-Fi helper scripts remain available for development. Inspect each script and its `--help` before use. GitHub Actions is manual and checks/builds source only; it does not download stock firmware, package images or publish releases.

## Upstream, modifications and licensing

Skyward is by [kirklin and upstream contributors](https://github.com/kirklin/skyward/graphs/contributors). Original names, copyright notices and the unmodified [`LICENSE`](LICENSE) are retained. The workspace declares **GPL-3.0-or-later**; the device adaptation is distributed under the same license. No upstream endorsement is implied.

See [`NOTICE.md`](NOTICE.md) for the dated modification notice and third-party distribution requirements. Third-party libraries and fonts keep their own licenses. The interface uses Xiaomi MiSans, retained unchanged as a Skyward resource and not offered as a standalone font distribution. Its separate [license agreement](resources/fonts/MiSans-LICENSE.txt), reproduced from [Xiaomi](https://hyperos.mi.com/font/download), is not the GPL and must be respected. Kirk Mono and its OFL notice remain together.

Before distributing compiled binaries or images, supply the complete corresponding source and required third-party notices/licenses for that exact build, including relevant build scripts and dependencies under their applicable licenses. A lockfile or a reference to a previously delivered private archive is not a substitute. Stock firmware, proprietary runtime files and a third-party redistribution grant are not supplied here.

## Reporting issues

Include the model, firmware build, source revision, selected configuration and a minimal reproduction. Redact serial numbers, keys, Wi-Fi information and personal data from logs. Do not test destructive operations merely to prepare an issue report.
