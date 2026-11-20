![Skyward](assets/hero.jpg)

# 一加 Ace 竞速版 Skyward · qqcandy

[English](README.md) | 简体中文

本仓库（`skyward-qqcandy`）是 [Skyward](https://github.com/kirklin/skyward) 的**非官方设备移植**，Skyward 是一个从零使用 Rust 编写的 Recovery。仓库包含一加 Ace 竞速版的适配源码、PGZ110 配置、镜像构建工具和手机端移植助手，不是一加官方或 Skyward 上游发布的版本。

## 设备

| 项目 | 内容 |
| --- | --- |
| 设备 | 一加 Ace 竞速版 / OnePlus Ace Racing Edition |
| 型号 | PGZ110 |
| 设备代号 | `qqcandy`（本适配使用的公开名称） |
| 配置内部标识 | `OP5911` —— 保留给现有运行时与工具的安全校验使用 |
| 处理器 | 联发科天玑 8100-MAX |
| Recovery 所在位置 | A/B `vendor_boot`，**不是独立的 `recovery` 分区** |
| 上游源码基线 | [`c5e09f6`](https://github.com/kirklin/skyward/commit/c5e09f6eb644e75e051b309f98d6745ccbc97d81) |

已知固件基线：

| 固件 | Android | 原厂内核 |
| --- | --- | --- |
| ColorOS 12.1 A.16 | 12 | `5.10.66` |
| ColorOS 13.1 | 13 | 本仓库未记录 |
| ColorOS 15 `PGZ110_15.0.0.1600(CN01)` | 15 | `5.10.236` |

## 本适配新增的功能

- **官方全量包安装。** Recovery 可安装本机官方 PGZ110 全量 OTA：先校验官方签名，再规划单 A 载荷与 `super`，并在写入前准备好全部物理分区。
- **网络安装。** 安装页按机型和 ColorOS 版本浏览内置目录，直接在手机上通过 HTTPS 下载官方全量 OTA，支持断点续传与长度校验；下载完成后从内部存储安装。
- **自动移植 Skyward 进对应系统版本。** 安装官方全量包时，从包内取出目标系统自带的原厂 `vendor_boot`，用当前运行的 Skyward 程序重新打包，让 Skyward 进入正在安装的系统版本而不是被覆盖丢失；DTB、bootconfig、原厂模块与固件仍取自目标镜像。
- **自动关闭 AVB 校验。** 同一流程会向当前槽顶层 `vbmeta` 写入 hashtree / verification 禁用标志；安装页同时提供「**禁用 AVB**」开关，保留 Skyward 时该开关锁定为开启，普通 OTA 不使用此选项。
- **手机端移植工具（`Skyward-Porter`）。** `tools/mobile-porter` 可构建手机端助手：先用 donor 的 Skyward 程序重打包本机 `vendor_boot`，保存 `vendor_boot` 与顶层 `vbmeta` 的全分区备份，只有在明确确认后才写回。

以上功能均只面向 PGZ110，需要 Bootloader 已解锁，并在已审查的布局、容量或 AVB 描述符不匹配时直接拒绝执行。

## 状态与限制

开发过程中报告过编译与主机测试结果，早期工作也记录过真机 data 解密和手动 Wi-Fi 联网。本仓库不包含这些原始日志，且维护本文档的环境**未**重新构建或在手机上重新验证当前工作树。

尚未在本机确认：任意固件之间的 OTA 升级兼容性、双系统、完整功能覆盖，以及各工具在 A.16、13.1、1600 上是否表现一致。移植工具尚未在手机上安装、授权 Root 或实际刷写。

## 安全须知

- 解锁、刷写、重打包 `vendor_boot` 以及关闭 AVB 都可能导致手机永久损坏或数据丢失。动手前请准备全分区备份和可用的救援途径。
- 不要照搬小米机型的 `fastboot flash recovery` 指令。本机 Recovery 位于 `vendor_boot`，请先确认固件、槽位和分区布局；本仓库不提供通用刷写命令。
- 写入顶层 `vbmeta` 会使原厂签名失效；Bootloader 已解锁也不保证它会接受这样的结果。
- `vendor_boot` 与 `vbmeta` 是先后写入而非原子写入，失败或断电可能留下部分写入。出现这类错误时不要直接重启。
- 原厂 init、文件系统检查和 Trustonic 服务可能写入持久分区。Recovery 和诊断模式都**不是**只读环境。
- 「全部数据」会关闭 data，再格式化 metadata 与 data，并保留 PGZ110 原厂共用的 cache/RBR 分区（`oplusreserve2`）。格式化 metadata 会销毁加密密钥，无法撤销。
- `userdebug` 镜像与调试工具可能启用 root/调试 ADB，或携带预授权的 ADB 公钥。不要把它们当作生产版本，也不要发布个人密钥或设备原始日志。

## 仓库结构

```text
crates/              Skyward 工作区、设备适配改动及源码测试
 devices/            上游设备定义及 OP5911 配置
 tools/              PGZ110 打包、OTA 提取与 userdebug 工具
 tools/mobile-porter/ 手机端移植工具：Java 应用、原生助手与 APK 构建脚本
 resources/          字体资源及其各自的许可声明
 assets/, slides/    上游项目图片与功能示意图
```

主配置：[`devices/OP5911.toml`](devices/OP5911.toml)。`devices/OP5911-decrypt.experimental.toml` 与 `devices/OP5911-boot.toml` 是另外的实验配置，不能当作可互换的稳定配置。请勿全局替换 `OP5911`，现有校验依赖它。

## 从源码构建

建议使用 Linux 或 WSL2，并把源码与 NDK 放在 Linux 文件系统中：需要 [`rust-toolchain.toml`](rust-toolchain.toml) 指定的 Rust（当前为 `1.100.0`）、`aarch64-linux-android` 目标、Android NDK r29 和 Python 3。打包还需要 `lz4`、AOSP `avbtool`、匹配固件的原厂 `vendor_boot.img` 以及随仓库提供的字体。这不是无需外部依赖的离线构建包。

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk-r29
export SKYWARD_SOURCE="$PWD"
sh tools/build_android.sh
```

该脚本为 Android API 30 构建 `skyward` 并运行选定的主机库测试，不会刷写任何设备。只运行主机测试：

```sh
cargo test --locked -p skyward-config -p skyward-crypto -p skyward-install -p skyward-systems --lib
```

不要盲目执行真机测试：其中部分测试会格式化文件系统、挂载分区或操作加密密钥。

### 打包 `vendor_boot`

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

这只是打包示例，不是刷机教程，也不是发布保证。`--allow-unified-platform-fragment` 仅适用于已审查的镜像布局。输出使用未签名的 AVB hash footer（`algorithm NONE`），不是原厂签名。

### 构建手机端移植工具

[`tools/mobile-porter/README.zh-CN.md`](tools/mobile-porter/README.zh-CN.md) 说明了 APK 构建（`tools/mobile-porter/build_apk.ps1` 与 `build_native.sh`）及 donor 提取步骤。该 APK 属于开发工具，不是可直接上架的应用。

## 上游、修改与许可证

Skyward 由 [kirklin 及上游贡献者](https://github.com/kirklin/skyward/graphs/contributors) 开发。保留原有名称、版权声明、Git 历史及未经改动的 [`LICENSE`](LICENSE)。工作区声明为 **GPL-3.0-or-later**，本适配按该许可证分发，不代表上游认可或背书。

修改日期与分发要求见 [`NOTICE.md`](NOTICE.md)。第三方库与字体保留各自许可。界面使用小米 MiSans，按[独立协议](resources/fonts/MiSans-LICENSE.txt)原样作为 Skyward 资源保留；Kirk Mono 保留其 OFL 声明。移植工具 APK 内含 GPL 的 Skyward 程序、MiSans 与 Kirk Mono 字体，许可全文位于 APK 资源内。

分发编译后的程序或镜像前，须提供与该版本对应的完整源码、构建脚本及所有必需的第三方声明。仅有 lockfile 不能替代这些义务。本仓库不附带原厂固件、专有运行时文件，也不代表取得了它们的再分发授权。

## 反馈问题

请提供机型、固件版本、源码版本、所用配置及最小复现步骤。日志需先去除序列号、密钥、Wi-Fi 信息与个人数据。不要为了反馈问题而执行破坏性操作。
