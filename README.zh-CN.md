![Skyward](assets/hero.jpg)

# 一加 Ace 竞速版 Skyward · qqcandy

[English](README.md) | 简体中文

本仓库 **skyward-qqcandy** 是 [Skyward](https://github.com/kirklin/skyward) 的一加 Ace 竞速版适配源码。Skyward 是从零使用 Rust 编写的第三方 Recovery；本适配为**非官方、实验性质项目**，不代表一加或 Skyward 上游的官方支持。

## 设备与当前状态

| 项目 | 内容 |
| --- | --- |
| 设备 | 一加 Ace 竞速版 / OnePlus Ace Racing Edition |
| 型号 | PGZ110 |
| 设备代号 | `qqcandy`（由适配维护者提供） |
| 配置内部标识 | `OP5911`，保留供现有运行时与工具安全校验使用 |
| 处理器 | 联发科天玑 8100-MAX |
| 适配固件基线 | ColorOS 15 / Android 15 — `PGZ110_15.0.0.1600(CN01)` |
| 原厂内核基线 | 官方原厂内核 `5.10.236` |
| Recovery 所在分区 | A/B `vendor_boot`，**并非独立 `recovery` 分区** |
| 上游源码基线 | [`c5e09f6`](https://github.com/kirklin/skyward/commit/c5e09f6eb644e75e051b309f98d6745ccbc97d81) |

源码包含 MediaTek / Trustonic 解密服务、亮屏恢复与背光、触控按键、LED 振动、Wi-Fi 校准及启动、USB/MTP、启动和分区擦除策略等适配。**包含实现不等于所有功能均已真机验证。**

既有交付说明记录了 Android 编译及部分主机测试通过，也记录过 data 解密和手动 Wi-Fi 联网的设备观察。本公开目录不包含这些原始日志，且本次仓库整理未独立复现上述结果。OTA 刷包、APEX RAM 后端、既有 device-mapper 映射复用、双系统和任意 ROM 兼容性，均不能视为本机已验证功能。其他设备配置来自上游，不表示本适配仓库对这些设备作出新的支持承诺。

## 使用前必读

- 解锁、刷写、解密和格式化可能导致数据永久丢失或无法开机。请先独立备份，并准备匹配的原厂固件及恢复途径。
- **不要照搬上游小米设备的 `fastboot flash recovery` 命令。** 本机使用 `vendor_boot`；必须先确认固件、分区布局、槽位和救砖方式，本仓库不提供通用刷写命令。
- 原厂 init、文件系统检查与 Trustonic 服务可能写入持久分区。Recovery 与诊断模式都**不是只读环境**。
- 当前源码中的“全部数据”按“关闭 data → 格式化 metadata → 格式化 data”执行，并保留 PGZ110 的原厂共用 cache/RBR 分区（`oplusreserve2`）。格式化 metadata 会销毁加密密钥，无法撤销。此处描述的是当前源码，不代表此前发布的镜像已包含该改动。
- userdebug 工具会启用 root/调试服务并使用显式提供的 ADB 公钥。不要把个人密钥、设备原始日志、Wi-Fi 凭据或调试镜像作为安全生产版本发布。
- 上游针对小米的在线更新行为，不构成本一加适配的可用更新渠道。

## 仓库结构

```text
crates/            Skyward 工作区、设备适配及源码测试
 devices/          上游设备定义及 OP5911 配置
 tools/            PGZ110 vendor_boot 打包与辅助工具
 resources/        字体资源及其单独许可声明
 assets/, slides/  上游项目图片和功能示意图
```

主配置为 [`devices/OP5911.toml`](devices/OP5911.toml)。[`devices/OP5911-decrypt.experimental.toml`](devices/OP5911-decrypt.experimental.toml) 和 [`devices/OP5911-boot.toml`](devices/OP5911-boot.toml) 为其他实验配置，不是可任意互换的稳定配置。`qqcandy` 用作设备展示名及仓库名；请勿全局替换 `OP5911`，现有机型校验依赖它。

## 从源码构建

建议使用 Linux 或 WSL2，并将源码和 NDK 放在 Linux 文件系统中。需要：[`rust-toolchain.toml`](rust-toolchain.toml) 指定的 Rust（当前为 `1.100.0`）、`aarch64-linux-android` 目标、Android NDK r29、Python 3。打包镜像还需要 `lz4`、AOSP `avbtool`、匹配固件的原厂 `vendor_boot.img` 及按各自许可使用的随附字体。**这不是无需外部依赖的离线一键构建包。**

在仓库根目录运行：

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk-r29
export SKYWARD_SOURCE="$PWD"
sh tools/build_android.sh
```

脚本为 Android API 30 编译 `skyward`，随后运行选定的主机库测试，不会刷写设备。依赖版本见 [`Cargo.lock`](Cargo.lock)，需自行保证依赖可获取。编译成功或主机测试通过不代表真机安全。仅运行这些主机测试可使用：

```sh
cargo test --locked -p skyward-config -p skyward-crypto -p skyward-install -p skyward-systems --lib
```

不要盲目执行真机测试；部分测试会格式化文件系统、挂载分区或操作加密密钥。

### 打包 vendor_boot

[`tools/vendor_boot.py`](tools/vendor_boot.py) 以匹配的原厂镜像为基础，检查结构并保留 DTB、ramdisk 布局及原厂组件。未知 init 模板会被拒绝；不要删除检查来强行支持其他固件。

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

这只是打包示例，**不是刷机教程或已验证版本保证**。`--allow-unified-platform-fragment` 仅适用于已审查的匹配镜像布局。若原镜像没有 AVB footer，还需提供已核实的分区容量。输出采用未签名 AVB hash footer（`algorithm NONE`），不是原厂签名。工具不执行刷写。

保留的 userdebug、OTA 提取和 Wi-Fi 辅助脚本面向开发者；使用前应检查源码和各自 `--help`。GitHub Actions 仅手动执行源码检查与编译，不下载原厂固件、不打包镜像、不自动发布 Release。

## 上游、修改与许可证

原项目由 [kirklin 及上游贡献者](https://github.com/kirklin/skyward/graphs/contributors) 开发。保留原有名称、版权声明和未经改动的 [`LICENSE`](LICENSE)。工作区声明为 **GPL-3.0-or-later**；本设备适配按相同许可证分发，不代表上游认可或背书。

修改日期、来源和第三方分发要求见 [`NOTICE.md`](NOTICE.md)。第三方库和字体保留各自许可，不能用项目 GPL 代替。界面使用小米 MiSans，字体原样保留为 Skyward 项目资源，不作为独立字体分发。已附上来自[小米官方](https://hyperos.mi.com/font/download)的中英文[许可协议](resources/fonts/MiSans-LICENSE.txt)，须遵守其独立条款，不将其重新授权为 GPL。Kirk Mono 与 OFL 声明一起保留。

分发编译后的程序或镜像前，须按适用许可证提供与该版本对应的完整源码、相关构建脚本、依赖及所需第三方许可和声明。仅有 lockfile 或“此前私下交付过压缩包”的说明不能替代这些义务。本仓库不附带原厂固件、专有运行时文件，也不代表取得了这些文件的第三方再分发授权。

## 反馈问题

请提供机型、固件版本、源码版本、所用配置及最小复现步骤。日志需先去除序列号、密钥、Wi-Fi 信息与个人数据。不要为了反馈问题而测试破坏性操作。
