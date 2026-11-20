# Attribution, modifications and third-party notices / 署名、修改及第三方声明

## Upstream / 上游

Skyward: https://github.com/kirklin/skyward

Authors: kirklin and the upstream contributors. / 原作者：kirklin 及上游贡献者。

Source baseline / 源码基线：`c5e09f6eb644e75e051b309f98d6745ccbc97d81`.

This is an unofficial modified version for OnePlus Ace Racing Edition (PGZ110 / qqcandy); it is not an upstream or OnePlus release. Upstream copyright notices and Git history are retained. The unchanged root LICENSE contains GPLv3; Cargo workspace metadata specifies GPL-3.0-or-later. The port does not impose additional restrictions on the GPL-covered code.

这是面向一加 Ace 竞速版（PGZ110 / qqcandy）的非官方修改版，不是原作者或一加发布的版本。保留上游版权声明及 Git 历史。根 LICENSE 为未经改动的 GPLv3 正文，Cargo 工作区声明为 GPL-3.0-or-later；本适配不对 GPL 源码附加额外限制。

## Modification notice / 修改声明 — 2026-11-16

The supplied working tree already contained device-port changes on top of the baseline. Their original development dates and individual authors are not reconstructed here. They include OP5911 configurations and changes to Binder, block/partition operations, decryption/Trustonic, startup/runtime services, display/input/haptics, Wi-Fi, USB/MTP, install/system handling and wipe policies, plus source tests. Compare the working tree with the baseline to inspect exact changes; no upstream commits or test results have been fabricated.

本次整理前的工作树已包含设备适配改动；不伪造其原始开发日期或逐项作者。主要涉及 OP5911 配置、Binder、块设备/分区操作、解密与 Trustonic、启动及运行时服务、显示/输入/振动、Wi-Fi、USB/MTP、安装/系统处理和擦除策略，以及相应源码测试。可将工作树与上述基线比较查看准确改动；未伪造上游提交或测试结果。

Repository cleanup on the date above: promoted the existing source checkout to the repository root; added PGZ110 tools and the boot profile; rewrote English/Chinese READMEs for qqcandy; corrected shell environment-variable validation and locked Cargo dependency resolution; replaced the Xiaomi-oriented automatic image/release workflow with manual source checks/builds; added the official MiSans agreement. Historical porting notes, research notes, validation outputs, checksums and debug symbols were moved outside the public repository. Source tests, build-time integrity checks, licenses and attributions were not discarded.

上述日期的仓库整理：将现有源码仓库提升到根目录；纳入 PGZ110 工具及 boot 配置；编写 qqcandy 中英文 README；修正 shell 环境变量检查并锁定 Cargo 依赖解析；将面向小米的自动镜像/发布流程改为手动源码检查和编译；补充官方 MiSans 协议。历次移植说明、研究记录、验证输出、交付校验清单及调试符号移至公开仓库外。源码测试、构建完整性检查、许可证及署名予以保留。

## Source update / 源码更新 — 2026-11-18

Updated the PGZ110 recovery source for secure-service and VNDK handling, Android 12 storage compatibility for devices previously configured without a screen lock, Wi-Fi module planning, device/battery information, and factory-reset planning and safeguards. This source update did not replace the published `qqcandy-1600-userdebug` image or establish new firmware support.

本次更新了 PGZ110 的安全服务与 VNDK 处理、此前未设置屏幕锁的 Android 12 设备存储兼容逻辑、Wi-Fi 模块加载规划、设备及电池信息，以及恢复出厂设置的规划和安全检查。此次只更新源码，未替换已发布的 `qqcandy-1600-userdebug` 镜像，也不代表增加了已验证的固件支持。

## Source update / 源码更新 — 2026-11-21

Added the official full-package (factory bundle) install path, the in-recovery OTA catalogue and downloader, the PGZ110 vendor_boot repacker used to port the running Skyward into the target system version, the AVB-off preparation for that path, the single-A payload/super planning modules, and the Android porter tool under `tools/mobile-porter`. The bundle is restricted to the PGZ110 layouts it was audited against and requires an unlocked bootloader.

本次新增官方全量包（factory bundle）安装流程、Recovery 内的 OTA 目录与下载器、用于把当前 Skyward 移植进目标系统版本的 PGZ110 vendor_boot 重打包模块、该流程所需的 AVB 关闭准备、单 A 载荷与 super 规划模块，以及 `tools/mobile-porter` 手机端移植工具。该流程仅适用于已审查的 PGZ110 布局，并要求 Bootloader 已解锁。

## Fonts / 字体

- **MiSans**: Xiaomi / 小米科技有限责任公司. Used unchanged for Skyward's interface as a project resource, not distributed separately or relicensed as GPL. See [MiSans-LICENSE.txt](resources/fonts/MiSans-LICENSE.txt), which reproduces the Chinese and English agreement from https://hyperos.mi.com/font/download and https://hyperos.mi.com/font/en/download/ (retrieved 2026-11-16). The application already contains a MiSans attribution in its font information/about UI. / 原样用于 Skyward 界面，不单独分发，不重新授权为 GPL；程序字体信息/关于界面中已有 MiSans 使用声明。
- **Kirk Mono**: SIL Open Font License 1.1. The bundled [OFL notice](resources/fonts/KirkMono-OFL.txt), including JetBrains and Kirk Mono authors' copyright statements, must remain with the font. / 必须随字体保留 OFL 及 JetBrains、Kirk Mono 作者的版权声明。

## Dependencies and image distribution / 依赖与镜像分发

Cargo dependencies are resolved by Cargo.lock and are licensed independently. This tree does not vendor all registry source packages and does not contain a complete dependency license inventory. A reference to an old private source archive is not a current public source offer. Do not represent this notice as a completed binary-distribution compliance audit.

Cargo 依赖按 Cargo.lock 解析，分别遵守各自许可证。本目录没有收录全部 registry 依赖源码，也不是完整依赖许可清单；旧的私下源码归档引用不能作为当前公开源码提供。本声明不是二进制分发已全部合规的保证。

Before releasing a compiled program or recovery image, provide the complete corresponding source required by the GPL for that exact build and satisfy all relevant dependency, font and other component notices/licenses. Include the relevant build scripts, configurations and changes. Review any kernel, stock components or other firmware bundled into an image separately under their own terms; do not assume the project's GPL grants permission for them. A prebuilt stock vendor_boot image and proprietary runtime files are not supplied here. Runtime hashes in tools/logd-runtime-manifest.json are identification/checking data, not a redistribution license.

发布编译程序或 Recovery 镜像前，应提供 GPL 对该确切版本要求的完整对应源码，满足相关依赖、字体及其他组件的许可/声明要求，并包含相关构建脚本、配置和修改。镜像内的内核、原厂组件及固件须分别检查其许可，不能认为项目 GPL 自动为这些组件授权。本仓库不附带预编译原厂 vendor_boot 镜像或专有运行时文件。tools/logd-runtime-manifest.json 中的哈希仅用于识别/检查，不是再分发授权。
