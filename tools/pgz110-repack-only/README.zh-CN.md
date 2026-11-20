# PGZ110 一键重打包（不重新构建）

## 这是什么

输入同一PGZ110目标版本**干净原厂vendor_boot.img**，程序来源默认使用内置**现成Skyward程序资源（donor目录）**，也可指定另一份**Skyward vendor_boot.img**，只解包、按语义调整启动配置、注入现成程序/字体/设备配置、最高压缩和重打包。无Cargo/NDK/内核编译，无adb/fastboot刷写或自动重启。

**不是“任意版本全功能自动移植器”。** 镜像级变化可由脚本处理；现成程序缺少的运行时接口，不能用压缩/改DTB实现。本次A.09已知旧VNDK命名/系统服务路径与现成donor存在未验证项，默认报告并停止；显式输出也只能叫未验证候选。

## Windows 用法

使用交付的“PGZ110-一键重打包”目录：

1. 电脑已有WSL；Linux内需Python3.11+和lz4。无需安装Rust、NDK、Android编译环境。没有依赖时脚本只报错，不自动联网下载安装。
2. 双击“一键处理.cmd”。
3. 输入目标版本原厂vendor_boot路径；内置donor可作现成程序来源，也可指定另一份同机型Skyward镜像。
4. 输入PGZ110确认同机型。板号MT6895本身不足以鉴别手机，不能用这个确认适配其它型号。
5. 查看时间戳output目录的report.json；只有全部镜像检查通过才输出vendor_boot-REPACK-UNTESTED.img。输出已存在就拒绝覆盖。

PowerShell显式参数：

```powershell
.\一键处理.ps1 -TargetVendorBoot 'D:\固件\vendor_boot.img'
# 只做兼容分析，不输出镜像
.\一键处理.ps1 -TargetVendorBoot 'D:\固件\vendor_boot.img' -InspectOnly
# 换另一份现成donor（不会编译它）
.\一键处理.ps1 -TargetVendorBoot 'D:\固件\vendor_boot.img' -DonorVendorBoot 'D:\现成Rec\vendor_boot.img'
```

`-AllowUnverifiedRuntime`只允许越过已知的“运行时尚未验证”门槛，**不能越过损坏镜像、错误布局、歧义服务、容量或文件保留检查**。对A.09不得因此宣称解密/联网等已适配。普通双击默认不开此选项。

## Linux命令

```sh
python3 repack_only.py \
  --target /path/to/stock/vendor_boot.img \
  --donor /path/to/skyward/vendor_boot.img \
  --out /path/to/new-output.img \
  --report /path/to/report.json \
  --avbtool ./avbtool.py \
  --same-device-pgz110
```

只分析增加`--inspect-only`，无需`--out/--avbtool`。离线研究已知旧服务族时可显式`--allow-unverified-runtime`生成候选，仍需自己审核报告。

## 压缩与容量

强制保留legacy LZ4格式并使用**lz4 -12 -l -c**最高级别；不改成普通frame格式。新AVB使用algorithm NONE和vendor_boot SHA256描述符，不复用原签名、不改设备vbmeta。必须满足目标原厂footer记录的分区容量，avbtool再次校验空间；超限直接失败，不删除字体、模块或Rec基本功能。

报告中的remaining_bytes_in_partition是payload之外的总区间，其中包含AVB元数据与padding，不能全部当作可追加文件容量。

## 保留／修改范围

保留目标：DTB、bootconfig、分片类型/名称/board IDs、所有模块及modules.dep/load、固件、原厂库、adbd与认证库。**不移植donor的内核、模块、DTB、驱动、logd运行时、adb_keys或私钥。** 内置donor是Fix16未验证候选，仅作现成程序来源；其破坏性清除顺序等行为仍随程序继承，必须审阅DONOR-FIX16文档。

注入：donor中原样提取的Skyward ELF、device.toml、完整字体与许可，和PGZ110 MTP规则。没有重编译ELF，输出核对与donor哈希一致。

init：解析服务、接口、动作和续行。将已识别且由Skyward管理的原厂重复启动项隔离，保留服务定义、显式fastboot路径和其它无关动作。识别不清或路径不符即拒绝，不靠整文件版本哈希，也不去掉全部安全检查。每项变更和仍需审核的导入/持久写入动作列入报告。

属性：仅清理会阻止程序采用已安装系统版本的旧release/SPL副本；SDK/VNDK和原厂ADB/security策略保留。所以**不会自动免认证ADB**，也不会偷偷植入本电脑公钥。若目标adbd需要原厂UI授权，新界面未提供授权交互可能无法连ADB；不要当作已解决，可保留另一已授权调试入口自行评审，不在脚本中默认降安全。

logd：目标有就保留；目标缺少时如实报告，不复制可能不匹配的新系统库凑成能运行。完整日志需另备匹配运行时，不称已补齐。

## 明确限制

- 本版支持已审核的vendor_boot v4、单PLATFORM/RECOVERY分片、legacy LZ4、system/bin/recovery布局。其它布局安全拒绝。
- 目标boot、dtbo、vendor/odm、vendor_dlkm等必须配套。它们不作为这个简化入口的输入，所以不能检查全部内核/模块ABI或已安装VNDK版本。
- 新／旧init结构通过不等于驱动sysfs、TEE、密码解密、校准和刷包接口通过。
- A.09的`vndk.current`和system目录hwservicemanager等缺口属于程序能力层；若donor没有相应实现，纯重打包无法补齐。应提供已具备该支持的另一份现成donor，或接受仍不能保证A.09完整可用，不能违背“不编译”限制偷偷生成新程序。
- 原厂init挂persist和修复动作仍可能写盘，不是只读启动；报告会保留提示，不盲清所有OEM动作。
- 未在手机刷入本工具输出，未验证启动／解密／联网／刷包／清除／fastboot切换；不自动复制测试产物到手机，以免被误当正式修复版。

## 许可证与来源

Skyward及本项目修改按随附LICENSE和各文件原许可证；avbtool.py保留Android开源项目原始版权许可。内置donor目录仅含从现成Fix16提取的Skyward程序、device.toml、字体和字体许可，不含原厂ramdisk、驱动库、固件、ADB公钥或私钥。其对应源码为本会话Fix16 source-symbols交付，包内记录SHA256与来源。程序不是本次重新编译的；字体等依原作者许可，不能把全部资源宣称为本项目原创。目标OTA和其它专有固件不随工具重新授权。
