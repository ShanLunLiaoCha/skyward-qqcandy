# Fix16：关闭data前等待已核验init adbd完整退出

Fix15本轮真实失败：Data failed: unmount/data EBUSY。此时/sdcard已卸载但/data仍挂载，未进入metadata格式化阶段；当前日志不能说旧密钥已因本次失败删除。

只读FD检查确认adbd的stdout/stderr写/data/adb/...，Recovery自身未见data FD/maps/cwd引用。时间线更准确是：51.917s发kill旧adbd558→51.960s卸载data失败→52.002sinit才收到旧进程退出→52.003s重新启动adbd。旧进程尚未完全退出即卸载先失败，后续自动重启也会再次持有data，因此不能只靠kill加一次扫描。

新实现仅在完整清除事务中检测正在运行的init adbd确实持有/data时，核对initdebugPID、PPID1、精确/system/bin/adbd和前后PID一致，先取得pidfd，再ctl.stop adbd，等待init stopped并以pidfd确认原实例完整退出(有界)，确认无同路径daemon存活，之后才原关闭data流程。

RAII只恢复由本事务成功暂停且原先running的adbd，清除成功/失败作用域结束后ctl.start；恢复daemon不挂载或解密data。若有其它无法释放引用仍按原错误停止，不用lazy卸载绕过。不在普通卸载/部分缓存清理时新增暂停。

保留关闭data→格式化metadata→格式化data顺序和全工具/目标预检。metadata开始格式化后旧密钥不可回滚，失败不继续下一阶段。用户确认执行完整清除时，ADB会暂时断开，不能把这当成设备无响应就反复断电。

本轮没有实际停ADB、清除、刷写或重启；只有只读日志/引用元数据核证，离线Android构建与回归。Fix16仍未真机清除验证，不能承诺所有data占用已解除。新img按既有要求放已挂载持久sdcard并核验hash，不自动部署。
