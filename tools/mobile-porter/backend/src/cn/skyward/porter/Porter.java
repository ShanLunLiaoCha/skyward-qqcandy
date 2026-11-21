package cn.skyward.porter;

import android.content.Context;
import android.util.Log;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.function.Consumer;

/** The root bridge is restricted to the current slot's vendor_boot and top-level vbmeta. */
public final class Porter {
    private static final long VENDOR_BYTES = 64L << 20, AVB_BYTES = 8L << 20;
    private static final String[] ASSETS = {"system/bin/recovery", "skyward/device.toml",
        "skyward/MiSansVF.ttf", "skyward/KirkMono-Regular.ttf", "skyward/KirkMono-OFL.txt",
        "system/etc/init/skyward-mtp.rc"};
    private final Context context;
    private Prepared current;

    public Porter(Context ctx) { context = ctx.getApplicationContext(); }

    public static final class Prepared {
        public final String slot;
        public final File backup, image, vbmetaBackup, vbmetaImage;
        private final Target vendor, avb;
        private final String model, fingerprint, bootId, originalVendor, originalAvb, newVendor, newAvb;
        private Prepared(State s, File folder, File image, File vbmetaImage, String originalVendor, String originalAvb,
                String newVendor, String newAvb) {
            slot = s.slot; model = s.model; fingerprint = s.fingerprint; bootId = s.bootId;
            vendor = s.vendor; avb = s.avb;
            backup = new File(folder,"vendor_boot" + slot + "-original.img");
            vbmetaBackup = new File(folder,"vbmeta" + slot + "-original.img");
            this.image = image; this.vbmetaImage = vbmetaImage;
            this.originalVendor = originalVendor; this.originalAvb = originalAvb;
            this.newVendor = newVendor; this.newAvb = newAvb;
        }
    }

    private record Target(String label, String node, long bytes) {}
    private record State(String model, String slot, String fingerprint, String bootId, Target vendor, Target avb) {}

    public synchronized Prepared prepare(String model, Consumer<String> log) throws Exception {
        current = null;
        if (!model.equals("PGZ110") && !model.equals("PGJM10")) throw new IOException("请选择支持的机型");
        log.accept("检测到的 Root 管理器：" + rootManagers());
        log.accept("正在请求 Root 权限并核对当前槽位…");
        Log.i("SkywardPorter", "prepare: model=" + model + " su=" + su() + " root=" + rootManagers());
        requestRoot();
        Log.i("SkywardPorter", "prepare: root granted");
        State s = inspect(model, false);
        File privateFiles = context.getFilesDir();
        if (privateFiles.getUsableSpace() < 240L << 20) throw new IOException("应用存储不足，需要至少 240 MiB");
        File folder = Files.createTempDirectory(privateFiles.toPath(), "porter-").toFile();
        File vendorBackup = new File(folder,"vendor_boot" + s.slot + "-original.img");
        File avbBackup = new File(folder,"vbmeta" + s.slot + "-original.img");
        log.accept("只读备份原始 vendor_boot 和 vbmeta：" + s.slot);
        String originalVendor = capture(s, s.vendor, vendorBackup);
        String originalAvb = capture(s, s.avb, avbBackup);
        if (!originalVendor.equals(deviceHash(s, s.vendor)) || !originalAvb.equals(deviceHash(s, s.avb)))
            throw new IOException("备份期间源分区内容发生变化");
        log.accept("备份已保存。正在用内置 Fix50 1600 donor 重打包…");
        File donor = new File(folder,"donor");
        for (String path : ASSETS) {
            File file = new File(donor,path);
            if (!file.getParentFile().mkdirs() && !file.getParentFile().isDirectory()) throw new IOException("无法创建 donor 目录");
            try (InputStream in = context.getAssets().open("donor/" + path); FileOutputStream out = new FileOutputStream(file)) {
                copy(in, out, 32L << 20); out.getFD().sync();
            }
        }
        File image = new File(folder,"vendor_boot" + s.slot + "-skyward.img");
        File avbImage = new File(folder,"vbmeta" + s.slot + "-avb-off.img");
        output(new ProcessBuilder(helper(), vendorBackup.getPath(), avbBackup.getPath(), donor.getPath(), image.getPath(), avbImage.getPath()).redirectErrorStream(true));
        String newVendor = fileHash(image, VENDOR_BYTES), newAvb = fileHash(avbImage, AVB_BYTES);
        writeFile(new File(folder,"partition-backup.txt"), "profile=" + model + "\nslot="+s.slot+"\nbuild="+s.fingerprint+"\n"
            +"vendor_boot="+originalVendor+"\nvbmeta="+originalAvb+"\ncandidate_vendor_boot="+newVendor+"\ncandidate_vbmeta="+newAvb+"\n");
        current = new Prepared(s, folder, image, avbImage, originalVendor, originalAvb, newVendor, newAvb);
        return current;
    }

    public synchronized void flash(Prepared p, Consumer<String> log) throws Exception {
        if (p == null || current != p) throw new IOException("请先重新准备镜像");
        current = null;
        State expected = new State(p.model,p.slot,p.fingerprint,p.bootId,p.vendor,p.avb);
        if (!expected.equals(inspect(p.model, true))) throw new IOException("机型、分区、版本、槽位或本次启动已变化");
        if (!p.originalVendor.equals(fileHash(p.backup,VENDOR_BYTES)) || !p.originalAvb.equals(fileHash(p.vbmetaBackup,AVB_BYTES))
                || !p.newVendor.equals(fileHash(p.image,VENDOR_BYTES)) || !p.newAvb.equals(fileHash(p.vbmetaImage,AVB_BYTES)))
            throw new IOException("备份或候选文件不再与准备结果一致");
        File journal = new File(p.image.getParentFile(),"flash-state.txt");
        String guard = guard(expected,true);
        String check = checkHash(p.vendor.node,p.originalVendor) + checkHash(p.avb.node,p.originalAvb)
            + checkHash(p.image.getPath(),p.newVendor) + checkHash(p.vbmetaImage.getPath(),p.newAvb);
        root(guard + check);
        log.accept("先写入当前槽 AVB 标志，再刷入同槽 vendor_boot；不会重启…");
        writeFile(journal,"写入已请求；如程序中断，不要直接重启。\n");
        try {
            // Check again in the Root command that performs the writes. The
            // two raw writes cannot be atomic, so retain originals and journal.
            StringBuilder command = new StringBuilder(guard).append("exec ").append(q(helper())).append(" --flash");
            for (String argument : new String[]{p.slot, p.bootId, p.vendor.node, p.avb.node,
                    p.originalVendor, p.originalAvb, p.image.getPath(), p.vbmetaImage.getPath(), p.newVendor, p.newAvb}) {
                command.append(' ').append(q(argument));
            }
            root(command.toString());
            writeFile(journal,"已完成，两分区读回哈希匹配。未重启。\n");
        } catch (Exception e) {
            try { writeFile(journal,"写入或读回失败；可能部分写入。保持手机开机，保留两个原始备份。\n" + e + "\n"); }
            catch (IOException ignored) { }
            throw new IOException("刷写未确认成功，可能已部分写入。请勿重启；保留两个原始备份。",e);
        }
    }

    private static State inspect(String selected, boolean writing) throws Exception {
        String version = root("set -eu; test \"$(id -u)\" = 0; getprop ro.product.model; getprop ro.product.device; "
                + "getprop ro.boot.slot_suffix; getprop ro.build.fingerprint; cat /proc/sys/kernel/random/boot_id");
        String[] a = version.split("\\R",-1);
        if (a.length != 5 || a[3].isEmpty() || !a[4].matches("[0-9a-f-]{36}")) throw new IOException("无法确认手机身份与启动状态");
        boolean acerace = a[0].equals("PGZ110") || a[1].equals("PGZ110") || a[1].equals("OP5911") || a[1].equals("acerace");
        boolean k10 = a[0].equals("PGJM10") || a[1].equals("PGJM10");
        // PGZ110 and PGJM10 are the same hardware family and accept each
        // other's Recovery, so the chosen name is not matched against the
        // phone. Only membership in that family is required.
        if (!acerace && !k10) throw new IOException("本机不是 PGZ110 / PGJM10，无法使用此移植");
        String slot = a[2];
        if (!slot.equals("_a") && !slot.equals("_b")) throw new IOException("无法确认活动槽");
        Target vendor = target("vendor_boot"+slot,VENDOR_BYTES), avb = target("vbmeta"+slot,AVB_BYTES);
        if (vendor.node.equals(avb.node)) throw new IOException("刷写目标异常重叠");
        State s = new State(selected,slot,a[3],a[4],vendor,avb);
        root(guard(s,writing));
        return s;
    }

    private static Target target(String name, long bytes) throws Exception {
        String resolved = root("readlink -f /dev/block/by-name/"+name);
        if (!resolved.matches("/dev/block/(sd[a-z][0-9]+|mmcblk[0-9]+p[0-9]+)")) throw new IOException("未知分区路径："+name);
        return new Target(name,resolved,bytes);
    }

    private static String guard(State s, boolean write) {
        String slotNo = s.slot.equals("_a") ? "0" : "1";
        return "set -eu; test \"$(id -u)\" = 0; "
            + "test \"$(getprop ro.boot.slot_suffix)\" = "+q(s.slot)+"; "
            + "test \"$(getprop ro.build.fingerprint)\" = "+q(s.fingerprint)+"; "
            + "test \"$(cat /proc/sys/kernel/random/boot_id)\" = "+q(s.bootId)+"; "
            + guardTarget(s.vendor) + guardTarget(s.avb)
            + (write ? "state=$(getprop ro.boot.vbmeta.device_state); locked=$(getprop ro.boot.flash.locked); "
                + "test -z \"$state\" && state=unlocked; test \"$state\" = unlocked || { echo 'Bootloader is not unlocked' >&2; exit 1; }; "
                + "test -z \"$locked\" && locked=0; test \"$locked\" = 0 || { echo 'Bootloader lock properties disagree' >&2; exit 1; }; "
                + "test \"$(getprop ro.boot.verifiedbootstate)\" = orange || { echo 'Boot state is not orange' >&2; exit 1; }; "
                + "pending=$(ls -A /metadata/ota/snapshots 2>/dev/null | wc -l); test \"$pending\" = 0 || { echo 'Virtual A/B snapshot state is not idle' >&2; exit 1; }; "
                + "if command -v bootctl >/dev/null 2>&1; then "
                + "test \"$(bootctl get-current-slot)\" = "+slotNo+"; test \"$(bootctl get-active-boot-slot)\" = "+slotNo+"; "
                + "test \"$(bootctl get-snapshot-merge-status)\" = none || { echo 'Virtual A/B merge state is not idle' >&2; exit 1; }; fi; " : "");
    }

    private static String guardTarget(Target t) {
        String node = t.node.substring(t.node.lastIndexOf('/')+1);
        return "test \"$(readlink -f /dev/block/by-name/"+t.label+")\" = "+q(t.node)+"; test -b "+q(t.node)+"; "
            + "grep -Fxq "+q("PARTNAME="+t.label)+" /sys/class/block/"+node+"/uevent; "
            + "test \"$(blockdev --getsize64 "+q(t.node)+")\" = "+t.bytes+"; ";
    }

    private String helper() {
        return new File(context.getApplicationInfo().nativeLibraryDir,"libmobile_porter.so").getPath();
    }
    private static String checkHash(String path,String hash) {
        return "h=$(sha256sum "+q(path)+"); test \"${h%% *}\" = "+q(hash)+" || { echo 'Partition/file hash mismatch' >&2; exit 1; }; ";
    }
    private static String deviceHash(State s,Target t) throws Exception {
        String result = root(guard(s,false)+"sha256sum "+q(t.node));
        String hash = result.split("\\s+",2)[0];
        if(!hash.matches("[0-9a-f]{64}")) throw new IOException("分区哈希读取失败");
        return hash;
    }

    private static String capture(State s,Target t,File file) throws Exception {
        File diagnostics = new File(file.getParentFile(),file.getName()+".log");
        Process p = new ProcessBuilder(su(),"-c",guard(s,false)+"cat "+q(t.node)).redirectError(diagnostics).start();
        try (InputStream in = p.getInputStream(); FileOutputStream out = new FileOutputStream(file)) {
            if(copy(in,out,t.bytes) != t.bytes) throw new IOException("Root 读取的分区字节数不足："+ t.label);
            out.getFD().sync();
            if(p.waitFor()!=0) throw new IOException("Root 无法读取分区："+t.label);
        } finally { p.destroy(); }
        return fileHash(file,t.bytes);
    }
    /** Where each root manager puts its su; PATH alone often lacks it. */
    private static final String[] SU_PATHS = {"/product/bin/su","/system/bin/su","/system/xbin/su",
        "/sbin/su","/vendor/bin/su","/system_ext/bin/su","/odm/bin/su","/debug_ramdisk/su",
        "/data/adb/ksu/bin/su","/data/adb/magisk/su","/data/adb/ap/bin/su"};

    /** Root managers this build knows how to talk to, by their marker. */
    private static final String[][] ROOT_MANAGERS = {
        {"KernelSU", "/data/adb/ksu"}, {"KernelSU-Next", "/data/adb/ksunext"},
        {"APatch", "/data/adb/ap"}, {"Magisk", "/data/adb/magisk"}, {"Magisk", "/debug_ramdisk"},
    };

    /** Which root managers are installed, as the phone can see them now. */
    static String rootManagers() {
        StringBuilder found = new StringBuilder();
        for (String[] manager : ROOT_MANAGERS) {
            if (!new File(manager[1]).exists()) continue;
            if (found.indexOf(manager[0]) >= 0) continue;
            if (found.length() > 0) found.append(", ");
            found.append(manager[0]);
        }
        if (found.length() == 0) found.append("none detected");
        return found.toString();
    }

    private static String su() {
        for (String path : SU_PATHS) {
            File file = new File(path);
            if (file.isFile() && file.canExecute()) return path;
        }
        return "su";
    }

    /** Ask for Root once, so the manager can show its prompt before any work. */
    static void requestRoot() throws Exception {
        Log.i("SkywardPorter", "requestRoot via " + su());
        String id = root("id -u");
        Log.i("SkywardPorter", "requestRoot answered: " + id);
    }

    private static String root(String command) throws Exception {
        try {
            return output(new ProcessBuilder(su(),"-c",command).redirectErrorStream(true));
        } catch (IOException e) {
            Log.e("SkywardPorter", "su failed: " + e);
            throw new IOException("无法执行 su（请确认已安装 Root 管理器并允许本应用）：" + e.getMessage(), e);
        }
    }
    private static String output(ProcessBuilder builder) throws Exception {
        Process p = builder.start();
        try (InputStream in = p.getInputStream(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            copy(in,out,128L<<10);
            String message = out.toString(StandardCharsets.UTF_8).trim();
            if (p.waitFor()!=0) throw new IOException(message.isEmpty()? "命令失败（Root 未授权或分区检查不通过）":message);
            return message;
        } finally { p.destroy(); }
    }
    private static String q(String value) { return "'" + value.replace("'", "'\\''") + "'"; }
    private static long copy(InputStream in,OutputStream out,long max) throws IOException {
        byte[] buf = new byte[256<<10]; long total=0;
        for(int n;(n=in.read(buf))!=-1;){ total+=n; if(total>max) throw new IOException("文件超出允许的大小"); out.write(buf,0,n); }
        return total;
    }
    private static String fileHash(File file,long size) throws Exception {
        if(!file.isFile() || file.length()!=size) throw new IOException("文件大小不正确：" +file.getName());
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); byte[] buf = new byte[256<<10];
        try(InputStream in = new FileInputStream(file)){ for(int n;(n=in.read(buf))!=-1;) digest.update(buf,0,n); }
        StringBuilder hex=new StringBuilder(64); for(byte value:digest.digest()) hex.append(String.format(Locale.ROOT,"%02x",value&255));
        return hex.toString();
    }
    private static void writeFile(File file,String text) throws IOException {
        try(FileOutputStream out = new FileOutputStream(file)){out.write(text.getBytes(StandardCharsets.UTF_8));out.getFD().sync();}
    }
}
