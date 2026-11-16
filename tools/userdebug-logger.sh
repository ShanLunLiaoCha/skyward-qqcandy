#!/system/bin/sh
# Independent init service: capture even if recovery fails before main()/DRM.
umask 022
mkdir -p /tmp/skyward-userdebug
OUT=/tmp/skyward-userdebug
exec >>"$OUT/collector.log" 2>&1
echo "collector start"
getprop > "$OUT/properties.txt"
cat /proc/cmdline > "$OUT/cmdline.txt"
cat /proc/bootconfig > "$OUT/bootconfig.txt" 2>/dev/null
cat /proc/modules > "$OUT/modules.txt"
logcat -b all -v threadtime -f "$OUT/logcat.txt" -r 2048 -n 2 &
while true; do
    dmesg > "$OUT/dmesg-latest.txt.new" 2>&1
    mv "$OUT/dmesg-latest.txt.new" "$OUT/dmesg-latest.txt"
    getprop > "$OUT/properties-latest.txt"
    ls -l /dev/dri /dev/input /sys/class/backlight /sys/class/leds/lcd-backlight > "$OUT/devices-latest.txt" 2>&1
    sleep 3
done
