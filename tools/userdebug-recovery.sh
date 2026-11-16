#!/system/bin/sh
# Run full Recovery; no function is skipped. Capture loader/stderr before Rust.
umask 022
mkdir -p /tmp/skyward-userdebug
OUT=/tmp/skyward-userdebug
echo "recovery wrapper entered" >> "$OUT/recovery-entry.txt"
export RUST_BACKTRACE=full
export RUST_LIB_BACKTRACE=1
/system/bin/recovery >> "$OUT/recovery-stdio.txt" 2>&1
status=$?
echo "recovery exited: $status" >> "$OUT/recovery-entry.txt"
dmesg > "$OUT/dmesg-on-exit.txt" 2>&1
exit "$status"
