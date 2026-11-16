#!/bin/sh
# Run from the port root; no flashing, no system-global Rust configuration.
set -eu
: "${SKYWARD_SOURCE:?Set SKYWARD_SOURCE to the skyward-qqcandy repository root}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to Android NDK r29}"
: "${CARGO_TARGET_DIR:=$SKYWARD_SOURCE/target}"
export CARGO_TARGET_DIR
HOST_TAG=linux-x86_64
NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"
[ -x "$NDK_BIN/aarch64-linux-android30-clang" ] || { echo 'NDK r29 Linux compiler not found' >&2; exit 1; }
export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android30-clang"
export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android30-clang"
cargo build --locked --manifest-path "$SKYWARD_SOURCE/Cargo.toml" --target aarch64-linux-android --release -p skyward
# Test data mapping/parser and filesystem-independent startup policies, not decryption on a phone.
cargo test --locked --manifest-path "$SKYWARD_SOURCE/Cargo.toml" -p skyward-config -p skyward-crypto -p skyward-install -p skyward-systems --lib
printf '%s\n' "Built $CARGO_TARGET_DIR/aarch64-linux-android/release/skyward; no device was flashed."
