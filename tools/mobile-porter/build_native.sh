#!/bin/sh
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out="$1"
ndk="$HOME/skyward-pgz110-build/ndk/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin"
export PATH="$base/build-tools/rust-linux/bin:$ndk:$PATH"
export CARGO_HOME="$base/build-tools/cargo-home" CARGO_TARGET_DIR="$base/build-tools/android-userdebug-target"
export CC_aarch64_linux_android="$ndk/aarch64-linux-android30-clang" AR_aarch64_linux_android="$ndk/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk/aarch64-linux-android30-clang"
cargo build --locked --offline --manifest-path "$base/skyward-source/Cargo.toml" --release --target aarch64-linux-android -p skyward-install --features lz4-sys --example mobile_porter
mkdir -p "$out"
"$ndk/llvm-objcopy" --strip-debug "$CARGO_TARGET_DIR/aarch64-linux-android/release/examples/mobile_porter" "$out/libmobile_porter.so"
"$ndk/llvm-readelf" -h -l -d "$out/libmobile_porter.so" > "$out/elf-report.txt"
python3 -B "$base/skyward-mobile-porter/extract_donor.py" "$out/assets" > "$out/donor-sha256.txt"
