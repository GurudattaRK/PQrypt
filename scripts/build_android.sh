#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PQRYPT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OPENSSL_BASE="${PQRYPT_CUSTOM_OPENSSL_DIR:-"$PQRYPT_ROOT/Openssl"}"
INSTALL_PREFIX="$OPENSSL_BASE/static_libs"

CLEAN="${PQRYPT_CLEAN:-0}"

OPENSSL_SRC="$OPENSSL_BASE/openssl-3.6.0"
LIBOQS_SRC="$OPENSSL_BASE/liboqs"

OPENSSL_DIR="$INSTALL_PREFIX/openssl-3.6-android"
OQS_DIR="$INSTALL_PREFIX/liboqs-0.15-android"

ANDROID_API="${ANDROID_API:-34}"
ANDROID_ABI="${ANDROID_ABI:-arm64-v8a}"
ANDROID_TARGET="${ANDROID_TARGET:-aarch64-linux-android}"

if ! command -v cmake >/dev/null 2>&1; then
  echo "Error: cmake not found in PATH." >&2
  exit 1
fi

if ! command -v ninja >/dev/null 2>&1; then
  echo "Error: ninja not found in PATH." >&2
  exit 1
fi

if ! command -v perl >/dev/null 2>&1; then
  echo "Error: perl not found in PATH (required by OpenSSL build)." >&2
  exit 1
fi

ADB=""
if command -v adb >/dev/null 2>&1; then
  ADB="$(command -v adb)"
else
  SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
  if [ -z "$SDK_ROOT" ]; then
    if [ -d "$HOME/Library/Android/sdk" ]; then
      SDK_ROOT="$HOME/Library/Android/sdk"
    elif [ -d "$HOME/Android/Sdk" ]; then
      SDK_ROOT="$HOME/Android/Sdk"
    fi
  fi

  if [ -n "$SDK_ROOT" ] && [ -x "$SDK_ROOT/platform-tools/adb" ]; then
    ADB="$SDK_ROOT/platform-tools/adb"
  fi
fi

if [ -z "$ADB" ]; then
  echo "Error: adb not found. Install Android platform-tools and ensure adb is available." >&2
  echo "Tried: PATH, ANDROID_SDK_ROOT/ANDROID_HOME, and standard SDK locations." >&2
  exit 1
fi

if [ ! -x "$OPENSSL_SRC/Configure" ]; then
  echo "Error: OpenSSL source not found at $OPENSSL_SRC" >&2
  echo "Expected $OPENSSL_SRC/Configure to exist." >&2
  exit 1
fi

if [ ! -f "$LIBOQS_SRC/CMakeLists.txt" ]; then
  echo "Error: liboqs source not found at $LIBOQS_SRC" >&2
  echo "Expected $LIBOQS_SRC/CMakeLists.txt to exist." >&2
  exit 1
fi

NDK_VERSION_REQUIRED=""
if [ -f "$PQRYPT_ROOT/android/app/build.gradle.kts" ]; then
  NDK_VERSION_REQUIRED="$(sed -n 's/^[[:space:]]*ndkVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$PQRYPT_ROOT/android/app/build.gradle.kts" | head -n1)"
fi

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  if [ -n "$NDK_VERSION_REQUIRED" ] && [ -d "$HOME/Library/Android/sdk/ndk/$NDK_VERSION_REQUIRED" ]; then
    ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/$NDK_VERSION_REQUIRED"
  elif [ -d "$HOME/Library/Android/sdk/ndk" ]; then
    NDK_VERSION_FALLBACK="$(ls -1 "$HOME/Library/Android/sdk/ndk" | sort -V | tail -1)"
    ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/$NDK_VERSION_FALLBACK"
  elif [ -d "$HOME/Android/Sdk/ndk" ]; then
    NDK_VERSION_FALLBACK="$(ls -1 "$HOME/Android/Sdk/ndk" | sort -V | tail -1)"
    ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/$NDK_VERSION_FALLBACK"
  else
    echo "Error: Android NDK not found. Set ANDROID_NDK_HOME." >&2
    exit 1
  fi
fi

if [ ! -d "$ANDROID_NDK_HOME" ]; then
  echo "Error: ANDROID_NDK_HOME is set but does not exist: $ANDROID_NDK_HOME" >&2
  exit 1
fi

# OpenSSL's Android Configure expects ANDROID_NDK_ROOT.
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"

NDK_PREBUILT=""
if [ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-arm64" ]; then
  NDK_PREBUILT="darwin-arm64"
elif [ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64" ]; then
  NDK_PREBUILT="darwin-x86_64"
elif [ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64" ]; then
  NDK_PREBUILT="linux-x86_64"
else
  echo "Error: Unsupported/unknown NDK prebuilt host in $ANDROID_NDK_HOME/toolchains/llvm/prebuilt" >&2
  exit 1
fi

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_PREBUILT"
export PATH="$TOOLCHAIN/bin:$PATH"
export CC="${ANDROID_TARGET}${ANDROID_API}-clang"
export CXX="${ANDROID_TARGET}${ANDROID_API}-clang++"
export AR=llvm-ar
export RANLIB=llvm-ranlib
export AS=llvm-as
export LD=ld.lld

mkdir -p "$OPENSSL_BASE" "$INSTALL_PREFIX"

if [ ! -f "$OPENSSL_DIR/lib/libcrypto.a" ] || [ ! -f "$OPENSSL_DIR/lib/libssl.a" ]; then
  rm -rf "$OPENSSL_DIR"

  pushd "$OPENSSL_SRC" >/dev/null

  make clean >/dev/null 2>&1 || true

  CFLAGS="-O3 -march=armv8-a -flto -fno-semantic-interposition -ffunction-sections -fdata-sections" \
  LDFLAGS="-flto -Wl,--gc-sections" \
  ./Configure android-arm64 \
    -D__ANDROID_API__="$ANDROID_API" \
    no-shared \
    --prefix="$OPENSSL_DIR" \
    --openssldir="$OPENSSL_DIR/ssl"

  make -j"$(sysctl -n hw.ncpu)" && make install_sw

  popd >/dev/null
fi

if [ ! -f "$OPENSSL_DIR/lib/libcrypto.a" ] || [ ! -f "$OPENSSL_DIR/lib/libssl.a" ]; then
  echo "Error: OpenSSL Android static build did not produce expected archives in $OPENSSL_DIR/lib" >&2
  exit 1
fi

if [ ! -f "$OQS_DIR/lib/liboqs.a" ]; then
  rm -rf "$OQS_DIR"

  rm -rf "$LIBOQS_SRC/build-android" && mkdir -p "$LIBOQS_SRC/build-android"

  pushd "$LIBOQS_SRC/build-android" >/dev/null

  cmake -GNinja \
    -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ANDROID_ABI" \
    -DANDROID_PLATFORM="android-$ANDROID_API" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_INSTALL_PREFIX="$OQS_DIR" \
    -DOQS_USE_OPENSSL=ON \
    -DOPENSSL_ROOT_DIR="$OPENSSL_DIR" \
    -DOPENSSL_CRYPTO_LIBRARY="$OPENSSL_DIR/lib/libcrypto.a" \
    -DOPENSSL_SSL_LIBRARY="$OPENSSL_DIR/lib/libssl.a" \
    -DOPENSSL_INCLUDE_DIR="$OPENSSL_DIR/include" \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_ENABLE_KEM_HQC=ON \
    -DCMAKE_C_FLAGS="-O3 -march=armv8-a -flto -fno-semantic-interposition" \
    -DCMAKE_EXE_LINKER_FLAGS="-flto -Wl,--gc-sections" \
    -DCMAKE_SHARED_LINKER_FLAGS="-flto -Wl,--gc-sections" \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
    ..

  ninja && ninja install

  popd >/dev/null
fi

if [ ! -f "$OQS_DIR/lib/liboqs.a" ]; then
  echo "Error: liboqs Android static build did not produce expected archive at $OQS_DIR/lib/liboqs.a" >&2
  exit 1
fi

if ! rustup target list --installed | grep -q "^aarch64-linux-android$"; then
  echo "Error: Rust target aarch64-linux-android is not installed." >&2
  echo "Run: rustup target add aarch64-linux-android" >&2
  exit 1
fi

export PQRYPT_CUSTOM_OPENSSL_DIR="$OPENSSL_BASE"

pushd "$PQRYPT_ROOT/android" >/dev/null

if [ "$CLEAN" = "1" ]; then
  rm -rf "$PQRYPT_ROOT/android/app/build" "$PQRYPT_ROOT/android/build" "$PQRYPT_ROOT/android/app/.cxx" "$PQRYPT_ROOT/android/app/.externalNativeBuild" "$PQRYPT_ROOT/android/app/src/main/rust/target" || true
  ./gradlew clean
fi

./gradlew :app:assembleDebug

APK_PATH="$(find "$PQRYPT_ROOT/android/app/build/outputs/apk" -type f \( -name 'PQrypt-debug.apk' -o -name 'app-debug.apk' -o -name '*debug*.apk' \) | head -n1)"
if [ -z "$APK_PATH" ] || [ ! -f "$APK_PATH" ]; then
  echo "Error: debug APK not found under android/app/build/outputs/apk" >&2
  exit 1
fi

echo "Installing APK: $APK_PATH"

"$ADB" devices | awk 'NR>1 && $2=="device" {print $1}' | while read -r serial; do
  if [ -n "$serial" ]; then
    "$ADB" -s "$serial" install -r "$APK_PATH"
  fi
done

echo "Android output: $APK_PATH"

popd >/dev/null

echo "OK: android build complete."
