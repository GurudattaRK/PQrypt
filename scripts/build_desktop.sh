#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PQRYPT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OPENSSL_BASE="${PQRYPT_CUSTOM_OPENSSL_DIR:-"$PQRYPT_ROOT/Openssl"}"
INSTALL_PREFIX="$OPENSSL_BASE/static_libs"

CLEAN="${PQRYPT_CLEAN:-0}"

OPENSSL_SRC="$OPENSSL_BASE/openssl-3.6.0"
LIBOQS_SRC="$OPENSSL_BASE/liboqs"

OPENSSL_DIR="$INSTALL_PREFIX/openssl-3.6"
OQS_DIR="$INSTALL_PREFIX/liboqs-0.15"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "Error: scripts/build_desktop.sh currently supports macOS only." >&2
  exit 1
fi

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

mkdir -p "$OPENSSL_BASE" "$INSTALL_PREFIX"

ARCH="$(uname -m)"
if [ "$ARCH" = "arm64" ]; then
  OPENSSL_TARGET="darwin64-arm64-cc"
else
  OPENSSL_TARGET="darwin64-x86_64-cc"
fi

if [ ! -f "$OPENSSL_DIR/lib/libcrypto.a" ] || [ ! -f "$OPENSSL_DIR/lib/libssl.a" ]; then
  rm -rf "$OPENSSL_DIR"

  pushd "$OPENSSL_SRC" >/dev/null

  make clean >/dev/null 2>&1 || true

  CFLAGS="-O3 -march=native -mtune=native -flto -fno-semantic-interposition -ffunction-sections -fdata-sections" \
  LDFLAGS="-flto -Wl,-dead_strip" \
  ./Configure "$OPENSSL_TARGET" no-shared \
    --prefix="$OPENSSL_DIR" \
    --openssldir="$OPENSSL_DIR/ssl" \
    enable-ec_nistp_64_gcc_128

  make -j"$(sysctl -n hw.ncpu)" && make install_sw

  popd >/dev/null
fi

if [ ! -f "$OPENSSL_DIR/lib/libcrypto.a" ] || [ ! -f "$OPENSSL_DIR/lib/libssl.a" ]; then
  echo "Error: OpenSSL static build did not produce expected archives in $OPENSSL_DIR/lib" >&2
  exit 1
fi

if [ ! -f "$OQS_DIR/lib/liboqs.a" ]; then
  rm -rf "$OQS_DIR"

  rm -rf "$LIBOQS_SRC/build" && mkdir -p "$LIBOQS_SRC/build"

  pushd "$LIBOQS_SRC/build" >/dev/null

  cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_INSTALL_PREFIX="$OQS_DIR" \
    -DOQS_USE_OPENSSL=ON \
    -DOPENSSL_ROOT_DIR="$OPENSSL_DIR" \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_ENABLE_KEM_HQC=ON \
    -DCMAKE_C_FLAGS="-O3 -march=native -mtune=native -flto -fno-semantic-interposition" \
    -DCMAKE_EXE_LINKER_FLAGS="-flto -Wl,-dead_strip" \
    -DCMAKE_SHARED_LINKER_FLAGS="-flto -Wl,-dead_strip" \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
    ..

  ninja && ninja install

  popd >/dev/null
fi

if [ ! -f "$OQS_DIR/lib/liboqs.a" ]; then
  echo "Error: liboqs static build did not produce expected archive at $OQS_DIR/lib/liboqs.a" >&2
  exit 1
fi

export OPENSSL_DIR
export OPENSSL_STATIC=1
export OPENSSL_LIB_DIR="$OPENSSL_DIR/lib"
export OPENSSL_INCLUDE_DIR="$OPENSSL_DIR/include"
export OQS_DIR
export PKG_CONFIG_PATH="$OQS_DIR/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export SDKROOT
SDKROOT="$(xcrun --show-sdk-path)"

pushd "$PQRYPT_ROOT/desktop" >/dev/null

if [ "$CLEAN" = "1" ]; then
  cargo clean
fi

cargo build --release

APP_NAME="$(awk -F'=' '
  $0 ~ /^\[\[bin\]\]/ {in_bin=1; next}
  in_bin && $0 ~ /^name[[:space:]]*=/ {
    gsub(/[\"[:space:]]/, "", $2);
    print $2;
    exit
  }
  $0 ~ /^\[/ {in_bin=0}
' Cargo.toml)"

if [ -z "$APP_NAME" ]; then
  APP_NAME="$(awk -F'=' '
    $0 ~ /^\[package\]/ {in_pkg=1; next}
    in_pkg && $0 ~ /^name[[:space:]]*=/ {
      gsub(/[\"[:space:]]/, "", $2);
      print $2;
      exit
    }
    $0 ~ /^\[/ {in_pkg=0}
  ' Cargo.toml)"
fi

BIN_PATH="$PQRYPT_ROOT/desktop/target/release/$APP_NAME"
if [ -n "$APP_NAME" ] && [ -x "$BIN_PATH" ]; then
  echo "Desktop output: $BIN_PATH"
else
  FOUND_BIN="$(find "$PQRYPT_ROOT/desktop/target/release" -maxdepth 1 -type f -perm -111 2>/dev/null | head -n1)"
  if [ -n "$FOUND_BIN" ]; then
    echo "Desktop output: $FOUND_BIN"
  fi
fi

popd >/dev/null

echo "OK: desktop build complete."
