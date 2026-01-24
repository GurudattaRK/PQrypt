#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PQRYPT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OPENSSL_BASE="${PQRYPT_CUSTOM_OPENSSL_DIR:-"$PQRYPT_ROOT/Openssl"}"
INSTALL_PREFIX="$OPENSSL_BASE/static_libs"

CLEAN="${PQRYPT_CLEAN:-0}"

OPENSSL_TARBALL="$OPENSSL_BASE/openssl-3.6.0.tar.gz"
OPENSSL_SRC_DEFAULT="$OPENSSL_BASE/openssl-3.6.0"
OPENSSL_SRC_ALT="$OPENSSL_BASE/openssl"
OPENSSL_SRC="$OPENSSL_SRC_DEFAULT"
LIBOQS_SRC="$OPENSSL_BASE/liboqs"

OPENSSL_DIR="$INSTALL_PREFIX/openssl-3.6"
OQS_DIR="$INSTALL_PREFIX/liboqs-0.15"

OS_NAME="$(uname -s)"
ARCH="$(uname -m)"

IS_WINDOWS=0
MAKE_BIN="make"

if [ "$OS_NAME" = "Darwin" ]; then
  if [ "$ARCH" = "arm64" ]; then
    OPENSSL_TARGET="darwin64-arm64-cc"
  else
    OPENSSL_TARGET="darwin64-x86_64-cc"
  fi
  NCPU="$(sysctl -n hw.ncpu)"
  OPENSSL_LDFLAGS="-flto -Wl,-dead_strip"
  LIBOQS_LDFLAGS="-flto -Wl,-dead_strip"
elif [ "$OS_NAME" = "Linux" ]; then
  if [ "$ARCH" = "x86_64" ]; then
    OPENSSL_TARGET="linux-x86_64"
  elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    OPENSSL_TARGET="linux-aarch64"
  else
    echo "Error: Unsupported Linux arch: $ARCH" >&2
    exit 1
  fi
  if command -v nproc >/dev/null 2>&1; then
    NCPU="$(nproc)"
  else
    NCPU="4"
  fi
  OPENSSL_LDFLAGS="-flto -Wl,--gc-sections"
  LIBOQS_LDFLAGS="-flto -Wl,--gc-sections"
elif [[ "$OS_NAME" == MINGW* || "$OS_NAME" == MSYS* || "$OS_NAME" == CYGWIN* ]]; then
  IS_WINDOWS=1
  if [ "$ARCH" = "x86_64" ]; then
    OPENSSL_TARGET="mingw64"
  else
    echo "Error: Unsupported Windows/MINGW arch: $ARCH" >&2
    exit 1
  fi
  if command -v nproc >/dev/null 2>&1; then
    NCPU="$(nproc)"
  else
    NCPU="4"
  fi
  if command -v mingw32-make >/dev/null 2>&1; then
    MAKE_BIN="mingw32-make"
  fi
  OPENSSL_LDFLAGS="-Wl,--gc-sections"
  LIBOQS_LDFLAGS="-Wl,--gc-sections"
else
  echo "Error: Unsupported OS: $OS_NAME" >&2
  exit 1
fi

OPENSSL_CFLAGS="-O3 -march=native -mtune=native -flto -ffunction-sections -fdata-sections"
LIBOQS_CFLAGS="-O3 -march=native -mtune=native -flto"
if [ "$IS_WINDOWS" = "0" ]; then
  OPENSSL_CFLAGS="$OPENSSL_CFLAGS -fno-semantic-interposition"
  LIBOQS_CFLAGS="$LIBOQS_CFLAGS -fno-semantic-interposition"
fi

mkdir -p "$OPENSSL_BASE" "$INSTALL_PREFIX"

if [ "$CLEAN" = "1" ]; then
  rm -rf "$OPENSSL_DIR" "$OQS_DIR" || true
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

if [ ! -x "$OPENSSL_SRC_DEFAULT/Configure" ] && [ -x "$OPENSSL_SRC_ALT/Configure" ]; then
  OPENSSL_SRC="$OPENSSL_SRC_ALT"
fi

if [ ! -x "$OPENSSL_SRC/Configure" ] && [ -f "$OPENSSL_TARBALL" ]; then
  rm -rf "$OPENSSL_SRC_DEFAULT" || true
  tar -xzf "$OPENSSL_TARBALL" -C "$OPENSSL_BASE"
  OPENSSL_SRC="$OPENSSL_SRC_DEFAULT"
fi

if [ ! -x "$OPENSSL_SRC/Configure" ]; then
  echo "Error: OpenSSL source not found." >&2
  echo "Expected Configure at one of:" >&2
  echo "  - $OPENSSL_SRC_DEFAULT/Configure" >&2
  echo "  - $OPENSSL_SRC_ALT/Configure" >&2
  echo "Or provide $OPENSSL_TARBALL and let the script extract it." >&2
  exit 1
fi

if [ ! -f "$LIBOQS_SRC/CMakeLists.txt" ]; then
  echo "Error: liboqs source not found at $LIBOQS_SRC" >&2
  echo "Expected $LIBOQS_SRC/CMakeLists.txt to exist." >&2
  exit 1
fi

if [ ! -f "$OPENSSL_DIR/lib/libcrypto.a" ] || [ ! -f "$OPENSSL_DIR/lib/libssl.a" ]; then
  rm -rf "$OPENSSL_DIR"

  pushd "$OPENSSL_SRC" >/dev/null

  "$MAKE_BIN" clean >/dev/null 2>&1 || true

  OPENSSL_EXTRA=()
  if [ "$OS_NAME" = "Darwin" ]; then
    OPENSSL_EXTRA+=(enable-ec_nistp_64_gcc_128)
  fi

  CFLAGS="$OPENSSL_CFLAGS" \
  LDFLAGS="$OPENSSL_LDFLAGS" \
  ./Configure "$OPENSSL_TARGET" no-shared \
    --prefix="$OPENSSL_DIR" \
    --openssldir="$OPENSSL_DIR/ssl" \
    "${OPENSSL_EXTRA[@]}"

  "$MAKE_BIN" -j"$NCPU" && "$MAKE_BIN" install_sw

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
    -DCMAKE_C_FLAGS="$LIBOQS_CFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$LIBOQS_LDFLAGS" \
    -DCMAKE_SHARED_LINKER_FLAGS="$LIBOQS_LDFLAGS" \
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

if [ "$OS_NAME" = "Darwin" ]; then
  export SDKROOT
  SDKROOT="$(xcrun --show-sdk-path)"
fi

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
