#!/bin/bash
# Environment variables for static OpenSSL 3.6 + liboqs 0.15 build

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENSSL_BASE="${PQRYPT_CUSTOM_OPENSSL_DIR:-"$SCRIPT_DIR"}"

export PQRYPT_CUSTOM_OPENSSL_DIR="$OPENSSL_BASE"
export OPENSSL_DIR="$OPENSSL_BASE/static_libs/openssl-3.6"
export OPENSSL_STATIC=1
export OPENSSL_LIB_DIR="$OPENSSL_DIR/lib"
export OPENSSL_INCLUDE_DIR="$OPENSSL_DIR/include"
export OQS_DIR="$OPENSSL_BASE/static_libs/liboqs-0.15"
export PKG_CONFIG_PATH="$OQS_DIR/lib/pkgconfig:$PKG_CONFIG_PATH"
export SDKROOT=$(xcrun --show-sdk-path)

echo "Static build environment loaded:"
echo "  OpenSSL: $OPENSSL_DIR"
echo "  liboqs: $OQS_DIR"
echo "  Static linking: ENABLED"
