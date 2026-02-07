# PQrypt OpenSSL / liboqs Toolchain Folder

This directory is **not** shipped with vendored cryptographic source code. Instead, it is a placeholder that defines where you must place your own OpenSSL and liboqs checkouts.

The current build scripts expect the following layout:

- `Openssl/openssl-3.6.0/` – OpenSSL 3.6.0 source tree (or a symlink named `openssl` pointing to a compatible tree)
- `Openssl/liboqs/` – liboqs 0.15 source checkout
- `Openssl/static_libs/openssl-3.6/` – install prefix where the desktop OpenSSL static libs will be built
- `Openssl/static_libs/liboqs-0.15/` – install prefix where the desktop liboqs static lib will be built
- `Openssl/static_libs/openssl-3.6-android/` – install prefix where the Android OpenSSL static libs will be built
- `Openssl/static_libs/liboqs-0.15-android/` – install prefix where the Android liboqs static lib will be built

The shell scripts under `scripts/` (`build_desktop.sh`, `build_android.sh`, and their Windows wrappers) will:

- Build OpenSSL and liboqs from the source trees placed here.
- Populate the corresponding `static_libs/` subdirectories with the resulting static libraries and headers.

> Do **not** commit third‑party OpenSSL or liboqs source code or tarballs to this repository. Only commit small metadata files like this README so the folder structure is preserved.
