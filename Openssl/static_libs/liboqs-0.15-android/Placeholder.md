# Static Library Output Layout

This directory is the **output location** for static libraries built from your local OpenSSL and liboqs sources.

The PQrypt build scripts will populate the following subdirectories:

- `openssl-3.6/` – desktop OpenSSL static libraries and headers
- `liboqs-0.15/` – desktop liboqs static library and headers
- `openssl-3.6-android/` – Android OpenSSL static libraries and headers
- `liboqs-0.15-android/` – Android liboqs static library and headers

These folders are created and filled automatically when you run:

- `PQRYPT_CLEAN=1 bash scripts/build_desktop.sh`
- `PQRYPT_CLEAN=1 bash scripts/build_android.sh`

You should not manually place third‑party libraries here; instead, provide the source trees under `Openssl/openssl-3.6.0/` and `Openssl/liboqs/` and let the scripts build into this directory.
