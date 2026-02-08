# 🔐 PQrypt

**Quantum-Resistant Encryption for Everyone**

PQrypt is a next-generation post quantum cryptographic application that can protect your files and communications against both current and future quantum attacks. Available for Windows, macOS, Linux, and Android.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android-blue)](https://github.com/GurudattaRK/PQrypt)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)

---

## 📥 Installation for Windows & Android (Pre-built Binaries)

### 🪟 Windows
1. Go to [Releases](https://github.com/GurudattaRK/PQrypt/releases)
2. Download `pqrypt-windows.exe`
3. Double-click to run (Windows Defender may show a warning - click "More info" → "Run anyway")


### 📱 Android
1. Go to [Releases](https://github.com/GurudattaRK/PQrypt/releases)
2. Download `PQrypt.apk`
3. Open the APK file on your phone
4. Allow installation from unknown sources if prompted
5. Install and open the app



---

## 🛠️ Build Desktop app from Source (Linux, macOS, windows)

### Prerequisites
- **Rust**: Install from [rustup.rs](https://rustup.rs/)
- **Git**: For cloning the repository

For builds that use PQC (ML-KEM / HQC / SLH-DSA), PQrypt relies on a custom OpenSSL build and liboqs.
This repo uses the `Openssl/` folder to build and cache static libraries, but **does not** vendor those
third-party sources. You must provide your own OpenSSL and liboqs checkouts in that folder.

Required for the build scripts:
- **cmake**
- **ninja**
- **perl** (OpenSSL build)

The current scripts are wired for:

- **OpenSSL**: 3.6.x (paths currently default to `openssl-3.6.0`)
- **liboqs**: 0.15

Expected `Openssl/` layout:

- `Openssl/openssl-3.6.0/` – OpenSSL 3.6.x source tree (or `Openssl/openssl/` pointing to a compatible tree)
- `Openssl/liboqs/` – liboqs 0.15 source checkout
- `Openssl/static_libs/openssl-3.6/` – desktop OpenSSL static libs build/install prefix
- `Openssl/static_libs/liboqs-0.15/` – desktop liboqs static lib build/install prefix
- `Openssl/static_libs/openssl-3.6-android/` – Android OpenSSL static libs build/install prefix
- `Openssl/static_libs/liboqs-0.15-android/` – Android liboqs static lib build/install prefix

Only small metadata files (like these READMEs) are included in this repository under `Openssl/`.

### 🍎 macOS

1. **Install Xcode Command Line Tools**:
   ```bash
   xcode-select --install
   ```

2. **Clone**:
   ```bash
   git clone https://github.com/GurudattaRK/PQrypt.git
   ```

3. **Build Desktop (from scratch)**:

This builds:
- OpenSSL static libs into `Openssl/static_libs/openssl-3.6/`
- liboqs static libs into `Openssl/static_libs/liboqs-0.15/`
- the PQrypt desktop binary

```bash
PQRYPT_CLEAN=1 bash scripts/build_desktop.sh
```

4. **Run the App**:
   ```bash
   ./desktop/target/release/pqrypt
   ```

### 🐧 Linux

Linux builds from source use the same script as macOS, but require standard build tooling (`gcc/g++`, `make`, etc.).

```bash
PQRYPT_CLEAN=1 bash scripts/build_desktop.sh
```

### 🪟 Windows

Windows build-from-source uses **MSYS2 (mingw64)** so OpenSSL + liboqs can be built as static **`.a`** archives.

Follow these steps exactly:

1. Install MSYS2 from the official site.

2. Open the correct terminal:

- In the Windows Start Menu, search for:
  - `MSYS2 MinGW 64-bit`
- Open that one (important). The shell prompt should mention `MINGW64`.

3. Navigate to the PQrypt folder by following this:

In MSYS2, Windows locations look like this:

- `C:\` becomes `/c/`
- `D:\` becomes `/d/`

Example, if your folder is at `C:\Users\gurudatta\Documents\GitHub\PQrypt` then use below command to reach that location in MSYS2 MinGW terminal:

```sh
cd /c/Users/gurudatta/Documents/GitHub/PQrypt
```

Verify you are in the right place by running ``` pwd ``` command which would then show if you are at correct location or not (example: ``` /c/Users/gurudatta/Documents/GitHub/PQrypt```)

4. Next, install required build tools inside MSYS2. Do that by Copy pasting this whole command:

```sh
pacman -Syu && pacman -S --needed git mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja mingw-w64-x86_64-make mingw-w64-x86_64-perl perl mingw-w64-x86_64-rust
```

5. Ensure OpenSSL uses the correct `perl`.

OpenSSL `Configure` will fail if `perl` is the Windows one. So, Force MSYS perl by running these commands one by one:

```sh
export PATH="/usr/bin:$PATH" && hash -r
which perl
perl -V:osname
```

6. Ensure Rust is using the **GNU** toolchain.

In MSYS2 MinGW64, Rust should be `x86_64-pc-windows-gnu` (not MSVC), To ensure that install and select the GNU toolchain by running these commands one by one:

```sh
rustup toolchain install stable-gnu
rustup default stable-gnu
rustc -Vv | grep host
```

7. Build Desktop (from scratch).

assuming you are at root of project (Example: ``` /c/Users/gurudatta/Documents/GitHub/PQrypt```), run this command and wait for it to finish (it may take a long time) :

```sh
PQRYPT_CLEAN=1 bash scripts/build_desktop.sh
```

### 📱 Build the Android app from source

Before you start You must set `ANDROID_NDK_HOME` (example path shown):

```sh
export ANDROID_NDK_HOME=/c/Path/To/Android/Sdk/ndk/<version>
```
You find this path using your installed Android Studio path. If you don't have Android studio then: 

1. **Install Android Studio** from [developer.android.com](https://developer.android.com/studio)

2. **Open the Project**:
   - Open Android Studio
   - Select "Open an existing project"
   - Navigate to `PQrypt/android/`

3. **Install SDK Components**:
   - Open SDK Manager (Tools → SDK Manager)
   - Install Android SDK Platform 34
   - Install NDK version 25 or higher
   - Install CMake 3.22.1

4. **Run `build_android.sh` to Build and Install**:
```bash
PQRYPT_CLEAN=1 bash scripts/build_android.sh
```

This builds:
- OpenSSL static libs for Android into `Openssl/static_libs/openssl-3.6-android/`
- liboqs static libs for Android into `Openssl/static_libs/liboqs-0.15-android/`
- the Android debug APK, This APK file can be found in `android/app/build/outputs/apk/debug/` and it can be used to install the app on Android devices.



---

## 🔒 Cryptographic Architecture

PQrypt is built on using 8 different cryptographic algorithms:

### Asymmetric cryptography: Key Exchange & Key Encapsulation
1. **ML-KEM-1024** (a.k.a Crystals-Kyber)
2. **X448** (a.k.a Curve448)
3. **HQC-256** (a.k.a Hamming-Quasi-Cyclic KEM)
4. **SecP521R1** (a.k.a P-521)

### Symmetric cryptography: File Encryption (Authenticated)
5. **ChaCha20**
6. **AES-256-GCM** (Also responsible for Ciphertext authentication)

### Cryptographic Digital Signatures: Secure Signing & Authencation of data
7. **SLH-DSA-SHAKE-256f** (a.k.a SPHINCS+)

### Cryptographic Hashing: Memory-hard secure hashing
8. **Argon2id** (with PBKDF2-HMAC-SHA256 fallback)

---

## ✨ Features

- 🛡️ **Post-Quantum Secure**: Resistant against quantum attacks.
- 📁 **File Encryption**: Encrypt any file with password or key file.
- 💬 **Secure Messaging**: Send encrypted text/files between devices
- 🔑 **Password Generator**: Generate strong passwords securely & deterministically
- 📱 **Cross-Platform**: Works on Android, Windows, macOS, and Linux

---

## 🏗️ Project Architecture

- **Desktop Application** (`desktop/`): Cross-platform GUI app for Linux, MacOS, and Windows built with Rust & Slint UI framework
- **Android Application** (`android/`): Native Android app with Kotlin fronted bridged  to Rust backend using java/C++ FFI.

---



## ⚠️ Disclaimer

This software is provided "as is" without warranty or guarantee. While industry-standard algorithms are used & best practices are followed, no encryption or security is 100% unbreakable & no software is 100% safe. Hence, if any kind of damage or loss is caused by using this Project, software or any component of this project to anyone/any group of people then this project, App(s), or any of its contributors and creators shall not be held responsible.
Always:
- Keep backups of important data
- Use strong, unique passwords
- Keep your software updated
- Don't share your encryption keys & sensitive data
