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
This repo uses the `Openssl/` folder to build and cache static libraries.

Required for the build scripts:
- **cmake**
- **ninja**
- **perl** (OpenSSL build)

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

- Install MSYS2 and the mingw64 toolchain (bash/make/perl/cmake/ninja)
- Ensure Rust is using the **GNU** toolchain (`x86_64-pc-windows-gnu`)

Build Desktop (from scratch):

```bat
set PQRYPT_CLEAN=1
scripts\build_desktop_windows.bat
```

Build Android (from scratch, builds OpenSSL+liboqs for Android and installs to all connected devices):

```bat
set ANDROID_NDK_HOME=C:\Path\To\Android\Sdk\ndk\<version>
set PQRYPT_CLEAN=1
scripts\build_android_windows.bat
```

### 📱 Build the Android app from source

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

4. **Run `build_android.sh` to Build and Install (this works on Linux & macOS but its unstable on Windows)**:
```bash
PQRYPT_CLEAN=1 bash scripts/build_android.sh
```

This builds:
- OpenSSL static libs for Android into `Openssl/static_libs/openssl-3.6-android/`
- liboqs static libs for Android into `Openssl/static_libs/liboqs-0.15-android/`
- the Android debug APK, then installs it to all connected devices



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
