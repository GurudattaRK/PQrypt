# 🔐 PQrypt

**Quantum-Resistant Encryption for Everyone**

PQrypt is a next-generation encryption application that protects your files and communications against both current and future quantum computer attacks. Available for **Desktop** (Windows, macOS, Linux) and **Android**.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android-blue)](https://github.com/GurudattaRK/PQrypt)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)

---

## 📥 Installation (Pre-built Binaries)

### 🪟 Windows
1. Go to [Releases](https://github.com/GurudattaRK/PQrypt/releases)
2. Download `pqrypt-windows.exe`
3. Double-click to run (Windows Defender may show a warning - click "More info" → "Run anyway")

### 🐧 Linux
1. Go to [Releases](https://github.com/GurudattaRK/PQrypt/releases)
2. Download `pqrypt-linux`
3. Open Terminal in the download folder
4. Run:
   ```bash
   chmod +x pqrypt-linux
   ./pqrypt-linux
   ```

### 🍎 macOS (Build Required)
macOS requires building from source due to security restrictions. See [Build from Source](#-build-from-source) below.

### 📱 Android
1. Go to [Releases](https://github.com/GurudattaRK/PQrypt/releases)
2. Download `PQrypt.apk`
3. Open the APK file on your phone
4. Allow installation from unknown sources if prompted
5. Install and open the app



---

## 🛠️ Build from Source

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

### 📱 Android

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

4. **Build and Install (from scratch)**:

This builds:
- OpenSSL static libs for Android into `Openssl/static_libs/openssl-3.6-android/`
- liboqs static libs for Android into `Openssl/static_libs/liboqs-0.15-android/`
- the Android debug APK, then installs it to all connected devices

```bash
PQRYPT_CLEAN=1 bash scripts/build_android.sh
```

---

## 🔒 Cryptographic Architecture

PQrypt implements a hybrid post-quantum + classical key exchange and then encrypts data using authenticated encryption.

### Layer 1: Post-Quantum Key Exchange
1. **ML-KEM-1024** (FIPS 203)
2. **X448**
3. **HQC-256**
4. **SecP521R1**

### Layer 2: Symmetric Encryption (Authenticated)
5. **ChaCha20**
6. **AES-256-GCM** (authenticates the ciphertext)

### Layer 3: Key Derivation & Authentication
7. **Argon2id** (with PBKDF2-HMAC-SHA256 fallback)
8. **SLH-DSA-SHAKE-256f** (signs key exchange packages)

### How They Work Together
```
┌─────────────────────────────────────────────────────┐
│  Key Exchange: ML-KEM ⊕ X448 + HQC ⊕ P521           │
│  (Post-quantum + Classical hybrid)                  │
└──────────────────────┬──────────────────────────────┘
                       ↓
              ┌──────────────────────────────┐
              │   Double Encryption Layer    │
              │  ChaCha20 → AES-256-GCM      │
              └──────────────────────────────┘
```

This architecture ensures:
- **Quantum Resistance**: Even if quantum computers break one algorithm, others remain secure
- **Defense in Depth**: Multiple encryption layers protect against cryptanalysis
- **Forward Secrecy**: Each session uses unique ephemeral keys
- **Authentication**: Digital signatures prevent tampering

---

## ✨ Features

- 🛡️ **Post-Quantum Secure**: Protected against quantum computer attacks
- 📁 **File Encryption**: Encrypt any file with password or key file
- 💬 **Secure Messaging**: Send encrypted text/files between devices
- 🔑 **Password Vault**: Store passwords with quantum-resistant encryption
- 📱 **Cross-Platform**: Works on Android, Windows, macOS, and Linux
- 🔄 **Key Exchange**: Secure key sharing via Bluetooth or manual transfer
- 🎯 **Zero Knowledge**: Your keys never leave your device

---

## 🏗️ Architecture

- **Desktop Application** (`desktop/`): Cross-platform GUI built with Rust and Slint UI framework
- **Android Application** (`android/`): Native Android app with Kotlin/Java frontend and optimized C++/Rust backend

---

## 🔐 Secure Share File Flow (Manual)

Secure Share uses the PQC exchange and produces one encrypted `.pqrypt` file.

- Sender:
  - Create `1.key` and send it to the receiver
  - Open `2.key` from the receiver
  - The app produces one encrypted file (`.pqrypt`). For text mode this is typically `text.pqrypt`.

- Receiver:
  - Open `1.key` and send back `2.key`
  - Open the received encrypted `.pqrypt` file to decrypt

For Secure Share, the encrypted `.pqrypt` payload includes the final exchange piece embedded inside it, so the receiver usually does not need a separate `3.key` file.

After successful decryption, the app may try to delete key files and the encrypted file (best effort).

---


## ⚠️ Disclaimer

This software is provided "as is" without warranty. While we use industry-standard algorithms and best practices, no encryption or security is 100% unbreakable. Always:
- Keep backups of important data
- Use strong, unique passwords
- Keep your software updated
- Don't share your encryption keys

## 🔗 Links

- [Rust Documentation](https://doc.rust-lang.org/)
- [Slint UI Framework](https://slint.dev/)
- [Android NDK Guide](https://developer.android.com/ndk/guides)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)