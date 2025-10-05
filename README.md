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

### 🍎 macOS (Required)

1. **Install Xcode Command Line Tools**:
   ```bash
   xcode-select --install
   ```

2. **Clone and Build**:
   ```bash
   git clone https://github.com/GurudattaRK/PQrypt.git
   cd PQrypt/desktop
   cargo build --release
   ```

3. **Run the App**:
   ```bash
   ./target/release/pqrypt
   ```

### 🪟 Windows

1. **Install Visual Studio Build Tools**:
   - Download from [Visual Studio](https://visualstudio.microsoft.com/downloads/)
   - Select "Desktop development with C++"

2. **Clone and Build**:
   ```bash
   git clone https://github.com/GurudattaRK/PQrypt.git
   cd PQrypt/desktop
   cargo build --release
   ```

3. **Run the App**:
   ```bash
   .\target\release\pqrypt.exe
   ```

### 🐧 Linux

1. **Install Dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install build-essential libxcb-dev libfontconfig1-dev
   
   # Fedora/RHEL
   sudo dnf install gcc-c++ libxcb-devel fontconfig-devel
   ```

2. **Clone and Build**:
   ```bash
   git clone https://github.com/GurudattaRK/PQrypt.git
   cd PQrypt/desktop
   cargo build --release
   ```

3. **Run the App**:
   ```bash
   ./target/release/pqrypt
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

4. **Build and Install**:
   - Connect your Android device via USB (enable Developer Mode)
   - Click the green "Run" button in Android Studio
   - Or use command line:
     ```bash
     cd android
     ./gradlew installDebug
     ```
   - Or if you want to build an APK in debug mode, use command line:
     ```bash
     cd android
     ./gradlew assembleDebug
     ```
   - Or if you want to build an APK in release mode (for release mnode you'll have to sign it by setting up a signing key in android studio), use command line:
     ```bash
     cd android
     ./gradlew assembleRelease
     ```

---

## 🔒 Cryptographic Architecture

PQrypt implements a **9-algorithm hybrid cryptographic system** combining classical and post-quantum algorithms for maximum security:

### Layer 1: Post-Quantum Key Exchange
1. **ML-KEM-1024** (FIPS 203) - NIST-standardized lattice-based key encapsulation
2. **X448** - Elliptic curve Diffie-Hellman for classical security
3. **HQC-256** - Code-based post-quantum algorithm
4. **SecP521R1** - NIST elliptic curve for additional classical strength

### Layer 2: Triple-Layer Symmetric Encryption
5. **Threefish-1024** - 1024-bit block cipher (outermost layer)
6. **Serpent-256** - AES finalist cipher (middle layer)
7. **AES-256-GCM** - NIST standard with authentication (innermost layer)

### Layer 3: Key Derivation & Authentication
8. **Argon2id** - Memory-hard password hashing (winner of Password Hashing Competition)
9. **ML-DSA** (FIPS 205) - Post-quantum digital signatures for authentication

### How They Work Together
```
┌─────────────────────────────────────────────────────┐
│  Key Exchange: ML-KEM ⊕ X448 + HQC ⊕ P521           │
│  (Post-quantum + Classical hybrid)                  │
└──────────────────────┬──────────────────────────────┘
                       ↓
              ┌────────────────┐
              │  Argon2id KDF  │ ← Password derivation
              └────────┬───────┘
                       ↓
        ┌──────────────────────────────┐
        │   Triple Encryption Layers   │
        │  Threefish → Serpent → AES   │
        │  (Each layer adds security)  │
        └──────────────┬───────────────┘
                       ↓
              ┌────────────────┐
              │  ML-DSA Sign   │ ← Authentication
              └────────────────┘
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