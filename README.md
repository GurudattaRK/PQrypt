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

### 📱 Android
1. Go to [Releases](https://github.com/GurudattaRK/PQrypt/releases)
2. Download `PQrypt.apk`
3. Open the APK file on your phone
4. Allow installation from unknown sources if prompted
5. Install and open the app

### 🍎 macOS (Build Required)
macOS requires building from source due to security restrictions. See [Build from Source](#-build-from-source) below.

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

---

## 🔒 Cryptographic Architecture

PQrypt implements a **9-algorithm hybrid cryptographic system** combining classical and post-quantum algorithms for maximum security:

### Layer 1: Post-Quantum Key Exchange
1. **ML-KEM-1024** (FIPS 203) - NIST-standardized lattice-based key encapsulation
2. **X448** - Elliptic curve Diffie-Hellman for classical security
3. **HQC-256** - Code-based post-quantum algorithm
4. **P-521** - NIST elliptic curve for additional classical strength

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
│  Key Exchange: ML-KEM ⊕ X448 + HQC ⊕ P521          │
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

## 📚 Advanced: Development & Testing

## 🔧 Development

### Desktop Development
```bash
cd desktop

# Run with cargo watch for auto-reload during development
cargo install cargo-watch
cargo watch -x run

# Run tests
cargo test

# Check for linting issues
cargo clippy

# Format code
cargo fmt
```

### Android Development
```bash
cd android

# Clean build
./gradlew clean

# Run Android tests
./gradlew test

# Run connected tests (requires device/emulator)
./gradlew connectedAndroidTest

# Generate test coverage report
./gradlew jacocoTestReport
```

## 🐛 Troubleshooting

### Desktop Issues
- **Build fails on Linux**: Install required system dependencies:
  ```bash
  # Ubuntu/Debian
  sudo apt update
  sudo apt install build-essential libxcb-dev libfontconfig1-dev
  
  # Fedora/RHEL
  sudo dnf install gcc-c++ libxcb-devel fontconfig-devel
  ```

- **Slint UI not displaying**: Ensure graphics drivers are up to date

### Android Issues
- **NDK not found**: Set NDK path in `local.properties`:
  ```
  ndk.dir=/path/to/android-ndk
  ```

- **CMake version issues**: Install CMake 3.22.1 via SDK Manager

- **Build fails with "rust not found"**: Ensure Rust is installed and in PATH:
  ```bash
  rustc --version
  cargo --version
  ```

- **Gradle sync fails**: Clear Gradle cache:
  ```bash
  cd android
  ./gradlew clean
  rm -rf ~/.gradle/caches
  ```

## 🔒 Security Features

- **Post-Quantum Cryptography**: Implements FIPS 203 (ML-KEM), HQC-256 (Hamming Quasi-Cyclic), and FIPS 205 (ML-DSA)
- **Hybrid Encryption**: Combines classical and post-quantum algorithms
- **Key Derivation**: Argon2 for secure password-based key generation
- **Memory Safety**: Rust's memory safety prevents buffer overflows
- **Secure Deletion**: Zeroization of sensitive data in memory

## 📚 Project Structure

```
PQrypt/
├── desktop/                 # Desktop application (Rust + Slint)
│   ├── src/
│   │   ├── main.rs          # Desktop main entry point
│   │   ├── lib.rs           # Shared cryptographic library
│   │   └── rusty_api/       # Core crypto implementations
│   ├── ui/
│   │   └── main.slint       # UI definition
│   └── Cargo.toml           # Rust dependencies
│
├── android/                 # Android application
│   ├── app/
│   │   ├── src/main/
│   │   │   ├── java/        # Kotlin/Java source
│   │   │   ├── cpp/         # JNI C++ bridge
│   │   │   ├── rust/        # Rust cryptographic backend
│   │   │   └── res/         # Android resources
│   │   └── build.gradle.kts
│   └── build.gradle.kts     # Android build configuration
│
└── README.md                # This file
```

## ❓ FAQ

### Why do I need post-quantum cryptography?
Quantum computers, when fully developed, will break current encryption methods (RSA, ECC). PQrypt uses algorithms designed to resist quantum attacks, protecting your data today and in the future.

### Is this overkill for personal use?
"Store now, decrypt later" attacks are already happening. Adversaries collect encrypted data today to decrypt when quantum computers become available. PQrypt protects against this threat.

### How is this different from other encryption tools?
- **9-algorithm hybrid system**: Multiple layers of protection
- **NIST-standardized**: Uses officially approved post-quantum algorithms (FIPS 203, 205)
- **Cross-platform**: Works on desktop and mobile
- **Open source**: Fully auditable code

### Can I trust the encryption?
- All algorithms are peer-reviewed and NIST-standardized
- Open-source code available for audit
- Uses battle-tested implementations
- No backdoors, no telemetry

### What file sizes can I encrypt?
PQrypt uses streaming encryption and can handle files of any size, limited only by your device's storage.

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Run tests: `cargo test` (desktop) and `./gradlew test` (Android)
5. Submit a pull request

**Areas where help is needed:**
- 🌍 Translations/internationalization
- 📱 iOS version development
- 🎨 UI/UX improvements
- 📝 Documentation
- 🔒 Security audits
- 🐛 Bug reports and fixes

---

## 🛡️ Security

Found a security vulnerability? Please **DO NOT** open a public issue. Instead:
- Email: [Add your security contact email]
- Use GitHub Security Advisories (private reporting)

We take security seriously and will respond promptly to all reports.

---

## 🗺️ Roadmap

- [ ] iOS version
- [ ] Browser extension
- [ ] CLI version for automation
- [ ] Cloud backup integration (encrypted)
- [ ] Hardware security key support
- [ ] Multi-language support
- [ ] Dark mode improvements
- [ ] Performance optimizations

---

## 🙏 Acknowledgments

Built with these amazing open-source projects:
- **Rust** - Memory-safe systems programming
- **Slint** - Modern UI framework
- **NIST PQC** - Post-quantum cryptography standards
- **Argon2** - Password hashing competition winner
- All the cryptographic library maintainers

Special thanks to the post-quantum cryptography research community.

---

## ⚠️ Disclaimer

This software is provided "as is" without warranty. While we use industry-standard algorithms and best practices, no encryption is 100% unbreakable. Always:
- Keep backups of important data
- Use strong, unique passwords
- Keep your software updated
- Don't share your encryption keys

---

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/GurudattaRK/PQrypt/issues)
- **Discussions**: [GitHub Discussions](https://github.com/GurudattaRK/PQrypt/discussions)
- **Email**: [Add your contact email]
- **Twitter**: [Add your Twitter if applicable]

---

## ⭐ Show Your Support

If you find PQrypt useful, please:
- ⭐ Star this repository
- 🐦 Share on social media
- 📝 Write a review or blog post
- 🤝 Contribute to the project
- ☕ [Buy me a coffee](https://buymeacoffee.com/yourusername) (optional)

---

## 📄 License

This project is licensed under the MIT License - see below for details:

```
MIT License

Copyright (c) 2025 Gurudatta R K

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 🔗 Links

- [Rust Documentation](https://doc.rust-lang.org/)
- [Slint UI Framework](https://slint.dev/)
- [Android NDK Guide](https://developer.android.com/ndk/guides)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)