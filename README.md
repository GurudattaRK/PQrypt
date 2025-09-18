# PQrypt

A quantum-resistant encryption application available for both desktop and Android platforms, implementing post-quantum cryptographic algorithms for secure file encryption and communication.

## 🏗️ Architecture

- **Desktop Application** (`desktop/`): Cross-platform GUI built with Rust and Slint UI framework
- **Android Application** (`android/`): Native Android app with Kotlin/Java frontend and optimized C++/Rust backend

## 📋 Prerequisites

### Common Requirements
- **Rust**: Install from [rustup.rs](https://rustup.rs/)
- **Git**: For cloning the repository

### Android Development
- **Android Studio**: Latest version with SDK tools
- **Android NDK**: Version 25 or higher
- **CMake**: Version 3.22.1 or higher (usually bundled with Android Studio)
- **Java**: OpenJDK 11 or higher

### Desktop Development
- **System Dependencies** (platform-specific):
  - **Linux**: `build-essential`, `libxcb-dev`, `libfontconfig1-dev`
  - **macOS**: Xcode command line tools (`xcode-select --install`)
  - **Windows**: Visual Studio Build Tools or Visual Studio with C++ support

## 🚀 Quick Start

### Clone the Repository
```bash
git clone https://github.com/your-username/PQrypt.git
cd PQrypt
```

## 🖥️ Desktop Application (Rust/Slint)

### Build and Run
```bash
# Navigate to desktop application directory
cd desktop

# Build and run in development mode
cargo run

# Build optimized release version
cargo build --release

# Run release version
./target/release/pqrypt
```

### Desktop Installation
```bash
# Build release version
cd desktop
cargo build --release

# The executable will be located at:
# - Linux/macOS: ./target/release/pqrypt
# - Windows: ./target/release/pqrypt.exe

# Copy to system path (optional)
# Linux/macOS:
sudo cp target/release/pqrypt /usr/local/bin/pqrypt

# Windows: Copy pqrypt.exe to a directory in your PATH
```

### Desktop Dependencies
The desktop application will automatically download and compile all Rust dependencies on first build. This may take several minutes initially.

## 📱 Android Application

### Initial Setup
1. **Open in Android Studio**:
   ```bash
   # Open Android Studio and select "Open an existing project"
   # Navigate to: PQrypt/android/
   ```

2. **Configure SDK and NDK**:
   - Open SDK Manager in Android Studio
   - Install Android SDK Platform 34 (or latest)
   - Install NDK version 25.0.8775105 or newer
   - Install CMake 3.22.1

3. **Sync Project**:
   - Android Studio will automatically sync Gradle files
   - Wait for all dependencies to download

### Build Methods

#### Method 1: Android Studio (Recommended for beginners)
1. Open `android/` project in Android Studio
2. Wait for Gradle sync to complete
3. Click **Build → Make Project** or press `Ctrl+F9`
4. For release build: **Build → Generate Signed Bundle/APK**

#### Method 2: Command Line
```bash
# Navigate to Android project
cd android

# Debug build
./gradlew assembleDebug

# Release build (requires signing configuration)
./gradlew assembleRelease

# Install debug version to connected device
./gradlew installDebug

# Install and run
./gradlew installDebug && adb shell am start -n com.pqrypt.app/.MainActivity
```

### Android Installation

#### Development Installation
```bash
# Install debug APK to connected device/emulator
cd android
./gradlew installDebug
```

#### Production Installation
1. Build signed release APK in Android Studio
2. Transfer APK to device
3. Enable "Install from unknown sources" in device settings
4. Install APK file

### Android Build Outputs
- **Debug APK**: `android/app/build/outputs/apk/debug/app-debug.apk`
- **Release APK**: `android/app/build/outputs/apk/release/app-release.apk`

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

- **Post-Quantum Cryptography**: Implements FIPS 203 (ML-KEM) and FIPS 205 (ML-DSA)
- **Hybrid Encryption**: Combines classical and post-quantum algorithms
- **Key Derivation**: Argon2 for secure password-based key generation
- **Memory Safety**: Rust's memory safety prevents buffer overflows
- **Secure Deletion**: Zeroization of sensitive data in memory

## 📚 Project Structure

```
PQrypt/
├── desktop/               # Desktop application (Rust + Slint)
│   ├── src/
│   │   ├── main.rs        # Desktop main entry point
│   │   ├── lib.rs         # Shared cryptographic library
│   │   └── rusty_api/     # Core crypto implementations
│   ├── ui/
│   │   └── main.slint     # UI definition
│   └── Cargo.toml        # Rust dependencies
│
├── android/               # Android application
│   ├── app/
│   │   ├── src/main/
│   │   │   ├── java/      # Kotlin/Java source
│   │   │   ├── cpp/       # JNI C++ bridge
│   │   │   ├── rust/      # Rust cryptographic backend
│   │   │   └── res/       # Android resources
│   │   └── build.gradle.kts
│   └── build.gradle.kts   # Android build configuration
│
└── README.md              # This file
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Run tests: `cargo test` (desktop) and `./gradlew test` (Android)
5. Submit a pull request

## 📄 License

[Add your license information here]

## 🔗 Links

- [Rust Documentation](https://doc.rust-lang.org/)
- [Slint UI Framework](https://slint.dev/)
- [Android NDK Guide](https://developer.android.com/ndk/guides)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)