# Pineapple - Post-Quantum Cryptography Android App

A secure Android application implementing Post-Quantum Cryptography (PQC) with hybrid key exchange protocols, built with Rust cryptographic backend and Android Studio.

## Features

- **Post-Quantum Cryptography**: ML-KEM (Kyber) + HQC hybrid key exchange
- **Bluetooth Key Exchange**: Secure PQC key exchange over Bluetooth
- **File Encryption**: AES-GCM + Serpent + Custom 1024-bit cipher
- **Hybrid Protocols**: X448 + P521 elliptic curve integration
- **Modern Android UI**: Material Design with biometric authentication

## Prerequisites

Before building this app, ensure you have the following installed:

### Required Software

1. **Android Studio** (Latest stable version)
   - Download from: https://developer.android.com/studio
   - Ensure Android SDK and NDK are installed

2. **Rust** (Already installed ✓)
   - Verify installation: `rustc --version`

### Additional Rust Components

Install the required Rust targets for Android cross-compilation:

```bash
# Add Android targets for Rust
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi  
rustup target add i686-linux-android
rustup target add x86_64-linux-android
```

### Android NDK Setup

1. Open Android Studio
2. Go to **Tools** → **SDK Manager**
3. Click **SDK Tools** tab
4. Check and install:
   - **Android NDK (Side by side)**
   - **CMake** (version 3.22.1 or higher)
   - **LLDB** (for debugging)

## Project Structure

```
Pineapple/
├── app/
│   ├── src/main/
│   │   ├── cpp/                          # Native C++ code
│   │   │   ├── Pineapple_API/
│   │   │   │   └── rusty_pineapple/      # Rust cryptographic library
│   │   │   │       ├── src/
│   │   │   │       │   └── rusty_api/    # Modular crypto implementation
│   │   │   │       ├── Cargo.toml       # Rust dependencies
│   │   │   │       └── .cargo/config.toml # Android build config
│   │   │   ├── CMakeLists.txt            # CMake build configuration
│   │   │   └── rusty_crypto_jni.cpp      # JNI bridge
│   │   ├── java/com/pineapple/app/       # Android Kotlin/Java code
│   │   └── res/                          # Android resources
│   └── build.gradle.kts                  # App-level Gradle config
├── gradle/libs.versions.toml             # Dependency versions
└── build.gradle.kts                      # Project-level Gradle config
```

## Building the App

### Method 1: Using Android Studio (Recommended)

1. **Open Project**
   ```bash
   # Navigate to project directory
   cd /path/to/AndroidStudioProjects/Pineapple
   
   # Open in Android Studio
   open -a "Android Studio" .
   ```

2. **Sync Project**
   - Android Studio will automatically detect the project
   - Click **"Sync Now"** when prompted
   - Wait for Gradle sync to complete

3. **Build the App**
   - Click **Build** → **Make Project** (Ctrl+F9 / Cmd+F9)
   - Or click **Build** → **Generate Signed Bundle/APK**

4. **Run on Device/Emulator**
   - Connect Android device or start emulator
   - Click **Run** → **Run 'app'** (Shift+F10)

### Method 2: Command Line Build

1. **Navigate to Project Directory**
   ```bash
   cd /Users/gkondampallikar/AndroidStudioProjects/Pineapple
   ```

2. **Build Debug APK**
   ```bash
   ./gradlew assembleDebug
   ```

3. **Build Release APK**
   ```bash
   ./gradlew assembleRelease
   ```

4. **Install on Connected Device**
   ```bash
   ./gradlew installDebug
   ```

### APK Output Locations

- **Debug APK**: `app/build/outputs/apk/debug/app-debug.apk`
- **Release APK**: `app/build/outputs/apk/release/app-release.apk`

## Build Process Details

### Rust Library Compilation

The build process automatically:

1. **Cross-compiles Rust** for Android targets:
   - `aarch64-linux-android` (ARM64)
   - `armv7-linux-androideabi` (ARM32)
   - `i686-linux-android` (x86)
   - `x86_64-linux-android` (x86_64)

2. **Optimizes for Performance**:
   - Link-time optimization (LTO)
   - Maximum optimization level (opt-level=3)
   - Single codegen unit for better optimization

3. **Generates Static Library**: `librusty_pineapple.a`

### CMake Integration

CMake automatically:
- Detects Android ABI and maps to Rust target
- Sets up Android NDK toolchain
- Builds Rust library using `cargo`
- Links static library with JNI bridge
- Creates shared library: `librusty_crypto_jni.so`

## Troubleshooting

### Common Issues

1. **NDK Not Found**
   ```
   Error: Android NDK not found
   ```
   **Solution**: Install NDK via Android Studio SDK Manager

2. **Rust Target Missing**
   ```
   Error: target 'aarch64-linux-android' not found
   ```
   **Solution**: Install Android targets:
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
   ```

3. **CMake Version**
   ```
   Error: CMake version 3.22.1 required
   ```
   **Solution**: Update CMake via SDK Manager

4. **Build Cache Issues**
   ```bash
   # Clean and rebuild
   ./gradlew clean
   ./gradlew assembleDebug
   ```

### Performance Notes

- **Release builds** are highly optimized with LTO and maximum optimization
- **Debug builds** include symbols for debugging but are still optimized
- First build may take longer due to Rust dependency compilation
- Subsequent builds use incremental compilation

## Development

### Key Components

1. **Cryptographic Backend** (`rusty_pineapple/src/rusty_api/`)
   - `hybrid.rs`: PQC hybrid key exchange
   - `symmetric.rs`: AES-GCM + Serpent encryption
   - `asymmetric.rs`: X448 + P521 operations
   - `cipher_1024.rs`: Custom Threefish-1024 cipher

2. **Android Activities**
   - `KeyExchangeProcessActivity.kt`: Manual PQC key exchange
   - `BluetoothKeyExchangeActivity.kt`: Bluetooth PQC exchange
   - `FileEncryptionActivity.kt`: File encryption/decryption

3. **JNI Bridge** (`rusty_crypto_jni.cpp`)
   - Exposes Rust functions to Android
   - Handles memory management and type conversion

### Testing

The app has been tested on:
- Multiple Android devices (API 26+)
- Various Android emulators
- ARM64 and x86_64 architectures

## Security Features

- **Post-Quantum Resistant**: ML-KEM + HQC algorithms
- **Hybrid Security**: Classical + quantum-resistant cryptography
- **Memory Safety**: Rust prevents buffer overflows and memory corruption
- **Secure Key Storage**: Android Keystore integration
- **Biometric Authentication**: Fingerprint and face unlock support

## License

This project implements cryptographic algorithms for educational and research purposes. Ensure compliance with local regulations regarding cryptographic software.

---

**Built with ❤️ using Rust + Android Studio**
