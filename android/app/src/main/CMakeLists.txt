# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

# Declares the project name. The project name can be accessed via ${ PROJECT_NAME},
# Since this is the top level CMakeLists.txt, the project name is also accessible
# with ${CMAKE_PROJECT_NAME} (both CMake variables are in-sync within the top level
# build script scope).
project("pqrypt")

# Set the path to the Rust library (relative to this CMake file in app/src/main)
set(RUST_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust)
set(CPP_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cpp)

# Add include directories
include_directories(${CPP_INCLUDE_DIR})

# Determine the Android ABI for Rust target
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(RUST_TARGET "aarch64-linux-android")
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(RUST_TARGET "armv7-linux-androideabi")
elseif(ANDROID_ABI STREQUAL "x86")
    set(RUST_TARGET "i686-linux-android")
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(RUST_TARGET "x86_64-linux-android")
else()
    message(FATAL_ERROR "Unsupported Android ABI: ${ANDROID_ABI}")
endif()

# Paths for Rust build outputs
set(RUST_STATIC_LIB ${RUST_LIB_DIR}/target/${RUST_TARGET}/release/libPqrypt.a)

# Ensure Ninja knows what file is produced by cargo using BYPRODUCTS/OUTPUT
# Derive Android API level safely for toolchain triple
# ANDROID_PLATFORM is like "android-24"; ANDROID_PLATFORM_LEVEL is an integer (e.g., 24)
if(DEFINED ANDROID_PLATFORM_LEVEL)
    set(ANDROID_API_LEVEL ${ANDROID_PLATFORM_LEVEL})
elseif(DEFINED ANDROID_PLATFORM)
    string(REPLACE "android-" "" ANDROID_API_LEVEL ${ANDROID_PLATFORM})
else()
    # Fallback to 21 for arm64 if not provided
    set(ANDROID_API_LEVEL 21)
endif()

# Use the target-specific clang driver (note: armeabi-v7a uses armv7a-linux-androideabi)
if(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(CLANG_TRIPLE "armv7a-linux-androideabi")
else()
    set(CLANG_TRIPLE ${RUST_TARGET})
endif()
set(CLANG_BIN ${ANDROID_TOOLCHAIN_ROOT}/bin/${CLANG_TRIPLE}${ANDROID_API_LEVEL}-clang)
set(AR_BIN ${ANDROID_TOOLCHAIN_ROOT}/bin/llvm-ar)

# Set paths to prebuilt OpenSSL and liboqs static libraries (allow override via env)
set(OPENSSL_BASE $ENV{OPENSSL_ANDROID_DIR})
if(NOT OPENSSL_BASE)
    set(OPENSSL_BASE "$ENV{HOME}/crypto-static-libs/openssl-3.6-android")
endif()
set(OQS_BASE $ENV{LIBOQS_ANDROID_DIR})
if(NOT OQS_BASE)
    set(OQS_BASE "$ENV{HOME}/crypto-static-libs/liboqs-0.15-android")
endif()

# Compute lib/include directories (prefer ABI-specific layout if present)
if(EXISTS "${OPENSSL_BASE}/${ANDROID_ABI}/lib")
    set(OPENSSL_LIB_DIR "${OPENSSL_BASE}/${ANDROID_ABI}/lib")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_BASE}/include")
elseif(EXISTS "${OPENSSL_BASE}/lib")
    set(OPENSSL_LIB_DIR "${OPENSSL_BASE}/lib")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_BASE}/include")
else()
    message(FATAL_ERROR "OpenSSL not found. Set OPENSSL_ANDROID_DIR to prebuilt path or install to ${OPENSSL_BASE}")
endif()

if(EXISTS "${OQS_BASE}/${ANDROID_ABI}/lib")
    set(OQS_LIB_DIR "${OQS_BASE}/${ANDROID_ABI}/lib")
    set(OQS_INCLUDE_DIR "${OQS_BASE}/include")
elseif(EXISTS "${OQS_BASE}/lib")
    set(OQS_LIB_DIR "${OQS_BASE}/lib")
    set(OQS_INCLUDE_DIR "${OQS_BASE}/include")
else()
    message(FATAL_ERROR "liboqs not found. Set LIBOQS_ANDROID_DIR to prebuilt path or install to ${OQS_BASE}")
endif()

include_directories(${OPENSSL_INCLUDE_DIR} ${OQS_INCLUDE_DIR})

add_custom_command(
    OUTPUT ${RUST_STATIC_LIB}
    # Invoke cargo with Android NDK clang/llvm-ar for the specific Rust target
    COMMAND ${CMAKE_COMMAND} -E env 
        CC_${RUST_TARGET}=${CLANG_BIN} 
        AR=${AR_BIN} 
        AR_${RUST_TARGET}=${AR_BIN}
        OPENSSL_DIR=${OPENSSL_BASE}
        OPENSSL_STATIC=1
        OPENSSL_LIB_DIR=${OPENSSL_LIB_DIR}
        OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}
        OQS_DIR=${OQS_BASE}
        PKG_CONFIG_PATH=${OQS_LIB_DIR}/pkgconfig
        cargo build --release --lib --target ${RUST_TARGET}
    WORKING_DIRECTORY ${RUST_LIB_DIR}
    COMMENT "Building Rust library for ${RUST_TARGET} (API ${ANDROID_API_LEVEL})"
    VERBATIM
)

add_custom_target(rust_build ALL
    DEPENDS ${RUST_STATIC_LIB}
)

# Create the JNI bridge library
# Build JNI bridge from existing working version
add_library(rusty_crypto_jni SHARED
    cpp/rusty_crypto_jni.cpp
    cpp/compat_shims.c
)

# Set maximum optimization flags for C++
target_compile_options(rusty_crypto_jni PRIVATE
    -O3                         # Maximum optimization level
    -flto                       # Link-time optimization
    -fomit-frame-pointer        # Omit frame pointer for performance
    -DNDEBUG                    # Disable assertions
)

# Use absolute static libraries (must exist for this ABI)
set(OQS_LIB "${OQS_LIB_DIR}/liboqs.a")
set(SSL_LIB "${OPENSSL_LIB_DIR}/libssl.a")
set(CRYPTO_LIB "${OPENSSL_LIB_DIR}/libcrypto.a")
if(NOT EXISTS ${OQS_LIB})
    message(FATAL_ERROR "liboqs.a not found at ${OQS_LIB}")
endif()
if(NOT EXISTS ${SSL_LIB})
    message(FATAL_ERROR "libssl.a not found at ${SSL_LIB}")
endif()
if(NOT EXISTS ${CRYPTO_LIB})
    message(FATAL_ERROR "libcrypto.a not found at ${CRYPTO_LIB}")
endif()

# Link the Rust staticlib and required third-party static libs (absolute paths)
target_link_libraries(rusty_crypto_jni
    ${RUST_STATIC_LIB}
    ${OQS_LIB}
    ${CRYPTO_LIB}
    ${SSL_LIB}
    android
    log
)

# Set target properties
target_compile_features(rusty_crypto_jni PRIVATE cxx_std_17)