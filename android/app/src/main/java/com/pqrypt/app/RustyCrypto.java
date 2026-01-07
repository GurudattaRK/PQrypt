package com.pqrypt.app; // Package namespace for this Java class

/**
 * RustyCrypto - Java interface to the Rust crypto library // Class-level description
 * This class provides access to all crypto functions needed for the PQrypt app // Summary of purpose
 */
public class RustyCrypto { // Public JNI bridge class exposing native crypto methods
    
    // Load the native library // Ensures JNI symbols are available at runtime
    static {
        System.loadLibrary("rusty_crypto_jni"); // Loads librusty_crypto_jni.so from app's native libs
    }
    
    // Constants from the Rust library // Error codes mirrored from native side
    public static final int CRYPTO_SUCCESS = 0; // Operation completed successfully
    public static final int CRYPTO_ERROR_NULL_POINTER = -1; // Input pointer was null
    public static final int CRYPTO_ERROR_INVALID_LENGTH = -2; // Supplied length/size invalid
    public static final int CRYPTO_ERROR_DECRYPTION_FAILED = -3; // Auth/tag check failed or corrupt data
    public static final int CRYPTO_ERROR_INVALID_INPUT = -4; // Inputs did not meet preconditions
    public static final int CRYPTO_ERROR_MEMORY_ALLOCATION = -5; // Allocation failed on native side
    public static final int CRYPTO_ERROR_HASHING_FAILED = -6; // Password hashing failed
    public static final int CRYPTO_ERROR_ENCRYPTION_FAILED = -7; // Encryption operation failed
    public static final int CRYPTO_ERROR_KEY_GENERATION = -8; // Key generation failure
    public static final int CRYPTO_ERROR_PQC_OPERATION = -9; // Post-quantum crypto operation failed
    
    // Updated AES-256-GCM constants (match crypto-core)
    public static final int AES_KEY_SIZE = 32; // 256-bit key
    public static final int AES_NONCE_SIZE = 12; // 96-bit IV/nonce recommended for GCM
    public static final int AES_TAG_SIZE = 16; // 128-bit authentication tag

    // ChaCha20 constants
    public static final int CHACHA_KEY_SIZE = 32;
    public static final int CHACHA_NONCE_SIZE = 12;

    // Argon2id constants (UPDATED)
    public static final int ARGON2_OUTPUT_SIZE = 64; // Changed from 32 to 64 bytes

    // Legacy constants (kept for compatibility during transition)
    public static final int AES256_KEY_SIZE = AES_KEY_SIZE;
    public static final int AES256_IV_SIZE = AES_NONCE_SIZE;
    public static final int AES256_TAG_SIZE = AES_TAG_SIZE;

    // Password generation constants
    public static final int NUM_SETS = 6;
    public static final int MAX_PASSWORD_LEN = 64;
    
    // Legacy functions - kept for backward compatibility during migration
    public static native byte[] derivePasswordHashUnified64(byte[] appName, byte[] appPassword, byte[] masterPassword);

    // Hybrid Key Exchange Functions
    public static native byte[] hybridSenderInit();
    public static native Object[] hybridReceiver(byte[] package1);
    public static native byte[] hybridSenderFinal(byte[] package2);

    // Dual mutual exchange
    public static native byte[] hybridReceiverDual(byte[] package1);
    public static native Object[] hybridSenderThird(byte[] package2Bundle);
    public static native byte[] hybridReceiverFinalDual(byte[] package3);

    // Double Encryption Functions
    public static native int doubleEncryptFd(byte[] secret, boolean isKeyFile, int inFd, int outFd);
    public static native int doubleDecryptFd(byte[] secret, boolean isKeyFile, int inFd, int outFd);
    public static native String generatePasswordFromHash(byte[] hash64, int desiredLen, int enabledSetsMask);
}
