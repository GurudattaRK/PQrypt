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
    
    // AES-256-GCM constants // Sizes in bytes used by AES-GCM implementation
    public static final int AES256_KEY_SIZE = 32; // 256-bit key
    public static final int AES256_IV_SIZE = 12; // 96-bit IV/nonce recommended for GCM
    public static final int AES256_TAG_SIZE = 16; // 128-bit authentication tag
    
    // Legacy functions - kept for backward compatibility during migration
    public static native byte[] argon2Hash(byte[] password, byte[] salt, int outputLength);
    public static native byte[] derivePasswordHashUnified128(byte[] appName, byte[] appPassword, byte[] masterPassword);
    
    // PQC 4-Algorithm Hybrid Key Exchange Functions (ML-KEM+X448 and HQC+P521)
    public static native Object[] pqc4HybridInit(); // Returns [hybrid1Key, senderState]
    public static native Object[] pqc4HybridRecv(byte[] hybrid1Key); // Returns [hybrid2Key, receiverState]
    public static native Object[] pqc4HybridSndFinal(byte[] hybrid2Key, byte[] senderState); // Returns [finalKey(128B), hybrid3Key]
    public static native byte[] pqc4HybridRecvFinal(byte[] hybrid3Key, byte[] receiverState); // Returns finalKey(128B)

    // Minimal new surface
    public static native int tripleEncryptFd(byte[] secret, boolean isKeyFile, int inFd, int outFd);
    public static native int tripleDecryptFd(byte[] secret, boolean isKeyFile, int inFd, int outFd);
    public static native String generatePasswordUnified(byte[] appName, byte[] appPassword, byte[] masterPassword, int desiredLen, int enabledSetsMask);
}
