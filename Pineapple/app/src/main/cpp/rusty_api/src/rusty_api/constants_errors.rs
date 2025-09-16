// Cryptographic constants and configuration

// AES-GCM constants
pub const AES256_IV_SIZE: usize = 12;
pub const AES256_TAG_SIZE: usize = 16;

// Serpent constants
pub const SERPENT_KEY_SIZE: usize = 32;
pub const SERPENT_BLOCK_SIZE: usize = 16;

// X448 constants
pub const X448_KEY_SIZE: usize = 56;

// Kyber1024 constants
pub const KYBER_PUBLICKEYBYTES: usize = 1568;
pub const KYBER_SECRETKEYBYTES: usize = 3168;
pub const KYBER_CIPHERTEXTBYTES: usize = 1568;
pub const KYBER_SHAREDSECRETBYTES: usize = 32;

// HQC256 constants
pub const HQC256_PUBLICKEYBYTES: usize = 7245;
pub const HQC256_SECRETKEYBYTES: usize = 7317;
pub const HQC256_SHAREDSECRETBYTES: usize = 64;

// P521 constants
pub const P521_KEY_SIZE: usize = 133;
pub const P521_SECRET_SIZE: usize = 66;

// SLH-DSA constants (SPHINCS+-SHAKE-256f)
pub const SLH_DSA_PUBKEYBYTES: usize = 64;       // Public key length
pub const SLH_DSA_SECRETKEYBYTES: usize = 128;   // Secret key length
pub const SLH_DSA_SIGNATUREBYTES: usize = 49856; // Signature length

// Signed .key file header format (prepended)
// Layout: MAGIC(8) + content_len(u64, LE) + sig_len(u64, LE) + pk_len(u64, LE)
pub const SLH_DSA_HEADER_MAGIC: [u8; 8] = *b"SLHDSA10";
pub const SLH_DSA_HEADER_SIZE: usize = 8 + 8 + 8 + 8; // 32 bytes

// Argon2 constants
pub const ARGON2_SALT_SIZE: usize = 32;

// Processing constants
pub const CHUNK_SIZE: usize = 128;

// Password generation constants
pub const NUM_SETS: usize = 6;
pub const MAX_PASSWORD_LEN: usize = 256;

// Character sets for password generation
pub const CHAR_SETS: [&str; NUM_SETS] = [
    "abcdefghijklmnopqrstuvwxyz",           // lowercase
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",           // uppercase  
    "0123456789",                          // digits
    "~!@#$%^&*()",                        // symbols set 1
    "/.,';][=-",                          // symbols set 2
    "><\":}{+_"                           // symbols set 3
];

// Application identifier for deterministic salt derivation
pub const APP_IDENTIFIER: &[u8] = b"xq7m9k2w8r4t6y1u3i5o";

// C FFI Return codes
pub const CRYPTO_SUCCESS: i32 = 0;
pub const CRYPTO_ERROR_NULL_POINTER: i32 = -1;
pub const CRYPTO_ERROR_HASHING_FAILED: i32 = -2;
pub const CRYPTO_ERROR_ENCRYPTION_FAILED: i32 = -3;
pub const CRYPTO_ERROR_DECRYPTION_FAILED: i32 = -4;
pub const CRYPTO_ERROR_KEY_GENERATION_FAILED: i32 = -5;
pub const CRYPTO_ERROR_INVALID_INPUT: i32 = -6;

// Error types for cryptographic operations

#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidInput,
    InvalidKeyLength,
    HashingFailed,
    EncryptionFailed,
    AuthenticationFailed,
    KeyGenerationFailed,
    KeyDerivationFailed,
    RandomGenerationFailed,
    IntegerOverflow,
    InvalidParameters,
    PqcOperationFailed,
    DebugCode(i32)  // For debugging specific failure points
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidInput => write!(f, "Invalid input provided"),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::HashingFailed => write!(f, "Password hashing failed"),
            CryptoError::EncryptionFailed => write!(f, "Encryption operation failed"),
            CryptoError::AuthenticationFailed => write!(f, "Authentication verification failed"),
            CryptoError::KeyGenerationFailed => write!(f, "Key generation failed"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::RandomGenerationFailed => write!(f, "Random number generation failed"),
            CryptoError::IntegerOverflow => write!(f, "Integer overflow detected"),
            CryptoError::InvalidParameters => write!(f, "Invalid parameters provided"),
            CryptoError::PqcOperationFailed => write!(f, "Post-quantum cryptography operation failed"),
            CryptoError::DebugCode(code) => write!(f, "Debug error code: {}", code),
        }
    }
}

impl std::error::Error for CryptoError {}