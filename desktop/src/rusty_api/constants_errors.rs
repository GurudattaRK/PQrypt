// Cryptographic constants and configuration

// AES-256-GCM constants
pub const AES_KEY_SIZE: usize = 32;
pub const AES_NONCE_SIZE: usize = 12;
pub const AES_TAG_SIZE: usize = 16;
pub type AesKey = [u8; AES_KEY_SIZE];
pub type AesNonce = [u8; AES_NONCE_SIZE];
pub type AesTag = [u8; AES_TAG_SIZE];

// ChaCha20 constants
pub const CHACHA_KEY_SIZE: usize = 32;
pub const CHACHA_NONCE_SIZE: usize = 12;  // Standard ChaCha20 uses 12-byte nonce
pub type ChaChaKey = [u8; CHACHA_KEY_SIZE];
pub type ChaChaNonce = [u8; CHACHA_NONCE_SIZE];

// Argon2id constants (UPDATED)
pub const ARGON2_OUTPUT_SIZE: usize = 64; // Changed from 32 to 64 bytes
pub type Argon2Salt = [u8; 16]; // Changed from 32 to 16 bytes
pub type Argon2Key = [u8; ARGON2_OUTPUT_SIZE];

// ML-KEM-1024 constants (UPDATED from Kyber)
pub const MLKEM1024_PUBLIC_SIZE: usize = 1568;
pub const MLKEM1024_SECRET_SIZE: usize = 3168;
pub const MLKEM1024_CIPHERTEXT_SIZE: usize = 1568;
pub const MLKEM1024_SHARED_SIZE: usize = 32;
pub type MlKem1024PublicKey = [u8; MLKEM1024_PUBLIC_SIZE];
pub type MlKem1024SecretKey = [u8; MLKEM1024_SECRET_SIZE];
pub type MlKem1024Ciphertext = [u8; MLKEM1024_CIPHERTEXT_SIZE];
pub type MlKem1024SharedSecret = [u8; MLKEM1024_SHARED_SIZE];

// X448 constants
pub const X448_PUBLIC_SIZE: usize = 56;
pub const X448_SECRET_SIZE: usize = 56;
pub const X448_SHARED_SIZE: usize = 56;
pub type X448PublicKey = [u8; X448_PUBLIC_SIZE];
pub type X448SecretKey = [u8; X448_SECRET_SIZE];
pub type X448SharedSecret = [u8; X448_SHARED_SIZE];

// ML-KEM-1024 + X448 Hybrid constants
pub const MLKEM1024X448_COMBINED_SHARED_SIZE: usize = MLKEM1024_SHARED_SIZE + X448_SHARED_SIZE;
pub type MlKem1024X448PublicKey = ([u8; MLKEM1024_PUBLIC_SIZE], [u8; X448_PUBLIC_SIZE]);
pub type MlKem1024X448SecretKey = ([u8; MLKEM1024_SECRET_SIZE], [u8; X448_SECRET_SIZE]);
pub type MlKem1024X448Ciphertext = ([u8; MLKEM1024_CIPHERTEXT_SIZE], [u8; X448_PUBLIC_SIZE]);
pub type MlKem1024X448SharedSecret = [u8; MLKEM1024X448_COMBINED_SHARED_SIZE];

// HQC-P521 Hybrid constants
pub const HQC256_PUBLIC_SIZE: usize = 7245;
pub const HQC256_SECRET_SIZE: usize = 7317;
pub const HQC256_CIPHERTEXT_SIZE: usize = 14421;
pub const HQC256_SHARED_SIZE: usize = 64;
pub const P521_PUBLIC_SIZE: usize = 133;
pub const P521_SECRET_SIZE: usize = 66;
pub const P521_SHARED_SIZE: usize = 66;
pub const HQCP521_COMBINED_SHARED_SIZE: usize = HQC256_SHARED_SIZE + P521_SHARED_SIZE;
pub type HqcP521PublicKey = ([u8; HQC256_PUBLIC_SIZE], [u8; P521_PUBLIC_SIZE]);
pub type HqcP521SecretKey = ([u8; HQC256_SECRET_SIZE], [u8; P521_SECRET_SIZE]);
pub type HqcP521Ciphertext = ([u8; HQC256_CIPHERTEXT_SIZE], [u8; P521_PUBLIC_SIZE]);
pub type HqcP521SharedSecret = [u8; HQCP521_COMBINED_SHARED_SIZE];

// SLH-DSA constants (UPDATED)
pub const SLHDSA_PUBLIC_SIZE: usize = 64;
pub const SLHDSA_SECRET_SIZE: usize = 8; // EVP_PKEY pointer as u64
pub const SLHDSA_SIGNATURE_SIZE: usize = 49856; // Fixed signature size
pub type SlhDsaPublicKey = [u8; SLHDSA_PUBLIC_SIZE];
pub type SlhDsaSecretKey = [u8; SLHDSA_SECRET_SIZE];
pub type SlhDsaSignature = [u8; SLHDSA_SIGNATURE_SIZE];

// Hybrid key exchange packet sizes
pub const PACKAGE1_SIZE: usize = 58922; // SLHDSA_SIGNATURE_SIZE + COMBINED_KEY1_SIZE + SLHDSA_PUBLIC_SIZE
pub const PACKAGE2_SIZE: usize = 66098; // SLHDSA_SIGNATURE_SIZE + COMBINED_KEY2_SIZE + SLHDSA_PUBLIC_SIZE
pub const COMBINED_KEY1_SIZE: usize = MLKEM1024_PUBLIC_SIZE + X448_PUBLIC_SIZE + HQC256_PUBLIC_SIZE + P521_PUBLIC_SIZE;
pub const COMBINED_KEY2_SIZE: usize = MLKEM1024_CIPHERTEXT_SIZE + X448_PUBLIC_SIZE + HQC256_CIPHERTEXT_SIZE + P521_PUBLIC_SIZE;

// Legacy constants (kept for compatibility during transition)
pub const AES256_IV_SIZE: usize = AES_NONCE_SIZE;
pub const AES256_TAG_SIZE: usize = AES_TAG_SIZE;

// Processing constants
pub const CHUNK_SIZE: usize = 128;

// Password generation constants
pub const NUM_SETS: usize = 6;
pub const MAX_PASSWORD_LEN: usize = 64;

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

pub const CRYPTO_SUCCESS: i32 = 0;
pub const CRYPTO_ERROR_NULL_POINTER: i32 = -1;
pub const CRYPTO_ERROR_HASHING_FAILED: i32 = -2;
pub const CRYPTO_ERROR_ENCRYPTION_FAILED: i32 = -3;
pub const CRYPTO_ERROR_DECRYPTION_FAILED: i32 = -4;
pub const CRYPTO_ERROR_KEY_GENERATION_FAILED: i32 = -5;
pub const CRYPTO_ERROR_INVALID_INPUT: i32 = -6;
pub const CRYPTO_ERROR_PQC_OPERATION: i32 = -9;
pub const CRYPTO_ERROR_IO: i32 = -10;
pub const CRYPTO_ERROR_FORMAT: i32 = -11;
pub const CRYPTO_ERROR_UNSUPPORTED: i32 = -12;

#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidInput,
    InvalidKeyLength,
    HashingFailed,
    EncryptionFailed,
    DecryptionFailed,        // Added
    AuthenticationFailed,
    KeyGenerationFailed,
    KeyDerivationFailed,
    RandomGenerationFailed,
    IntegerOverflow,
    InvalidParameters,
    PqcOperationFailed,
    IOError,                 // Added
    DebugCode(i32)
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidInput => write!(f, "Invalid input provided"),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::HashingFailed => write!(f, "Password hashing failed"),
            CryptoError::EncryptionFailed => write!(f, "Encryption operation failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption operation failed"),  // Added
            CryptoError::AuthenticationFailed => write!(f, "Authentication verification failed"),
            CryptoError::KeyGenerationFailed => write!(f, "Key generation failed"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::RandomGenerationFailed => write!(f, "Random number generation failed"),
            CryptoError::IntegerOverflow => write!(f, "Integer overflow detected"),
            CryptoError::InvalidParameters => write!(f, "Invalid parameters provided"),
            CryptoError::PqcOperationFailed => write!(f, "Post-quantum cryptography operation failed"),
            CryptoError::IOError => write!(f, "I/O operation failed"),  // Added
            CryptoError::DebugCode(code) => write!(f, "Debug error code: {}", code),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<String> for CryptoError {
    fn from(error: String) -> Self {
        // For argon2id_derive errors, map them to appropriate CryptoError variants
        if error.contains("Plaintext too large") || error.contains("Invalid input") {
            CryptoError::InvalidInput
        } else if error.contains("not available") || error.contains("not supported") {
            CryptoError::PqcOperationFailed
        } else {
            CryptoError::HashingFailed
        }
    }
}

// MARK: secure_random_bytes
#[inline(always)]
pub fn secure_random_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(buf).map_err(|_| CryptoError::RandomGenerationFailed)
}