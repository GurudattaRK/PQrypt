// Utility functions and helper operations

use getrandom::getrandom;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroize;

use super::constants_errors::*;

// Secure random number generation
#[inline]
pub fn secure_random_bytes(buffer: &mut [u8]) -> Result<(), CryptoError> {
    getrandom(buffer).map_err(|_| CryptoError::RandomGenerationFailed)
}

// Generate deterministic salt for password generation using Argon2
#[inline]
pub fn derive_password_salt(user_id: &str) -> Result<[u8; 32], CryptoError> {
    if user_id.is_empty() {
        return Err(CryptoError::InvalidInput);
    }
    
    // Create a deterministic salt by combining user_id with APP_IDENTIFIER
    let mut salt_input = Vec::new();
    salt_input.extend_from_slice(APP_IDENTIFIER);
    salt_input.extend_from_slice(user_id.as_bytes());
    salt_input.extend_from_slice(b"3uyfe874g?ef");
    
    // Use a fixed salt for this deterministic derivation
    let fixed_salt: [u8; 32] = [
        0x3a, 0x7f, 0x2e, 0x91, 0x5c, 0x48, 0xd3, 0x76,
        0xa9, 0x1b, 0x8e, 0x42, 0xf5, 0x67, 0x29, 0x8d,
        0x4c, 0xe1, 0x73, 0x96, 0x2a, 0x5f, 0x84, 0x37,
        0xb0, 0x6d, 0x19, 0x7e, 0x4b, 0x95, 0x28, 0xfc
    ];
    
    let hash_result = super::symmetric::argon2id_hash(&salt_input, &fixed_salt, ARGON2_SALT_SIZE, 10240, 1, 1)?;
    let mut salt = [0u8; ARGON2_SALT_SIZE];
    salt.copy_from_slice(&hash_result[..ARGON2_SALT_SIZE]);
    
    Ok(salt)
}



// Checked integer operations to prevent overflow
#[inline(always)]
pub fn checked_add_usize(a: usize, b: usize) -> Result<usize, CryptoError> {
    a.checked_add(b).ok_or(CryptoError::IntegerOverflow)
}

pub fn checked_mul_usize(a: usize, b: usize) -> Result<usize, CryptoError> {
    a.checked_mul(b).ok_or(CryptoError::IntegerOverflow)
}

// Secure padding calculation with overflow protection
#[inline]
pub fn calculate_padded_length(input_len: usize) -> Result<usize, CryptoError> {
    if input_len == 0 {
        return Ok(CHUNK_SIZE);
    }
    
    let chunks_needed = (input_len + CHUNK_SIZE - 1) / CHUNK_SIZE; // Ceiling division
    let padded_len = checked_mul_usize(chunks_needed, CHUNK_SIZE)?;
    
    Ok(padded_len)
}

// Helper function: bytes to u32 array with validation
#[inline]
pub fn bytes_to_u32_array(bytes: &[u8]) -> Result<[u32; 32], CryptoError> {
    if bytes.len() < 128 {
        return Err(CryptoError::InvalidInput);
    }
    
    let mut result = [0u32; 32];
    for i in 0..32 {
        let start = i * 4;
        result[i] = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]);
    }
    Ok(result)
}

// Helper function: u32 array to bytes
pub fn u32_array_to_bytes(data: &[u32; 32]) -> [u8; 128] {
    let mut result = [0u8; 128];
    for i in 0..32 {
        let bytes = data[i].to_le_bytes();
        result[i * 4] = bytes[0];
        result[i * 4 + 1] = bytes[1];
        result[i * 4 + 2] = bytes[2];
        result[i * 4 + 3] = bytes[3];
    }
    result
}

// Secure key encryption using AES-GCM
pub fn encrypt_key_with_shared_secret(
    key_data: &[u8],
    shared_secret: &[u8]
) -> Result<Vec<u8>, CryptoError> {
    if shared_secret.len() < 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    
    // Derive AES key using Argon2 (match Android salt exactly)
    let mut salt = [0u8; 32];
    salt[..17].copy_from_slice(b"9xk2m7q4w8r3t6y1u");
    let aes_key_vec = crate::rusty_api::symmetric::argon2id_hash(shared_secret, &salt, 32, 10240, 1, 1)?;
    let mut aes_key: [u8; 32] = aes_key_vec.try_into().map_err(|_| CryptoError::KeyDerivationFailed)?;
    
    let cipher = Aes256Gcm::new_from_slice(&aes_key).expect("AES-256 key must be exactly 32 bytes");

    let mut nonce_bytes = [0u8; AES256_IV_SIZE];
    secure_random_bytes(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, key_data)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    
    let mut result = Vec::with_capacity(AES256_IV_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    // Zeroize sensitive buffers
    aes_key.zeroize();
    nonce_bytes.zeroize();
    
    Ok(result)
}

// Secure key decryption using AES-GCM
pub fn decrypt_key_with_shared_secret(
    encrypted_data: &[u8],
    shared_secret: &[u8]
) -> Result<Vec<u8>, CryptoError> {
    const MAX_SINGLE_PASS_SIZE: usize = 128 * 1024 * 1024; // 128MB
    if encrypted_data.len() > MAX_SINGLE_PASS_SIZE {
        return Err(CryptoError::InvalidInput);
    }
    
    if encrypted_data.len() < AES256_IV_SIZE + AES256_TAG_SIZE {
        return Err(CryptoError::InvalidInput);
    }
    
    if shared_secret.len() < 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    
    // Derive AES key using Argon2 (match Android salt exactly)
    let mut salt = [0u8; 32];
    salt[..17].copy_from_slice(b"9xk2m7q4w8r3t6y1u");
    let aes_key_vec = crate::rusty_api::symmetric::argon2id_hash(shared_secret, &salt, 32, 10240, 1, 1)?;
    let mut aes_key: [u8; 32] = aes_key_vec.try_into().map_err(|_| CryptoError::KeyDerivationFailed)?;
    
    let nonce = &encrypted_data[0..AES256_IV_SIZE];
    let ciphertext = &encrypted_data[AES256_IV_SIZE..];
    let cipher = Aes256Gcm::new_from_slice(&aes_key).expect("AES-256 key must be exactly 32 bytes");

    let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    
    // Zeroize sensitive material
    aes_key.zeroize();
    
    Ok(plaintext)
}