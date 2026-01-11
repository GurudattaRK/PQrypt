// Desktop file encryption/decryption using Android's ChaCha20 + AES-GCM scheme
use super::constants_errors::*;
use crate::crypto_core::openssl_ffi::argon2id_derive;
use crate::crypto_core::hybrids::{double_encrypt, double_decrypt};
use std::fs::File;
use std::io::{Read, Write};

/// Encrypt file using Android's exact crypto scheme
pub fn encrypt_file(
    input_path: &str,
    output_path: &str,
    secret: &[u8],
) -> Result<(), CryptoError> {
    // Generate random salt
    let mut salt = [0u8; 16];
    secure_random_bytes(&mut salt)?;
    
    // Derive keys from secret and salt (EXACT Android logic)
    let mut chacha_key_secret = secret.to_vec();
    let chacha_key_vec = argon2id_derive(&mut chacha_key_secret, &mut salt, 32)?;
    let mut chacha_key = [0u8; 32];
    chacha_key.copy_from_slice(&chacha_key_vec[..32]);
    
    let mut chacha_nonce_secret = secret.to_vec();
    let mut chacha_nonce_salt = [b'n', b'o', b'n', b'c', b'e', b'1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let chacha_nonce_vec = argon2id_derive(&mut chacha_nonce_secret, &mut chacha_nonce_salt, 12)?;
    let mut chacha_nonce = [0u8; 12];
    chacha_nonce.copy_from_slice(&chacha_nonce_vec[..12]);
    
    let mut aes_key_secret = secret.to_vec();
    let mut aes_key_salt = [b'a', b'e', b's', b'k', b'e', b'y', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let aes_key_vec = argon2id_derive(&mut aes_key_secret, &mut aes_key_salt, 32)?;
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&aes_key_vec[..32]);
    
    let mut aes_nonce_secret = secret.to_vec();
    let mut aes_nonce_salt = [b'a', b'e', b's', b'n', b'o', b'n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let aes_nonce_vec = argon2id_derive(&mut aes_nonce_secret, &mut aes_nonce_salt, 12)?;
    let mut aes_nonce = [0u8; 12];
    aes_nonce.copy_from_slice(&aes_nonce_vec[..12]);
    
    // Read input file
    let mut input_data = std::fs::read(input_path)
        .map_err(|_| CryptoError::InvalidInput)?;
    
    // Double encrypt
    let (ciphertext, aes_tag) = double_encrypt(
        &mut chacha_key,
        &mut chacha_nonce,
        &mut aes_key,
        &mut aes_nonce,
        &mut input_data,
    )?;
    
    // Write output: salt (16) + ciphertext + tag (16)
    let mut output = Vec::with_capacity(16 + ciphertext.len() + 16);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&aes_tag);
    
    std::fs::write(output_path, &output)
        .map_err(|_| CryptoError::InvalidInput)?;
    
    Ok(())
}

/// Decrypt file using Android's exact crypto scheme
pub fn decrypt_file(
    input_path: &str,
    output_path: &str,
    secret: &[u8],
) -> Result<(), CryptoError> {
    // Read encrypted file
    let input_data = std::fs::read(input_path)
        .map_err(|_| CryptoError::InvalidInput)?;
    
    if input_data.len() < 32 {
        return Err(CryptoError::InvalidInput);
    }
    
    // Extract salt, ciphertext, tag
    let salt = &input_data[..16];
    let ciphertext = &input_data[16..input_data.len() - 16];
    let tag_slice = &input_data[input_data.len() - 16..];
    
    // Derive keys (EXACT Android logic)
    let mut chacha_key_secret = secret.to_vec();
    let mut salt_array = [0u8; 16];
    salt_array.copy_from_slice(&salt[..16]);
    let chacha_key_vec = argon2id_derive(&mut chacha_key_secret, &mut salt_array, 32)?;
    let mut chacha_key = [0u8; 32];
    chacha_key.copy_from_slice(&chacha_key_vec[..32]);
    
    let mut chacha_nonce_secret = secret.to_vec();
    let mut chacha_nonce_salt = [b'n', b'o', b'n', b'c', b'e', b'1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let chacha_nonce_vec = argon2id_derive(&mut chacha_nonce_secret, &mut chacha_nonce_salt, 12)?;
    let mut chacha_nonce = [0u8; 12];
    chacha_nonce.copy_from_slice(&chacha_nonce_vec[..12]);
    
    let mut aes_key_secret = secret.to_vec();
    let mut aes_key_salt = [b'a', b'e', b's', b'k', b'e', b'y', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let aes_key_vec = argon2id_derive(&mut aes_key_secret, &mut aes_key_salt, 32)?;
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&aes_key_vec[..32]);
    
    let mut aes_nonce_secret = secret.to_vec();
    let mut aes_nonce_salt = [b'a', b'e', b's', b'n', b'o', b'n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let aes_nonce_vec = argon2id_derive(&mut aes_nonce_secret, &mut aes_nonce_salt, 12)?;
    let mut aes_nonce = [0u8; 12];
    aes_nonce.copy_from_slice(&aes_nonce_vec[..12]);
    
    let mut aes_tag = [0u8; 16];
    aes_tag.copy_from_slice(tag_slice);
    
    // Double decrypt
    let mut ciphertext_copy = ciphertext.to_vec();
    let plaintext = double_decrypt(
        &mut aes_key,
        &mut aes_nonce,
        &mut aes_tag,
        &mut chacha_key,
        &mut chacha_nonce,
        &mut ciphertext_copy,
    )?;
    
    // Write output
    std::fs::write(output_path, &plaintext)
        .map_err(|_| CryptoError::InvalidInput)?;
    
    Ok(())
}

/// Derive password key (matches Android exactly)
pub fn derive_password_key(password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut password_copy = password.to_vec();
    let mut empty_salt = [0u8; 16];
    argon2id_derive(&mut password_copy, &mut empty_salt, 64)
        .map_err(|e| {
            eprintln!("ERROR in argon2id_derive: {}", e);
            CryptoError::HashingFailed
        })
}
