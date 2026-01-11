// Main API functions that combine lower-level cryptographic operations

use super::constants_errors::*;
pub use super::constants_errors::secure_random_bytes;
use openssl::hash::{hash, MessageDigest};
use libc::c_int;
use libc;
use zeroize::Zeroize;

pub use super::password::{generate_password, derive_password_hash_secure};

const FIXED_SALT: &[u8] = b"PQryptFixedSalt1"; // 16 bytes

// MARK: double_encrypt_fd_raw (Android-compatible PQRYPT header + GCM trailer)
#[inline(always)]
pub fn double_encrypt_fd_raw(
    secret: &[u8],
    _is_keyfile: bool,
    in_fd: c_int,
    out_fd: c_int,
) -> Result<(), CryptoError> {
    use crate::crypto_core::double_encrypt;

    // STEP 1: Base secret = SHA-512(password || FIXED_SALT)
    let mut buf = Vec::with_capacity(secret.len() + FIXED_SALT.len());
    buf.extend_from_slice(secret);
    buf.extend_from_slice(FIXED_SALT);
    let mut base_secret = hash(MessageDigest::sha512(), &buf)
        .map_err(|_| CryptoError::HashingFailed)?
        .to_vec();

    // STEP 2: Derive keys via SHA-256(base || label)
    let mut chacha_key = [0u8; 32];
    let ck = hash(MessageDigest::sha256(), &[&base_secret[..], b"CHACHA_KEY"].concat())
        .map_err(|_| CryptoError::HashingFailed)?;
    chacha_key.copy_from_slice(&ck[0..32]);

    let mut aes_key = [0u8; 32];
    let ak = hash(MessageDigest::sha256(), &[&base_secret[..], b"AES_KEY"].concat())
        .map_err(|_| CryptoError::HashingFailed)?;
    aes_key.copy_from_slice(&ak[0..32]);

    // STEP 3: Random nonces per-encryption
    let mut chacha_nonce = [0u8; 12];
    secure_random_bytes(&mut chacha_nonce).map_err(|_| CryptoError::RandomGenerationFailed)?;
    let mut aes_nonce = [0u8; 12];
    secure_random_bytes(&mut aes_nonce).map_err(|_| CryptoError::RandomGenerationFailed)?;

    // Read entire input file
    let mut input_data = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read_result = unsafe { libc::read(in_fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if read_result < 0 { return Err(CryptoError::IOError); }
        if read_result == 0 { break; }
        input_data.extend_from_slice(&buffer[..read_result as usize]);
    }

    // Build fixed-size binary header (54 bytes):
    // Magic (6) + original_size (8) + aes_nonce (12) + chacha_nonce (12) + salt (16 - unused here)
    let mut header = [0u8; 54];
    header[0..6].copy_from_slice(b"PQRYPT");
    header[6..14].copy_from_slice(&(input_data.len() as u64).to_le_bytes());
    header[14..26].copy_from_slice(&aes_nonce);
    header[26..38].copy_from_slice(&chacha_nonce);
    header[38..54].copy_from_slice(&[0u8; 16]);

    // Double encrypt the data with header as AAD
    let (ciphertext, aes_tag) = double_encrypt(
        &mut chacha_key,
        &mut chacha_nonce,
        &mut aes_key,
        &mut aes_nonce,
        &mut input_data,
        &header,
    ).map_err(|_| CryptoError::EncryptionFailed)?;

    let mut ciphertext = ciphertext;

    // Build GCM trailer (19 bytes): "GCM" + 16-byte tag
    let mut gcm_trailer = [0u8; 19];
    gcm_trailer[0..3].copy_from_slice(b"GCM");
    gcm_trailer[3..19].copy_from_slice(&aes_tag);

    // Write helper
    let write_buf = |fd: c_int, buf: &[u8]| -> Result<(), CryptoError> {
        let mut written = 0usize;
        while written < buf.len() {
            let chunk = &buf[written..];
            let to_write = chunk.len().min(8192);
            let res = unsafe { libc::write(fd, chunk.as_ptr() as *const libc::c_void, to_write) };
            if res < 0 { return Err(CryptoError::IOError); }
            written += res as usize;
        }
        Ok(())
    };

    // Write header, ciphertext, trailer
    write_buf(out_fd, &header)?;
    write_buf(out_fd, &ciphertext)?;
    write_buf(out_fd, &gcm_trailer)?;

    // Zeroize header/trailer
    for b in &mut header { *b = 0; }
    for b in &mut gcm_trailer { *b = 0; }

    ciphertext.zeroize();
    input_data.zeroize();
    base_secret.zeroize();
    buf.zeroize();
    chacha_key.zeroize();
    chacha_nonce.zeroize();
    aes_key.zeroize();
    aes_nonce.zeroize();

    unsafe { libc::fsync(out_fd); }
    Ok(())
}

// MARK: double_decrypt_fd_raw
#[inline(always)]
pub fn double_decrypt_fd_raw(
    secret: &[u8],
    _is_keyfile: bool,
    in_fd: c_int,
    out_fd: c_int,
) -> Result<(), CryptoError> {
    use crate::crypto_core::double_decrypt;

    // Read all input data
    let mut input_data = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read_result = unsafe { libc::read(in_fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if read_result < 0 { return Err(CryptoError::IOError); }
        if read_result == 0 { break; }
        input_data.extend_from_slice(&buffer[..read_result as usize]);
    }

    // Check minimum file size (54 header + 19 GCM = 73 bytes minimum)
    if input_data.len() < 73 { return Err(CryptoError::InvalidInput); }

    // Parse fixed binary header (54 bytes)
    if &input_data[..6] != b"PQRYPT" { return Err(CryptoError::InvalidInput); }

    let _original_size = u64::from_le_bytes(input_data[6..14].try_into().unwrap()) as usize;
    let aes_nonce_bytes = &input_data[14..26];
    let chacha_nonce_bytes = &input_data[26..38];

    // Nonce validation (must not be all zeros)
    if aes_nonce_bytes.iter().all(|&b| b == 0) || chacha_nonce_bytes.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidInput);
    }

    // Check GCM trailer (last 19 bytes)
    let gcm_start = input_data.len() - 19;
    if &input_data[gcm_start..gcm_start + 3] != b"GCM" { return Err(CryptoError::InvalidInput); }
    let tag_slice = &input_data[gcm_start + 3..];

    // Extract ciphertext
    let ciphertext = &input_data[54..gcm_start];

    // Base secret = SHA-512(password || FIXED_SALT)
    let mut buf = Vec::with_capacity(secret.len() + FIXED_SALT.len());
    buf.extend_from_slice(secret);
    buf.extend_from_slice(FIXED_SALT);
    let mut base_secret = hash(MessageDigest::sha512(), &buf)
        .map_err(|_| CryptoError::HashingFailed)?
        .to_vec();

    // Derive keys via SHA-256(base || label)
    let mut chacha_key = [0u8; 32];
    let ck = hash(MessageDigest::sha256(), &[&base_secret[..], b"CHACHA_KEY"].concat())
        .map_err(|_| CryptoError::HashingFailed)?;
    chacha_key.copy_from_slice(&ck[0..32]);

    let mut chacha_nonce = [0u8; 12];
    chacha_nonce.copy_from_slice(chacha_nonce_bytes);

    let mut aes_key = [0u8; 32];
    let ak = hash(MessageDigest::sha256(), &[&base_secret[..], b"AES_KEY"].concat())
        .map_err(|_| CryptoError::HashingFailed)?;
    aes_key.copy_from_slice(&ak[0..32]);

    let mut aes_nonce = [0u8; 12];
    aes_nonce.copy_from_slice(aes_nonce_bytes);

    let mut aes_tag = [0u8; 16];
    aes_tag.copy_from_slice(tag_slice);

    // Double decrypt the data
    let mut ciphertext_copy = ciphertext.to_vec();
    let mut plaintext = double_decrypt(
        &mut aes_key,
        &mut aes_nonce,
        &mut aes_tag,
        &mut chacha_key,
        &mut chacha_nonce,
        &mut ciphertext_copy,
        &input_data[..54],
    ).map_err(|_| CryptoError::DecryptionFailed)?;

    // Write output using raw syscall
    let mut written = 0;
    while written < plaintext.len() {
        let chunk_size = (plaintext.len() - written).min(8192);
        let write_result = unsafe {
            libc::write(out_fd, plaintext[written..].as_ptr() as *const libc::c_void, chunk_size)
        };
        if write_result < 0 { return Err(CryptoError::IOError); }
        written += write_result as usize;
    }

    let _ = unsafe { libc::ftruncate(out_fd, plaintext.len() as i64) };
    let _ = unsafe { libc::fsync(out_fd) };

    plaintext.zeroize();
    ciphertext_copy.zeroize();
    input_data.zeroize();
    base_secret.zeroize();
    buf.zeroize();
    chacha_key.zeroize();
    chacha_nonce.zeroize();
    aes_key.zeroize();
    aes_nonce.zeroize();
    aes_tag.zeroize();
    Ok(())
}

// Path-based helpers (open files and call fd functions)
#[inline(always)]
pub fn encrypt_file_pqrypt(input_path: &str, output_path: &str, secret: &[u8]) -> Result<(), CryptoError> {
    use std::fs::File;
    #[cfg(unix)] use std::os::unix::io::AsRawFd;
    let in_f = File::open(input_path).map_err(|_| CryptoError::IOError)?;
    let out_f = File::create(output_path).map_err(|_| CryptoError::IOError)?;
    double_encrypt_fd_raw(secret, false, in_f.as_raw_fd(), out_f.as_raw_fd())
}

#[inline(always)]
pub fn decrypt_file_pqrypt(input_path: &str, output_path: &str, secret: &[u8]) -> Result<(), CryptoError> {
    use std::fs::File;
    #[cfg(unix)] use std::os::unix::io::AsRawFd;
    let in_f = File::open(input_path).map_err(|_| CryptoError::IOError)?;
    let out_f = File::create(output_path).map_err(|_| CryptoError::IOError)?;
    double_decrypt_fd_raw(secret, false, in_f.as_raw_fd(), out_f.as_raw_fd())
}

// MARK: derive_password_hash_unified_64
#[inline(always)]
pub fn derive_password_hash_unified_64(
    app_name: &str,
    app_password: &str,
    master_password: &str,
) -> Result<Vec<u8>, CryptoError> {
    use crate::crypto_core::argon2id_derive;

    let mut app_salt = [0u8; 16];
    app_salt[0] = b'a';
    app_salt[1] = b'p';
    app_salt[2] = b'p';
    let mut master_salt = [0u8; 16];
    master_salt[0] = b'm';
    master_salt[1] = b's';
    master_salt[2] = b't';
    let mut pwd_salt = [0u8; 16];
    pwd_salt[0] = b'p';
    pwd_salt[1] = b'w';
    pwd_salt[2] = b'd';

    let mut app_name_copy = app_name.as_bytes().to_vec();
    let mut app_name_hash = argon2id_derive(&mut app_name_copy, &mut app_salt, 64)
        .map_err(|_| CryptoError::HashingFailed)?;
    app_name_copy.zeroize();
    app_salt.zeroize();

    let mut master_password_copy = master_password.as_bytes().to_vec();
    let mut master_hash = argon2id_derive(&mut master_password_copy, &mut master_salt, 64)
        .map_err(|_| CryptoError::HashingFailed)?;
    master_password_copy.zeroize();
    master_salt.zeroize();

    let mut combined_salt = [0u8; 16];
    combined_salt[..8].copy_from_slice(&master_hash[..8]);
    master_hash.zeroize();
    let mut final_hash = argon2id_derive(&mut app_name_hash, &mut combined_salt, 64)
        .map_err(|_| CryptoError::HashingFailed)?;
    combined_salt.zeroize();

    if !app_password.is_empty() {
        let mut app_password_copy = app_password.as_bytes().to_vec();
        let mut pwd_hash = argon2id_derive(&mut app_password_copy, &mut pwd_salt, 64)
            .map_err(|_| CryptoError::HashingFailed)?;
        app_password_copy.zeroize();
        pwd_salt.zeroize();

        let mut final_salt = [0u8; 16];
        final_salt[..8].copy_from_slice(&pwd_hash[..8]);
        pwd_hash.zeroize();
        final_hash = argon2id_derive(&mut final_hash, &mut final_salt, 64)
            .map_err(|_| CryptoError::HashingFailed)?;
        final_salt.zeroize();
    } else {
        pwd_salt.zeroize();
    }

    app_name_hash.zeroize();
    Ok(final_hash)
}
