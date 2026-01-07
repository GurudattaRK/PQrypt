// Main API functions that combine lower-level cryptographic operations

use super::constants_errors::*;
pub use super::constants_errors::secure_random_bytes;
use crate::c_ffi::log_debug;
use libc::c_int;
use libc;
use openssl::hash::{hash, MessageDigest};

// =============================
// PQRYPT2 single-tag streaming
// =============================

const IO_BUF_SIZE: usize = 128 * 1024; // 128 KiB IO buffer

const FIXED_SALT: &[u8] = b"PQryptFixedSalt1"; // 16 bytes

// MARK: double_encrypt_fd_raw
#[inline(always)]
pub fn double_encrypt_fd_raw(
    secret: &[u8],
    _is_keyfile: bool,
    in_fd: c_int,
    out_fd: c_int,
) -> Result<(), CryptoError> {
    use crate::crypto_core::double_encrypt;


    // STEP 0: Begin
    let mut step: i32 = 0;

    // STEP 1: Base secret = SHA-512(password || FIXED_SALT)
    let mut buf = Vec::with_capacity(secret.len() + FIXED_SALT.len());
    buf.extend_from_slice(secret);
    buf.extend_from_slice(FIXED_SALT);
    let base_secret = match hash(MessageDigest::sha512(), &buf).map(|d| d.to_vec()) {
        Ok(v) => v,
        Err(_) => return Err(CryptoError::DebugCode(step)),
    };

    // STEP 2: Derive keys via SHA-256(base || label)
    let mut chacha_key = [0u8; 32];
    let ck = match hash(MessageDigest::sha256(), &[&base_secret[..], b"CHACHA_KEY"].concat()) {
        Ok(d) => d,
        Err(_) => return Err(CryptoError::DebugCode(step)),
    };
    chacha_key.copy_from_slice(&ck[0..32]);

    let mut aes_key = [0u8; 32];
    let ak = match hash(MessageDigest::sha256(), &[&base_secret[..], b"AES_KEY"].concat()) {
        Ok(d) => d,
        Err(_) => return Err(CryptoError::DebugCode(step)),
    };
    aes_key.copy_from_slice(&ak[0..32]);

    // STEP 3: Random nonces per-encryption
    let mut chacha_nonce = [0u8; 12];
    secure_random_bytes(&mut chacha_nonce).map_err(|_| CryptoError::DebugCode(step))?;
    let mut aes_nonce = [0u8; 12];
    secure_random_bytes(&mut aes_nonce).map_err(|_| CryptoError::DebugCode(step))?;

    // Read entire input file
    let mut input_data = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read_result = unsafe { libc::read(in_fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if read_result < 0 {
            return Err(CryptoError::DebugCode(step));
        }
        if read_result == 0 {
            break;
        }
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
    ).map_err(|_| {
        CryptoError::DebugCode(step)
    })?;

    // Build GCM trailer (19 bytes): "GCM" + 16-byte tag
    let mut gcm_trailer = [0u8; 19];
    gcm_trailer[0..3].copy_from_slice(b"GCM");
    gcm_trailer[3..19].copy_from_slice(&aes_tag);

    // Write header
    let mut write_buf = |fd: c_int, buf: &[u8], err_step: i32| -> Result<(), CryptoError> {
        let mut written = 0usize;
        while written < buf.len() {
            let chunk = &buf[written..];
            let to_write = chunk.len().min(8192);
            let res = unsafe { libc::write(fd, chunk.as_ptr() as *const libc::c_void, to_write) };
            if res < 0 { return Err(CryptoError::DebugCode(err_step)); }
            written += res as usize;
        }
        Ok(())
    };

    // Write header
    write_buf(out_fd, &header, step)?;
    // Write ciphertext
    write_buf(out_fd, &ciphertext, step)?;
    // Write trailer
    write_buf(out_fd, &gcm_trailer, step)?;

    // Zeroize header/trailer
    for b in &mut header { *b = 0; }
    for b in &mut gcm_trailer { *b = 0; }

    // Truncate file to actual size and sync to disk
    // We wrote exact number of bytes; still call fsync
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
    use crate::c_ffi::log_debug;

    let mut step: i32 = 0;

    // Read all input data
    let mut input_data = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read_result = unsafe { libc::read(in_fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if read_result < 0 {
            return Err(CryptoError::DebugCode(step));
        }
        if read_result == 0 {
            break;
        }
        input_data.extend_from_slice(&buffer[..read_result as usize]);
    }


    // Check minimum file size (54 header + 19 GCM = 73 bytes minimum)
    if input_data.len() < 73 {
        return Err(CryptoError::DebugCode(step));
    }

    // Parse fixed binary header (54 bytes)
    if &input_data[..6] != b"PQRYPT" {
        return Err(CryptoError::DebugCode(step));
    }

    let original_size = u64::from_le_bytes(input_data[6..14].try_into().unwrap()) as usize;
    let aes_nonce_bytes = &input_data[14..26];
    let chacha_nonce_bytes = &input_data[26..38];
    let salt = &input_data[38..54];

    // STEP: Nonce validation (must not be all zeros)
    let aes_zero = aes_nonce_bytes.iter().all(|&b| b == 0);
    let chacha_zero = chacha_nonce_bytes.iter().all(|&b| b == 0);
    if aes_zero || chacha_zero {
        return Err(CryptoError::DebugCode(step));
    } else {
    }

    // Check GCM trailer (last 19 bytes)
    let gcm_start = input_data.len() - 19;
    if &input_data[gcm_start..gcm_start + 3] != b"GCM" {
        return Err(CryptoError::DebugCode(step));
    }
    let tag_slice = &input_data[gcm_start + 3..];

    // Extract ciphertext (from after header to before GCM trailer)
    let ciphertext = &input_data[54..gcm_start];


    // Base secret = SHA-512(password || FIXED_SALT)
    let mut buf = Vec::with_capacity(secret.len() + FIXED_SALT.len());
    buf.extend_from_slice(secret);
    buf.extend_from_slice(FIXED_SALT);
    let base_secret = match hash(MessageDigest::sha512(), &buf).map(|d| d.to_vec()) {
        Ok(v) => v,
        Err(_) => return Err(CryptoError::DebugCode(step)),
    };

    // Derive keys via SHA-256(base || label)
    let mut chacha_key = [0u8; 32];
    let ck = match hash(MessageDigest::sha256(), &[&base_secret[..], b"CHACHA_KEY"].concat()) {
        Ok(d) => d,
        Err(_) => return Err(CryptoError::DebugCode(step)),
    };
    chacha_key.copy_from_slice(&ck[0..32]);

    // Use ChaCha nonce from header
    let mut chacha_nonce = [0u8; 12];
    chacha_nonce.copy_from_slice(chacha_nonce_bytes);

    let mut aes_key = [0u8; 32];
    let ak = match hash(MessageDigest::sha256(), &[&base_secret[..], b"AES_KEY"].concat()) {
        Ok(d) => d,
        Err(_) => return Err(CryptoError::DebugCode(step)),
    };
    aes_key.copy_from_slice(&ak[0..32]);

    // Use AES nonce from header
    let mut aes_nonce = [0u8; 12];
    aes_nonce.copy_from_slice(aes_nonce_bytes);

    let mut aes_tag = [0u8; 16];
    aes_tag.copy_from_slice(tag_slice);

    // Double decrypt the data
    let mut ciphertext_copy = ciphertext.to_vec();
    let plaintext = double_decrypt(
        &mut aes_key,
        &mut aes_nonce,
        &mut aes_tag,
        &mut chacha_key,
        &mut chacha_nonce,
        &mut ciphertext_copy,
        &input_data[..54],
    ).map_err(|_| {
        CryptoError::DebugCode(step)
    })?;


    // Write output using raw syscall
    let mut written = 0;
    while written < plaintext.len() {
        let chunk_size = (plaintext.len() - written).min(8192);
        let write_result = unsafe {
            libc::write(out_fd, plaintext[written..].as_ptr() as *const libc::c_void, chunk_size)
        };
        if write_result < 0 {
            return Err(CryptoError::DebugCode(step));
        }
        written += write_result as usize;
    }

    // Truncate file to actual size and sync to disk
    let truncate_result = unsafe {
        libc::ftruncate(out_fd, plaintext.len() as i64)
    };
    if truncate_result < 0 {
    } else {
    }

    let fsync_result = unsafe {
        libc::fsync(out_fd)
    };
    if fsync_result < 0 {
    } else {
    }

    Ok(())
}
