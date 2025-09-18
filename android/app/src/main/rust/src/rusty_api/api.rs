// Main API functions that combine lower-level cryptographic operations

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use cipher::generic_array::GenericArray as Ga;
use ctr::Ctr128BE;
use ghash::{GHash, Block};
use universal_hash::UniversalHash;
use std::time::{Duration, Instant};
use log::debug;
//
use super::constants_errors::*;
use super::utils::*;
use super::symmetric::*;
use threefish::Threefish1024;
use cipher::{BlockEncrypt, BlockDecrypt};
use cipher::generic_array::GenericArray;
use cipher::consts::U128;
use zeroize::Zeroize;
use std::os::raw::c_int;
use libc;
use subtle::ConstantTimeEq;

// Debug file logging disabled in release builds

// =============================
// PQRYPT2 single-tag streaming
// =============================

const IO_BUF_SIZE: usize = 128 * 1024; // 128 KiB IO buffer
const HEADER_MAGIC: &[u8; 8] = b"PQRYPT2\0"; // 8-byte magic (binary header)
const HEADER_VERSION: u8 = 1;

// Flags bitmask
const FLAG_SINGLE_TAG: u8 = 0b0000_0001;      // One GCM tag for entire file
const FLAG_TRAILER_LEN: u8 = 0b0000_0010;     // u64 original length is in trailer

#[inline]
fn build_header(
    salt: &[u8; 32],
    nonce: &[u8; AES256_IV_SIZE],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(8 + 1 + 1 + 4 + 4 + 4 + 32 + 12 + 8);
    header.extend_from_slice(HEADER_MAGIC);
    header.push(HEADER_VERSION);
    header.push(FLAG_SINGLE_TAG | FLAG_TRAILER_LEN);
    header.extend_from_slice(&mem_kib.to_le_bytes());
    header.extend_from_slice(&time_cost.to_le_bytes());
    header.extend_from_slice(&lanes.to_le_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);
    header.extend_from_slice(&[0u8; 8]); // reserved
    header
}

#[inline]
fn derive_file_keys_from_secret(
    secret: &[u8],
    salt: &[u8; 32],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Result<TripleCipherKeys, CryptoError> {
    // Updated to derive 336 bytes for keys + CBC IVs
    let mut derived = super::symmetric::argon2id_hash(secret, salt, 336, mem_kib, time_cost, lanes)?;
    if derived.len() != 336 { return Err(CryptoError::KeyDerivationFailed); }

    let mut tf_key_128 = [0u8; 128];
    tf_key_128.copy_from_slice(&derived[0..128]);
    let mut serpent_key = [0u8; 32];
    serpent_key.copy_from_slice(&derived[128..160]);
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&derived[160..192]);
    let mut serpent_iv = [0u8; 16];
    serpent_iv.copy_from_slice(&derived[192..208]);
    let mut threefish_iv = [0u8; 128];
    threefish_iv.copy_from_slice(&derived[208..336]);

    derived.zeroize();
    Ok(TripleCipherKeys { aes_key, serpent_key, tf_key_128, serpent_iv, threefish_iv })
}

#[inline]
fn aes_gcm_subkey_h(aes_key: &[u8; 32]) -> [u8; 16] {
    // H = E(K, 0^128)
    let cipher = Aes256::new(Ga::from_slice(aes_key));
    let mut block = [0u8; 16];
    let mut ga = Ga::from_mut_slice(&mut block);
    cipher.encrypt_block(&mut ga);
    block
}

#[inline]
fn gcm_encryptor_init(
    aes_key: &[u8; 32],
    nonce: &[u8; AES256_IV_SIZE],
) -> (Ctr128BE<Aes256>, [u8; 16], [u8; 16]) {
    // Build J0 and initial CTR = inc32(J0)
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[12..].copy_from_slice(&1u32.to_be_bytes());

    // initial counter = J0 + 1
    let mut ctr0 = j0;
    let c = u32::from_be_bytes([ctr0[12], ctr0[13], ctr0[14], ctr0[15]]).wrapping_add(1);
    ctr0[12..].copy_from_slice(&c.to_be_bytes());

    // init CTR stream cipher
    let ctr = Ctr128BE::<Aes256>::new(Ga::from_slice(aes_key), Ga::from_slice(&ctr0));

    // compute subkey H and E(K, J0)
    let h = aes_gcm_subkey_h(aes_key);
    let cipher = Aes256::new(Ga::from_slice(aes_key));
    let mut ek_j0 = j0;
    let mut ekj0_ga = Ga::from_mut_slice(&mut ek_j0);
    cipher.encrypt_block(&mut ekj0_ga);

    (ctr, h, ek_j0)
}

#[inline]
fn ghash_update_blocks(gh: &mut GHash, buf: &[u8]) {
    debug_assert!(buf.len() % 16 == 0);
    for block in buf.chunks(16) {
        let ga: Block = Block::clone_from_slice(block);
        gh.update(&[ga]);
    }
}

#[inline]
fn ghash_append_lengths(gh: &mut GHash, aad_len: usize, ct_len: usize) {
    let mut len_block = [0u8; 16];
    let aad_bits = (aad_len as u128) * 8;
    let ct_bits = (ct_len as u128) * 8;
    len_block[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
    len_block[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
    // process as padded (exactly one block)
    gh.update_padded(&len_block);
}



// Cached keys structure for performance with CBC IVs
struct TripleCipherKeys {
    aes_key: [u8; 32],
    serpent_key: [u8; 32],
    tf_key_128: [u8; 128],
    serpent_iv: [u8; 16],    // IV for Serpent CBC
    threefish_iv: [u8; 128], // IV for Threefish CBC
}

impl Zeroize for TripleCipherKeys {
    fn zeroize(&mut self) {
        self.aes_key.zeroize();
        self.serpent_key.zeroize();
        self.tf_key_128.zeroize();
        self.serpent_iv.zeroize();
        self.threefish_iv.zeroize();
    }
}

impl TripleCipherKeys {
    #[inline]
    fn derive_from_master(master_key: &[u8; 128]) -> Result<Self, CryptoError> {
        // Argon2 derivation to 336 bytes (128 + 32 + 32 + 16 + 128) for keys + IVs
        const SALT_COMBINED: [u8; 32] = [
            b'P', b'Q', b'r', b'y', b'p', b't', b':', b'T', b'F', b'S', b'-', b'K', b'D', b':', b'2', b'.', b'0',
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ];

        let mut derived = argon2id_hash(master_key, &SALT_COMBINED, 336, 10240, 1, 1)?;
        if derived.len() != 336 { return Err(CryptoError::KeyDerivationFailed); }

        let mut tf_key_128 = [0u8; 128];
        tf_key_128.copy_from_slice(&derived[0..128]);
        let mut serpent_key = [0u8; 32];
        serpent_key.copy_from_slice(&derived[128..160]);
        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&derived[160..192]);
        let mut serpent_iv = [0u8; 16];
        serpent_iv.copy_from_slice(&derived[192..208]);
        let mut threefish_iv = [0u8; 128];
        threefish_iv.copy_from_slice(&derived[208..336]);

        // Zeroize derived material before returning keys
        derived.zeroize();
        Ok(TripleCipherKeys { aes_key, serpent_key, tf_key_128, serpent_iv, threefish_iv })
    }
}

// CBC mode encryption for triple cipher (128-byte chunks)
#[inline(always)]
fn triple_encrypt_chunk_inplace_cbc(chunk: &mut [u8; CHUNK_SIZE], keys: &TripleCipherKeys, threefish_prev: &mut [u8; 128], serpent_prev: &mut [u8; 16]) -> Result<(), CryptoError> {
    use log::debug;
    
    // Log first 16 bytes before encryption
    debug!("ENCRYPT: Before Threefish CBC: {:02x?}", &chunk[..16]);
    
    // Threefish-1024 CBC: XOR with previous block, then encrypt
    for i in 0..CHUNK_SIZE {
        chunk[i] ^= threefish_prev[i];
    }
    let cipher = Threefish1024::new(&keys.tf_key_128.into());
    let block_ga: &mut GenericArray<u8, U128> = GenericArray::from_mut_slice(chunk);
    cipher.encrypt_block(block_ga);
    threefish_prev.copy_from_slice(chunk); // Update previous block for next iteration
    
    debug!("ENCRYPT: After Threefish CBC: {:02x?}", &chunk[..16]);
    
    // Serpent CBC encryption - process 8 blocks of 16 bytes each
    serpent_encrypt_8blocks_cbc(chunk, &keys.serpent_key, serpent_prev)?;
    
    debug!("ENCRYPT: After Serpent CBC: {:02x?}", &chunk[..16]);
    
    Ok(())
}

// Legacy ECB function for compatibility (if needed)
#[inline(always)]
fn triple_encrypt_chunk_inplace(chunk: &mut [u8; CHUNK_SIZE], keys: &TripleCipherKeys) -> Result<(), CryptoError> {
    // Initialize CBC state with IVs
    let mut threefish_prev = keys.threefish_iv;
    let mut serpent_prev = keys.serpent_iv;
    triple_encrypt_chunk_inplace_cbc(chunk, keys, &mut threefish_prev, &mut serpent_prev)
}

// Serpent CBC encryption for 8 blocks (128 bytes)
#[inline(always)]
fn serpent_encrypt_8blocks_cbc(data: &mut [u8; CHUNK_SIZE], key: &[u8; 32], prev_block: &mut [u8; 16]) -> Result<(), CryptoError> {
    use serpent::{Serpent, cipher::KeyInit};
    
    let cipher = Serpent::new_from_slice(key)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    for i in 0..8 {
        let block_start = i * 16;
        let block_end = block_start + 16;
        
        // Direct in-place operation with zero-copy
        let block_slice = &mut data[block_start..block_end];
        let block_array: &mut [u8; 16] = block_slice.try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        
        // CBC: XOR with previous ciphertext block before encryption
        for j in 0..16 {
            block_array[j] ^= prev_block[j];
        }
        
        serpent_encrypt_inplace(&cipher, block_array);
        
        // Update previous block for next iteration
        prev_block.copy_from_slice(block_array);
    }
    Ok(())
}

// Legacy ECB function for compatibility (if needed)
#[inline(always)]
fn serpent_encrypt_8blocks(data: &mut [u8; CHUNK_SIZE], key: &[u8; 32]) -> Result<(), CryptoError> {
    use serpent::{Serpent, cipher::KeyInit};
    
    let cipher = Serpent::new_from_slice(key)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    for i in 0..8 {
        let block_start = i * 16;
        let block_end = block_start + 16;
        
        // Direct in-place operation with zero-copy
        let block_slice = &mut data[block_start..block_end];
        let block_array: &mut [u8; 16] = block_slice.try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        serpent_encrypt_inplace(&cipher, block_array);
    }
    Ok(())
}

// CBC mode decryption for triple cipher (128-byte chunks)
#[inline(always)]
fn triple_decrypt_chunk_inplace_cbc(chunk: &mut [u8; CHUNK_SIZE], keys: &TripleCipherKeys, threefish_prev: &mut [u8; 128], serpent_prev: &mut [u8; 16]) -> Result<(), CryptoError> {
    use log::debug;
    
    // Log first 16 bytes before decryption
    debug!("DECRYPT: Before Serpent CBC: {:02x?}", &chunk[..16]);
    
    // Store original ciphertext for CBC
    let _serpent_ct_backup = chunk.clone();
    
    // Serpent CBC decryption - process 8 blocks of 16 bytes each
    serpent_decrypt_8blocks_cbc(chunk, &keys.serpent_key, serpent_prev)?;
    
    debug!("DECRYPT: After Serpent CBC: {:02x?}", &chunk[..16]);
    
    // Store ciphertext for Threefish CBC
    let threefish_ct_backup = chunk.clone();
    
    // Threefish-1024 CBC: decrypt, then XOR with previous block
    let cipher = Threefish1024::new(&keys.tf_key_128.into());
    let block_ga: &mut GenericArray<u8, U128> = GenericArray::from_mut_slice(chunk);
    cipher.decrypt_block(block_ga);
    
    // XOR with previous ciphertext block
    for i in 0..CHUNK_SIZE {
        chunk[i] ^= threefish_prev[i];
    }
    threefish_prev.copy_from_slice(&threefish_ct_backup); // Update for next iteration
    
    debug!("DECRYPT: After Threefish CBC: {:02x?}", &chunk[..16]);
    
    Ok(())
}

// Legacy ECB function for compatibility (if needed)
#[inline(always)]
fn triple_decrypt_chunk_inplace(chunk: &mut [u8; CHUNK_SIZE], keys: &TripleCipherKeys) -> Result<(), CryptoError> {
    // Initialize CBC state with IVs
    let mut threefish_prev = keys.threefish_iv;
    let mut serpent_prev = keys.serpent_iv;
    triple_decrypt_chunk_inplace_cbc(chunk, keys, &mut threefish_prev, &mut serpent_prev)
}

// Serpent CBC decryption for 8 blocks (128 bytes)
#[inline(always)]
fn serpent_decrypt_8blocks_cbc(data: &mut [u8; CHUNK_SIZE], key: &[u8; 32], prev_block: &mut [u8; 16]) -> Result<(), CryptoError> {
    use serpent::{Serpent, cipher::KeyInit};
    
    let cipher = Serpent::new_from_slice(key)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    for i in 0..8 {
        let block_start = i * 16;
        let block_end = block_start + 16;
        
        // Direct in-place operation with zero-copy
        let block_slice = &mut data[block_start..block_end];
        let block_array: &mut [u8; 16] = block_slice.try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        
        // Store original ciphertext for CBC
        let ct_backup = *block_array;
        
        serpent_decrypt_inplace(&cipher, block_array);
        
        // CBC: XOR with previous ciphertext block after decryption
        for j in 0..16 {
            block_array[j] ^= prev_block[j];
        }
        
        // Update previous block for next iteration
        prev_block.copy_from_slice(&ct_backup);
    }
    Ok(())
}

// Legacy ECB function for compatibility (if needed)
#[inline(always)]
fn serpent_decrypt_8blocks(data: &mut [u8; CHUNK_SIZE], key: &[u8; 32]) -> Result<(), CryptoError> {
    use serpent::{Serpent, cipher::KeyInit};
    
    let cipher = Serpent::new_from_slice(key)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    for i in 0..8 {
        let block_start = i * 16;
        let block_end = block_start + 16;
        
        // Direct in-place operation with zero-copy
        let block_slice = &mut data[block_start..block_end];
        let block_array: &mut [u8; 16] = block_slice.try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        serpent_decrypt_inplace(&cipher, block_array);
    }
    Ok(())
}

//MARK: Ultra-optimized block-by-block triple encryption
#[inline]
pub fn triple_encrypt(master_key: &[u8; 128], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let start_time = Instant::now();
    eprintln!("DEBUG: triple_encrypt called with plaintext len: {}", plaintext.len());
    
    // Derive keys once and cache them
    let key_derive_time = Instant::now();
    eprintln!("DEBUG: Deriving keys from master key");
    let mut keys = TripleCipherKeys::derive_from_master(master_key)?;
    println!("[ENCRYPT] Key derivation: {:.2?}", key_derive_time.elapsed());
    
    // Calculate padded length with overflow protection
    eprintln!("DEBUG: Calculating padded length");
    let padded_len = calculate_padded_length(plaintext.len())?;
    eprintln!("DEBUG: Padded length: {}", padded_len);
    
    // Block-by-block processing for memory efficiency (optimized - minimize allocations)
    let cipher_time = Instant::now();
    eprintln!("DEBUG: Creating processed vector with capacity: {}", padded_len);
    let mut processed = Vec::with_capacity(padded_len);
    processed.extend_from_slice(plaintext);
    processed.resize(padded_len, 0); // Pad with zeros
    eprintln!("DEBUG: Processed vector created, actual len: {}", processed.len());
    
    let mut threefish_total = Duration::new(0, 0);
    let mut serpent_total = Duration::new(0, 0);
    
    eprintln!("DEBUG: Starting chunk processing, {} chunks", processed.len() / CHUNK_SIZE);
    // Process in-place by chunks for maximum memory efficiency
    let tf_cipher = Threefish1024::new(&keys.tf_key_128.into());
    for (i, chunk) in processed.chunks_mut(CHUNK_SIZE).enumerate() {
        eprintln!("DEBUG: Processing chunk {}, chunk len: {}", i, chunk.len());
        let chunk_array: &mut [u8; CHUNK_SIZE] = chunk.try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        
        // Time individual cipher operations
        let threefish_start = Instant::now();
        eprintln!("DEBUG: Processing chunk {} with Threefish-1024", i);
        let block_ga: &mut GenericArray<u8, U128> = GenericArray::from_mut_slice(chunk_array);
        tf_cipher.encrypt_block(block_ga);
        threefish_total += threefish_start.elapsed();
        
        let serpent_start = Instant::now();
        eprintln!("DEBUG: Processing chunk {} with serpent cipher", i);
        serpent_encrypt_8blocks(chunk_array, &keys.serpent_key)?;
        serpent_total += serpent_start.elapsed();
        eprintln!("DEBUG: Completed chunk {}", i);
    }
    
    println!("[ENCRYPT] Threefish-1024: {:.2?}", threefish_total);
    println!("[ENCRYPT] Serpent cipher: {:.2?}", serpent_total);
    println!("[ENCRYPT] Custom ciphers total: {:.2?}", cipher_time.elapsed());
    
    // AES-GCM encryption
    let aes_time = Instant::now();
    let cipher = Aes256Gcm::new_from_slice(&keys.aes_key).expect("AES-256 key must be exactly 32 bytes");

    let mut iv = [0u8; AES256_IV_SIZE];
    secure_random_bytes(&mut iv)?;
    let nonce = Nonce::from_slice(&iv);
    
    let ciphertext = cipher.encrypt(nonce, processed.as_slice())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    println!("[ENCRYPT] AES-GCM: {:.2?}", aes_time.elapsed());
    
    // Construct final output: IV + ciphertext + tag
    let mut result = Vec::with_capacity(AES256_IV_SIZE + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);

    // Zeroize sensitive buffers
    processed.zeroize();
    iv.zeroize();
    keys.aes_key.zeroize();
    keys.serpent_key.zeroize();
    keys.tf_key_128.zeroize();
    
    let elapsed = start_time.elapsed();
    println!("Triple encryption completed in: {:.2?} ({} bytes)", elapsed, plaintext.len());
    
    Ok(result)
}

//MARK: Ultra-optimized block-by-block triple decryption with debug error codes
#[inline]
pub fn triple_decrypt(master_key: &[u8; 128], input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let start_time = Instant::now();
    // ERROR -100: Input too small
    if input.len() < AES256_IV_SIZE + AES256_TAG_SIZE {
        return Err(CryptoError::DebugCode(-100));
    }
    
    // ERROR -101: Key derivation failed
    let mut keys = TripleCipherKeys::derive_from_master(master_key)
        .map_err(|_| CryptoError::DebugCode(-101))?;
    
    // Extract IV and ciphertext (which includes the TAG)
    let iv = &input[0..AES256_IV_SIZE];
    let ciphertext = &input[AES256_IV_SIZE..];
    
    // ERROR -102: AES key setup failed
    let cipher = Aes256Gcm::new_from_slice(&keys.aes_key)
        .map_err(|_| CryptoError::DebugCode(-102))?;
    let nonce = Nonce::from_slice(iv);
    
    // ERROR -103: AES-GCM authentication/decryption failed
    let mut processed = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DebugCode(-103))?;
    
    // ERROR -104: Chunk alignment error
    if processed.len() % CHUNK_SIZE != 0 {
        return Err(CryptoError::DebugCode(-104));
    }
    
    // Block-by-block in-place processing
    let mut chunk_index = 0;
    let tf_cipher = Threefish1024::new(&keys.tf_key_128.into());
    for chunk in processed.chunks_mut(CHUNK_SIZE) {
        // ERROR -105 - (chunk_index): Chunk conversion failed
        let chunk_array: &mut [u8; CHUNK_SIZE] = chunk.try_into()
            .map_err(|_| CryptoError::DebugCode(-105 - chunk_index as i32))?;
        
        // ERROR -200 - (chunk_index): Serpent decryption failed
        serpent_decrypt_8blocks(chunk_array, &keys.serpent_key)
            .map_err(|_| CryptoError::DebugCode(-200 - chunk_index as i32))?;
        
        // ERROR -300 - (chunk_index): Threefish decryption failed
        let block_ga: &mut GenericArray<u8, U128> = GenericArray::from_mut_slice(chunk_array);
        tf_cipher.decrypt_block(block_ga);
        chunk_index += 1;
    }
    
    // Zeroize keys before returning plaintext
    keys.aes_key.zeroize();
    keys.serpent_key.zeroize();
    keys.tf_key_128.zeroize();
    
    let _elapsed = start_time.elapsed();
    Ok(processed)
}

//MARK: generate_password
pub fn generate_password(
    mode: u8,
    hash_bytes: &[u8],
    desired_len: usize,
    enabled_symbol_sets: &[bool; 3]
) -> Option<String> {
    if hash_bytes.is_empty() || desired_len == 0 || desired_len > MAX_PASSWORD_LEN {
        return None;
    }
    
    let mut password = vec![0u8; desired_len];
    
    if mode == 0 {
        // BASE93 MODE - Direct generation from hash bytes
        const BASE93_MIN: u8 = 33;
        const BASE93_MAX: u8 = 126;
        const BASE93_RANGE: u8 = BASE93_MAX - BASE93_MIN + 1;
        
        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_symbol = false;
        
        for i in 0..desired_len {
            let ch = (hash_bytes[i % hash_bytes.len()] % BASE93_RANGE) + BASE93_MIN;
            password[i] = ch;
            
            let c = ch as char;
            if c.is_ascii_lowercase() { has_lower = true; }
            else if c.is_ascii_uppercase() { has_upper = true; }
            else if c.is_ascii_digit() { has_digit = true; }
            else if !c.is_ascii_alphanumeric() { has_symbol = true; }
        }
        
        // Ensure all character classes are present
        for i in 0..desired_len {
            if has_lower && has_upper && has_digit && has_symbol { break; }
            
            let b = hash_bytes[(i + 1) % hash_bytes.len()];
            let current_char = password[i] as char;
            
            if !has_lower && !current_char.is_ascii_lowercase() {
                password[i] = CHAR_SETS[0].as_bytes()[b as usize % 26];
                has_lower = true;
            } else if !has_upper && !current_char.is_ascii_uppercase() {
                password[i] = CHAR_SETS[1].as_bytes()[b as usize % 26];
                has_upper = true;
            } else if !has_digit && !current_char.is_ascii_digit() {
                password[i] = CHAR_SETS[2].as_bytes()[b as usize % 10];
                has_digit = true;
            } else if !has_symbol && !current_char.is_ascii_alphanumeric() {
                let candidate = (b % BASE93_RANGE) + BASE93_MIN;
                if !(candidate as char).is_ascii_alphanumeric() {
                    password[i] = candidate;
                    has_symbol = true;
                }
            }
        }
    } else {
        // CHARACTER SET MODE
        generate_charset_password(&mut password, hash_bytes, desired_len, enabled_symbol_sets);
    }
    
    String::from_utf8(password).ok()
}

// Helper function for charset mode
fn generate_charset_password(
    password: &mut [u8],
    hash_bytes: &[u8],
    desired_len: usize,
    enabled_symbol_sets: &[bool; 3]
) {
    let mut active_set_flags = [true, true, true, false, false, false];
    for i in 0..3 {
        if enabled_symbol_sets[i] {
            active_set_flags[3 + i] = true;
        }
    }
    
    let mut active_sets = Vec::new();
    for i in 0..NUM_SETS {
        if active_set_flags[i] {
            active_sets.push(i);
        }
    }
    
    let total_active_sets = active_sets.len();
    let mut set_counts = [0; NUM_SETS];
    let mut char_set_index = vec![0; desired_len];
    
    for i in 0..desired_len {
        let b = hash_bytes[i % hash_bytes.len()];
        let set_idx = (b as usize) % total_active_sets;
        let actual_set = active_sets[set_idx];
        let charset = CHAR_SETS[actual_set];
        let ch = charset.as_bytes()[b as usize % charset.len()];
        
        password[i] = ch;
        set_counts[actual_set] += 1;
        char_set_index[i] = actual_set;
    }
    
    // Ensure all active sets are represented
    let mut missing_sets = Vec::new();
    for i in 0..NUM_SETS {
        if active_set_flags[i] && set_counts[i] == 0 {
            missing_sets.push(i);
        }
    }
    
    for &missing in &missing_sets {
        let mut max_set = 0;
        let mut max_count = 0;
        for i in 0..NUM_SETS {
            if active_set_flags[i] && set_counts[i] > max_count {
                max_set = i;
                max_count = set_counts[i];
            }
        }
        
        for i in 0..desired_len {
            if char_set_index[i] == max_set {
                let b = hash_bytes[(i + missing) % hash_bytes.len()];
                let charset = CHAR_SETS[missing];
                password[i] = charset.as_bytes()[b as usize % charset.len()];
                set_counts[max_set] -= 1;
                set_counts[missing] += 1;
                char_set_index[i] = missing;
                break;
            }
        }
    }
}

//MARK: LAYERED HYBRID KEY EXCHANGE (Kyber+X448 and HQC+P521)

//MARK: pqc_4hybrid_init
/// Initialize layered hybrid key exchange combining ML-KEM+X448 and HQC+P521
pub fn pqc_4hybrid_init() -> Result<(Vec<u8>, super::hybrid::HybridSenderState), CryptoError> {
    super::hybrid::pqc_4hybrid_init()
}

//MARK: pqc_4hybrid_recv
/// Layered hybrid receiver response
pub fn pqc_4hybrid_recv(
    hybrid_1_key: &[u8]
) -> Result<(Vec<u8>, super::hybrid::HybridReceiverState), CryptoError> {
    super::hybrid::pqc_4hybrid_recv(hybrid_1_key)
}

//MARK: pqc_4hybrid_snd_final
/// Complete layered hybrid exchange with secure key expansion
pub fn pqc_4hybrid_snd_final(
    hybrid_2_key: &[u8],
    hybrid_sender_state: &super::hybrid::HybridSenderState
) -> Result<([u8; 128], Vec<u8>), CryptoError> {
    super::hybrid::pqc_4hybrid_snd_final(hybrid_2_key, hybrid_sender_state)
}

//MARK: pqc_4hybrid_recv_final
/// Finalize layered hybrid exchange  
pub fn pqc_4hybrid_recv_final(
    hybrid_3_key: &[u8],
    hybrid_receiver_state: &super::hybrid::HybridReceiverState
) -> Result<[u8; 128], CryptoError> {
    super::hybrid::pqc_4hybrid_recv_final(hybrid_3_key, hybrid_receiver_state)
}

//MARK: triple_encrypt_fd_raw
/// Raw FD version of triple_encrypt_fd that avoids Rust File objects to prevent fdsan conflicts
pub fn triple_encrypt_fd_raw(
    secret: &[u8],
    _is_keyfile: bool,
    in_fd: c_int,
    out_fd: c_int,
) -> Result<(), CryptoError> {
    use log::debug;
    debug!("triple_encrypt_fd_raw start: secret_len={}, in_fd={}, out_fd={}", secret.len(), in_fd, out_fd);
    
    // Argon2 params for file encryption
    let mem_kib = 8 * 1024; // 8 MiB
    let time_cost = 1;
    let lanes = 1;

    // Per-file salt and AES nonce
    let mut salt = [0u8; 32];
    secure_random_bytes(&mut salt)?;
    debug!("Generated salt");
    let mut iv = [0u8; AES256_IV_SIZE];
    secure_random_bytes(&mut iv)?;
    debug!("Generated IV");

    // Derive keys
    debug!("About to derive keys");
    let mut keys = derive_file_keys_from_secret(secret, &salt, mem_kib, time_cost, lanes)?;
    debug!("Keys derived successfully");

    // Build header and write it using raw FD
    debug!("Building header");
    let header = build_header(&salt, &iv, mem_kib, time_cost, lanes);
    
    // Write header using raw write syscall
    let write_result = unsafe { libc::write(out_fd, header.as_ptr() as *const libc::c_void, header.len()) };
    if write_result < 0 || write_result as usize != header.len() {
        debug!("Failed to write header");
        return Err(CryptoError::InvalidInput);
    }
    debug!("Header written via raw FD");

    // Init GCM state
    let (mut ctr, h, ek_j0) = gcm_encryptor_init(&keys.aes_key, &iv);
    let mut ghash = GHash::new(ghash::Key::from_slice(&h));
    ghash.update_padded(&header); // header as AAD

    // Streaming buffers
    let mut io_buf = [0u8; IO_BUF_SIZE];
    let mut carry128 = Vec::with_capacity(128); // carry for <128B residual between reads
    let mut total_plain_len: u64 = 0;
    let mut total_ct_len: usize = 0;

    loop {
        // Read using raw read syscall
        let read_len = unsafe { libc::read(in_fd, io_buf.as_mut_ptr() as *mut libc::c_void, IO_BUF_SIZE) };
        if read_len < 0 {
            debug!("Raw read failed");
            return Err(CryptoError::InvalidInput);
        }
        if read_len == 0 { break; } // EOF
        
        let read_len = read_len as usize;
        total_plain_len = total_plain_len.saturating_add(read_len as u64);

        // Prepare working buffer = carry128 + read bytes
        let mut work_buf = Vec::with_capacity(carry128.len() + read_len);
        work_buf.extend_from_slice(&carry128);
        work_buf.extend_from_slice(&io_buf[..read_len]);
        carry128.clear();

        // MATCH ORIGINAL ALGORITHM: Process multiple of 128B, then AES-CTR entire batch
        let process_len = (work_buf.len() / CHUNK_SIZE) * CHUNK_SIZE; // multiple of 128
        let (process_slice, remainder) = work_buf.split_at(process_len);

        if process_len > 0 {
            // Triple encrypt in-place per 128B block (Threefish -> Serpent only)
            let mut process_vec = process_slice.to_vec();
            for chunk in process_vec.chunks_mut(CHUNK_SIZE) {
                let chunk_array: &mut [u8; CHUNK_SIZE] = chunk.try_into().map_err(|_| CryptoError::InvalidInput)?;
                triple_encrypt_chunk_inplace(chunk_array, &keys)?;
            }

            // AES-CTR encrypt the ENTIRE processed vector (not per chunk!)
            ctr.apply_keystream(&mut process_vec);

            // Update GHASH with ciphertext
            ghash_update_blocks(&mut ghash, &process_vec);
            
            // Write entire processed vector using raw write syscall
            let write_result = unsafe { libc::write(out_fd, process_vec.as_ptr() as *const libc::c_void, process_vec.len()) };
            if write_result < 0 || write_result as usize != process_vec.len() {
                debug!("Failed to write encrypted block batch");
                return Err(CryptoError::InvalidInput);
            }
            
            total_ct_len += process_vec.len();
        }

        // Save remainder (<128) to carry128 for next read (match original algorithm)
        carry128.clear();
        carry128.extend_from_slice(remainder);
    }

    // Handle final residual: pad to 128B if needed and process (EXACT MATCH TO ORIGINAL)
    if !carry128.is_empty() {
        debug!("Processing final block of {} bytes", carry128.len());
        
        let mut last_block = [0u8; CHUNK_SIZE];
        last_block[..carry128.len()].copy_from_slice(&carry128);
        // Triple encrypt
        triple_encrypt_chunk_inplace(&mut last_block, &keys)?;
        // AES-CTR
        let mut last_vec = last_block.to_vec();
        ctr.apply_keystream(&mut last_vec);
        // GHASH and write
        ghash_update_blocks(&mut ghash, &last_vec);
        
        // Write using raw write syscall
        let write_result = unsafe { libc::write(out_fd, last_vec.as_ptr() as *const libc::c_void, last_vec.len()) };
        if write_result < 0 || write_result as usize != last_vec.len() {
            debug!("Failed to write final encrypted block");
            return Err(CryptoError::InvalidInput);
        }
        
        total_ct_len += last_vec.len();
    }

    // Trailer: original plaintext length (u64 LE) - MISSING FROM RAW FD VERSION!
    let trailer = total_plain_len.to_le_bytes();
    ghash.update_padded(&trailer);
    
    // Write trailer using raw write syscall
    let write_result = unsafe { libc::write(out_fd, trailer.as_ptr() as *const libc::c_void, trailer.len()) };
    if write_result < 0 || write_result as usize != trailer.len() {
        debug!("Failed to write trailer");
        return Err(CryptoError::InvalidInput);
    }

    // Finalize GHASH with lengths and compute tag - MISSING FROM RAW FD VERSION!
    let aad_len = header.len() + trailer.len();
    ghash_append_lengths(&mut ghash, aad_len, total_ct_len);
    let s_tag_ga = ghash.clone().finalize();
    let s_tag_slice: &[u8] = s_tag_ga.as_slice();
    let mut tag = [0u8; 16];
    for i in 0..16 { tag[i] = ek_j0[i] ^ s_tag_slice[i]; }

    // Write authentication tag using raw write syscall
    let write_result = unsafe { libc::write(out_fd, tag.as_ptr() as *const libc::c_void, tag.len()) };
    if write_result < 0 || write_result as usize != tag.len() {
        debug!("Failed to write authentication tag");
        return Err(CryptoError::InvalidInput);
    }

    debug!("Raw FD encryption completed successfully");
    
    // Zeroize sensitive material
    keys.aes_key.zeroize();
    keys.serpent_key.zeroize();
    keys.tf_key_128.zeroize();

    Ok(())
}

//MARK: triple_decrypt_fd_raw
/// Raw FD version of triple_decrypt_fd that avoids Rust File objects to prevent fdsan conflicts
pub fn triple_decrypt_fd_raw(
    secret: &[u8],
    _is_keyfile: bool,
    in_fd: c_int,
    out_fd: c_int,
) -> Result<(), CryptoError> {
    use log::debug;
    debug!("triple_decrypt_fd_raw start: secret_len={}, in_fd={}, out_fd={}", secret.len(), in_fd, out_fd);
    
    // Read and parse header using raw syscalls
    let mut header = vec![0u8; 8 + 1 + 1 + 4 + 4 + 4 + 32 + 12 + 8];
    let header_read = unsafe { libc::read(in_fd, header.as_mut_ptr() as *mut libc::c_void, header.len()) };
    if header_read < 0 || header_read as usize != header.len() {
        debug!("Failed to read header");
        return Err(CryptoError::InvalidInput);
    }
    
    if &header[0..8] != HEADER_MAGIC { return Err(CryptoError::InvalidInput); }
    if header[8] != HEADER_VERSION { return Err(CryptoError::InvalidInput); }
    let flags = header[9];
    if (flags & FLAG_SINGLE_TAG) == 0 { return Err(CryptoError::InvalidInput); }
    if (flags & FLAG_TRAILER_LEN) == 0 { return Err(CryptoError::InvalidInput); }
    let mem_kib = u32::from_le_bytes(header[10..14].try_into().unwrap());
    let time_cost = u32::from_le_bytes(header[14..18].try_into().unwrap());
    let lanes = u32::from_le_bytes(header[18..22].try_into().unwrap());
    let mut salt = [0u8; 32]; salt.copy_from_slice(&header[22..54]);
    let mut iv = [0u8; AES256_IV_SIZE]; iv.copy_from_slice(&header[54..66]);

    // Derive keys
    let mut keys = derive_file_keys_from_secret(secret, &salt, mem_kib, time_cost, lanes)?;

    // Init GCM state
    let (mut ctr, h, ek_j0) = gcm_encryptor_init(&keys.aes_key, &iv);
    let mut ghash = GHash::new(ghash::Key::from_slice(&h));
    ghash.update_padded(&header);

    // Streaming decrypt while reserving last 24 bytes (trailer 8 + tag 16)
    let mut io_buf = [0u8; IO_BUF_SIZE];
    let mut ring = Vec::with_capacity(IO_BUF_SIZE + 24);
    let mut total_ct_len: usize = 0; // ciphertext length excluding trailer+tag
    let mut all_plaintext = Vec::new(); // collect all plaintext for final trimming

    loop {
        let read_len = unsafe { libc::read(in_fd, io_buf.as_mut_ptr() as *mut libc::c_void, IO_BUF_SIZE) };
        if read_len < 0 {
            debug!("Raw read failed");
            return Err(CryptoError::InvalidInput);
        }
        if read_len == 0 { break; } // EOF
        
        let read_len = read_len as usize;
        ring.extend_from_slice(&io_buf[..read_len]);

        // While we have more than 24 bytes in ring, we can process bytes except the last 24
        while ring.len() > 24 {
            let to_process = ring.len() - 24;
            // Limit processing to a multiple of 128 for triple pipeline
            let proc_len = (to_process / CHUNK_SIZE) * CHUNK_SIZE;
            if proc_len == 0 { break; }

            // Take proc_len bytes as ciphertext
            let mut ct_chunk = ring.drain(..proc_len).collect::<Vec<u8>>();
            // Update GHASH with ciphertext
            ghash_update_blocks(&mut ghash, &ct_chunk);
            total_ct_len += ct_chunk.len();

            // CTR decrypt in-place to get triple-processed bytes
            debug!("DECRYPT: Before AES-CTR: {:02x?}", &ct_chunk[..16]);
            ctr.apply_keystream(&mut ct_chunk);
            debug!("DECRYPT: After AES-CTR: {:02x?}", &ct_chunk[..16]);

            // Reverse triple pipeline per 128B
            for chunk in ct_chunk.chunks_mut(CHUNK_SIZE) {
                let chunk_array: &mut [u8; CHUNK_SIZE] = chunk.try_into().map_err(|_| CryptoError::InvalidInput)?;
                triple_decrypt_chunk_inplace(chunk_array, &keys)?;
            }

            // Collect all plaintext for final trimming
            all_plaintext.extend_from_slice(&ct_chunk);
        }
    }

    // At EOF, ring contains remaining ciphertext + 24 bytes (trailer+tag)
    if ring.len() < 24 { return Err(CryptoError::InvalidInput); }
    let trailer_tag = ring.split_off(ring.len() - 24);
    let trailer = &trailer_tag[..8];
    let mut tag_in_arr = [0u8; 16];
    tag_in_arr.copy_from_slice(&trailer_tag[8..24]);

    // Any remaining ciphertext (multiple of 128 or zero)
    let mut ct_rem = ring; // may be empty
    if !ct_rem.is_empty() {
        // Update GHASH
        ghash_update_blocks(&mut ghash, &ct_rem);
        total_ct_len += ct_rem.len();

        // CTR decrypt in-place
        ctr.apply_keystream(&mut ct_rem);
        // Reverse triple
        for chunk in ct_rem.chunks_mut(CHUNK_SIZE) {
            let chunk_array: &mut [u8; CHUNK_SIZE] = chunk.try_into().map_err(|_| CryptoError::InvalidInput)?;
            triple_decrypt_chunk_inplace(chunk_array, &keys)?;
        }
        
        // Add remaining plaintext
        all_plaintext.extend_from_slice(&ct_rem);
    }

    // Include trailer as AAD in GHASH and finalize
    ghash.update_padded(trailer);
    let aad_len = header.len() + trailer.len();
    ghash_append_lengths(&mut ghash, aad_len, total_ct_len);
    let s_tag_ga = ghash.clone().finalize();
    let s_tag_slice: &[u8] = s_tag_ga.as_slice();
    let mut tag = [0u8; 16];
    for i in 0..16 { tag[i] = ek_j0[i] ^ s_tag_slice[i]; }

    // Verify tag (constant time)
    if tag.ct_eq(&tag_in_arr).unwrap_u8() == 0 {
        return Err(CryptoError::AuthenticationFailed);
    }

    // Trim plaintext to original length and write using raw syscalls
    let orig_len = u64::from_le_bytes(trailer.try_into().unwrap()) as usize;
    if orig_len <= all_plaintext.len() {
        let output_data = &all_plaintext[..orig_len];
        
        // Write output using raw write syscall in chunks
        let mut written = 0;
        while written < output_data.len() {
            let chunk_size = (output_data.len() - written).min(IO_BUF_SIZE);
            let write_result = unsafe { 
                libc::write(out_fd, output_data[written..].as_ptr() as *const libc::c_void, chunk_size) 
            };
            if write_result < 0 {
                debug!("Failed to write decrypted data");
                return Err(CryptoError::InvalidInput);
            }
            written += write_result as usize;
        }
    } else {
        return Err(CryptoError::InvalidInput);
    }

    debug!("Raw FD decryption completed successfully");

    // Zeroize sensitive material
    keys.aes_key.zeroize();
    keys.serpent_key.zeroize();
    keys.tf_key_128.zeroize();
    salt.zeroize();
    iv.zeroize();
    io_buf.zeroize();

    Ok(())
}