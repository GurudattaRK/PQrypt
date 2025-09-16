// Main API functions that combine lower-level cryptographic operations

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Argon2, Algorithm, Version, Params};
use std::time::{Duration, Instant};
use std::fs::OpenOptions;
use std::io::Write;
use super::constants_errors::*;
use super::utils::*;
use super::symmetric::*;
use threefish::Threefish1024;
use cipher::{BlockEncrypt, BlockDecrypt, KeyInit as _};
use cipher::generic_array::GenericArray;
use cipher::consts::U128;
use zeroize::Zeroize;

// Debug file logging function
fn log_to_file(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/sdcard/rust_debug.log") {
        let _ = writeln!(file, "[{}] {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(), message);
    }
}

// Cached keys structure for performance
struct TripleCipherKeys {
    aes_key: [u8; 32],
    serpent_key: [u8; 32],
    tf_key_128: [u8; 128],
}

impl TripleCipherKeys {
    #[inline]
    fn derive_from_master(master_key: &[u8; 128]) -> Result<Self, CryptoError> {
        // Single Argon2 derivation to 192 bytes (128 + 32 + 32) so each cipher has its own key
        const SALT_COMBINED: [u8; 32] = [
            b'P', b'Q', b'r', b'y', b'p', b't', b':', b'T', b'F', b'S', b'-', b'K', b'D', b':', b'1', b'.', b'0',
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ];

        let mut derived = argon2id_hash(master_key, &SALT_COMBINED, 192, 10240, 1, 1)?;
        if derived.len() != 192 { return Err(CryptoError::KeyDerivationFailed); }

        let mut tf_key_128 = [0u8; 128];
        tf_key_128.copy_from_slice(&derived[0..128]);
        let mut serpent_key = [0u8; 32];
        serpent_key.copy_from_slice(&derived[128..160]);
        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&derived[160..192]);

        // Zeroize derived material before returning keys
        derived.zeroize();
        Ok(TripleCipherKeys { aes_key, serpent_key, tf_key_128 })
    }
}

// Optimized in-place chunk processing
#[inline(always)]
fn triple_encrypt_chunk_inplace(chunk: &mut [u8; CHUNK_SIZE], keys: &TripleCipherKeys) -> Result<(), CryptoError> {
    // Threefish-1024 encryption (in-place)
    let cipher = Threefish1024::new(&keys.tf_key_128.into());
    let block_ga: &mut GenericArray<u8, U128> = GenericArray::from_mut_slice(chunk);
    cipher.encrypt_block(block_ga);
    
    // Serpent encryption - batched 8-block processing
    serpent_encrypt_8blocks(chunk, &keys.serpent_key)?;
    
    Ok(())
}

// Ultra-optimized Serpent processing using single cipher instance
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

// Optimized in-place chunk decryption
#[inline(always)]
fn triple_decrypt_chunk_inplace(chunk: &mut [u8; CHUNK_SIZE], keys: &TripleCipherKeys) -> Result<(), CryptoError> {
    // Serpent decryption - batched 8-block processing
    serpent_decrypt_8blocks(chunk, &keys.serpent_key)?;
    
    // Threefish-1024 decryption (in-place)
    let cipher = Threefish1024::new(&keys.tf_key_128.into());
    let block_ga: &mut GenericArray<u8, U128> = GenericArray::from_mut_slice(chunk);
    cipher.decrypt_block(block_ga);
    
    Ok(())
}

// Ultra-optimized Serpent decryption using single cipher instance
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
    
    let elapsed = start_time.elapsed();
    Ok(processed)
}

// Password generation matching the old working implementation
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

/// Initialize layered hybrid key exchange combining ML-KEM+X448 and HQC+P521
pub fn pqc_4hybrid_init() -> Result<(Vec<u8>, super::hybrid::HybridSenderState), CryptoError> {
    super::hybrid::pqc_4hybrid_init()
}

/// Layered hybrid receiver response
pub fn pqc_4hybrid_recv(
    hybrid_1_key: &[u8]
) -> Result<(Vec<u8>, super::hybrid::HybridReceiverState), CryptoError> {
    super::hybrid::pqc_4hybrid_recv(hybrid_1_key)
}

/// Complete layered hybrid exchange with secure key expansion
pub fn pqc_4hybrid_snd_final(
    hybrid_2_key: &[u8],
    hybrid_sender_state: &super::hybrid::HybridSenderState
) -> Result<([u8; 128], Vec<u8>), CryptoError> {
    super::hybrid::pqc_4hybrid_snd_final(hybrid_2_key, hybrid_sender_state)
}

/// Finalize layered hybrid exchange  
pub fn pqc_4hybrid_recv_final(
    hybrid_3_key: &[u8],
    hybrid_receiver_state: &super::hybrid::HybridReceiverState
) -> Result<[u8; 128], CryptoError> {
    super::hybrid::pqc_4hybrid_recv_final(hybrid_3_key, hybrid_receiver_state)
}