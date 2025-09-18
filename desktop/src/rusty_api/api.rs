// Main API functions that combine lower-level cryptographic operations

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use super::constants_errors::*;
use super::utils::*;
use super::symmetric::*;
use ctr::Ctr128BE;
use aes::Aes256;
use ghash::{GHash, universal_hash::UniversalHash, Key as GhashKey, Block as GhashBlock};
use cipher::{KeyIvInit, StreamCipher, BlockEncrypt, BlockDecrypt};
use cipher::generic_array::GenericArray as Ga;
use threefish::Threefish1024;
use cipher::generic_array::GenericArray;
use cipher::consts::U128;
use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::Zeroize;


// Cached keys structure for performance with CBC IVs
struct TripleCipherKeys {
    aes_key: [u8; 32],
    serpent_key: [u8; 32],
    tf_key_128: [u8; 128],
    serpent_iv: [u8; 16],      // CBC IV for Serpent
    threefish_iv: [u8; 128],   // CBC IV for Threefish
}

// Unified 128-byte password derivation: each step outputs 128 bytes
pub fn derive_password_hash_unified_128(
    app_name: &str,
    app_password: &str,
    master_password: &str,
) -> Result<Vec<u8>, CryptoError> {
    // Salts: "app", "mst", "pwd" in first 3 bytes of 32-byte salt
    let mut app_salt = [0u8; 32]; app_salt[0] = b'a'; app_salt[1] = b'p'; app_salt[2] = b'p';
    let mut mst_salt = [0u8; 32]; mst_salt[0] = b'm'; mst_salt[1] = b's'; mst_salt[2] = b't';
    let mut pwd_salt = [0u8; 32]; pwd_salt[0] = b'p'; pwd_salt[1] = b'w'; pwd_salt[2] = b'd';

    // Argon2 parameters for PASSWORD GENERATOR (mem=16 MiB, time=3, lanes=1) - MATCH ANDROID
    let mem_kib: u32 = 16 * 1024;  // 16 MB to match Android
    let time_cost: u32 = 3;        // 3 iterations to match Android
    let lanes: u32 = 1;            // 1 lane

    // Step 1: 128-byte hash of app_name
    let app_name_hash = argon2id_hash(app_name.as_bytes(), &app_salt, 128, mem_kib, time_cost, lanes)?;

    // Step 2: 128-byte hash of master_password
    let master_hash = argon2id_hash(master_password.as_bytes(), &mst_salt, 128, mem_kib, time_cost, lanes)?;

    // Step 3: rehash app_name_hash with first 16 bytes of master_hash as salt -> 128 bytes
    let mut combined_salt = [0u8; 32];
    combined_salt[..16].copy_from_slice(&master_hash[..16]);
    let mut out_hash = argon2id_hash(&app_name_hash, &combined_salt, 128, mem_kib, time_cost, lanes)?;

    // Step 4: If app_password present, rehash with first 16 bytes of its 128-byte hash as salt
    if !app_password.is_empty() {
        let pwd_hash = argon2id_hash(app_password.as_bytes(), &pwd_salt, 128, mem_kib, time_cost, lanes)?;
        let mut final_salt = [0u8; 32];
        final_salt[..16].copy_from_slice(&pwd_hash[..16]);
        out_hash = argon2id_hash(&out_hash, &final_salt, 128, mem_kib, time_cost, lanes)?;
    }

    Ok(out_hash)
}

impl TripleCipherKeys {
    #[inline]
    fn derive_from_master(master_key: &[u8; 128]) -> Result<Self, CryptoError> {
        // Updated to derive 336 bytes for keys + CBC IVs (192 + 16 + 128)
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


// CBC mode encryption with chaining state
#[inline(always)]
fn triple_encrypt_chunk_inplace(
    chunk: &mut [u8; CHUNK_SIZE], 
    keys: &TripleCipherKeys,
    threefish_chain: &mut [u8; 128],
    serpent_chain: &mut [u8; 16]
) -> Result<(), CryptoError> {
    // Threefish-1024 CBC encryption (in-place)
    // XOR with previous ciphertext (chain)
    for i in 0..128 {
        chunk[i] ^= threefish_chain[i];
    }
    
    let cipher = Threefish1024::new(&keys.tf_key_128.into());
    let block_ga: &mut GenericArray<u8, U128> = GenericArray::from_mut_slice(chunk);
    cipher.encrypt_block(block_ga);
    
    // Update Threefish chain with new ciphertext
    threefish_chain.copy_from_slice(chunk);
    
    // Serpent CBC encryption - process 8 blocks with chaining
    serpent_encrypt_8blocks_cbc(chunk, &keys.serpent_key, serpent_chain)?;
    
    Ok(())
}


// CBC mode Serpent processing with chaining
#[inline(always)]
fn serpent_encrypt_8blocks_cbc(data: &mut [u8; CHUNK_SIZE], key: &[u8; 32], chain: &mut [u8; 16]) -> Result<(), CryptoError> {
    use serpent::{Serpent, cipher::KeyInit};
    
    let cipher = Serpent::new_from_slice(key)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    for i in 0..8 {
        let block_start = i * 16;
        let block_end = block_start + 16;
        
        // Get current block
        let block_slice = &mut data[block_start..block_end];
        let block_array: &mut [u8; 16] = block_slice.try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        
        // CBC: XOR with previous ciphertext (chain)
        for j in 0..16 {
            block_array[j] ^= chain[j];
        }
        
        // Encrypt block
        serpent_encrypt_inplace(&cipher, block_array);
        
        // Update chain with new ciphertext
        chain.copy_from_slice(block_array);
    }
    Ok(())
}


// CBC mode decryption with chaining state
#[inline(always)]
fn triple_decrypt_chunk_inplace(
    chunk: &mut [u8; CHUNK_SIZE], 
    keys: &TripleCipherKeys,
    threefish_chain: &mut [u8; 128],
    serpent_chain: &mut [u8; 16]
) -> Result<(), CryptoError> {
    // Save current ciphertext for Serpent chain update
    let mut serpent_prev_blocks = [[0u8; 16]; 8];
    for i in 0..8 {
        let block_start = i * 16;
        serpent_prev_blocks[i].copy_from_slice(&chunk[block_start..block_start + 16]);
    }
    
    // Serpent CBC decryption - process 8 blocks with chaining
    serpent_decrypt_8blocks_cbc(chunk, &keys.serpent_key, serpent_chain, &serpent_prev_blocks)?;
    
    // Save current Threefish ciphertext for chain update
    let threefish_prev = *chunk;
    
    // Threefish-1024 decryption (in-place)
    let cipher = Threefish1024::new(&keys.tf_key_128.into());
    let block_ga: &mut GenericArray<u8, U128> = GenericArray::from_mut_slice(chunk);
    cipher.decrypt_block(block_ga);
    
    // CBC: XOR with previous ciphertext (chain)
    for i in 0..128 {
        chunk[i] ^= threefish_chain[i];
    }
    
    // Update Threefish chain with current ciphertext
    threefish_chain.copy_from_slice(&threefish_prev);
    
    Ok(())
}


// CBC mode Serpent decryption with chaining
#[inline(always)]
fn serpent_decrypt_8blocks_cbc(
    data: &mut [u8; CHUNK_SIZE], 
    key: &[u8; 32], 
    chain: &mut [u8; 16],
    prev_blocks: &[[u8; 16]; 8]
) -> Result<(), CryptoError> {
    use serpent::{Serpent, cipher::KeyInit};
    
    let cipher = Serpent::new_from_slice(key)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    for i in 0..8 {
        let block_start = i * 16;
        let block_end = block_start + 16;
        
        // Get current block
        let block_slice = &mut data[block_start..block_end];
        let block_array: &mut [u8; 16] = block_slice.try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        
        // Decrypt block
        serpent_decrypt_inplace(&cipher, block_array);
        
        // CBC: XOR with previous ciphertext (chain)
        for j in 0..16 {
            block_array[j] ^= chain[j];
        }
        
        // Update chain with the previous ciphertext block
        chain.copy_from_slice(&prev_blocks[i]);
    }
    Ok(())
}

//MARK: Ultra-optimized block-by-block triple encryption
#[inline]
pub fn triple_encrypt(master_key: &[u8; 128], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Derive keys once and cache them
    let mut keys = TripleCipherKeys::derive_from_master(master_key)?;
    
    // Calculate padded length with overflow protection
    let padded_len = calculate_padded_length(plaintext.len())?;
    
    // Block-by-block processing for memory efficiency (optimized - minimize allocations)
    let mut processed = Vec::with_capacity(padded_len);
    processed.extend_from_slice(plaintext);
    processed.resize(padded_len, 0); // Pad with zeros
    
    // Initialize CBC chaining state with IVs
    let mut threefish_chain = keys.threefish_iv;
    let mut serpent_chain = keys.serpent_iv;
    
    // Process in-place by chunks with CBC mode
    for chunk in processed.chunks_mut(CHUNK_SIZE) {
        let chunk_array: &mut [u8; CHUNK_SIZE] = chunk.try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        
        // Use CBC mode encryption with chaining state
        triple_encrypt_chunk_inplace(chunk_array, &keys, &mut threefish_chain, &mut serpent_chain)?;
    }
    
    // AES-GCM encryption
    let cipher = Aes256Gcm::new_from_slice(&keys.aes_key).expect("AES-256 key must be exactly 32 bytes");

    let mut iv = [0u8; AES256_IV_SIZE];
    secure_random_bytes(&mut iv)?;
    let nonce = Nonce::from_slice(&iv);
    
    let ciphertext = cipher.encrypt(nonce, processed.as_slice())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    
    // Construct final output: IV + ciphertext + tag
    let mut result = Vec::with_capacity(AES256_IV_SIZE + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);

    // Zeroize sensitive buffers including CBC IVs
    processed.zeroize();
    iv.zeroize();
    keys.aes_key.zeroize();
    keys.serpent_key.zeroize();
    keys.serpent_iv.zeroize();
    keys.threefish_iv.zeroize();
    keys.tf_key_128.zeroize();
    
    Ok(result)
}

//MARK: Ultra-optimized block-by-block triple decryption
#[inline]
pub fn triple_decrypt(master_key: &[u8; 128], input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Input validation
    if input.len() < AES256_IV_SIZE + AES256_TAG_SIZE {
        return Err(CryptoError::InvalidInput);
    }
    
    // Key derivation
    let mut keys = TripleCipherKeys::derive_from_master(master_key)?;
    
    // Extract IV and ciphertext (which includes the TAG)
    let iv = &input[0..AES256_IV_SIZE];
    let ciphertext = &input[AES256_IV_SIZE..];
    
    // AES-GCM decryption
    let cipher = Aes256Gcm::new_from_slice(&keys.aes_key)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    let nonce = Nonce::from_slice(iv);
    
    let mut processed = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    
    // Chunk alignment validation
    if processed.len() % CHUNK_SIZE != 0 {
        return Err(CryptoError::InvalidInput);
    }
    
    // Initialize CBC chaining state with IVs
    let mut threefish_chain = keys.threefish_iv;
    let mut serpent_chain = keys.serpent_iv;
    
    // Block-by-block in-place processing with CBC mode
    for chunk in processed.chunks_mut(CHUNK_SIZE) {
        let chunk_array: &mut [u8; CHUNK_SIZE] = chunk.try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        
        // Use CBC mode decryption with chaining state
        triple_decrypt_chunk_inplace(chunk_array, &keys, &mut threefish_chain, &mut serpent_chain)?;
    }
    
    // Zeroize keys and CBC IVs before returning plaintext
    keys.aes_key.zeroize();
    keys.serpent_key.zeroize();
    keys.tf_key_128.zeroize();
    keys.serpent_iv.zeroize();
    keys.threefish_iv.zeroize();
    
    Ok(processed)
}

// PQRYPT2 streaming file encryption to match Android exactly
pub fn encrypt_file_pqrypt2(
    input_path: &str,
    output_path: &str,
    secret: &[u8],
) -> Result<(), CryptoError> {
    use std::fs::File;
    use std::io::{Read, Write};
    
    // Android Argon2 params for file encryption (8 MiB, not 10 MiB)
    let mem_kib = 8 * 1024; // 8 MiB to match Android exactly
    let time_cost = 1;
    let lanes = 1;

    // Per-file random salt and AES nonce (match Android)
    let mut salt = [0u8; 32];
    secure_random_bytes(&mut salt)?;
    let mut iv = [0u8; AES256_IV_SIZE];
    secure_random_bytes(&mut iv)?;

    // Derive keys using Android's exact parameters
    let mut keys = derive_file_keys_from_secret(secret, &salt, mem_kib, time_cost, lanes)?;

    // Build PQRYPT2 binary header (match Android exactly)
    let header = build_pqrypt2_header(&salt, &iv, mem_kib, time_cost, lanes);

    // Open files
    let mut in_file = File::open(input_path).map_err(|_| CryptoError::InvalidInput)?;
    let mut out_file = File::create(output_path).map_err(|_| CryptoError::InvalidInput)?;
    
    // Write header
    out_file.write_all(&header).map_err(|_| CryptoError::InvalidInput)?;

    // Init GCM state (match Android)
    let (mut ctr, h, ek_j0) = gcm_encryptor_init(&keys.aes_key, &iv);
    let mut ghash = GHash::new(GhashKey::from_slice(&h));
    ghash.update_padded(&header); // header as AAD

    // Streaming encryption
    let mut io_buf = [0u8; 131072]; // 128 KiB buffer
    let mut carry128 = Vec::with_capacity(128);
    let mut total_plain_len: u64 = 0;
    let mut total_ct_len: usize = 0;

    loop {
        let read_len = in_file.read(&mut io_buf).map_err(|_| CryptoError::InvalidInput)?;
        if read_len == 0 { break; } // EOF
        
        total_plain_len = total_plain_len.saturating_add(read_len as u64);

        // Prepare working buffer = carry128 + read bytes
        let mut work_buf = Vec::with_capacity(carry128.len() + read_len);
        work_buf.extend_from_slice(&carry128);
        work_buf.extend_from_slice(&io_buf[..read_len]);
        carry128.clear();

        // Process multiple of 128B, then AES-CTR entire batch
        let process_len = (work_buf.len() / CHUNK_SIZE) * CHUNK_SIZE;
        let (process_slice, remainder) = work_buf.split_at(process_len);

        if process_len > 0 {
            // Triple encrypt in-place per 128B block
            let mut process_vec = process_slice.to_vec();
            let mut threefish_chain = keys.threefish_iv;
            let mut serpent_chain = keys.serpent_iv;
            
            for chunk in process_vec.chunks_mut(CHUNK_SIZE) {
                let chunk_array: &mut [u8; CHUNK_SIZE] = chunk.try_into().map_err(|_| CryptoError::InvalidInput)?;
                triple_encrypt_chunk_inplace(chunk_array, &keys, &mut threefish_chain, &mut serpent_chain)?;
            }

            // AES-CTR encrypt the ENTIRE processed vector
            ctr.apply_keystream(&mut process_vec);

            // Update GHASH with ciphertext
            ghash_update_blocks(&mut ghash, &process_vec);
            
            // Write processed vector
            out_file.write_all(&process_vec).map_err(|_| CryptoError::InvalidInput)?;
            total_ct_len += process_vec.len();
        }

        // Save remainder (<128) for next read
        carry128.clear();
        carry128.extend_from_slice(remainder);
    }

    // Handle final residual: pad to 128B if needed
    if !carry128.is_empty() {
        let mut last_block = [0u8; CHUNK_SIZE];
        last_block[..carry128.len()].copy_from_slice(&carry128);
        
        // Triple encrypt
        let mut threefish_chain = keys.threefish_iv;
        let mut serpent_chain = keys.serpent_iv;
        triple_encrypt_chunk_inplace(&mut last_block, &keys, &mut threefish_chain, &mut serpent_chain)?;
        
        // AES-CTR
        let mut last_vec = last_block.to_vec();
        ctr.apply_keystream(&mut last_vec);
        
        // GHASH and write
        ghash_update_blocks(&mut ghash, &last_vec);
        out_file.write_all(&last_vec).map_err(|_| CryptoError::InvalidInput)?;
        total_ct_len += last_vec.len();
    }

    // Trailer: original plaintext length (u64 LE)
    let trailer = total_plain_len.to_le_bytes();
    ghash.update_padded(&trailer);
    out_file.write_all(&trailer).map_err(|_| CryptoError::InvalidInput)?;

    // Finalize GHASH with lengths and compute tag
    let aad_len = header.len() + trailer.len();
    ghash_append_lengths(&mut ghash, aad_len, total_ct_len);
    let s_tag_ga = ghash.clone().finalize();
    let s_tag_slice: &[u8] = s_tag_ga.as_slice();
    let mut tag = [0u8; 16];
    for i in 0..16 { tag[i] = ek_j0[i] ^ s_tag_slice[i]; }

    // Write authentication tag
    out_file.write_all(&tag).map_err(|_| CryptoError::InvalidInput)?;

    // Zeroize sensitive material
    keys.aes_key.zeroize();
    keys.serpent_key.zeroize();
    keys.tf_key_128.zeroize();
    keys.serpent_iv.zeroize();
    keys.threefish_iv.zeroize();

    Ok(())
}

// PQRYPT2 streaming file decryption to match Android exactly
pub fn decrypt_file_pqrypt2(
    input_path: &str,
    output_path: &str,
    secret: &[u8],
) -> Result<(), CryptoError> {
    use std::fs::File;
    use std::io::{Read, Write};
    
    let mut in_file = File::open(input_path).map_err(|_| CryptoError::InvalidInput)?;
    let mut out_file = File::create(output_path).map_err(|_| CryptoError::InvalidInput)?;
    
    // Read and parse PQRYPT2 binary header
    let mut header = vec![0u8; 74]; // PQRYPT2 header is 74 bytes
    in_file.read_exact(&mut header).map_err(|_| CryptoError::InvalidInput)?;
    
    if &header[0..8] != b"PQRYPT2\0" { return Err(CryptoError::InvalidInput); }
    if header[8] != 1 { return Err(CryptoError::InvalidInput); } // version
    let flags = header[9];
    if (flags & 0x01) == 0 { return Err(CryptoError::InvalidInput); } // FLAG_SINGLE_TAG
    if (flags & 0x02) == 0 { return Err(CryptoError::InvalidInput); } // FLAG_TRAILER_LEN
    
    let mem_kib = u32::from_le_bytes(header[10..14].try_into().unwrap());
    let time_cost = u32::from_le_bytes(header[14..18].try_into().unwrap());
    let lanes = u32::from_le_bytes(header[18..22].try_into().unwrap());
    let mut salt = [0u8; 32]; salt.copy_from_slice(&header[22..54]);
    let mut iv = [0u8; AES256_IV_SIZE]; iv.copy_from_slice(&header[54..66]);

    // Derive keys
    let mut keys = derive_file_keys_from_secret(secret, &salt, mem_kib, time_cost, lanes)?;

    // Init GCM state
    let (mut ctr, h, ek_j0) = gcm_encryptor_init(&keys.aes_key, &iv);
    let mut ghash = GHash::new(GhashKey::from_slice(&h));
    ghash.update_padded(&header);

    // Streaming decrypt while reserving last 24 bytes (trailer 8 + tag 16)
    let mut io_buf = [0u8; 131072]; // 128 KiB buffer
    let mut all_ciphertext = Vec::new();
    
    // Read all remaining data
    loop {
        let read_len = in_file.read(&mut io_buf).map_err(|_| CryptoError::InvalidInput)?;
        if read_len == 0 { break; }
        all_ciphertext.extend_from_slice(&io_buf[..read_len]);
    }
    
    if all_ciphertext.len() < 24 { return Err(CryptoError::InvalidInput); }
    
    // Split ciphertext, trailer, and tag
    let ct_len = all_ciphertext.len() - 24;
    let (ciphertext, trailer_and_tag) = all_ciphertext.split_at(ct_len);
    let (trailer, tag_bytes) = trailer_and_tag.split_at(8);
    let mut tag_in_arr = [0u8; 16];
    tag_in_arr.copy_from_slice(tag_bytes);

    // Process ciphertext in chunks
    let mut all_plaintext = Vec::with_capacity(ciphertext.len());
    let mut threefish_chain = keys.threefish_iv;
    let mut serpent_chain = keys.serpent_iv;
    
    // GHASH all ciphertext
    ghash_update_blocks(&mut ghash, ciphertext);
    
    let mut ct_copy = ciphertext.to_vec();
    
    // Process complete 128-byte chunks
    let complete_chunks = ct_copy.len() / CHUNK_SIZE;
    for i in 0..complete_chunks {
        let chunk_start = i * CHUNK_SIZE;
        let chunk_end = chunk_start + CHUNK_SIZE;
        let chunk_slice = &mut ct_copy[chunk_start..chunk_end];
        let chunk_array: &mut [u8; CHUNK_SIZE] = chunk_slice.try_into().map_err(|_| CryptoError::InvalidInput)?;
        
        // CTR decrypt
        ctr.apply_keystream(chunk_array);
        // Reverse triple
        triple_decrypt_chunk_inplace(chunk_array, &keys, &mut threefish_chain, &mut serpent_chain)?;
        
        all_plaintext.extend_from_slice(chunk_array);
    }
    
    // Handle remaining bytes (less than 128)
    let remaining_start = complete_chunks * CHUNK_SIZE;
    if remaining_start < ct_copy.len() {
        let mut last_block = [0u8; CHUNK_SIZE];
        let remaining_len = ct_copy.len() - remaining_start;
        last_block[..remaining_len].copy_from_slice(&ct_copy[remaining_start..]);
        
        // CTR decrypt
        ctr.apply_keystream(&mut last_block);
        // Reverse triple
        triple_decrypt_chunk_inplace(&mut last_block, &keys, &mut threefish_chain, &mut serpent_chain)?;
        
        all_plaintext.extend_from_slice(&last_block[..remaining_len]);
    }

    // Include trailer as AAD in GHASH and finalize
    ghash.update_padded(trailer);
    let aad_len = header.len() + trailer.len();
    ghash_append_lengths(&mut ghash, aad_len, ciphertext.len());
    let s_tag_ga = ghash.clone().finalize();
    let s_tag_slice: &[u8] = s_tag_ga.as_slice();
    let mut tag = [0u8; 16];
    for i in 0..16 { tag[i] = ek_j0[i] ^ s_tag_slice[i]; }

    // Verify tag (constant time)
    use subtle::ConstantTimeEq;
    if tag.ct_eq(&tag_in_arr).unwrap_u8() == 0 {
        return Err(CryptoError::AuthenticationFailed);
    }

    // Trim plaintext to original length and write
    let orig_len = u64::from_le_bytes(trailer.try_into().unwrap()) as usize;
    let final_plaintext = if orig_len <= all_plaintext.len() {
        &all_plaintext[..orig_len]
    } else {
        &all_plaintext
    };
    
    out_file.write_all(final_plaintext).map_err(|_| CryptoError::InvalidInput)?;

    // Zeroize sensitive material
    keys.aes_key.zeroize();
    keys.serpent_key.zeroize();
    keys.tf_key_128.zeroize();
    keys.serpent_iv.zeroize();
    keys.threefish_iv.zeroize();

    Ok(())
}

// Password generation matching the Android implementation exactly
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

// Secure password hash derivation function
pub fn derive_password_hash_secure(
    _app_name: &str,
    app_password: &str,
    master_password: &str,
    salt_source: &str
) -> Result<Vec<u8>, CryptoError> {
    // Create salt from app_name
    let salt_bytes = salt_source.as_bytes();
    let mut salt = [0u8; 32];
    let copy_len = salt_bytes.len().min(32);
    salt[..copy_len].copy_from_slice(&salt_bytes[..copy_len]);
    
    // First hash: master_password with app_name as salt
    let first_hash = argon2id_hash(master_password.as_bytes(), &salt, 64, 10240, 1, 1)?;
    
    // If app_password exists, hash again with app_password as salt
    if !app_password.is_empty() {
        let app_salt_bytes = app_password.as_bytes();
        let mut app_salt = [0u8; 32];
        let app_copy_len = app_salt_bytes.len().min(32);
        app_salt[..app_copy_len].copy_from_slice(&app_salt_bytes[..app_copy_len]);
        
        argon2id_hash(&first_hash, &app_salt, 64, 10240, 1, 1)
    } else {
        Ok(first_hash)
    }
}

// Secure password generation function
pub fn generate_password_secure(
    mode: u8,
    hash_bytes: &[u8],
    desired_len: usize,
    enabled_symbol_sets: &[bool; 3],
    _user_id: &str
) -> Result<String, CryptoError> {
    generate_password(mode, hash_bytes, desired_len, enabled_symbol_sets)
        .ok_or(CryptoError::KeyGenerationFailed)
}

// Android-compatible Argon2id hashing (matches JNI c_ffi argon2_hash_c)
// - memory = 16MB, iterations = 3, lanes = 1 - MATCH ANDROID EXACTLY
// - variable output length as requested
// - salt uses ONLY the first 16 bytes (remaining ignored), zeros if empty
pub fn argon2_hash_mobile_compat(
    password: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if output_len == 0 || output_len > 1024 { return Err(CryptoError::InvalidParameters); }

    // Prepare 32-byte salt from provided bytes (pad/truncate)
    let mut salt_buf = [0u8; 32];
    let copy_len = salt.len().min(32);
    salt_buf[..copy_len].copy_from_slice(&salt[..copy_len]);
    let salt16 = &salt_buf[..16];  // Use first 16 bytes for Argon2

    // MATCH ANDROID: 16MB memory, 3 iterations, 1 thread, caller-specified output length
    let params = Params::new(16384, 3, 1, Some(output_len)).map_err(|_| CryptoError::InvalidParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt16, &mut out)
        .map_err(|_| CryptoError::HashingFailed)?;
    Ok(out)
}

// Android-compatible multi-step password derivation to match PasswordVaultActivity
// Steps replicate Kotlin flow using argon2Hash() JNI with the same parameters
pub fn derive_password_hash_android_compat(
    app_name: &str,
    app_password: &str,
    master_password: &str,
) -> Result<Vec<u8>, CryptoError> {
    // Step 1: Hash app name with salt "app" (32 bytes, ascii 'a','p','p') -> 128 bytes
    let mut app_salt = [0u8; 32];
    app_salt[0] = b'a'; app_salt[1] = b'p'; app_salt[2] = b'p';
    let app_name_hash = argon2_hash_mobile_compat(app_name.as_bytes(), &app_salt, 128)?;

    // Step 2: Hash master password with salt "mst" -> 128 bytes
    let mut master_salt = [0u8; 32];
    master_salt[0] = b'm'; master_salt[1] = b's'; master_salt[2] = b't';
    let master_hash = argon2_hash_mobile_compat(master_password.as_bytes(), &master_salt, 128)?;

    // Step 3: Hash(app_name_hash) with salt = first 16 bytes of master_hash -> 128 bytes
    let mut combined_salt = [0u8; 32];
    combined_salt[..16].copy_from_slice(&master_hash[..16]);
    let mut out_hash = argon2_hash_mobile_compat(&app_name_hash, &combined_salt, 128)?;

    // Step 4: If app_password present, rehash with app_password salt "pwd"
    if !app_password.is_empty() {
        let mut pwd_salt = [0u8; 32];
        pwd_salt[0] = b'p'; pwd_salt[1] = b'w'; pwd_salt[2] = b'd';
        let pwd_hash = argon2_hash_mobile_compat(app_password.as_bytes(), &pwd_salt, 128)?;
        let mut final_salt = [0u8; 32];
        final_salt[..16].copy_from_slice(&pwd_hash[..16]);
        out_hash = argon2_hash_mobile_compat(&out_hash, &final_salt, 128)?;
    }

    Ok(out_hash)
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

// Build PQRYPT2 binary header to match Android exactly
#[inline]
fn build_pqrypt2_header(
    salt: &[u8; 32],
    nonce: &[u8; AES256_IV_SIZE],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(74);
    header.extend_from_slice(b"PQRYPT2\0");  // 8 bytes magic
    header.push(1);                           // 1 byte version
    header.push(0x01 | 0x02);                // 1 byte flags (SINGLE_TAG | TRAILER_LEN)
    header.extend_from_slice(&mem_kib.to_le_bytes());   // 4 bytes
    header.extend_from_slice(&time_cost.to_le_bytes()); // 4 bytes
    header.extend_from_slice(&lanes.to_le_bytes());     // 4 bytes
    header.extend_from_slice(salt);                     // 32 bytes
    header.extend_from_slice(nonce);                    // 12 bytes
    header.extend_from_slice(&[0u8; 8]);               // 8 bytes reserved
    header
}

// Derive file encryption keys from secret using Android's exact parameters
#[inline]
fn derive_file_keys_from_secret(
    secret: &[u8],
    salt: &[u8; 32],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Result<TripleCipherKeys, CryptoError> {
    // Derive 336 bytes for keys + CBC IVs (match Android exactly)
    let mut derived = argon2id_hash(secret, salt, 336, mem_kib, time_cost, lanes)?;
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

// GCM encryptor initialization (match Android)
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

// Compute AES-GCM subkey H
#[inline]
fn aes_gcm_subkey_h(aes_key: &[u8; 32]) -> [u8; 16] {
    // H = E(K, 0^128)
    let cipher = Aes256::new(Ga::from_slice(aes_key));
    let mut block = [0u8; 16];
    let mut ga = Ga::from_mut_slice(&mut block);
    cipher.encrypt_block(&mut ga);
    block
}

// GHASH block update
#[inline]
fn ghash_update_blocks(gh: &mut GHash, buf: &[u8]) {
    for chunk in buf.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        let ga = GhashBlock::from_slice(&block);
        gh.update(&[*ga]);
    }
}

// GHASH length finalization
#[inline]
fn ghash_append_lengths(gh: &mut GHash, aad_len: usize, ct_len: usize) {
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad_len * 8) as u64).to_be_bytes());
    len_block[8..16].copy_from_slice(&((ct_len * 8) as u64).to_be_bytes());
    let ga = GhashBlock::from_slice(&len_block);
    gh.update(&[*ga]);
}
