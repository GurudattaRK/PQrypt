use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uchar};
use std::slice;
use std::ptr;
use libc::size_t;
use crate::rusty_api::constants_errors::{CRYPTO_SUCCESS, CRYPTO_ERROR_NULL_POINTER, CRYPTO_ERROR_HASHING_FAILED, CRYPTO_ERROR_ENCRYPTION_FAILED, CRYPTO_ERROR_DECRYPTION_FAILED, CRYPTO_ERROR_KEY_GENERATION_FAILED, CRYPTO_ERROR_INVALID_INPUT};
use crate::rusty_api::symmetric::argon2id_hash;
use crate::rusty_api::api::{triple_encrypt, triple_decrypt, generate_password};
use crate::rusty_api::asymmetric::{crypto_kyber1024_keypair, crypto_x448_keypair};
use crate::rusty_api::hybrid::{pqc_4hybrid_init, pqc_4hybrid_recv, pqc_4hybrid_snd_final, pqc_4hybrid_recv_final, HybridSenderState, HybridReceiverState};

// Argon2 password hashing
#[no_mangle]
pub extern "C" fn argon2_hash_c(
    password: *const c_uchar,
    password_len: usize,
    salt: *const c_uchar,
    salt_len: usize,
    output: *mut c_uchar,
    output_len: usize,
) -> c_int {
    if password.is_null() || output.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let password_slice = unsafe { slice::from_raw_parts(password, password_len) };
    let mut salt_array = [0u8; 32];
    if !salt.is_null() && salt_len > 0 {
        let salt_slice = unsafe { slice::from_raw_parts(salt, salt_len.min(32)) };
        salt_array[..salt_slice.len()].copy_from_slice(salt_slice);
    }

    // Use Argon2 parameters per app policy
    // 10MB memory, 2 iterations, 1 thread
    // Always use 32-byte output from Argon2, then extend if needed
    use argon2::{Argon2, Algorithm, Version, Params, PasswordHasher};
    use argon2::password_hash::SaltString;
    
    let params = Params::new(10240, 2, 1, Some(32)).unwrap(); // Fixed 32-byte output
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    // SaltString expects exactly 16 bytes, so take first 16 bytes of salt_array
    let salt_16 = &salt_array[..16];
    let salt_string = match SaltString::encode_b64(salt_16) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };
    
    match argon2.hash_password(password_slice, &salt_string) {
        Ok(password_hash) => {
            if let Some(hash_bytes) = password_hash.hash {
                let hash_slice = hash_bytes.as_bytes();
                
                // Ensure we have valid hash data and output buffer
                if output_len == 0 || hash_slice.is_empty() {
                    return CRYPTO_ERROR_HASHING_FAILED;
                }
                
                // Argon2 gives us exactly 32 bytes, extend safely if more needed
                unsafe {
                    if output_len <= 32 {
                        // Simple case: just copy what we need
                        ptr::copy_nonoverlapping(hash_slice.as_ptr(), output, output_len);
                    } else {
                        // Copy the full 32 bytes first
                        ptr::copy_nonoverlapping(hash_slice.as_ptr(), output, 32);
                        
                        // Extend by cycling through the 32-byte hash for remaining bytes
                        for i in 32..output_len {
                            *output.add(i) = hash_slice[i % 32];
                        }
                    }
                }
                CRYPTO_SUCCESS
            } else {
                CRYPTO_ERROR_HASHING_FAILED
            }
        },
        Err(_) => CRYPTO_ERROR_HASHING_FAILED,
    }
}

// Triple encryption (AES + Serpent + ChaCha20)
#[no_mangle]
pub extern "C" fn triple_encrypt_c(
    key: *const c_uchar,
    plaintext: *const c_uchar,
    plaintext_len: usize,
    output: *mut c_uchar,
    output_len: *mut usize,
) -> c_int {
    eprintln!("DEBUG: triple_encrypt_c called with plaintext_len: {}", plaintext_len);
    
    if key.is_null() || plaintext.is_null() || output.is_null() || output_len.is_null() {
        eprintln!("DEBUG: Null pointer detected in encrypt");
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let key_slice = unsafe { slice::from_raw_parts(key, 128) };
    let key_array: [u8; 128] = key_slice.try_into().map_err(|_| CRYPTO_ERROR_INVALID_INPUT).ok().unwrap_or([0u8; 128]);
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };

    eprintln!("DEBUG: About to call triple_encrypt");
    match triple_encrypt(&key_array, plaintext_slice) {
        Ok(ciphertext) => {
            eprintln!("DEBUG: triple_encrypt succeeded, ciphertext len: {}", ciphertext.len());
            unsafe {
                *output_len = ciphertext.len();
                ptr::copy_nonoverlapping(ciphertext.as_ptr(), output, ciphertext.len());
            }
            CRYPTO_SUCCESS
        }
        Err(e) => {
            eprintln!("DEBUG: triple_encrypt failed with error: {:?}", e);
            CRYPTO_ERROR_ENCRYPTION_FAILED
        },
    }
}

// Test function to verify roundtrip
#[no_mangle]
pub extern "C" fn test_encrypt_decrypt_roundtrip() -> c_int {
    // Create a test master key
    let mut master_key = [0u8; 128];
    for i in 0..128 {
        master_key[i] = (i as u8) ^ 0x55;
    }
    
    // Test data
    let plaintext = b"Hello, World! This is a test message.";
    
    // Encrypt
    match triple_encrypt(&master_key, plaintext) {
        Ok(ciphertext) => {
            // Decrypt
            match triple_decrypt(&master_key, &ciphertext) {
                Ok(decrypted) => {
                    // Compare (accounting for padding)
                    if &decrypted[..plaintext.len()] == plaintext {
                        return CRYPTO_SUCCESS; // Test passed
                    } else {
                        return -99; // Data mismatch
                    }
                }
                Err(_) => return -98, // Decryption failed
            }
        }
        Err(_) => return -97, // Encryption failed
    }
}

// Triple decryption - simplified version without debug prints
#[no_mangle]
pub extern "C" fn triple_decrypt_c(
    key: *const c_uchar,
    ciphertext: *const c_uchar,
    ciphertext_len: usize,
    output: *mut c_uchar,
    output_len: *mut usize,
) -> c_int {
    // Check null pointers first
    if key.is_null() || ciphertext.is_null() || output.is_null() || output_len.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Create slices from pointers
    let key_slice = unsafe { slice::from_raw_parts(key, 128) };
    let key_array: [u8; 128] = match key_slice.try_into() {
        Ok(arr) => arr,
        Err(_) => return CRYPTO_ERROR_INVALID_INPUT,
    };
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };

    // Call the actual decryption function
    match triple_decrypt(&key_array, ciphertext_slice) {
        Ok(plaintext) => {
            unsafe {
                *output_len = plaintext.len();
                ptr::copy_nonoverlapping(plaintext.as_ptr(), output, plaintext.len());
            }
            CRYPTO_SUCCESS
        }
        Err(e) => {
            // Return the specific debug code if available
            match e {
                crate::rusty_api::constants_errors::CryptoError::DebugCode(code) => code,
                _ => CRYPTO_ERROR_DECRYPTION_FAILED,
            }
        }
    }
}

// Password generation
#[no_mangle]
pub extern "C" fn generate_password_c(
    mode: c_uchar,
    hash_bytes: *const c_uchar,
    hash_len: size_t,
    desired_len: size_t,
    enabled_symbol_sets: *const c_uchar,
    output: *mut c_char,
    output_len: *mut size_t,
) -> c_int {
    if hash_bytes.is_null() || enabled_symbol_sets.is_null() || 
       output.is_null() || output_len.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let hash_slice = unsafe { slice::from_raw_parts(hash_bytes, hash_len) };
    let enabled_slice = unsafe { slice::from_raw_parts(enabled_symbol_sets, 3) };
    
    let enabled_bool = [
        enabled_slice[0] != 0,
        enabled_slice[1] != 0,
        enabled_slice[2] != 0,
    ];

    match generate_password(mode, hash_slice, desired_len, &enabled_bool) {
        Some(password) => {
            let password_cstr = match CString::new(password) {
                Ok(s) => s,
                Err(_) => return CRYPTO_ERROR_INVALID_INPUT,
            };
            let password_bytes = password_cstr.as_bytes_with_nul();
            
            unsafe {
                *output_len = password_bytes.len() - 1; // Exclude null terminator from length
                ptr::copy_nonoverlapping(password_bytes.as_ptr() as *const c_char, output, password_bytes.len());
            }
            CRYPTO_SUCCESS
        }
        None => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

// Basic Kyber keypair generation
#[no_mangle]
pub extern "C" fn kyber_keypair_c(
    public_key: *mut c_uchar,
    secret_key: *mut c_uchar,
) -> c_int {
    if public_key.is_null() || secret_key.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    match crypto_kyber1024_keypair() {
        Ok((pk, sk)) => {
            unsafe {
                ptr::copy_nonoverlapping(pk.as_ptr(), public_key, pk.len().min(1568));
                ptr::copy_nonoverlapping(sk.as_ptr(), secret_key, sk.len().min(3168));
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

// Basic X448 keypair generation
#[no_mangle]
pub extern "C" fn x448_keypair_c(
    public_key: *mut c_uchar,
    private_key: *mut c_uchar,
) -> c_int {
    if public_key.is_null() || private_key.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    match crypto_x448_keypair() {
        Ok((pk, sk)) => {
            unsafe {
                ptr::copy_nonoverlapping(pk.as_ptr(), public_key, pk.len().min(56));
                ptr::copy_nonoverlapping(sk.as_ptr(), private_key, sk.len().min(56));
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

// PQC 4-Algorithm Hybrid Key Exchange Functions

// Initialize 4-hybrid key exchange (ML-KEM+X448 and HQC+P521)
#[no_mangle]
pub extern "C" fn pqc_4hybrid_init_c(
    hybrid_1_key: *mut c_uchar,
    hybrid_1_key_len: *mut usize,
    sender_state: *mut c_uchar,
    sender_state_len: *mut usize,
) -> c_int {
    if hybrid_1_key.is_null() || hybrid_1_key_len.is_null() || sender_state.is_null() || sender_state_len.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    match pqc_4hybrid_init() {
        Ok((h1_key, s_state)) => {
            unsafe {
                // Copy hybrid_1_key
                *hybrid_1_key_len = h1_key.len();
                ptr::copy_nonoverlapping(h1_key.as_ptr(), hybrid_1_key, h1_key.len());
                
                // Serialize sender state (simplified - in production use proper serialization)
                let state_bytes = bincode::serialize(&s_state).unwrap_or_default();
                *sender_state_len = state_bytes.len();
                ptr::copy_nonoverlapping(state_bytes.as_ptr(), sender_state, state_bytes.len());
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

// Receiver response for 4-hybrid key exchange
#[no_mangle]
pub extern "C" fn pqc_4hybrid_recv_c(
    hybrid_1_key: *const c_uchar,
    hybrid_1_key_len: usize,
    hybrid_2_key: *mut c_uchar,
    hybrid_2_key_len: *mut usize,
    receiver_state: *mut c_uchar,
    receiver_state_len: *mut usize,
) -> c_int {
    if hybrid_1_key.is_null() || hybrid_2_key.is_null() || hybrid_2_key_len.is_null() || 
       receiver_state.is_null() || receiver_state_len.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let h1_key_slice = unsafe { slice::from_raw_parts(hybrid_1_key, hybrid_1_key_len) };

    match pqc_4hybrid_recv(h1_key_slice) {
        Ok((h2_key, r_state)) => {
            unsafe {
                // Copy hybrid_2_key
                *hybrid_2_key_len = h2_key.len();
                ptr::copy_nonoverlapping(h2_key.as_ptr(), hybrid_2_key, h2_key.len());
                
                // Serialize receiver state
                let state_bytes = bincode::serialize(&r_state).unwrap_or_default();
                *receiver_state_len = state_bytes.len();
                ptr::copy_nonoverlapping(state_bytes.as_ptr(), receiver_state, state_bytes.len());
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

// Sender final step for 4-hybrid key exchange
#[no_mangle]
pub extern "C" fn pqc_4hybrid_snd_final_c(
    hybrid_2_key: *const c_uchar,
    hybrid_2_key_len: usize,
    sender_state: *const c_uchar,
    sender_state_len: usize,
    final_key: *mut c_uchar,
    hybrid_3_key: *mut c_uchar,
    hybrid_3_key_len: *mut usize,
) -> c_int {
    if hybrid_2_key.is_null() || sender_state.is_null() || final_key.is_null() || 
       hybrid_3_key.is_null() || hybrid_3_key_len.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let h2_key_slice = unsafe { slice::from_raw_parts(hybrid_2_key, hybrid_2_key_len) };
    let state_slice = unsafe { slice::from_raw_parts(sender_state, sender_state_len) };
    
    // Deserialize sender state
    let s_state: HybridSenderState = match bincode::deserialize(state_slice) {
        Ok(state) => state,
        Err(_) => return CRYPTO_ERROR_INVALID_INPUT,
    };

    match pqc_4hybrid_snd_final(h2_key_slice, &s_state) {
        Ok((f_key, h3_key)) => {
            unsafe {
                // Copy final key (128 bytes)
                ptr::copy_nonoverlapping(f_key.as_ptr(), final_key, 128);
                
                // Copy hybrid_3_key
                *hybrid_3_key_len = h3_key.len();
                ptr::copy_nonoverlapping(h3_key.as_ptr(), hybrid_3_key, h3_key.len());
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

// Receiver final step for 4-hybrid key exchange
#[no_mangle]
pub extern "C" fn pqc_4hybrid_recv_final_c(
    hybrid_3_key: *const c_uchar,
    hybrid_3_key_len: usize,
    receiver_state: *const c_uchar,
    receiver_state_len: usize,
    final_key: *mut c_uchar,
) -> c_int {
    if hybrid_3_key.is_null() || receiver_state.is_null() || final_key.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let h3_key_slice = unsafe { slice::from_raw_parts(hybrid_3_key, hybrid_3_key_len) };
    let state_slice = unsafe { slice::from_raw_parts(receiver_state, receiver_state_len) };
    
    // Deserialize receiver state
    let r_state: HybridReceiverState = match bincode::deserialize(state_slice) {
        Ok(state) => state,
        Err(_) => return CRYPTO_ERROR_INVALID_INPUT,
    };

    match pqc_4hybrid_recv_final(h3_key_slice, &r_state) {
        Ok(f_key) => {
            unsafe {
                // Copy final key (128 bytes)
                ptr::copy_nonoverlapping(f_key.as_ptr(), final_key, 128);
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}
