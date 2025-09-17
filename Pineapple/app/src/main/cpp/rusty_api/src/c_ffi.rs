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

// Argon2 password hashing - true variable-length output
#[no_mangle]
pub extern "C" fn argon2_hash_c(
    password: *const c_uchar,
    password_len: usize,
    salt: *const c_uchar,
    salt_len: usize,
    output: *mut c_uchar,
    output_len: usize,
) -> c_int {
    if password.is_null() || output.is_null() || output_len == 0 {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let password_slice = unsafe { slice::from_raw_parts(password, password_len) };
    let mut salt_array = [0u8; 32];
    if !salt.is_null() && salt_len > 0 {
        let salt_slice = unsafe { slice::from_raw_parts(salt, salt_len.min(32)) };
        salt_array[..salt_slice.len()].copy_from_slice(salt_slice);
    }

    use argon2::{Argon2, Algorithm, Version, Params};

    // 10MB memory, 2 iterations, 1 thread, caller-specified output length
    let params = match Params::new(10240, 2, 1, Some(output_len)) {
        Ok(p) => p,
        Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Use first 16 bytes of salt for compatibility across platforms
    let salt16 = &salt_array[..16];
    let mut out_vec = vec![0u8; output_len];
    if argon2.hash_password_into(password_slice, salt16, &mut out_vec).is_err() {
        return CRYPTO_ERROR_HASHING_FAILED;
    }

    unsafe { ptr::copy_nonoverlapping(out_vec.as_ptr(), output, output_len); }
    CRYPTO_SUCCESS
}

// Unified 128-byte password derivation (all steps Argon2id -> 128 bytes)
#[no_mangle]
pub extern "C" fn derive_password_hash_unified_128_c(
    app_name: *const c_uchar,
    app_name_len: usize,
    app_password: *const c_uchar,
    app_password_len: usize,
    master_password: *const c_uchar,
    master_password_len: usize,
    out: *mut c_uchar,
    out_len: usize,
) -> c_int {
    if app_name.is_null() || master_password.is_null() || out.is_null() || out_len < 128 {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let app_name_slice = unsafe { slice::from_raw_parts(app_name, app_name_len) };
    let app_password_slice = if !app_password.is_null() && app_password_len > 0 {
        unsafe { slice::from_raw_parts(app_password, app_password_len) }
    } else { &[][..] };
    let master_password_slice = unsafe { slice::from_raw_parts(master_password, master_password_len) };

    // salts "app", "mst", "pwd"
    let mut app_salt = [0u8; 32]; app_salt[0]=b'a'; app_salt[1]=b'p'; app_salt[2]=b'p';
    let mut mst_salt = [0u8; 32]; mst_salt[0]=b'm'; mst_salt[1]=b's'; mst_salt[2]=b't';
    let mut pwd_salt = [0u8; 32]; pwd_salt[0]=b'p'; pwd_salt[1]=b'w'; pwd_salt[2]=b'd';

    // Step 1: app name hash (128 bytes)
    let app_name_hash = match argon2id_hash(app_name_slice, &app_salt, 128, 10240, 2, 1) {
        Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };

    // Step 2: master password hash (128 bytes)
    let master_hash = match argon2id_hash(master_password_slice, &mst_salt, 128, 10240, 2, 1) {
        Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };

    // Step 3: rehash app_name_hash with first 16 bytes of master_hash as salt -> 128 bytes
    let mut combined_salt = [0u8; 32];
    combined_salt[..16].copy_from_slice(&master_hash[..16]);
    let mut final_hash = match argon2id_hash(&app_name_hash, &combined_salt, 128, 10240, 2, 1) {
        Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };

    // Step 4: optional app password rehash with first 16 bytes of its hash as salt -> 128 bytes
    if !app_password_slice.is_empty() {
        let pwd_hash = match argon2id_hash(app_password_slice, &pwd_salt, 128, 10240, 2, 1) {
            Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
        };
        let mut final_salt = [0u8; 32];
        final_salt[..16].copy_from_slice(&pwd_hash[..16]);
        final_hash = match argon2id_hash(&final_hash, &final_salt, 128, 10240, 2, 1) {
            Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
        };
    }

    unsafe { ptr::copy_nonoverlapping(final_hash.as_ptr(), out, 128); }
    CRYPTO_SUCCESS
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
