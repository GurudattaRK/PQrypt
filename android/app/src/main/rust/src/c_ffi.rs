use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr;
use std::slice;
use std::ffi::CString;
use libc::size_t;
use crate::rusty_api::api::{*, triple_decrypt_fd_raw};
use crate::rusty_api::constants_errors::*;
use crate::rusty_api::symmetric::argon2id_hash;
use crate::rusty_api::hybrid::{pqc_4hybrid_init, pqc_4hybrid_recv, pqc_4hybrid_snd_final, pqc_4hybrid_recv_final, HybridSenderState, HybridReceiverState};

// MARK: generate_password_from_hash_c
#[no_mangle]
pub extern "C" fn generate_password_from_hash_c(
    hash_128: *const c_uchar,
    hash_len: usize,
    desired_len: usize,
    enabled_sets_mask: u32,
    output: *mut c_char,
    output_len: *mut size_t,
) -> c_int {
    if hash_128.is_null() || output.is_null() || output_len.is_null() || hash_len != 128 {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let hash_slice = unsafe { slice::from_raw_parts(hash_128, 128) };

    let enabled_bool = [
        (enabled_sets_mask & 0b001) != 0,
        (enabled_sets_mask & 0b010) != 0,
        (enabled_sets_mask & 0b100) != 0,
    ];
    let password = match generate_password(1, hash_slice, desired_len, &enabled_bool) {
        Some(p) => p,
        None => return CRYPTO_ERROR_KEY_GENERATION_FAILED,
    };

    let password_cstr = match CString::new(password) {
        Ok(s) => s,
        Err(_) => return CRYPTO_ERROR_INVALID_INPUT,
    };
    let bytes = password_cstr.as_bytes_with_nul();
    unsafe {
        *output_len = (bytes.len() - 1) as size_t;
        ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, output, bytes.len());
    }
    CRYPTO_SUCCESS
}

// MARK: triple_encrypt_fd_c
#[no_mangle]
pub extern "C" fn triple_encrypt_fd_c(
    secret: *const c_uchar,
    secret_len: std::os::raw::c_ulong,
    is_keyfile: c_int,
    in_fd: c_int,
    out_fd: c_int,
) -> c_int {
    if secret.is_null() || secret_len == 0 || secret_len > 4096 || in_fd < 0 || out_fd < 0 {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    let secret_slice = unsafe { slice::from_raw_parts(secret, secret_len as usize) };
    
    match triple_encrypt_fd_raw(secret_slice, is_keyfile != 0, in_fd, out_fd) {
        Ok(_) => CRYPTO_SUCCESS,
        Err(e) => match e {
            crate::rusty_api::constants_errors::CryptoError::InvalidInput => CRYPTO_ERROR_INVALID_INPUT,
            crate::rusty_api::constants_errors::CryptoError::HashingFailed | crate::rusty_api::constants_errors::CryptoError::KeyDerivationFailed => CRYPTO_ERROR_HASHING_FAILED,
            crate::rusty_api::constants_errors::CryptoError::EncryptionFailed => CRYPTO_ERROR_ENCRYPTION_FAILED,
            crate::rusty_api::constants_errors::CryptoError::AuthenticationFailed => CRYPTO_ERROR_DECRYPTION_FAILED,
            _ => CRYPTO_ERROR_IO,
        }
    }
}

// MARK: triple_decrypt_fd_c
#[no_mangle]
pub extern "C" fn triple_decrypt_fd_c(
    secret: *const c_uchar,
    secret_len: std::os::raw::c_ulong,
    is_keyfile: c_int,
    in_fd: c_int,
    out_fd: c_int,
) -> c_int {
    if secret.is_null() || secret_len == 0 || secret_len > 4096 || in_fd < 0 || out_fd < 0 {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    let secret_slice = unsafe { slice::from_raw_parts(secret, secret_len as usize) };
    
    match triple_decrypt_fd_raw(secret_slice, is_keyfile != 0, in_fd, out_fd) {
        Ok(_) => CRYPTO_SUCCESS,
        Err(e) => match e {
            crate::rusty_api::constants_errors::CryptoError::InvalidInput => CRYPTO_ERROR_INVALID_INPUT,
            crate::rusty_api::constants_errors::CryptoError::HashingFailed | crate::rusty_api::constants_errors::CryptoError::KeyDerivationFailed => CRYPTO_ERROR_HASHING_FAILED,
            crate::rusty_api::constants_errors::CryptoError::EncryptionFailed => CRYPTO_ERROR_ENCRYPTION_FAILED,
            crate::rusty_api::constants_errors::CryptoError::AuthenticationFailed => CRYPTO_ERROR_DECRYPTION_FAILED,
            _ => CRYPTO_ERROR_IO,
        }
    }
}

// MARK: derive_password_hash_unified_128_c
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

    let mut app_salt = [0u8; 32]; app_salt[0]=b'a'; app_salt[1]=b'p'; app_salt[2]=b'p';
    let mut mst_salt = [0u8; 32]; mst_salt[0]=b'm'; mst_salt[1]=b's'; mst_salt[2]=b't';
    let mut pwd_salt = [0u8; 32]; pwd_salt[0]=b'p'; pwd_salt[1]=b'w'; pwd_salt[2]=b'd';
    
    // Argon2 parameters for PASSWORD GENERATOR (mem=16 MiB, time=3, lanes=1) - MATCH DESKTOP
    let mem_kib: u32 = 16 * 1024;
    let time_cost: u32 = 3;
    let lanes: u32 = 1;
    
    let app_name_hash = match argon2id_hash(app_name_slice, &app_salt, 128, mem_kib, time_cost, lanes) {
        Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };

    let master_hash = match argon2id_hash(master_password_slice, &mst_salt, 128, mem_kib, time_cost, lanes) {
        Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };
    let mut combined_salt = [0u8; 32];
    combined_salt[..16].copy_from_slice(&master_hash[..16]);
    let mut final_hash = match argon2id_hash(&app_name_hash, &combined_salt, 128, mem_kib, time_cost, lanes) {
        Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };

    if !app_password_slice.is_empty() {
        let pwd_hash = match argon2id_hash(app_password_slice, &pwd_salt, 128, mem_kib, time_cost, lanes) {
            Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
        };
        let mut final_salt = [0u8; 32];
        final_salt[..16].copy_from_slice(&pwd_hash[..16]);
        final_hash = match argon2id_hash(&final_hash, &final_salt, 128, mem_kib, time_cost, lanes) {
            Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
        };
    }

    unsafe { ptr::copy_nonoverlapping(final_hash.as_ptr(), out, 128); }
    CRYPTO_SUCCESS
}

// MARK: pqc_4hybrid_init_c
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
                *hybrid_1_key_len = h1_key.len();
                ptr::copy_nonoverlapping(h1_key.as_ptr(), hybrid_1_key, h1_key.len());
                let state_bytes = bincode::serialize(&s_state).unwrap_or_default();
                *sender_state_len = state_bytes.len();
                ptr::copy_nonoverlapping(state_bytes.as_ptr(), sender_state, state_bytes.len());
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

// MARK: pqc_4hybrid_recv_c
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
                *hybrid_2_key_len = h2_key.len();
                ptr::copy_nonoverlapping(h2_key.as_ptr(), hybrid_2_key, h2_key.len());
                let state_bytes = bincode::serialize(&r_state).unwrap_or_default();
                *receiver_state_len = state_bytes.len();
                ptr::copy_nonoverlapping(state_bytes.as_ptr(), receiver_state, state_bytes.len());
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

// MARK: pqc_4hybrid_snd_final_c
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
    
    let s_state: HybridSenderState = match bincode::deserialize(state_slice) {
        Ok(state) => state,
        Err(_) => return CRYPTO_ERROR_INVALID_INPUT,
    };

    match pqc_4hybrid_snd_final(h2_key_slice, &s_state) {
        Ok((f_key, h3_key)) => {
            unsafe {
                ptr::copy_nonoverlapping(f_key.as_ptr(), final_key, 128);
                *hybrid_3_key_len = h3_key.len();
                ptr::copy_nonoverlapping(h3_key.as_ptr(), hybrid_3_key, h3_key.len());
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

// MARK: pqc_4hybrid_recv_final_c
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
    
    let r_state: HybridReceiverState = match bincode::deserialize(state_slice) {
        Ok(state) => state,
        Err(_) => return CRYPTO_ERROR_INVALID_INPUT,
    };

    match pqc_4hybrid_recv_final(h3_key_slice, &r_state) {
        Ok(f_key) => {
            unsafe {
                ptr::copy_nonoverlapping(f_key.as_ptr(), final_key, 128);
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}
