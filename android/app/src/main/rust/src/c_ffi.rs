use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr;
use std::slice;
use std::ffi::CString;
use libc::size_t;

// Android logging function
extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
}

// Status codes for debugging execution flow
const STATUS_ENTER_C_FUNC: c_int = 100;
const STATUS_INPUT_VALID: c_int = 101;
const STATUS_CALLING_RUST: c_int = 102;
const STATUS_RUST_SUCCESS: c_int = 103;
const STATUS_RUST_ERROR: c_int = 104;
const STATUS_RUST_ENCRYPT_START: c_int = 105;
const STATUS_RUST_ENCRYPT_KEY_DERIVED: c_int = 106;
const STATUS_RUST_ENCRYPT_FILE_READ: c_int = 107;
const STATUS_RUST_ENCRYPT_DOUBLE_ENCRYPT: c_int = 108;
const STATUS_RUST_ENCRYPT_HEADER_WRITE: c_int = 109;
const STATUS_RUST_DECRYPT_START: c_int = 110;
const STATUS_RUST_DECRYPT_HEADER_PARSED: c_int = 111;
const STATUS_RUST_DECRYPT_KEY_DERIVED: c_int = 112;
const STATUS_RUST_DECRYPT_DOUBLE_DECRYPT: c_int = 113;
const STATUS_RUST_DECRYPT_FILE_WRITE: c_int = 114;

const ANDROID_LOG_DEBUG: c_int = 3;
const ANDROID_LOG_ERROR: c_int = 6;

pub fn log_debug(message: &str) {
    log_android(ANDROID_LOG_DEBUG, message);
}

pub fn log_error(message: &str) {
    log_android(ANDROID_LOG_ERROR, message);
}

fn log_android(priority: c_int, message: &str) {
    if let (Ok(tag), Ok(msg), Ok(fmt)) = (
        CString::new("RustyCrypto"),
        CString::new(message),
        CString::new("%s"),
    ) {
        unsafe {
            __android_log_print(priority, tag.as_ptr(), fmt.as_ptr(), msg.as_ptr());
        }
    }
}

// Initialize Android logger
fn init_android_logger() {
    #[cfg(target_os = "android")]
    {
        use android_logger::Config;
        use log::LevelFilter;
        
        android_logger::init_once(
            Config::default()
                .with_max_level(LevelFilter::Debug)
                .with_tag("PQryptRust")
        );
    }
}

// Call init on module load
#[ctor::ctor]
fn init_logging() {
    init_android_logger();
    // Ensure OpenSSL providers are loaded in static builds
    unsafe {
        use std::ptr;
        use std::ffi::CString;
        // Try loading the 'default' provider first
        if let Ok(name) = CString::new("default") {
            let prov = openssl_sys::OSSL_PROVIDER_load(ptr::null_mut(), name.as_ptr());
            if prov.is_null() {
                log_error("[OPENSSL] Failed to load 'default' provider");
            } else {
                log_debug("[OPENSSL] Loaded 'default' provider");
            }
        }
        // Also attempt to load 'legacy' (some KDFs may reside here depending on build)
        if let Ok(name) = CString::new("legacy") {
            let prov = openssl_sys::OSSL_PROVIDER_load(ptr::null_mut(), name.as_ptr());
            if prov.is_null() {
                log_debug("[OPENSSL] 'legacy' provider not available (ok)");
            } else {
                log_debug("[OPENSSL] Loaded 'legacy' provider");
            }
        }
    }
}
use crate::crypto_core::func::*;
use crate::rusty_api::constants_errors::*;
use crate::rusty_api::api::{double_encrypt_fd_raw, double_decrypt_fd_raw};
use crate::rusty_api::password::generate_password;
use crate::crypto_core::{sender_init, receiver, sender_final};
use crate::crypto_core::hybrids::{Package1, Package2};
use crate::crypto_core::func::{MlKem1024X448SecretKey, HqcP521SecretKey};

static mut SENDER_STATE: Option<(MlKem1024X448SecretKey, HqcP521SecretKey)> = None;
static mut RECEIVER_STATE: Option<(MlKem1024X448SecretKey, HqcP521SecretKey)> = None;
static mut RECEIVER_HASH_AB: Option<[u8; 64]> = None;

// MARK: crypto_self_test_c
#[no_mangle]
pub extern "C" fn crypto_self_test_c(
    result_msg: *mut c_char,
    result_len: size_t,
) -> c_int {
    if result_msg.is_null() || result_len < 256 {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Test 1: ChaCha20 encrypt/decrypt with known values
    let test_plaintext = b"Hello World Test 123";
    let mut key = [0x01u8; 32];
    let mut nonce = [0x99u8; 12];
    let mut plaintext_copy = test_plaintext.to_vec();
    
    // Encrypt
    let ciphertext_result = chacha20_encrypt(&mut key, &mut nonce, &mut plaintext_copy);
    if ciphertext_result.is_err() {
        let msg = CString::new("ChaCha20 encrypt failed").unwrap();
        unsafe { ptr::copy_nonoverlapping(msg.as_ptr(), result_msg, msg.as_bytes_with_nul().len().min(result_len)); }
        return -1;
    }
    
    // Decrypt
    let mut ciphertext = ciphertext_result.unwrap();
    let mut key2 = [0x01u8; 32];
    let mut nonce2 = [0x99u8; 12];
    let decrypted_result = chacha20_decrypt(&mut key2, &mut nonce2, &mut ciphertext);
    
    if decrypted_result.is_err() {
        let msg = CString::new("ChaCha20 decrypt failed").unwrap();
        unsafe { ptr::copy_nonoverlapping(msg.as_ptr(), result_msg, msg.as_bytes_with_nul().len().min(result_len)); }
        return -2;
    }
    
    let decrypted = decrypted_result.unwrap();
    if decrypted != test_plaintext {
        let msg = format!("ChaCha20 mismatch: expected {:02x?}, got {:02x?}", &test_plaintext[..10], &decrypted[..10.min(decrypted.len())]);
        let msg_cstr = CString::new(msg).unwrap();
        unsafe { ptr::copy_nonoverlapping(msg_cstr.as_ptr(), result_msg, msg_cstr.as_bytes_with_nul().len().min(result_len)); }
        return -3;
    }
    
    // Test 2: Argon2 parameter check
    let mut password = b"test".to_vec();
    let mut salt = [0x42u8; 16];
    let argon_result = argon2id_derive(&mut password, &mut salt, 32);
    if argon_result.is_err() {
        let msg = CString::new("Argon2 failed").unwrap();
        unsafe { ptr::copy_nonoverlapping(msg.as_ptr(), result_msg, msg.as_bytes_with_nul().len().min(result_len)); }
        return -4;
    }
    
    let msg = CString::new("All tests passed").unwrap();
    unsafe { ptr::copy_nonoverlapping(msg.as_ptr(), result_msg, msg.as_bytes_with_nul().len().min(result_len)); }
    CRYPTO_SUCCESS
}

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
    if hash_128.is_null() || output.is_null() || output_len.is_null() || hash_len != 64 {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let hash_slice = unsafe { slice::from_raw_parts(hash_128, 64) };

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

// MARK: double_encrypt_fd_c
#[no_mangle]
pub extern "C" fn double_encrypt_fd_c(
    secret: *const c_uchar,
    secret_len: std::os::raw::c_ulong,
    is_keyfile: c_int,
    in_fd: c_int,
    out_fd: c_int,
) -> c_int {
    // Return status codes instead of generic error codes for debugging
    if secret.is_null() || secret_len == 0 || secret_len > 4096 || in_fd < 0 || out_fd < 0 {
        return -1; // Invalid input
    }

    let secret_slice = unsafe { slice::from_raw_parts(secret, secret_len as usize) };
    
    // Call Rust function and return status codes
    match double_encrypt_fd_raw(secret_slice, is_keyfile != 0, in_fd, out_fd) {
        Ok(_) => STATUS_RUST_SUCCESS,  // 103
        Err(e) => match e {
            crate::rusty_api::constants_errors::CryptoError::InvalidInput => -2,
            crate::rusty_api::constants_errors::CryptoError::HashingFailed | crate::rusty_api::constants_errors::CryptoError::KeyDerivationFailed => -3,
            crate::rusty_api::constants_errors::CryptoError::EncryptionFailed => -4,
            crate::rusty_api::constants_errors::CryptoError::AuthenticationFailed => -5,
            crate::rusty_api::constants_errors::CryptoError::DebugCode(code) => code,
            _ => -6,
        }
    }
}

// MARK: double_decrypt_fd_c
#[no_mangle]
pub extern "C" fn double_decrypt_fd_c(
    secret: *const c_uchar,
    secret_len: std::os::raw::c_ulong,
    is_keyfile: c_int,
    in_fd: c_int,
    out_fd: c_int,
) -> c_int {
    if secret.is_null() || secret_len == 0 || secret_len > 4096 || in_fd < 0 || out_fd < 0 {
        return -1; // Invalid input
    }
    let secret_slice = unsafe { slice::from_raw_parts(secret, secret_len as usize) };
    
    match double_decrypt_fd_raw(secret_slice, is_keyfile != 0, in_fd, out_fd) {
        Ok(_) => STATUS_RUST_SUCCESS,  // 103
        Err(e) => match e {
            crate::rusty_api::constants_errors::CryptoError::InvalidInput => -2,
            crate::rusty_api::constants_errors::CryptoError::HashingFailed | crate::rusty_api::constants_errors::CryptoError::KeyDerivationFailed => -3,
            crate::rusty_api::constants_errors::CryptoError::EncryptionFailed => -4,
            crate::rusty_api::constants_errors::CryptoError::AuthenticationFailed => -5,
            crate::rusty_api::constants_errors::CryptoError::DebugCode(code) => code,
            _ => -6,
        }
    }
}

// MARK: derive_password_hash_unified_64_c
#[no_mangle]
pub extern "C" fn derive_password_hash_unified_64_c(
    app_name: *const c_uchar,
    app_name_len: usize,
    app_password: *const c_uchar,
    app_password_len: usize,
    master_password: *const c_uchar,
    master_password_len: usize,
    out: *mut c_uchar,
    out_len: usize,
) -> c_int {
    if app_name.is_null() || master_password.is_null() || out.is_null() || out_len < 64 {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let app_name_slice = unsafe { slice::from_raw_parts(app_name, app_name_len) };
    let app_password_slice = if !app_password.is_null() && app_password_len > 0 {
        unsafe { slice::from_raw_parts(app_password, app_password_len) }
    } else { &[][..] };
    let master_password_slice = unsafe { slice::from_raw_parts(master_password, master_password_len) };

    // Simple case removed; this API is now only for the password vault path.

    // Complex case: for password vault with app_name and app_password
    let mut app_salt = [0u8; 16]; app_salt[0] = b'a'; app_salt[1] = b'p'; app_salt[2] = b'p';
    let mut master_salt = [0u8; 16]; master_salt[0] = b'm'; master_salt[1] = b's'; master_salt[2] = b't';
    let mut pwd_salt = [0u8; 16]; pwd_salt[0] = b'p'; pwd_salt[1] = b'w'; pwd_salt[2] = b'd';

    let mut app_name_copy = app_name_slice.to_vec();
    let app_name_hash = match argon2id_derive(&mut app_name_copy, &mut app_salt, 64) {
        Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };

    let mut master_password_copy = master_password_slice.to_vec();
    let master_hash = match argon2id_derive(&mut master_password_copy, &mut master_salt, 64) {
        Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };
    let mut combined_salt = [0u8; 16];
    combined_salt[..8].copy_from_slice(&master_hash[..8]);
    let mut final_hash = match argon2id_derive(&mut app_name_hash.clone(), &mut combined_salt, 64) {
        Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };

    if !app_password_slice.is_empty() {
        let mut app_password_copy = app_password_slice.to_vec();
        let pwd_hash = match argon2id_derive(&mut app_password_copy, &mut pwd_salt, 64) {
            Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
        };
        let mut final_salt = [0u8; 16];
        final_salt[..8].copy_from_slice(&pwd_hash[..8]);
        final_hash = match argon2id_derive(&mut final_hash.clone(), &mut final_salt, 64) {
            Ok(h) => h, Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
        };
    }

    unsafe { ptr::copy_nonoverlapping(final_hash.as_ptr(), out, 64); }
    CRYPTO_SUCCESS
}

// MARK: hybrid_sender_init_c
#[no_mangle]
pub extern "C" fn hybrid_sender_init_c(
    package1: *mut c_uchar,
    package1_len: *mut usize,
) -> c_int {
    if package1.is_null() || package1_len.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    match sender_init() {
        Ok((pkg1, x448_secret, hqc_secret, _slhdsa_secret)) => {
            unsafe {
                SENDER_STATE = Some((x448_secret, hqc_secret));
                *package1_len = pkg1.len();
                ptr::copy_nonoverlapping(pkg1.as_ptr(), package1, pkg1.len());
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

// MARK: hybrid_receiver_c
#[no_mangle]
pub extern "C" fn hybrid_receiver_c(
    package1: *const c_uchar,
    package1_len: usize,
    derived_hash: *mut c_uchar,
    package2: *mut c_uchar,
    package2_len: *mut usize,
) -> c_int {
    if package1.is_null() || derived_hash.is_null() || package2.is_null() || package2_len.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Build Package1 from input
    let p1_slice = unsafe { slice::from_raw_parts(package1, package1_len) };
    let mut p1: Package1 = unsafe { std::mem::zeroed() };
    if p1_slice.len() != p1.len() {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    p1.copy_from_slice(p1_slice);

    let res = match receiver(&mut p1) {
        Ok((hash, mut pkg2)) => {
            unsafe {
                ptr::copy_nonoverlapping(hash.as_ptr(), derived_hash, hash.len());
                *package2_len = pkg2.len();
                ptr::copy_nonoverlapping(pkg2.as_ptr(), package2, pkg2.len());
            }
            // Zeroize local pkg2 copy
            secure_zero(&mut pkg2[..]);
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_PQC_OPERATION,
    };

    // Zeroize local p1 buffer before returning
    secure_zero(&mut p1[..]);
    res
}

// MARK: hybrid_receiver_dual_c
#[no_mangle]
pub extern "C" fn hybrid_receiver_dual_c(
    package1: *const c_uchar,
    package1_len: usize,
    package2_bundle: *mut c_uchar,
    package2_bundle_len: *mut usize,
) -> c_int {
    if package1.is_null() || package2_bundle.is_null() || package2_bundle_len.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Build Package1 from input
    let p1_slice = unsafe { slice::from_raw_parts(package1, package1_len) };
    let mut p1: Package1 = unsafe { std::mem::zeroed() };
    if p1_slice.len() != p1.len() {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    p1.copy_from_slice(p1_slice);

    // First direction: receiver to sender (A->B flow)
    let (hash_ab, pkg2_a) = match receiver(&mut p1) {
        Ok(v) => v,
        Err(_) => return CRYPTO_ERROR_PQC_OPERATION,
    };

    // Second init: start B->A flow by generating package1_b and keeping B secrets
    let (pkg1_b, mut x448_secret_b, mut hqc_secret_b, _slh_sec_b) = match sender_init() {
        Ok(v) => v,
        Err(_) => return CRYPTO_ERROR_KEY_GENERATION_FAILED,
    };

    // Persist receiver state for finalization after 3.key
    unsafe {
        RECEIVER_STATE = Some((x448_secret_b, hqc_secret_b));
        RECEIVER_HASH_AB = Some(hash_ab);
    }

    // Build bundle = package2_a || package1_b (dynamic sizing)
    let mut bundle = vec![0u8; pkg2_a.len() + pkg1_b.len()];
    let p2_len = pkg2_a.len();
    bundle[..p2_len].copy_from_slice(&pkg2_a);
    bundle[p2_len..].copy_from_slice(&pkg1_b);

    unsafe {
        *package2_bundle_len = bundle.len();
        ptr::copy_nonoverlapping(bundle.as_ptr(), package2_bundle, bundle.len());
    }

    // Zeroize locals
    let mut pkg2_a_copy = pkg2_a;
    secure_zero(&mut pkg2_a_copy[..]);
    let mut pkg1_b_copy = pkg1_b;
    secure_zero(&mut pkg1_b_copy[..]);

    CRYPTO_SUCCESS
}

// MARK: hybrid_sender_third_c
#[no_mangle]
pub extern "C" fn hybrid_sender_third_c(
    package2_bundle: *const c_uchar,
    package2_bundle_len: usize,
    package3_out: *mut c_uchar,
    package3_out_len: *mut usize,
    final_hash_out: *mut c_uchar,
) -> c_int {
    if package2_bundle.is_null() || package3_out.is_null() || package3_out_len.is_null() || final_hash_out.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Retrieve sender state
    let (x448_secret_a, hqc_secret_a) = unsafe {
        match SENDER_STATE.as_mut() {
            Some((x, h)) => (x, h),
            None => return CRYPTO_ERROR_INVALID_INPUT,
        }
    };

    // Parse bundle: [package2_a || package1_b]
    let b_slice = unsafe { slice::from_raw_parts(package2_bundle, package2_bundle_len) };
    let mut p2_a: Package2 = unsafe { std::mem::zeroed() };
    let mut p1_b: Package1 = unsafe { std::mem::zeroed() };
    let expected = p2_a.len() + p1_b.len();
    if b_slice.len() != expected {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    let p2_len = p2_a.len();
    let p2_src = &b_slice[..p2_len];
    p2_a.copy_from_slice(p2_src);
    p1_b.copy_from_slice(&b_slice[p2_len..]);

    // 1) Finalize first direction to get hash_ab
    let hash_ab = match sender_final(&mut p2_a, x448_secret_a, hqc_secret_a) {
        Ok(h) => h,
        Err(_) => return CRYPTO_ERROR_PQC_OPERATION,
    };

    // 2) Act as receiver for B->A to get (hash_ba, package2_b)
    let (hash_ba, mut p2_b) = match receiver(&mut p1_b) {
        Ok(v) => v,
        Err(_) => return CRYPTO_ERROR_PQC_OPERATION,
    };

    // 3) Combine hashes into final
    let mut combo = [0u8; crate::rusty_api::constants_errors::ARGON2_OUTPUT_SIZE * 2];
    combo[..crate::rusty_api::constants_errors::ARGON2_OUTPUT_SIZE].copy_from_slice(&hash_ab);
    combo[crate::rusty_api::constants_errors::ARGON2_OUTPUT_SIZE..].copy_from_slice(&hash_ba);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&hash_ab[..16]);
    let final_vec = match argon2id_derive(&mut combo, &mut salt, crate::rusty_api::constants_errors::ARGON2_OUTPUT_SIZE) {
        Ok(v) => v,
        Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };
    let mut final_hash = [0u8; crate::rusty_api::constants_errors::ARGON2_OUTPUT_SIZE];
    final_hash.copy_from_slice(&final_vec);

    // Output package3 (== package2_b) and final
    unsafe {
        *package3_out_len = p2_b.len();
        ptr::copy_nonoverlapping(p2_b.as_ptr(), package3_out, p2_b.len());
        ptr::copy_nonoverlapping(final_hash.as_ptr(), final_hash_out, final_hash.len());
    }

    // Zeroize locals and clear sender state
    secure_zero(&mut p2_a[..]);
    secure_zero(&mut p1_b[..]);
    secure_zero(&mut p2_b[..]);
    unsafe {
        secure_zero(&mut (x448_secret_a.0)[..]);
        secure_zero(&mut (x448_secret_a.1)[..]);
        secure_zero(&mut (hqc_secret_a.0)[..]);
        secure_zero(&mut (hqc_secret_a.1)[..]);
        SENDER_STATE = None;
    }

    CRYPTO_SUCCESS
}

// MARK: hybrid_receiver_final_dual_c
#[no_mangle]
pub extern "C" fn hybrid_receiver_final_dual_c(
    package3: *const c_uchar,
    package3_len: usize,
    final_hash_out: *mut c_uchar,
) -> c_int {
    if package3.is_null() || final_hash_out.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Retrieve receiver state and stored hash_ab
    let (x448_secret_b, hqc_secret_b) = unsafe {
        match RECEIVER_STATE.as_mut() {
            Some((x, h)) => (x, h),
            None => return CRYPTO_ERROR_INVALID_INPUT,
        }
    };
    let hash_ab = unsafe {
        match RECEIVER_HASH_AB.as_ref() {
            Some(h) => *h,
            None => return CRYPTO_ERROR_INVALID_INPUT,
        }
    };

    // Build Package2 from input (this is package2_b)
    let p2_slice = unsafe { slice::from_raw_parts(package3, package3_len) };
    let mut p2_b: Package2 = unsafe { std::mem::zeroed() };
    if p2_slice.len() != p2_b.len() {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    p2_b.copy_from_slice(p2_slice);

    // Compute hash_ba by finalizing B direction
    let hash_ba = match sender_final(&mut p2_b, x448_secret_b, hqc_secret_b) {
        Ok(h) => h,
        Err(_) => return CRYPTO_ERROR_PQC_OPERATION,
    };

    // Combine to final
    let mut combo = [0u8; crate::rusty_api::constants_errors::ARGON2_OUTPUT_SIZE * 2];
    combo[..crate::rusty_api::constants_errors::ARGON2_OUTPUT_SIZE].copy_from_slice(&hash_ab);
    combo[crate::rusty_api::constants_errors::ARGON2_OUTPUT_SIZE..].copy_from_slice(&hash_ba);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&hash_ab[..16]);
    let final_vec = match argon2id_derive(&mut combo, &mut salt, crate::rusty_api::constants_errors::ARGON2_OUTPUT_SIZE) {
        Ok(v) => v,
        Err(_) => return CRYPTO_ERROR_HASHING_FAILED,
    };
    let mut final_hash = [0u8; crate::rusty_api::constants_errors::ARGON2_OUTPUT_SIZE];
    final_hash.copy_from_slice(&final_vec);

    unsafe {
        ptr::copy_nonoverlapping(final_hash.as_ptr(), final_hash_out, final_hash.len());
        // Clear receiver state
        secure_zero(&mut (x448_secret_b.0)[..]);
        secure_zero(&mut (x448_secret_b.1)[..]);
        secure_zero(&mut (hqc_secret_b.0)[..]);
        secure_zero(&mut (hqc_secret_b.1)[..]);
        RECEIVER_STATE = None;
        RECEIVER_HASH_AB = None;
    }

    // Zeroize locals
    secure_zero(&mut p2_b[..]);
    CRYPTO_SUCCESS
}

// MARK: hybrid_sender_final_c
#[no_mangle]
pub extern "C" fn hybrid_sender_final_c(
    package2: *const c_uchar,
    package2_len: usize,
    derived_hash: *mut c_uchar,
) -> c_int {
    if package2.is_null() || derived_hash.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Retrieve sender state (in-place, no cloning)
    let (x448_secret, hqc_secret) = unsafe {
        match SENDER_STATE.as_mut() {
            Some((x, h)) => (x, h),
            None => return CRYPTO_ERROR_INVALID_INPUT,
        }
    };

    // Build Package2 from input
    let p2_slice = unsafe { slice::from_raw_parts(package2, package2_len) };
    let mut p2: Package2 = unsafe { std::mem::zeroed() };
    if p2_slice.len() != p2.len() {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    p2.copy_from_slice(p2_slice);

    let res = match sender_final(&mut p2, x448_secret, hqc_secret) {
        Ok(hash) => {
            unsafe {
                ptr::copy_nonoverlapping(hash.as_ptr(), derived_hash, hash.len());
            }
            // Zeroize secrets and clear state
            unsafe {
                secure_zero(&mut (x448_secret.0)[..]);
                secure_zero(&mut (x448_secret.1)[..]);
                secure_zero(&mut (hqc_secret.0)[..]);
                secure_zero(&mut (hqc_secret.1)[..]);
                SENDER_STATE = None;
            }
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_PQC_OPERATION,
    };

    // Zeroize local p2 buffer before returning
    secure_zero(&mut p2[..]);
    res
}
