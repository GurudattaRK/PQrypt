//adb -s emulator-5554 pull /storage/emulated/0/Documents/PQrypt/test2.jpg.pqrypt2 /tmp/ && adb -s emulator-5556 push /tmp/test2.jpg.pqrypt2 /storage/emulated/0/Documents/PQrypt/
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::derive::Deriver;
use openssl::pkey::PKey;
use std::ptr;
use std::ffi::CString;
use std::os::raw::{c_int, c_uchar};
use zeroize::Zeroize;

//#MARK: Constants

// AES-256-GCM
pub const AES_KEY_SIZE: usize = 32;
pub const AES_NONCE_SIZE: usize = 12;
pub const AES_TAG_SIZE: usize = 16;
pub type AesKey = [u8; AES_KEY_SIZE];
pub type AesNonce = [u8; AES_NONCE_SIZE];
pub type AesTag = [u8; AES_TAG_SIZE];

// ChaCha20
pub const CHACHA_KEY_SIZE: usize = 32;
pub const CHACHA_NONCE_SIZE: usize = 12;  // TEST: Try 12 bytes to see what OpenSSL actually expects
pub type ChaChaKey = [u8; CHACHA_KEY_SIZE];
pub type ChaChaNonce = [u8; CHACHA_NONCE_SIZE];

// Argon2id
pub const ARGON2_OUTPUT_SIZE: usize = 64; // Changed from 32 to 64 bytes
pub type Argon2Salt = [u8; 16];
pub type Argon2Key = [u8; ARGON2_OUTPUT_SIZE];

// ML-KEM-1024 (standalone)
pub const MLKEM1024_PUBLIC_SIZE: usize = 1568;
pub const MLKEM1024_SECRET_SIZE: usize = 3168;
pub const MLKEM1024_CIPHERTEXT_SIZE: usize = 1568;
pub const MLKEM1024_SHARED_SIZE: usize = 32;
pub type MlKem1024PublicKey = [u8; MLKEM1024_PUBLIC_SIZE];
pub type MlKem1024SecretKey = [u8; MLKEM1024_SECRET_SIZE];
pub type MlKem1024Ciphertext = [u8; MLKEM1024_CIPHERTEXT_SIZE];
pub type MlKem1024SharedSecret = [u8; MLKEM1024_SHARED_SIZE];

// X448 (standalone)
pub const X448_PUBLIC_SIZE: usize = 56;
pub const X448_SECRET_SIZE: usize = 56;
pub const X448_SHARED_SIZE: usize = 56;
pub type X448PublicKey = [u8; X448_PUBLIC_SIZE];
pub type X448SecretKey = [u8; X448_SECRET_SIZE];
pub type X448SharedSecret = [u8; X448_SHARED_SIZE];

// ML-KEM-1024 + X448 Hybrid (manual combination)
pub const MLKEM1024X448_COMBINED_SHARED_SIZE: usize = MLKEM1024_SHARED_SIZE + X448_SHARED_SIZE;
pub type MlKem1024X448PublicKey = ([u8; MLKEM1024_PUBLIC_SIZE], [u8; X448_PUBLIC_SIZE]);
pub type MlKem1024X448SecretKey = ([u8; MLKEM1024_SECRET_SIZE], [u8; X448_SECRET_SIZE]);
pub type MlKem1024X448Ciphertext = ([u8; MLKEM1024_CIPHERTEXT_SIZE], [u8; X448_PUBLIC_SIZE]);
pub type MlKem1024X448SharedSecret = [u8; MLKEM1024X448_COMBINED_SHARED_SIZE];

// HQC-P521 Hybrid
pub const HQC256_PUBLIC_SIZE: usize = 7245;
pub const HQC256_SECRET_SIZE: usize = 7317;
pub const HQC256_CIPHERTEXT_SIZE: usize = 14421;
pub const HQC256_SHARED_SIZE: usize = 64;
pub const P521_PUBLIC_SIZE: usize = 133;
pub const P521_SECRET_SIZE: usize = 66;
pub const P521_SHARED_SIZE: usize = 66;
pub const HQCP521_COMBINED_SHARED_SIZE: usize = HQC256_SHARED_SIZE + P521_SHARED_SIZE;
pub type HqcP521PublicKey = ([u8; HQC256_PUBLIC_SIZE], [u8; P521_PUBLIC_SIZE]);
pub type HqcP521SecretKey = ([u8; HQC256_SECRET_SIZE], [u8; P521_SECRET_SIZE]);
pub type HqcP521Ciphertext = ([u8; HQC256_CIPHERTEXT_SIZE], [u8; P521_PUBLIC_SIZE]);
pub type HqcP521SharedSecret = [u8; HQCP521_COMBINED_SHARED_SIZE];

// SLH-DSA
pub const SLHDSA_PUBLIC_SIZE: usize = 64;
pub const SLHDSA_SECRET_SIZE: usize = 8; // EVP_PKEY pointer as u64
pub const SLHDSA_SIGNATURE_SIZE: usize = 49856; // Fixed signature size
pub type SlhDsaPublicKey = [u8; SLHDSA_PUBLIC_SIZE];
pub type SlhDsaSecretKey = [u8; SLHDSA_SECRET_SIZE];
pub type SlhDsaSignature = [u8; SLHDSA_SIGNATURE_SIZE];


//#MARK: Manual FFI
// These functions exist for OpenSSL 3.6 and liboqs 0.15 in our statically linked libraries
unsafe extern "C" {
    fn EVP_PKEY_encapsulate_init(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        params: *const openssl_sys::OSSL_PARAM
    ) -> c_int;
    
    fn EVP_PKEY_encapsulate(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        wrappedkey: *mut c_uchar,
        wrappedkeylen: *mut usize,
        secret: *mut c_uchar,
        secretlen: *mut usize
    ) -> c_int;
    
    fn EVP_PKEY_decapsulate_init(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        params: *const openssl_sys::OSSL_PARAM
    ) -> c_int;
    
    fn EVP_PKEY_decapsulate(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        secret: *mut c_uchar,
        secretlen: *mut usize,
        wrappedkey: *const c_uchar,
        wrappedkeylen: usize
    ) -> c_int;
    
    fn EVP_PKEY_fromdata_init(
        ctx: *mut openssl_sys::EVP_PKEY_CTX
    ) -> c_int;
    
    fn EVP_PKEY_fromdata(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        ppkey: *mut *mut openssl_sys::EVP_PKEY,
        selection: c_int,
        params: *mut openssl_sys::OSSL_PARAM
    ) -> c_int;
}

//#MARK: AES Decrypt with AAD
/// Note: All inputs zeroized before return. Caller must zeroize returned plaintext.
#[inline(always)]
pub fn aes_decrypt_with_aad(
    key: &mut [u8; AES_KEY_SIZE],
    nonce: &mut [u8; AES_NONCE_SIZE],
    ciphertext: &mut [u8],
    tag: &mut [u8; AES_TAG_SIZE],
    aad: &[u8]
) -> Result<Vec<u8>, String> {
    let cipher = Cipher::aes_256_gcm();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(nonce))
        .map_err(|e| {
            secure_zero(key);
            secure_zero(nonce);
            secure_zero(ciphertext);
            secure_zero(tag);
            e.to_string()
        })?;

    // Supply AAD before processing ciphertext
    decrypter.aad_update(aad).map_err(|e| {
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(ciphertext);
        secure_zero(tag);
        e.to_string()
    })?;

    // Set expected tag for verification (must be set before finalize)
    decrypter.set_tag(tag).map_err(|e| {
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(ciphertext);
        secure_zero(tag);
        e.to_string()
    })?;

    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
    let mut count = decrypter.update(ciphertext, &mut plaintext).map_err(|e| {
        secure_zero(&mut plaintext);
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(ciphertext);
        secure_zero(tag);
        e.to_string()
    })?;
    count += decrypter.finalize(&mut plaintext[count..]).map_err(|e| {
        secure_zero(&mut plaintext);
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(ciphertext);
        secure_zero(tag);
        e.to_string()
    })?;
    plaintext.truncate(count);

    // Zeroize inputs on success
    secure_zero(key);
    secure_zero(nonce);
    secure_zero(ciphertext);
    secure_zero(tag);

    Ok(plaintext)
}

// liboqs 0.15 types and functions for HQC-256
#[repr(C)]
pub struct OQS_KEM {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn OQS_KEM_new(method_name: *const std::os::raw::c_char) -> *mut OQS_KEM;
    fn OQS_KEM_free(kem: *mut OQS_KEM);
    fn OQS_KEM_keypair(kem: *const OQS_KEM, public_key: *mut c_uchar, secret_key: *mut c_uchar) -> c_int;
    fn OQS_KEM_encaps(
        kem: *const OQS_KEM,
        ciphertext: *mut c_uchar,
        shared_secret: *mut c_uchar,
        public_key: *const c_uchar
    ) -> c_int;
    fn OQS_KEM_decaps(
        kem: *const OQS_KEM,
        shared_secret: *mut c_uchar,
        ciphertext: *const c_uchar,
        secret_key: *const c_uchar
    ) -> c_int;
}

// Helper to securely zero sensitive data
#[inline(always)]
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

 

//#MARK: AES Encrypt with AAD
/// Note: All inputs are zeroized before return. Caller must zeroize returned (ciphertext, tag).
#[inline(always)]
pub fn aes_encrypt_with_aad(
    key: &mut [u8; AES_KEY_SIZE],
    nonce: &mut [u8; AES_NONCE_SIZE],
    plaintext: &mut [u8],
    aad: &[u8]
) -> Result<(Vec<u8>, [u8; AES_TAG_SIZE]), String> {
    let cipher = Cipher::aes_256_gcm();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce))
        .map_err(|e| {
            secure_zero(key);
            secure_zero(nonce);
            secure_zero(plaintext);
            e.to_string()
        })?;

    // AAD must be provided before processing plaintext
    encrypter.aad_update(aad).map_err(|e| {
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(plaintext);
        e.to_string()
    })?;

    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut count = encrypter.update(plaintext, &mut ciphertext).map_err(|e| {
        secure_zero(&mut ciphertext);
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(plaintext);
        e.to_string()
    })?;
    count += encrypter.finalize(&mut ciphertext[count..]).map_err(|e| {
        secure_zero(&mut ciphertext);
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(plaintext);
        e.to_string()
    })?;
    ciphertext.truncate(count);

    let mut tag = [0u8; AES_TAG_SIZE];
    encrypter.get_tag(&mut tag).map_err(|e| {
        secure_zero(&mut ciphertext);
        secure_zero(&mut tag);
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(plaintext);
        e.to_string()
    })?;

    // Zeroize inputs on success
    secure_zero(key);
    secure_zero(nonce);
    secure_zero(plaintext);

    Ok((ciphertext, tag))
}

 

//#MARK: ChaCha20 Encrypt
/// Note: All inputs zeroized before return. Caller must zeroize returned ciphertext.
#[inline(always)]
pub fn chacha20_encrypt(key: &mut [u8; CHACHA_KEY_SIZE], nonce: &mut [u8; CHACHA_NONCE_SIZE], plaintext: &mut [u8])
    -> Result<Vec<u8>, String> {
    let cipher = Cipher::chacha20();

    // Build 16-byte IV: counter (4 bytes, 0) + nonce (12 bytes)
    let mut iv = [0u8; 16];
    iv[4..16].copy_from_slice(nonce);

    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv))
        .map_err(|e| {
            secure_zero(key);
            secure_zero(nonce);
            secure_zero(plaintext);
            format!("ChaCha20 Crypter::new failed: {}", e)
        })?;
    
    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut count = encrypter.update(plaintext, &mut ciphertext).map_err(|e| {
        secure_zero(&mut ciphertext);
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(plaintext);
        e.to_string()
    })?;
    count += encrypter.finalize(&mut ciphertext[count..]).map_err(|e| {
        secure_zero(&mut ciphertext);
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(plaintext);
        e.to_string()
    })?;
    ciphertext.truncate(count);
    
    // Zeroize inputs on success
    secure_zero(key);
    secure_zero(nonce);
    secure_zero(plaintext);
    
    Ok(ciphertext)
}

//#MARK: ChaCha20 Decrypt
/// Note: All inputs zeroized before return. Caller must zeroize returned plaintext.
#[inline(always)]
pub fn chacha20_decrypt(key: &mut [u8; CHACHA_KEY_SIZE], nonce: &mut [u8; CHACHA_NONCE_SIZE], ciphertext: &mut [u8])
    -> Result<Vec<u8>, String> {
    let cipher = Cipher::chacha20();

    // Build 16-byte IV: counter (4 bytes, 0) + nonce (12 bytes)
    let mut iv = [0u8; 16];
    iv[4..16].copy_from_slice(nonce);

    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(&iv))
        .map_err(|e| {
            secure_zero(key);
            secure_zero(nonce);
            secure_zero(ciphertext);
            e.to_string()
        })?;
    
    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
    let mut count = decrypter.update(ciphertext, &mut plaintext).map_err(|e| {
        secure_zero(&mut plaintext);
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(ciphertext);
        e.to_string()
    })?;
    count += decrypter.finalize(&mut plaintext[count..]).map_err(|e| {
        secure_zero(&mut plaintext);
        secure_zero(key);
        secure_zero(nonce);
        secure_zero(ciphertext);
        e.to_string()
    })?;
    plaintext.truncate(count);
    
    // Zeroize inputs on success
    secure_zero(key);
    secure_zero(nonce);
    secure_zero(ciphertext);
    
    Ok(plaintext)
}

//#MARK: Argon2id
/// Note: All inputs zeroized before return. Caller must zeroize returned key.
/// output_size: Desired output size in bytes (0 = default 64, max 64)
#[inline(always)]
pub fn argon2id_derive(password: &mut [u8], salt: &mut [u8; 16], output_size: usize) -> Result<Vec<u8>, String> {
    // Validate output size
    let actual_output_size = if output_size == 0 || output_size > ARGON2_OUTPUT_SIZE {
        ARGON2_OUTPUT_SIZE // Default to 64 bytes
    } else {
        output_size
    };
    
    use openssl::kdf;
    
    let iterations = 3;
    let mem_cost = 8192;  // 8 MiB constant
    let lanes = 1;        // single-thread for Android friendliness
    let mut key = vec![0u8; actual_output_size]; // Variable size buffer

    // Try Argon2id with constant params; if it fails, use PBKDF2-HMAC-SHA256 fallback
    let result_vec = match kdf::argon2id(None, password, salt, None, None, iterations, mem_cost, lanes, &mut key) {
        Ok(()) => Ok(key.clone()),
        Err(e1) => {
            // PBKDF2 fallback (OpenSSL)
            match openssl::pkcs5::pbkdf2_hmac(password, &salt[..], 200_000, openssl::hash::MessageDigest::sha256(), &mut key) {
                Ok(()) => Ok(key.clone()),
                Err(e2) => Err(format!("Argon2id failed: {} ; PBKDF2 fallback failed: {}", e1, e2)),
            }
        }
    };

    match result_vec {
        Ok(k) => {
            // Zeroize inputs on success (and local copy of key)
            secure_zero(&mut key);
            secure_zero(password);
            secure_zero(salt);
            Ok(k)
        }
        Err(msg) => {
            // Zeroize inputs on error
            secure_zero(&mut key);
            secure_zero(password);
            secure_zero(salt);
            Err(msg)
        }
    }
}


// ===== X448MLKEM1024 HYBRID =====
//#MARK: X448MLKEM1024 KeyGen
/// All stack-based with compile-time known sizes. All inputs/outputs zeroized.
#[inline(always)]
pub fn x448mlkem1024_keygen() -> Result<(MlKem1024X448PublicKey, MlKem1024X448SecretKey), String> {
    unsafe {
        // Generate ML-KEM-1024 keypair
        let alg_name = CString::new("ML-KEM-1024").map_err(|e| e.to_string())?;
        let ctx = openssl_sys::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg_name.as_ptr(), ptr::null());
        if ctx.is_null() {
            return Err("ML-KEM-1024 not available (requires OpenSSL 3.6+)".to_string());
        }
        
        if openssl_sys::EVP_PKEY_keygen_init(ctx) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            return Err("ML-KEM keygen init failed".to_string());
        }
        
        let mut pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
        if openssl_sys::EVP_PKEY_keygen(ctx, &mut pkey) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            return Err("ML-KEM keygen failed".to_string());
        }
        
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        
        // Extract ML-KEM public key - stack array
        let pub_param = CString::new("pub").unwrap();
        let mut mlkem_public = [0u8; MLKEM1024_PUBLIC_SIZE];
        let mut pub_len = MLKEM1024_PUBLIC_SIZE;
        
        if openssl_sys::EVP_PKEY_get_octet_string_param(pkey,
            pub_param.as_ptr(),
            mlkem_public.as_mut_ptr(), MLKEM1024_PUBLIC_SIZE, &mut pub_len) <= 0 {
            openssl_sys::EVP_PKEY_free(pkey);
            secure_zero(&mut mlkem_public);
            return Err("Failed to extract ML-KEM public key".to_string());
        }
        
        // Extract ML-KEM private key - stack array
        let priv_param = CString::new("priv").unwrap();
        let mut mlkem_secret = [0u8; MLKEM1024_SECRET_SIZE];
        let mut priv_len = MLKEM1024_SECRET_SIZE;
        
        if openssl_sys::EVP_PKEY_get_octet_string_param(pkey,
            priv_param.as_ptr(),
            mlkem_secret.as_mut_ptr(), MLKEM1024_SECRET_SIZE, &mut priv_len) <= 0 {
            openssl_sys::EVP_PKEY_free(pkey);
            secure_zero(&mut mlkem_public);
            secure_zero(&mut mlkem_secret);
            return Err("Failed to extract ML-KEM private key".to_string());
        }
        
        openssl_sys::EVP_PKEY_free(pkey);
        
        // Generate X448 keypair  
        let ctx = openssl_sys::EVP_PKEY_CTX_new_id(openssl_sys::EVP_PKEY_X448, ptr::null_mut());
        if ctx.is_null() {
            secure_zero(&mut mlkem_public);
            secure_zero(&mut mlkem_secret);
            return Err("X448 not available".to_string());
        }
        
        if openssl_sys::EVP_PKEY_keygen_init(ctx) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(&mut mlkem_public);
            secure_zero(&mut mlkem_secret);
            return Err("X448 keygen init failed".to_string());
        }
        
        let mut pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
        if openssl_sys::EVP_PKEY_keygen(ctx, &mut pkey) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(&mut mlkem_public);
            secure_zero(&mut mlkem_secret);
            return Err("X448 keygen failed".to_string());
        }
        
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        
        // Extract X448 public key - stack array
        let mut x448_public = [0u8; X448_PUBLIC_SIZE];
        let mut pub_len = X448_PUBLIC_SIZE;
        
        if openssl_sys::EVP_PKEY_get_raw_public_key(pkey, x448_public.as_mut_ptr(), &mut pub_len) <= 0 {
            openssl_sys::EVP_PKEY_free(pkey);
            secure_zero(&mut mlkem_public);
            secure_zero(&mut mlkem_secret);
            secure_zero(&mut x448_public);
            return Err("Failed to extract X448 public key".to_string());
        }
        
        // Extract X448 private key - stack array
        let mut x448_secret = [0u8; X448_SECRET_SIZE];
        let mut priv_len = X448_SECRET_SIZE;
        
        if openssl_sys::EVP_PKEY_get_raw_private_key(pkey, x448_secret.as_mut_ptr(), &mut priv_len) <= 0 {
            openssl_sys::EVP_PKEY_free(pkey);
            secure_zero(&mut mlkem_public);
            secure_zero(&mut mlkem_secret);
            secure_zero(&mut x448_public);
            secure_zero(&mut x448_secret);
            return Err("Failed to extract X448 private key".to_string());
        }
        
        openssl_sys::EVP_PKEY_free(pkey);
        
        // Return tuple of stack arrays
        let public_key = (mlkem_public, x448_public);
        let secret_key = (mlkem_secret, x448_secret);
        
        Ok((public_key, secret_key))
    }
}

//#MARK: X448MLKEM1024 Encaps
/// Note: All inputs zeroized before return. Caller must zeroize returned (ciphertext, shared_secret).
/// All stack-based with compile-time known sizes.
#[inline(always)]
pub fn x448mlkem1024_encaps(public_key: &mut MlKem1024X448PublicKey) 
    -> Result<(MlKem1024X448Ciphertext, MlKem1024X448SharedSecret), String> {
    let (mlkem_public, x448_public) = public_key;
    
    unsafe {
        // Encapsulate ML-KEM-1024
        let alg_name = CString::new("ML-KEM-1024").map_err(|e| {
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            e.to_string()
        })?;
        
        let ctx = openssl_sys::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg_name.as_ptr(), ptr::null());
        if ctx.is_null() {
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("Failed to create ML-KEM context".to_string());
        }
        
        let pub_param_name = CString::new("pub").unwrap();
        let mut params = [
            openssl_sys::OSSL_PARAM_construct_octet_string(
                pub_param_name.as_ptr(),
                mlkem_public.as_mut_ptr() as *mut std::ffi::c_void,
                MLKEM1024_PUBLIC_SIZE
            ),
            openssl_sys::OSSL_PARAM_construct_end(),
        ];
        
        if EVP_PKEY_fromdata_init(ctx) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("ML-KEM fromdata init failed".to_string());
        }
        
        let mut recipient_pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
        if EVP_PKEY_fromdata(ctx, &mut recipient_pkey, 
            openssl_sys::EVP_PKEY_PUBLIC_KEY as i32, params.as_mut_ptr()) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("ML-KEM fromdata failed".to_string());
        }
        
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        
        let enc_ctx = openssl_sys::EVP_PKEY_CTX_new(recipient_pkey, ptr::null_mut());
        if enc_ctx.is_null() {
            openssl_sys::EVP_PKEY_free(recipient_pkey);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("Failed to create ML-KEM encaps context".to_string());
        }
        
        if EVP_PKEY_encapsulate_init(enc_ctx, ptr::null()) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(enc_ctx);
            openssl_sys::EVP_PKEY_free(recipient_pkey);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("ML-KEM encaps init failed".to_string());
        }
        
        // Stack arrays for ML-KEM results
        let mut mlkem_ct = [0u8; MLKEM1024_CIPHERTEXT_SIZE];
        let mut mlkem_ss = [0u8; MLKEM1024_SHARED_SIZE];
        let mut ct_len = MLKEM1024_CIPHERTEXT_SIZE;
        let mut ss_len = MLKEM1024_SHARED_SIZE;
        
        if EVP_PKEY_encapsulate(enc_ctx, mlkem_ct.as_mut_ptr(), &mut ct_len, 
                                mlkem_ss.as_mut_ptr(), &mut ss_len) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(enc_ctx);
            openssl_sys::EVP_PKEY_free(recipient_pkey);
            secure_zero(&mut mlkem_ct);
            secure_zero(&mut mlkem_ss);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("ML-KEM encapsulation failed".to_string());
        }
        
        openssl_sys::EVP_PKEY_CTX_free(enc_ctx);
        openssl_sys::EVP_PKEY_free(recipient_pkey);
        
        // Generate ephemeral X448 key and derive - all stack arrays
        let ctx = openssl_sys::EVP_PKEY_CTX_new_id(openssl_sys::EVP_PKEY_X448, ptr::null_mut());
        if ctx.is_null() {
            secure_zero(&mut mlkem_ct);
            secure_zero(&mut mlkem_ss);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("X448 context creation failed".to_string());
        }
        
        if openssl_sys::EVP_PKEY_keygen_init(ctx) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(&mut mlkem_ct);
            secure_zero(&mut mlkem_ss);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("X448 keygen init failed".to_string());
        }
        
        let mut eph_pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
        if openssl_sys::EVP_PKEY_keygen(ctx, &mut eph_pkey) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(&mut mlkem_ct);
            secure_zero(&mut mlkem_ss);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("X448 ephemeral keygen failed".to_string());
        }
        
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        
        // Extract ephemeral public key - stack array
        let mut x448_eph_public = [0u8; X448_PUBLIC_SIZE];
        let mut pub_len = X448_PUBLIC_SIZE;
        
        if openssl_sys::EVP_PKEY_get_raw_public_key(eph_pkey, x448_eph_public.as_mut_ptr(), &mut pub_len) <= 0 {
            openssl_sys::EVP_PKEY_free(eph_pkey);
            secure_zero(&mut mlkem_ct);
            secure_zero(&mut mlkem_ss);
            secure_zero(&mut x448_eph_public);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("Failed to extract X448 ephemeral public key".to_string());
        }
        
        // Load recipient's X448 public key
        let peer_pkey = openssl_sys::EVP_PKEY_new_raw_public_key(
            openssl_sys::EVP_PKEY_X448,
            ptr::null_mut(),
            x448_public.as_ptr(),
            X448_PUBLIC_SIZE
        );
        
        if peer_pkey.is_null() {
            openssl_sys::EVP_PKEY_free(eph_pkey);
            secure_zero(&mut mlkem_ct);
            secure_zero(&mut mlkem_ss);
            secure_zero(&mut x448_eph_public);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("Failed to load X448 peer public key".to_string());
        }
        
        // Derive X448 shared secret
        let ctx = openssl_sys::EVP_PKEY_CTX_new(eph_pkey, ptr::null_mut());
        if ctx.is_null() {
            openssl_sys::EVP_PKEY_free(eph_pkey);
            openssl_sys::EVP_PKEY_free(peer_pkey);
            secure_zero(&mut mlkem_ct);
            secure_zero(&mut mlkem_ss);
            secure_zero(&mut x448_eph_public);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("Failed to create X448 derive context".to_string());
        }
        
        if openssl_sys::EVP_PKEY_derive_init(ctx) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(eph_pkey);
            openssl_sys::EVP_PKEY_free(peer_pkey);
            secure_zero(&mut mlkem_ct);
            secure_zero(&mut mlkem_ss);
            secure_zero(&mut x448_eph_public);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("X448 derive init failed".to_string());
        }
        
        if openssl_sys::EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(eph_pkey);
            openssl_sys::EVP_PKEY_free(peer_pkey);
            secure_zero(&mut mlkem_ct);
            secure_zero(&mut mlkem_ss);
            secure_zero(&mut x448_eph_public);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("X448 derive set peer failed".to_string());
        }
        
        // Stack array for X448 shared secret
        let mut x448_ss = [0u8; X448_SHARED_SIZE];
        let mut shared_len = X448_SHARED_SIZE;
        
        if openssl_sys::EVP_PKEY_derive(ctx, x448_ss.as_mut_ptr(), &mut shared_len) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(eph_pkey);
            openssl_sys::EVP_PKEY_free(peer_pkey);
            secure_zero(&mut mlkem_ct);
            secure_zero(&mut mlkem_ss);
            secure_zero(&mut x448_eph_public);
            secure_zero(&mut x448_ss);
            secure_zero(mlkem_public);
            secure_zero(x448_public);
            return Err("X448 derive failed".to_string());
        }
        
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        openssl_sys::EVP_PKEY_free(eph_pkey);
        openssl_sys::EVP_PKEY_free(peer_pkey);
        
        // Combine shared secrets - stack array
        let mut combined_ss = [0u8; MLKEM1024X448_COMBINED_SHARED_SIZE];
        combined_ss[..MLKEM1024_SHARED_SIZE].copy_from_slice(&mlkem_ss);
        combined_ss[MLKEM1024_SHARED_SIZE..].copy_from_slice(&x448_ss);
        
        // Zeroize all inputs
        secure_zero(mlkem_public);
        secure_zero(x448_public);
        
        // Return tuple of stack arrays
        let ciphertext = (mlkem_ct, x448_eph_public);
        Ok((ciphertext, combined_ss))
    }
}

//#MARK: X448MLKEM1024 Decaps
/// Note: All inputs zeroized before return. Caller must zeroize returned shared_secret.
/// All stack-based with compile-time known sizes.
#[inline(always)]
pub fn x448mlkem1024_decaps(secret_key: &mut MlKem1024X448SecretKey, ciphertext: &mut MlKem1024X448Ciphertext)
    -> Result<MlKem1024X448SharedSecret, String> {
    let (mlkem_secret, x448_secret) = secret_key;
    let (mlkem_ct, x448_eph_public) = ciphertext;
    
    unsafe {
        // Decapsulate ML-KEM-1024
        let alg_name = CString::new("ML-KEM-1024").map_err(|e| {
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            e.to_string()
        })?;
        
        let ctx = openssl_sys::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg_name.as_ptr(), ptr::null());
        if ctx.is_null() {
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("Failed to create ML-KEM context".to_string());
        }
        
        let priv_param_name = CString::new("priv").unwrap();
        let mut params = [
            openssl_sys::OSSL_PARAM_construct_octet_string(
                priv_param_name.as_ptr(),
                mlkem_secret.as_mut_ptr() as *mut std::ffi::c_void,
                MLKEM1024_SECRET_SIZE
            ),
            openssl_sys::OSSL_PARAM_construct_end(),
        ];
        
        if EVP_PKEY_fromdata_init(ctx) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("ML-KEM fromdata init failed".to_string());
        }
        
        let mut pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
        if EVP_PKEY_fromdata(ctx, &mut pkey, 
            openssl_sys::EVP_PKEY_KEYPAIR as i32, params.as_mut_ptr()) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("ML-KEM fromdata failed".to_string());
        }
        
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        
        let dec_ctx = openssl_sys::EVP_PKEY_CTX_new(pkey, ptr::null_mut());
        if dec_ctx.is_null() {
            openssl_sys::EVP_PKEY_free(pkey);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("Failed to create ML-KEM decaps context".to_string());
        }
        
        if EVP_PKEY_decapsulate_init(dec_ctx, ptr::null()) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(dec_ctx);
            openssl_sys::EVP_PKEY_free(pkey);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("ML-KEM decaps init failed".to_string());
        }
        
        // Stack array for ML-KEM shared secret
        let mut mlkem_ss = [0u8; MLKEM1024_SHARED_SIZE];
        let mut ss_len = MLKEM1024_SHARED_SIZE;
        
        if EVP_PKEY_decapsulate(dec_ctx, mlkem_ss.as_mut_ptr(), &mut ss_len,
                                mlkem_ct.as_ptr(), MLKEM1024_CIPHERTEXT_SIZE) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(dec_ctx);
            openssl_sys::EVP_PKEY_free(pkey);
            secure_zero(&mut mlkem_ss);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("ML-KEM decapsulation failed".to_string());
        }
        
        openssl_sys::EVP_PKEY_CTX_free(dec_ctx);
        openssl_sys::EVP_PKEY_free(pkey);
        
        // Derive X448 shared secret using our secret and ephemeral public
        let our_pkey = openssl_sys::EVP_PKEY_new_raw_private_key(
            openssl_sys::EVP_PKEY_X448,
            ptr::null_mut(),
            x448_secret.as_ptr(),
            X448_SECRET_SIZE
        );
        
        if our_pkey.is_null() {
            secure_zero(&mut mlkem_ss);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("Failed to load X448 private key".to_string());
        }
        
        let peer_pkey = openssl_sys::EVP_PKEY_new_raw_public_key(
            openssl_sys::EVP_PKEY_X448,
            ptr::null_mut(),
            x448_eph_public.as_ptr(),
            X448_PUBLIC_SIZE
        );
        
        if peer_pkey.is_null() {
            openssl_sys::EVP_PKEY_free(our_pkey);
            secure_zero(&mut mlkem_ss);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("Failed to load X448 ephemeral public key".to_string());
        }
        
        let ctx = openssl_sys::EVP_PKEY_CTX_new(our_pkey, ptr::null_mut());
        if ctx.is_null() {
            openssl_sys::EVP_PKEY_free(our_pkey);
            openssl_sys::EVP_PKEY_free(peer_pkey);
            secure_zero(&mut mlkem_ss);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("Failed to create X448 derive context".to_string());
        }
        
        if openssl_sys::EVP_PKEY_derive_init(ctx) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(our_pkey);
            openssl_sys::EVP_PKEY_free(peer_pkey);
            secure_zero(&mut mlkem_ss);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("X448 derive init failed".to_string());
        }
        
        if openssl_sys::EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(our_pkey);
            openssl_sys::EVP_PKEY_free(peer_pkey);
            secure_zero(&mut mlkem_ss);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("X448 derive set peer failed".to_string());
        }
        
        // Stack array for X448 shared secret
        let mut x448_ss = [0u8; X448_SHARED_SIZE];
        let mut shared_len = X448_SHARED_SIZE;
        
        if openssl_sys::EVP_PKEY_derive(ctx, x448_ss.as_mut_ptr(), &mut shared_len) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(our_pkey);
            openssl_sys::EVP_PKEY_free(peer_pkey);
            secure_zero(&mut mlkem_ss);
            secure_zero(&mut x448_ss);
            secure_zero(mlkem_secret);
            secure_zero(x448_secret);
            secure_zero(mlkem_ct);
            secure_zero(x448_eph_public);
            return Err("X448 derive failed".to_string());
        }
        
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        openssl_sys::EVP_PKEY_free(our_pkey);
        openssl_sys::EVP_PKEY_free(peer_pkey);
        
        // Combine shared secrets - stack array
        let mut combined_ss = [0u8; MLKEM1024X448_COMBINED_SHARED_SIZE];
        combined_ss[..MLKEM1024_SHARED_SIZE].copy_from_slice(&mlkem_ss);
        combined_ss[MLKEM1024_SHARED_SIZE..].copy_from_slice(&x448_ss);
        
        // Zeroize all inputs
        secure_zero(mlkem_secret);
        secure_zero(x448_secret);
        secure_zero(mlkem_ct);
        secure_zero(x448_eph_public);
        
        Ok(combined_ss)
    }
}
// ===== HQC-P521 HYBRID =====
//#MARK: HQC-P521 KeyGen
#[inline(always)]
pub fn hqc_p521_keygen() -> Result<(HqcP521PublicKey, HqcP521SecretKey), String> {
    unsafe {
        let alg_name = CString::new("HQC-256").map_err(|e| e.to_string())?;
        let kem = OQS_KEM_new(alg_name.as_ptr());
        if kem.is_null() {
            return Err("HQC-256 not available".to_string());
        }
        
        let mut hqc_public = [0u8; HQC256_PUBLIC_SIZE];
        let mut hqc_secret = [0u8; HQC256_SECRET_SIZE];
        
        if OQS_KEM_keypair(kem, hqc_public.as_mut_ptr(), hqc_secret.as_mut_ptr()) != 0 {
            OQS_KEM_free(kem);
            secure_zero(&mut hqc_secret);
            return Err("HQC keypair generation failed".to_string());
        }
        
        OQS_KEM_free(kem);
        
        // Generate P-521 keypair
        let p521_group = EcGroup::from_curve_name(Nid::SECP521R1)
            .map_err(|e| e.to_string())?;
        let p521_key = EcKey::generate(&p521_group).map_err(|e| e.to_string())?;
        
        let p521_public_vec = p521_key.public_key().to_bytes(
            &p521_group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut openssl::bn::BigNumContext::new().unwrap()
        ).map_err(|e| e.to_string())?;
        
        let mut p521_private_vec = p521_key.private_key().to_vec();
        
        // Convert to fixed-size arrays
        let mut p521_public = [0u8; P521_PUBLIC_SIZE];
        let mut p521_private = [0u8; P521_SECRET_SIZE];
        
        p521_public[..p521_public_vec.len().min(P521_PUBLIC_SIZE)]
            .copy_from_slice(&p521_public_vec[..p521_public_vec.len().min(P521_PUBLIC_SIZE)]);
        
        // Copy private key with proper padding (right-align, pad with leading zeros)
        // P-521 private keys can be shorter if they have leading zeros
        let priv_len = p521_private_vec.len().min(P521_SECRET_SIZE);
        let offset = P521_SECRET_SIZE - priv_len;
        p521_private[offset..].copy_from_slice(&p521_private_vec[..priv_len]);
        
        secure_zero(&mut p521_private_vec);
        
        let public_key = (hqc_public, p521_public);
        let secret_key = (hqc_secret, p521_private);
        
        Ok((public_key, secret_key))
    }
}

//#MARK: HQC-P521 Encaps
/// Note: All inputs zeroized before return. Caller must zeroize returned (ciphertext, shared_secret).
#[inline(always)]
pub fn hqc_p521_encaps(public_key: &mut HqcP521PublicKey) 
    -> Result<(HqcP521Ciphertext, HqcP521SharedSecret), String> {
    let (hqc_public, p521_public) = public_key;
    
    unsafe {
        let alg_name = CString::new("HQC-256").map_err(|e| {
            secure_zero(hqc_public);
            secure_zero(p521_public);
            e.to_string()
        })?;
        let kem = OQS_KEM_new(alg_name.as_ptr());
        if kem.is_null() {
            secure_zero(hqc_public);
            secure_zero(p521_public);
            return Err("HQC-256 not available".to_string());
        }
        
        let mut hqc_ct = [0u8; HQC256_CIPHERTEXT_SIZE];
        let mut hqc_ss = [0u8; HQC256_SHARED_SIZE];
        
        if OQS_KEM_encaps(kem, hqc_ct.as_mut_ptr(), hqc_ss.as_mut_ptr(), hqc_public.as_ptr()) != 0 {
            OQS_KEM_free(kem);
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_public);
            secure_zero(p521_public);
            return Err("HQC encapsulation failed".to_string());
        }
        
        OQS_KEM_free(kem);
        
        // Generate ephemeral P-521 key and do ECDH
        let p521_group = EcGroup::from_curve_name(Nid::SECP521R1)
            .map_err(|e| {
                secure_zero(&mut hqc_ss);
                secure_zero(hqc_public);
                secure_zero(p521_public);
                e.to_string()
            })?;
        let eph_key = EcKey::generate(&p521_group).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_public);
            secure_zero(p521_public);
            e.to_string()
        })?;
        let eph_pkey = PKey::from_ec_key(eph_key.clone()).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_public);
            secure_zero(p521_public);
            e.to_string()
        })?;
        
        let eph_public_vec = eph_key.public_key().to_bytes(
            &p521_group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut openssl::bn::BigNumContext::new().unwrap()
        ).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_public);
            secure_zero(p521_public);
            e.to_string()
        })?;
        
        // Convert ephemeral public to fixed-size array
        let mut eph_public = [0u8; P521_PUBLIC_SIZE];
        eph_public[..eph_public_vec.len().min(P521_PUBLIC_SIZE)]
            .copy_from_slice(&eph_public_vec[..eph_public_vec.len().min(P521_PUBLIC_SIZE)]);
        
        // Parse peer public key and derive shared secret
        let peer_point = openssl::ec::EcPoint::from_bytes(
            &p521_group,
            p521_public,
            &mut openssl::bn::BigNumContext::new().unwrap()
        ).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_public);
            secure_zero(p521_public);
            e.to_string()
        })?;
        let peer_key = EcKey::from_public_key(&p521_group, &peer_point)
            .map_err(|e| {
                secure_zero(&mut hqc_ss);
                secure_zero(hqc_public);
                secure_zero(p521_public);
                e.to_string()
            })?;
        let peer_pkey = PKey::from_ec_key(peer_key).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_public);
            secure_zero(p521_public);
            e.to_string()
        })?;
        
        let mut deriver = Deriver::new(&eph_pkey).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_public);
            secure_zero(p521_public);
            e.to_string()
        })?;
        deriver.set_peer(&peer_pkey).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_public);
            secure_zero(p521_public);
            e.to_string()
        })?;
        let mut ecdh_ss_vec = deriver.derive_to_vec().map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_public);
            secure_zero(p521_public);
            e.to_string()
        })?;
        
        // Combine shared secrets
        let mut combined = [0u8; HQCP521_COMBINED_SHARED_SIZE];
        combined[..HQC256_SHARED_SIZE].copy_from_slice(&hqc_ss);
        if ecdh_ss_vec.len() != P521_SHARED_SIZE {
            secure_zero(&mut ecdh_ss_vec);
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_public);
            secure_zero(p521_public);
            return Err(format!("Invalid ECDH shared secret size: {} (expected {})", ecdh_ss_vec.len(), P521_SHARED_SIZE));
        }
        combined[HQC256_SHARED_SIZE..HQC256_SHARED_SIZE+P521_SHARED_SIZE]
            .copy_from_slice(&ecdh_ss_vec);
        
        secure_zero(&mut ecdh_ss_vec);
        secure_zero(&mut hqc_ss);
        secure_zero(hqc_public);
        secure_zero(p521_public);
        
        let ciphertext = (hqc_ct, eph_public);
        Ok((ciphertext, combined))
    }
}

//#MARK: HQC-P521 Decaps
/// Note: All inputs zeroized before return. Caller must zeroize returned shared_secret.
#[inline(always)]
pub fn hqc_p521_decaps(secret_key: &mut HqcP521SecretKey, ciphertext: &mut HqcP521Ciphertext)
    -> Result<HqcP521SharedSecret, String> {
    let (hqc_secret, p521_private_bytes) = secret_key;
    let (hqc_ct, eph_public) = ciphertext;
    
    unsafe {
        let alg_name = CString::new("HQC-256").map_err(|e| {
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            e.to_string()
        })?;
        let kem = OQS_KEM_new(alg_name.as_ptr());
        if kem.is_null() {
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            return Err("HQC-256 not available".to_string());
        }
        
        let mut hqc_ss = [0u8; HQC256_SHARED_SIZE];
        
        if OQS_KEM_decaps(kem, hqc_ss.as_mut_ptr(), hqc_ct.as_ptr(), hqc_secret.as_ptr()) != 0 {
            OQS_KEM_free(kem);
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            return Err("HQC decapsulation failed".to_string());
        }
        
        OQS_KEM_free(kem);
        
        // Reconstruct P-521 key and perform ECDH with ephemeral public key
        let p521_group = EcGroup::from_curve_name(Nid::SECP521R1)
            .map_err(|e| {
                secure_zero(&mut hqc_ss);
                secure_zero(hqc_secret);
                secure_zero(p521_private_bytes);
                secure_zero(hqc_ct);
                secure_zero(eph_public);
                e.to_string()
            })?;
        
        let bn = openssl::bn::BigNum::from_slice(p521_private_bytes)
            .map_err(|e| {
                secure_zero(&mut hqc_ss);
                secure_zero(hqc_secret);
                secure_zero(p521_private_bytes);
                secure_zero(hqc_ct);
                secure_zero(eph_public);
                e.to_string()
            })?;
        
        // Reconstruct our public key from private key
        let mut our_public = openssl::ec::EcPoint::new(&p521_group)
            .map_err(|e| {
                secure_zero(&mut hqc_ss);
                secure_zero(hqc_secret);
                secure_zero(p521_private_bytes);
                secure_zero(hqc_ct);
                secure_zero(eph_public);
                e.to_string()
            })?;
        our_public.mul_generator(
            &p521_group,
            &bn,
            &mut openssl::bn::BigNumContext::new().unwrap()
        ).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            e.to_string()
        })?;
        
        let key = EcKey::from_private_components(&p521_group, &bn, &our_public)
            .map_err(|e| {
                secure_zero(&mut hqc_ss);
                secure_zero(hqc_secret);
                secure_zero(p521_private_bytes);
                secure_zero(hqc_ct);
                secure_zero(eph_public);
                e.to_string()
            })?;
        let pkey = PKey::from_ec_key(key).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            e.to_string()
        })?;
        
        // Parse ephemeral public key from ciphertext
        let eph_point = openssl::ec::EcPoint::from_bytes(
            &p521_group,
            eph_public,
            &mut openssl::bn::BigNumContext::new().unwrap()
        ).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            e.to_string()
        })?;
        let eph_key = EcKey::from_public_key(&p521_group, &eph_point)
            .map_err(|e| {
                secure_zero(&mut hqc_ss);
                secure_zero(hqc_secret);
                secure_zero(p521_private_bytes);
                secure_zero(hqc_ct);
                secure_zero(eph_public);
                e.to_string()
            })?;
        let eph_pkey = PKey::from_ec_key(eph_key).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            e.to_string()
        })?;
        
        let mut deriver = Deriver::new(&pkey).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            e.to_string()
        })?;
        deriver.set_peer(&eph_pkey).map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            e.to_string()
        })?;
        let mut ecdh_ss_vec = deriver.derive_to_vec().map_err(|e| {
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            e.to_string()
        })?;
        
        let mut combined = [0u8; HQCP521_COMBINED_SHARED_SIZE];
        combined[..HQC256_SHARED_SIZE].copy_from_slice(&hqc_ss);
        if ecdh_ss_vec.len() != P521_SHARED_SIZE {
            secure_zero(&mut ecdh_ss_vec);
            secure_zero(&mut hqc_ss);
            secure_zero(hqc_secret);
            secure_zero(p521_private_bytes);
            secure_zero(hqc_ct);
            secure_zero(eph_public);
            return Err(format!("Invalid ECDH shared secret size: {} (expected {})", ecdh_ss_vec.len(), P521_SHARED_SIZE));
        }
        combined[HQC256_SHARED_SIZE..HQC256_SHARED_SIZE+P521_SHARED_SIZE]
            .copy_from_slice(&ecdh_ss_vec);
        
        secure_zero(&mut ecdh_ss_vec);
        secure_zero(&mut hqc_ss);
        secure_zero(hqc_secret);
        secure_zero(p521_private_bytes);
        secure_zero(hqc_ct);
        secure_zero(eph_public);
        
        Ok(combined)
    }
}

// ===== SLH-DSA =====
//#MARK: SLH-DSA keygen
#[inline(always)]
pub fn slhdsa_keygen() -> Result<(SlhDsaPublicKey, SlhDsaSecretKey), String> {
    unsafe {
        let alg_name = CString::new("SLH-DSA-SHAKE-256f").map_err(|e| e.to_string())?;
        let ctx = openssl_sys::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg_name.as_ptr(), ptr::null());
        if ctx.is_null() {
            return Err("SLH-DSA not available".to_string());
        }
        
        if openssl_sys::EVP_PKEY_keygen_init(ctx) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            return Err("Keygen init failed".to_string());
        }
        
        let mut pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
        if openssl_sys::EVP_PKEY_keygen(ctx, &mut pkey) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            return Err("Keygen failed".to_string());
        }
        
        let mut pub_key = [0u8; SLHDSA_PUBLIC_SIZE];
        let mut pub_len = SLHDSA_PUBLIC_SIZE;
        if openssl_sys::EVP_PKEY_get_octet_string_param(pkey,
            CString::new("pub").unwrap().as_ptr(),
            pub_key.as_mut_ptr(), SLHDSA_PUBLIC_SIZE, &mut pub_len) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(&mut pub_key);
            return Err("Failed to extract public key".to_string());
        }
        
        let pkey_val = pkey as usize as u64;
        let secret = pkey_val.to_le_bytes();
        
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        
        Ok((pub_key, secret))
    }
}

//#MARK: SLH-DSA Signing
/// Note: All inputs zeroized before return. Caller must zeroize returned signature.
#[inline(always)]
pub fn slhdsa_sign(message: &mut [u8], secret_material: &mut SlhDsaSecretKey) -> Result<SlhDsaSignature, String> {
    unsafe {
        let pkey_val = u64::from_le_bytes(*secret_material);
        let pkey = pkey_val as usize as *mut openssl_sys::EVP_PKEY;
        
        let md_ctx = openssl_sys::EVP_MD_CTX_new();
        if md_ctx.is_null() {
            secure_zero(message);
            secure_zero(secret_material);
            return Err("Failed to create context".to_string());
        }
        
        if openssl_sys::EVP_DigestSignInit(md_ctx, ptr::null_mut(), ptr::null(), ptr::null_mut(), pkey) <= 0 {
            openssl_sys::EVP_MD_CTX_free(md_ctx);
            secure_zero(message);
            secure_zero(secret_material);
            return Err("Sign init failed".to_string());
        }
        
        // Sign directly into fixed-size stack buffer
        let mut signature = [0u8; SLHDSA_SIGNATURE_SIZE];
        let mut sig_len = SLHDSA_SIGNATURE_SIZE;
        
        if openssl_sys::EVP_DigestSign(md_ctx, signature.as_mut_ptr(), &mut sig_len, message.as_ptr(), message.len()) <= 0 {
            openssl_sys::EVP_MD_CTX_free(md_ctx);
            secure_zero(&mut signature);
            secure_zero(message);
            secure_zero(secret_material);
            return Err("Signing failed".to_string());
        }
        
        openssl_sys::EVP_MD_CTX_free(md_ctx);
        
        // Zeroize inputs on success
        secure_zero(message);
        secure_zero(secret_material);
        
        Ok(signature)
    }
}

//#MARK: SLH-DSA Verification
/// Note: All inputs zeroized before return.
#[inline(always)]
pub fn slhdsa_verify(message: &mut [u8], signature: &mut SlhDsaSignature, public_key: &mut SlhDsaPublicKey) 
    -> Result<bool, String> {
    unsafe {
        let alg_name = CString::new("SLH-DSA-SHAKE-256f").map_err(|e| {
            secure_zero(message);
            secure_zero(signature);
            secure_zero(public_key);
            e.to_string()
        })?;
        
        // Reconstruct public key from bytes
        let ctx = openssl_sys::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg_name.as_ptr(), ptr::null());
        if ctx.is_null() {
            secure_zero(message);
            secure_zero(signature);
            secure_zero(public_key);
            return Err("Failed to create context".to_string());
        }
        
        // Initialize keygen to create a temporary key structure
        if openssl_sys::EVP_PKEY_keygen_init(ctx) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(message);
            secure_zero(signature);
            secure_zero(public_key);
            return Err("Keygen init failed".to_string());
        }
        
        let mut pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
        if openssl_sys::EVP_PKEY_keygen(ctx, &mut pkey) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(message);
            secure_zero(signature);
            secure_zero(public_key);
            return Err("Keygen failed".to_string());
        }
        
        // Set the public key parameter
        if openssl_sys::EVP_PKEY_set_octet_string_param(pkey,
            CString::new("pub").unwrap().as_ptr(),
            public_key.as_ptr(), SLHDSA_PUBLIC_SIZE) <= 0 {
            openssl_sys::EVP_PKEY_free(pkey);
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            secure_zero(message);
            secure_zero(signature);
            secure_zero(public_key);
            return Err("Failed to set public key".to_string());
        }
        
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        
        // Verify signature
        let md_ctx = openssl_sys::EVP_MD_CTX_new();
        if md_ctx.is_null() {
            openssl_sys::EVP_PKEY_free(pkey);
            secure_zero(message);
            secure_zero(signature);
            secure_zero(public_key);
            return Err("Failed to create verify context".to_string());
        }
        
        if openssl_sys::EVP_DigestVerifyInit(md_ctx, ptr::null_mut(), ptr::null(), ptr::null_mut(), pkey) <= 0 {
            openssl_sys::EVP_MD_CTX_free(md_ctx);
            openssl_sys::EVP_PKEY_free(pkey);
            secure_zero(message);
            secure_zero(signature);
            secure_zero(public_key);
            return Err("Verify init failed".to_string());
        }
        
        let result = openssl_sys::EVP_DigestVerify(md_ctx,
            signature.as_ptr(), SLHDSA_SIGNATURE_SIZE,
            message.as_ptr(), message.len());
        
        openssl_sys::EVP_MD_CTX_free(md_ctx);
        openssl_sys::EVP_PKEY_free(pkey);
        
        // Zeroize inputs
        secure_zero(message);
        secure_zero(signature);
        secure_zero(public_key);
        
        Ok(result == 1)
    }
}