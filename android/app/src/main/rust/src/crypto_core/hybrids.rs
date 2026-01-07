// Import functions from func module
use super::func::{
    chacha20_encrypt, chacha20_decrypt,
    aes_encrypt, aes_decrypt,
    x448mlkem1024_keygen, x448mlkem1024_encaps, x448mlkem1024_decaps,
    hqc_p521_keygen, hqc_p521_encaps, hqc_p521_decaps,
    slhdsa_keygen, slhdsa_sign, slhdsa_verify,
    argon2id_derive, secure_zero,
};
// Import all types and constants from constants_errors
use crate::rusty_api::constants_errors::*;

// Package sizes
const PACKAGE1_SIZE: usize = SLHDSA_SIGNATURE_SIZE + MLKEM1024_PUBLIC_SIZE + X448_PUBLIC_SIZE + HQC256_PUBLIC_SIZE + P521_PUBLIC_SIZE + SLHDSA_PUBLIC_SIZE;
const PACKAGE2_SIZE: usize = SLHDSA_SIGNATURE_SIZE + MLKEM1024_CIPHERTEXT_SIZE + X448_PUBLIC_SIZE + HQC256_CIPHERTEXT_SIZE + P521_PUBLIC_SIZE + SLHDSA_PUBLIC_SIZE;
const COMBINED_KEY1_SIZE: usize = MLKEM1024_PUBLIC_SIZE + X448_PUBLIC_SIZE + HQC256_PUBLIC_SIZE + P521_PUBLIC_SIZE;
const COMBINED_KEY2_SIZE: usize = MLKEM1024_CIPHERTEXT_SIZE + X448_PUBLIC_SIZE + HQC256_CIPHERTEXT_SIZE + P521_PUBLIC_SIZE;
const COMBINED_SHARED_SIZE: usize = MLKEM1024X448_COMBINED_SHARED_SIZE + HQCP521_COMBINED_SHARED_SIZE;

pub type Package1 = [u8; PACKAGE1_SIZE];
pub type Package2 = [u8; PACKAGE2_SIZE];
pub type DerivedHash = [u8; ARGON2_OUTPUT_SIZE];


//MARK: Double Encrypt
/// Returns (double_encrypted_ciphertext, gcm_tag)
#[inline(always)]
pub fn double_encrypt(
    chacha_key: &mut ChaChaKey,
    chacha_nonce: &mut ChaChaNonce,
    aes_key: &mut AesKey,
    aes_nonce: &mut AesNonce,
    plaintext: &mut [u8]
) -> Result<(Vec<u8>, AesTag), String> {
    // Step 1: ChaCha20 encryption
    eprintln!("[CRYPTO_CORE][DOUBLE_ENCRYPT] Input plaintext len={}, first 16 bytes: {:02x?}", plaintext.len(), &plaintext[..16.min(plaintext.len())]);
    println!("[CRYPTO_CORE][DOUBLE_ENCRYPT] Input plaintext len={}, first 16 bytes: {:02x?}", plaintext.len(), &plaintext[..16.min(plaintext.len())]);
    let mut chacha_ciphertext = chacha20_encrypt(chacha_key, chacha_nonce, plaintext)?;
    eprintln!("[CRYPTO_CORE][DOUBLE_ENCRYPT] After ChaCha20 encrypt, chacha_ciphertext len={}, first 16 bytes: {:02x?}", chacha_ciphertext.len(), &chacha_ciphertext[..16.min(chacha_ciphertext.len())]);
    println!("[CRYPTO_CORE][DOUBLE_ENCRYPT] After ChaCha20 encrypt, chacha_ciphertext len={}, first 16 bytes: {:02x?}", chacha_ciphertext.len(), &chacha_ciphertext[..16.min(chacha_ciphertext.len())]);
    
    // Step 2: AES-GCM encryption on ChaCha20 ciphertext
    let result = aes_encrypt(aes_key, aes_nonce, &mut chacha_ciphertext);
    match &result {
        Ok((ciphertext, tag)) => {
            eprintln!("[CRYPTO_CORE][DOUBLE_ENCRYPT] After AES-GCM encrypt, ciphertext len={}, first 16 bytes: {:02x?}, tag: {:02x?}", ciphertext.len(), &ciphertext[..16.min(ciphertext.len())], tag);
            println!("[CRYPTO_CORE][DOUBLE_ENCRYPT] After AES-GCM encrypt, ciphertext len={}, first 16 bytes: {:02x?}, tag: {:02x?}", ciphertext.len(), &ciphertext[..16.min(ciphertext.len())], tag);
        },
        Err(e) => {
            eprintln!("[CRYPTO_CORE][DOUBLE_ENCRYPT] AES-GCM encrypt failed: {}", e);
            println!("[CRYPTO_CORE][DOUBLE_ENCRYPT] AES-GCM encrypt failed: {}", e);
        },
    };
    
    // Zeroize intermediate data
    secure_zero(&mut chacha_ciphertext);
    
    result
}

//MARK: Double Decrypt
/// Returns plaintext
#[inline(always)]
pub fn double_decrypt(
    aes_key: &mut AesKey,
    aes_nonce: &mut AesNonce,
    aes_tag: &mut AesTag,
    chacha_key: &mut ChaChaKey,
    chacha_nonce: &mut ChaChaNonce,
    double_ciphertext: &mut [u8]
) -> Result<Vec<u8>, String> {
    // Step 1: AES-GCM decryption (includes tag verification)
    eprintln!("[CRYPTO_CORE][DOUBLE_DECRYPT] Input double_ciphertext len={}, first 16 bytes: {:02x?}", double_ciphertext.len(), &double_ciphertext[..16.min(double_ciphertext.len())]);
    println!("[CRYPTO_CORE][DOUBLE_DECRYPT] Input double_ciphertext len={}, first 16 bytes: {:02x?}", double_ciphertext.len(), &double_ciphertext[..16.min(double_ciphertext.len())]);
    let mut chacha_ciphertext = aes_decrypt(aes_key, aes_nonce, double_ciphertext, aes_tag)?;
    eprintln!("[CRYPTO_CORE][DOUBLE_DECRYPT] After AES-GCM decrypt, chacha_ciphertext len={}, first 16 bytes: {:02x?}", chacha_ciphertext.len(), &chacha_ciphertext[..16.min(chacha_ciphertext.len())]);
    println!("[CRYPTO_CORE][DOUBLE_DECRYPT] After AES-GCM decrypt, chacha_ciphertext len={}, first 16 bytes: {:02x?}", chacha_ciphertext.len(), &chacha_ciphertext[..16.min(chacha_ciphertext.len())]);
    
    // Step 2: ChaCha20 decryption
    let result = chacha20_decrypt(chacha_key, chacha_nonce, &mut chacha_ciphertext);
    match &result {
        Ok(plaintext) => {
            eprintln!("[CRYPTO_CORE][DOUBLE_DECRYPT] After ChaCha20 decrypt, plaintext len={}, first 16 bytes: {:02x?}", plaintext.len(), &plaintext[..16.min(plaintext.len())]);
            println!("[CRYPTO_CORE][DOUBLE_DECRYPT] After ChaCha20 decrypt, plaintext len={}, first 16 bytes: {:02x?}", plaintext.len(), &plaintext[..16.min(plaintext.len())]);
        },
        Err(e) => {
            eprintln!("[CRYPTO_CORE][DOUBLE_DECRYPT] ChaCha20 decrypt failed: {}", e);
            println!("[CRYPTO_CORE][DOUBLE_DECRYPT] ChaCha20 decrypt failed: {}", e);
        },
    };
    
    // Zeroize intermediate data
    secure_zero(&mut chacha_ciphertext);
    
    result
}

//MARK: Sender Initialization
/// Generates X448MLKEM and HQCP521 keys, combines them, signs with SLH-DSA
/// Returns package1 = [signature || combined_key1 || slhdsa_public]
#[inline(always)]
pub fn sender_init() -> Result<(Package1, MlKem1024X448SecretKey, HqcP521SecretKey, SlhDsaSecretKey), String> {
    // Generate ML-KEM-1024 + X448 keys
    let (x448_public, x448_secret) = x448mlkem1024_keygen()?;
    
    // Generate HQCP521 keys
    let (hqc_public, hqc_secret) = hqc_p521_keygen()?;
    
    // Combine public keys: x448_public || hqc_public.0 || hqc_public.1
    let mut combined_key1 = [0u8; COMBINED_KEY1_SIZE];
    let mut offset = 0;
    
    combined_key1[offset..offset + MLKEM1024_PUBLIC_SIZE].copy_from_slice(&x448_public.0);
    offset += MLKEM1024_PUBLIC_SIZE;
    combined_key1[offset..offset + X448_PUBLIC_SIZE].copy_from_slice(&x448_public.1);
    offset += X448_PUBLIC_SIZE;
    
    combined_key1[offset..offset + HQC256_PUBLIC_SIZE].copy_from_slice(&hqc_public.0);
    offset += HQC256_PUBLIC_SIZE;
    
    combined_key1[offset..offset + P521_PUBLIC_SIZE].copy_from_slice(&hqc_public.1);
    
    // Generate SLH-DSA keys
    let (slhdsa_public, slhdsa_secret) = slhdsa_keygen()?;
    
    // Sign combined_key1 (sign a copy since slhdsa_sign zeroizes its input)
    let mut combined_key1_copy = combined_key1;
    let mut slhdsa_secret_copy = slhdsa_secret;
    let signature = slhdsa_sign(&mut combined_key1_copy, &mut slhdsa_secret_copy)?;
    secure_zero(&mut combined_key1_copy); // Explicitly zero the copy
    
    // Create package1: signature || combined_key1 || slhdsa_public
    let mut package1 = [0u8; PACKAGE1_SIZE];
    offset = 0;
    
    package1[offset..offset + SLHDSA_SIGNATURE_SIZE].copy_from_slice(&signature);
    offset += SLHDSA_SIGNATURE_SIZE;
    
    package1[offset..offset + COMBINED_KEY1_SIZE].copy_from_slice(&combined_key1);
    offset += COMBINED_KEY1_SIZE;
    
    package1[offset..offset + SLHDSA_PUBLIC_SIZE].copy_from_slice(&slhdsa_public);
    
    Ok((package1, x448_secret, hqc_secret, slhdsa_secret))
}

//MARK: Receiver
/// Receiver's side function - verifies package1, creates package2 and hash
/// Returns (hash, package2)
#[inline(always)]
pub fn receiver(package1: &mut Package1) -> Result<(DerivedHash, Package2), String> {
    // Extract from package1
    let mut offset = 0;
    
    let mut signature = [0u8; SLHDSA_SIGNATURE_SIZE];
    signature.copy_from_slice(&package1[offset..offset + SLHDSA_SIGNATURE_SIZE]);
    offset += SLHDSA_SIGNATURE_SIZE;
    
    let mut combined_key1 = [0u8; COMBINED_KEY1_SIZE];
    combined_key1.copy_from_slice(&package1[offset..offset + COMBINED_KEY1_SIZE]);
    offset += COMBINED_KEY1_SIZE;
    
    let mut slhdsa_public = [0u8; SLHDSA_PUBLIC_SIZE];
    slhdsa_public.copy_from_slice(&package1[offset..offset + SLHDSA_PUBLIC_SIZE]);
    
    // Verify signature (verify a copy since slhdsa_verify zeroizes its input)
    let mut combined_key1_copy = combined_key1;
    slhdsa_verify(&mut combined_key1_copy, &mut signature, &mut slhdsa_public)?;
    secure_zero(&mut combined_key1_copy); // Explicitly zero the copy
    
    // Extract public keys from combined_key1
    offset = 0;
    let mut mlkem_public = [0u8; MLKEM1024_PUBLIC_SIZE];
    mlkem_public.copy_from_slice(&combined_key1[offset..offset + MLKEM1024_PUBLIC_SIZE]);
    offset += MLKEM1024_PUBLIC_SIZE;
    let mut x448_public_part = [0u8; X448_PUBLIC_SIZE];
    x448_public_part.copy_from_slice(&combined_key1[offset..offset + X448_PUBLIC_SIZE]);
    offset += X448_PUBLIC_SIZE;
    
    let mut mlkem_x448_public = (mlkem_public, x448_public_part);
    
    let mut hqc_public_0 = [0u8; HQC256_PUBLIC_SIZE];
    hqc_public_0.copy_from_slice(&combined_key1[offset..offset + HQC256_PUBLIC_SIZE]);
    offset += HQC256_PUBLIC_SIZE;
    
    let mut hqc_public_1 = [0u8; P521_PUBLIC_SIZE];
    hqc_public_1.copy_from_slice(&combined_key1[offset..offset + P521_PUBLIC_SIZE]);
    
    let mut hqc_public = (hqc_public_0, hqc_public_1);
    
    // Encapsulate with sender's public keys
    let (x448_ciphertext, x448_shared) = x448mlkem1024_encaps(&mut mlkem_x448_public)?;
    let (hqc_ciphertext, hqc_shared) = hqc_p521_encaps(&mut hqc_public)?;
    
    // Combine ciphertexts into combined_key2
    let mut combined_key2 = [0u8; COMBINED_KEY2_SIZE];
    offset = 0;
    
    combined_key2[offset..offset + MLKEM1024_CIPHERTEXT_SIZE].copy_from_slice(&x448_ciphertext.0);
    offset += MLKEM1024_CIPHERTEXT_SIZE;
    combined_key2[offset..offset + X448_PUBLIC_SIZE].copy_from_slice(&x448_ciphertext.1);
    offset += X448_PUBLIC_SIZE;
    
    combined_key2[offset..offset + HQC256_CIPHERTEXT_SIZE].copy_from_slice(&hqc_ciphertext.0);
    offset += HQC256_CIPHERTEXT_SIZE;
    
    combined_key2[offset..offset + P521_PUBLIC_SIZE].copy_from_slice(&hqc_ciphertext.1);
    
    // Generate receiver's SLH-DSA keys
    let (recv_slhdsa_public, recv_slhdsa_secret) = slhdsa_keygen()?;
    
    // Sign combined_key2 (sign a copy since slhdsa_sign zeroizes its input)
    let mut combined_key2_copy = combined_key2;
    let mut recv_slhdsa_secret_copy = recv_slhdsa_secret;
    let recv_signature = slhdsa_sign(&mut combined_key2_copy, &mut recv_slhdsa_secret_copy)?;
    secure_zero(&mut combined_key2_copy); // Explicitly zero the copy
    
    // Create package2: signature || combined_key2 || slhdsa_public
    let mut package2 = [0u8; PACKAGE2_SIZE];
    offset = 0;
    
    package2[offset..offset + SLHDSA_SIGNATURE_SIZE].copy_from_slice(&recv_signature);
    offset += SLHDSA_SIGNATURE_SIZE;
    
    package2[offset..offset + COMBINED_KEY2_SIZE].copy_from_slice(&combined_key2);
    offset += COMBINED_KEY2_SIZE;
    
    package2[offset..offset + SLHDSA_PUBLIC_SIZE].copy_from_slice(&recv_slhdsa_public);
    
    // Combine shared secrets and hash
    let mut combined_shared = [0u8; COMBINED_SHARED_SIZE];
    combined_shared[..MLKEM1024X448_COMBINED_SHARED_SIZE].copy_from_slice(&x448_shared);
    combined_shared[MLKEM1024X448_COMBINED_SHARED_SIZE..].copy_from_slice(&hqc_shared);
    
    // Hash with Argon2id
    let mut salt = [0u8; 16];
    // Use first 16 bytes of combined shared as salt
    salt.copy_from_slice(&combined_shared[..16]);
    
    let hash_vec = argon2id_derive(&mut combined_shared, &mut salt, ARGON2_OUTPUT_SIZE)?;
    let mut hash = [0u8; ARGON2_OUTPUT_SIZE];
    hash.copy_from_slice(&hash_vec);
    
    Ok((hash, package2))
}

//MARK: Sender Finalization
/// Sender's side function - verifies package2 and derives hash
/// Returns hash that should match receiver's hash
#[inline(always)]
pub fn sender_final(
    package2: &mut Package2,
    x448_secret: &mut MlKem1024X448SecretKey,
    hqc_secret: &mut HqcP521SecretKey
) -> Result<DerivedHash, String> {
    // Extract from package2
    let mut offset = 0;
    
    let mut signature = [0u8; SLHDSA_SIGNATURE_SIZE];
    signature.copy_from_slice(&package2[offset..offset + SLHDSA_SIGNATURE_SIZE]);
    offset += SLHDSA_SIGNATURE_SIZE;
    
    let mut combined_key2 = [0u8; COMBINED_KEY2_SIZE];
    combined_key2.copy_from_slice(&package2[offset..offset + COMBINED_KEY2_SIZE]);
    offset += COMBINED_KEY2_SIZE;
    
    let mut slhdsa_public = [0u8; SLHDSA_PUBLIC_SIZE];
    slhdsa_public.copy_from_slice(&package2[offset..offset + SLHDSA_PUBLIC_SIZE]);
    
    // Verify signature (verify a copy since slhdsa_verify zeroizes its input)
    let mut combined_key2_copy = combined_key2;
    slhdsa_verify(&mut combined_key2_copy, &mut signature, &mut slhdsa_public)?;
    secure_zero(&mut combined_key2_copy); // Explicitly zero the copy
    
    // Extract ciphertexts from combined_key2
    offset = 0;
    let mut mlkem_ciphertext = [0u8; MLKEM1024_CIPHERTEXT_SIZE];
    mlkem_ciphertext.copy_from_slice(&combined_key2[offset..offset + MLKEM1024_CIPHERTEXT_SIZE]);
    offset += MLKEM1024_CIPHERTEXT_SIZE;
    let mut x448_ciphertext_part = [0u8; X448_PUBLIC_SIZE];
    x448_ciphertext_part.copy_from_slice(&combined_key2[offset..offset + X448_PUBLIC_SIZE]);
    offset += X448_PUBLIC_SIZE;
    let mut x448_ciphertext = (mlkem_ciphertext, x448_ciphertext_part);
    
    let mut hqc_ciphertext_0 = [0u8; HQC256_CIPHERTEXT_SIZE];
    hqc_ciphertext_0.copy_from_slice(&combined_key2[offset..offset + HQC256_CIPHERTEXT_SIZE]);
    offset += HQC256_CIPHERTEXT_SIZE;
    
    let mut hqc_ciphertext_1 = [0u8; P521_PUBLIC_SIZE];
    hqc_ciphertext_1.copy_from_slice(&combined_key2[offset..offset + P521_PUBLIC_SIZE]);
    
    let mut hqc_ciphertext = (hqc_ciphertext_0, hqc_ciphertext_1);
    
    // Decapsulate to get shared secrets
    let x448_shared = x448mlkem1024_decaps(x448_secret, &mut x448_ciphertext)?;
    let hqc_shared = hqc_p521_decaps(hqc_secret, &mut hqc_ciphertext)?;
    
    // Combine shared secrets and hash
    let mut combined_shared = [0u8; COMBINED_SHARED_SIZE];
    combined_shared[..MLKEM1024X448_COMBINED_SHARED_SIZE].copy_from_slice(&x448_shared);
    combined_shared[MLKEM1024X448_COMBINED_SHARED_SIZE..].copy_from_slice(&hqc_shared);
    
    // Hash with Argon2id
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&combined_shared[..16]);
    
    let hash_vec = argon2id_derive(&mut combined_shared, &mut salt, ARGON2_OUTPUT_SIZE)?;
    let mut hash = [0u8; ARGON2_OUTPUT_SIZE];
    hash.copy_from_slice(&hash_vec);
    
    Ok(hash)
}
