// Post-quantum cryptography implementations

use fips203::ml_kem_1024;
use fips203::traits::{KeyGen, Encaps, Decaps, SerDes as Fips203SerDes};
use rand::rngs::OsRng;

use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};
use pqcrypto_hqc::hqc256::{
    keypair as hqc_keypair, encapsulate as hqc_encapsulate, decapsulate as hqc_decapsulate,
    PublicKey as HqcPublicKey, SecretKey as HqcSecretKey, Ciphertext as HqcCiphertext
};

use p521::{PublicKey as P521Public, SecretKey as P521Secret, NistP521};
use elliptic_curve::{ecdh::diffie_hellman, sec1::ToEncodedPoint, FieldBytes};

// SLH-DSA (SPHINCS+) FIPS-205 implementation
use fips205::slh_dsa_shake_256f;
use fips205::traits::{SerDes, Signer, Verifier};

use super::constants_errors::*;
use super::utils::secure_random_bytes;

//MARK: Kyber1024 operations with proper error handling
pub fn crypto_kyber1024_keypair() -> Result<
    ([u8; KYBER_PUBLICKEYBYTES], [u8; KYBER_SECRETKEYBYTES]),
    CryptoError,
> {
    // Generate key pair using FIPS-203 ML-KEM-1024
    let (ek, dk) = ml_kem_1024::KG::try_keygen()
        .map_err(|_| CryptoError::KeyGenerationFailed)?;

    let pk: [u8; KYBER_PUBLICKEYBYTES] = ek.into_bytes();
    let sk: [u8; KYBER_SECRETKEYBYTES] = dk.into_bytes();

    Ok((pk, sk))
}

//MARK: crypto_kyber1024_encaps
/// Encapsulate using a public key provided as a fixed-size array.
/// Returns (ciphertext, shared_secret) as fixed-size arrays.
pub fn crypto_kyber1024_encaps(
    public_key: &[u8; KYBER_PUBLICKEYBYTES],
) -> Result<([u8; KYBER_CIPHERTEXTBYTES], [u8; KYBER_SHAREDSECRETBYTES]), CryptoError> {
    // Deserialize public key and encapsulate using FIPS-203 ML-KEM-1024
    let ek = ml_kem_1024::EncapsKey::try_from_bytes(*public_key)
        .map_err(|_| CryptoError::InvalidInput)?;

    let (ss, ct) = ek.try_encaps()
        .map_err(|_| CryptoError::PqcOperationFailed)?;

    let ct_bytes: [u8; KYBER_CIPHERTEXTBYTES] = ct.into_bytes();
    let ss_bytes: [u8; KYBER_SHAREDSECRETBYTES] = ss.into_bytes();

    Ok((ct_bytes, ss_bytes))
}

//MARK: crypto_kyber1024_decaps
/// Decapsulate using ciphertext and secret key (both as fixed-size arrays).
/// Returns the shared secret as a fixed-size array.
pub fn crypto_kyber1024_decaps(
    ciphertext: &[u8; KYBER_CIPHERTEXTBYTES],
    secret_key: &[u8; KYBER_SECRETKEYBYTES],
) -> Result<[u8; KYBER_SHAREDSECRETBYTES], CryptoError> {
    // Deserialize secret key and ciphertext, then decapsulate using FIPS-203 ML-KEM-1024
    let dk = ml_kem_1024::DecapsKey::try_from_bytes(*secret_key)
        .map_err(|_| CryptoError::InvalidInput)?;
    let ct = ml_kem_1024::CipherText::try_from_bytes(*ciphertext)
        .map_err(|_| CryptoError::InvalidInput)?;

    let ss = dk.try_decaps(&ct)
        .map_err(|_| CryptoError::PqcOperationFailed)?;

    Ok(ss.into_bytes())
}

//MARK: HQC256 operations with proper error handling
pub fn crypto_hqc256_keypair() -> Result<([u8; HQC256_PUBLICKEYBYTES], [u8; HQC256_SECRETKEYBYTES]), CryptoError> {
    let (pk, sk) = hqc_keypair();
    let pk_bytes: [u8; HQC256_PUBLICKEYBYTES] = pk.as_bytes()
        .try_into()
        .map_err(|_| CryptoError::PqcOperationFailed)?;
    let sk_bytes: [u8; HQC256_SECRETKEYBYTES] = sk.as_bytes()
        .try_into()
        .map_err(|_| CryptoError::PqcOperationFailed)?;
    
    Ok((pk_bytes, sk_bytes))
}

//MARK: crypto_hqc256_encaps
pub fn crypto_hqc256_encaps(public_key: &[u8]) -> Result<(Vec<u8>, [u8; HQC256_SHAREDSECRETBYTES]), CryptoError> {
    if public_key.len() != HQC256_PUBLICKEYBYTES {
        return Err(CryptoError::InvalidInput);
    }
    
    let pk = HqcPublicKey::from_bytes(public_key)
        .map_err(|_| CryptoError::PqcOperationFailed)?;
    let (ss, ct) = hqc_encapsulate(&pk);
    
    let ct_bytes = ct.as_bytes().to_vec();
    let ss_bytes: [u8; HQC256_SHAREDSECRETBYTES] = ss.as_bytes()
        .try_into()
        .map_err(|_| CryptoError::PqcOperationFailed)?;
    
    Ok((ct_bytes, ss_bytes))
}

//MARK: crypto_hqc256_decaps
pub fn crypto_hqc256_decaps(
    ciphertext: &[u8], 
    secret_key: &[u8]
) -> Result<[u8; HQC256_SHAREDSECRETBYTES], CryptoError> {
    if secret_key.len() != HQC256_SECRETKEYBYTES {
        return Err(CryptoError::InvalidInput);
    }
    
    let sk = HqcSecretKey::from_bytes(secret_key)
        .map_err(|_| CryptoError::PqcOperationFailed)?;
    let ct = HqcCiphertext::from_bytes(ciphertext)
        .map_err(|_| CryptoError::PqcOperationFailed)?;
    let ss = hqc_decapsulate(&ct, &sk);
    
    ss.as_bytes()
        .try_into()
        .map_err(|_| CryptoError::PqcOperationFailed)
}

// Elliptic curve cryptography implementations

//MARK:X448 operations with secure random generation
pub fn crypto_x448_keypair() -> Result<([u8; X448_KEY_SIZE], [u8; X448_KEY_SIZE]), CryptoError> {
    let mut private_key = [0u8; X448_KEY_SIZE];
    secure_random_bytes(&mut private_key)?;
    
    let public_key = x448::x448(private_key, x448::X448_BASEPOINT_BYTES)
        .ok_or(CryptoError::KeyGenerationFailed)?;
    
    Ok((public_key, private_key))
}

//MARK: crypto_x448_shared_secret
pub fn crypto_x448_shared_secret(
    their_public: &[u8; X448_KEY_SIZE], 
    my_private: &[u8; X448_KEY_SIZE]
) -> Result<[u8; X448_KEY_SIZE], CryptoError> {
    x448::x448(*my_private, *their_public)
        .ok_or(CryptoError::KeyGenerationFailed)
}

//MARK: P521 operations with proper error handling
pub fn crypto_p521_keypair() -> Result<([u8; P521_KEY_SIZE], [u8; P521_SECRET_SIZE]), CryptoError> {
    let secret = P521Secret::random(&mut rand::rngs::OsRng);
    let scalar = secret.to_nonzero_scalar();
    let public = P521Public::from_secret_scalar(&scalar);
    
    let public_bytes: [u8; P521_KEY_SIZE] = public.to_encoded_point(false)
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    let secret_bytes: [u8; P521_SECRET_SIZE] = secret.to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    
    Ok((public_bytes, secret_bytes))
}

//MARK: crypto_p521_shared_secret
pub fn crypto_p521_shared_secret(
    their_public: &[u8; P521_KEY_SIZE], 
    my_private: &[u8; P521_SECRET_SIZE]
) -> Result<[u8; P521_SECRET_SIZE], CryptoError> {
    let my_secret_key = P521Secret::from_bytes(FieldBytes::<NistP521>::from_slice(my_private))
        .map_err(|_| CryptoError::InvalidInput)?;
    let my_scalar = my_secret_key.to_nonzero_scalar();
    let their_pub = P521Public::from_sec1_bytes(their_public)
        .map_err(|_| CryptoError::InvalidInput)?;
    
    let shared = diffie_hellman(my_scalar, their_pub.as_affine());
    shared.raw_secret_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KeyGenerationFailed)
}

//MARK: SLH-DSA (SPHINCS+) wrappers using FIPS-205 slh_dsa_shake_256f

/// Generate SLH-DSA keypair (SPHINCS+-SHAKE-256f)
pub fn crypto_slh_dsa_keypair() -> Result<([u8; SLH_DSA_PUBKEYBYTES], [u8; SLH_DSA_SECRETKEYBYTES]), CryptoError> {
    let (pk, sk) = slh_dsa_shake_256f::try_keygen_with_rng(&mut OsRng)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;
    let pk_bytes: [u8; SLH_DSA_PUBKEYBYTES] = pk.into_bytes();
    let sk_bytes: [u8; SLH_DSA_SECRETKEYBYTES] = sk.into_bytes();
    Ok((pk_bytes, sk_bytes))
}

//MARK: crypto_slh_dsa_sign
/// Sign message with SLH-DSA. `aad` is optional associated data for domain separation; pass empty slice if unused.
pub fn crypto_slh_dsa_sign(
    secret_key: &[u8; SLH_DSA_SECRETKEYBYTES],
    message: &[u8],
    aad: &[u8],
    randomized: bool
) -> Result<[u8; SLH_DSA_SIGNATUREBYTES], CryptoError> {
    let sk = slh_dsa_shake_256f::PrivateKey::try_from_bytes(secret_key)
        .map_err(|_| CryptoError::InvalidInput)?;
    let signature: [u8; SLH_DSA_SIGNATUREBYTES] = sk
        .try_sign_with_rng(&mut OsRng, message, aad, randomized)
        .map_err(|_| CryptoError::PqcOperationFailed)?;
    Ok(signature)
}

//MARK: crypto_slh_dsa_verify
/// Verify SLH-DSA signature. Returns true if valid.
pub fn crypto_slh_dsa_verify(
    public_key: &[u8; SLH_DSA_PUBKEYBYTES],
    message: &[u8],
    signature: &[u8],
    aad: &[u8]
) -> Result<bool, CryptoError> {
    if signature.len() != SLH_DSA_SIGNATUREBYTES {
        return Err(CryptoError::InvalidInput);
    }
    let pk = slh_dsa_shake_256f::PublicKey::try_from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidInput)?;
    let sig_arr: [u8; SLH_DSA_SIGNATUREBYTES] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidInput)?;
    Ok(pk.verify(message, &sig_arr, aad))
}