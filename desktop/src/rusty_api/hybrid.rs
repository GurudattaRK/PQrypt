use crate::crypto_core;
use crate::crypto_core::openssl_ffi::{argon2id_derive, secure_zero};
use crate::rusty_api::constants_errors::*;
use zeroize::Zeroize;

pub struct HybridSenderState {
    x448_secret: MlKem1024X448SecretKey,
    hqc_secret: HqcP521SecretKey,
}

impl Drop for HybridSenderState {
    #[inline(always)]
    fn drop(&mut self) {
        secure_zero(&mut (self.x448_secret.0)[..]);
        secure_zero(&mut (self.x448_secret.1)[..]);
        secure_zero(&mut (self.hqc_secret.0)[..]);
        secure_zero(&mut (self.hqc_secret.1)[..]);
    }
}

pub struct HybridReceiverState {
    x448_secret_b: MlKem1024X448SecretKey,
    hqc_secret_b: HqcP521SecretKey,
    hash_ab: crypto_core::hybrids::DerivedHash,
}

impl Drop for HybridReceiverState {
    #[inline(always)]
    fn drop(&mut self) {
        secure_zero(&mut (self.x448_secret_b.0)[..]);
        secure_zero(&mut (self.x448_secret_b.1)[..]);
        secure_zero(&mut (self.hqc_secret_b.0)[..]);
        secure_zero(&mut (self.hqc_secret_b.1)[..]);
        secure_zero(&mut self.hash_ab[..]);
    }
}

#[inline(always)]
pub fn hybrid_sender_init() -> Result<(Vec<u8>, HybridSenderState), CryptoError> {
    let (pkg1, x448_secret, hqc_secret, _slh) = crypto_core::sender_init().map_err(|_| CryptoError::PqcOperationFailed)?;
    Ok((
        pkg1.to_vec(),
        HybridSenderState {
            x448_secret,
            hqc_secret,
        },
    ))
}

#[inline(always)]
pub fn hybrid_receiver(package1: &[u8]) -> Result<(Vec<u8>, [u8; ARGON2_OUTPUT_SIZE]), CryptoError> {
    let mut p1: crypto_core::hybrids::Package1 = [0u8; PACKAGE1_SIZE];
    if package1.len() != p1.len() {
        return Err(CryptoError::InvalidInput);
    }
    p1.copy_from_slice(package1);

    let (hash_ab, pkg2) = crypto_core::receiver(&mut p1).map_err(|_| CryptoError::PqcOperationFailed)?;
    secure_zero(&mut p1[..]);

    Ok((pkg2.to_vec(), hash_ab))
}

#[inline(always)]
pub fn hybrid_sender_final(
    package2: &[u8],
    mut sender_state: HybridSenderState,
) -> Result<[u8; ARGON2_OUTPUT_SIZE], CryptoError> {
    let mut p2: crypto_core::hybrids::Package2 = [0u8; PACKAGE2_SIZE];
    if package2.len() != p2.len() {
        return Err(CryptoError::InvalidInput);
    }
    p2.copy_from_slice(package2);

    let hash_ab = crypto_core::sender_final(&mut p2, &mut sender_state.x448_secret, &mut sender_state.hqc_secret)
        .map_err(|_| CryptoError::PqcOperationFailed)?;

    secure_zero(&mut p2[..]);

    Ok(hash_ab)
}

#[inline(always)]
pub fn hybrid_receiver_dual(package1: &[u8]) -> Result<(Vec<u8>, HybridReceiverState), CryptoError> {
    let mut p1: crypto_core::hybrids::Package1 = [0u8; PACKAGE1_SIZE];
    if package1.len() != p1.len() {
        return Err(CryptoError::InvalidInput);
    }
    p1.copy_from_slice(package1);

    let (hash_ab, pkg2_a) = crypto_core::receiver(&mut p1).map_err(|_| CryptoError::PqcOperationFailed)?;

    let (pkg1_b, x448_secret_b, hqc_secret_b, _slh_b) = crypto_core::sender_init().map_err(|_| CryptoError::PqcOperationFailed)?;

    let mut bundle = Vec::with_capacity(pkg2_a.len() + pkg1_b.len());
    bundle.extend_from_slice(&pkg2_a);
    bundle.extend_from_slice(&pkg1_b);

    secure_zero(&mut p1[..]);

    Ok((
        bundle,
        HybridReceiverState {
            x448_secret_b,
            hqc_secret_b,
            hash_ab,
        },
    ))
}

#[inline(always)]
pub fn hybrid_sender_third(
    package2_bundle: &[u8],
    mut sender_state: HybridSenderState,
) -> Result<(Vec<u8>, [u8; ARGON2_OUTPUT_SIZE]), CryptoError> {
    let mut p2_a: crypto_core::hybrids::Package2 = [0u8; PACKAGE2_SIZE];
    let mut p1_b: crypto_core::hybrids::Package1 = [0u8; PACKAGE1_SIZE];
    let expected = p2_a.len() + p1_b.len();
    if package2_bundle.len() != expected {
        return Err(CryptoError::InvalidInput);
    }

    let p2_len = p2_a.len();
    p2_a.copy_from_slice(&package2_bundle[..p2_len]);
    p1_b.copy_from_slice(&package2_bundle[p2_len..]);

    let hash_ab = crypto_core::sender_final(&mut p2_a, &mut sender_state.x448_secret, &mut sender_state.hqc_secret)
        .map_err(|_| CryptoError::PqcOperationFailed)?;

    let (hash_ba, p2_b) = crypto_core::receiver(&mut p1_b).map_err(|_| CryptoError::PqcOperationFailed)?;

    let mut combo = [0u8; ARGON2_OUTPUT_SIZE * 2];
    combo[..ARGON2_OUTPUT_SIZE].copy_from_slice(&hash_ab);
    combo[ARGON2_OUTPUT_SIZE..].copy_from_slice(&hash_ba);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&hash_ab[..16]);

    let mut final_vec = argon2id_derive(&mut combo, &mut salt, ARGON2_OUTPUT_SIZE).map_err(|_| CryptoError::HashingFailed)?;
    if final_vec.len() != ARGON2_OUTPUT_SIZE {
        return Err(CryptoError::InvalidInput);
    }
    let mut final_key = [0u8; ARGON2_OUTPUT_SIZE];
    final_key.copy_from_slice(&final_vec);

    secure_zero(&mut p2_a[..]);
    secure_zero(&mut p1_b[..]);
    secure_zero(&mut combo[..]);
    secure_zero(&mut salt[..]);
    final_vec.zeroize();

    Ok((p2_b.to_vec(), final_key))
}

#[inline(always)]
pub fn hybrid_receiver_final_dual(
    package3: &[u8],
    mut receiver_state: HybridReceiverState,
) -> Result<[u8; ARGON2_OUTPUT_SIZE], CryptoError> {
    let mut p2_b: crypto_core::hybrids::Package2 = [0u8; PACKAGE2_SIZE];
    if package3.len() != p2_b.len() {
        return Err(CryptoError::InvalidInput);
    }
    p2_b.copy_from_slice(package3);

    let hash_ba = crypto_core::sender_final(&mut p2_b, &mut receiver_state.x448_secret_b, &mut receiver_state.hqc_secret_b)
        .map_err(|_| CryptoError::PqcOperationFailed)?;

    let mut combo = [0u8; ARGON2_OUTPUT_SIZE * 2];
    combo[..ARGON2_OUTPUT_SIZE].copy_from_slice(&receiver_state.hash_ab);
    combo[ARGON2_OUTPUT_SIZE..].copy_from_slice(&hash_ba);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&receiver_state.hash_ab[..16]);

    let mut final_vec = argon2id_derive(&mut combo, &mut salt, ARGON2_OUTPUT_SIZE).map_err(|_| CryptoError::HashingFailed)?;
    if final_vec.len() != ARGON2_OUTPUT_SIZE {
        return Err(CryptoError::InvalidInput);
    }
    let mut final_key = [0u8; ARGON2_OUTPUT_SIZE];
    final_key.copy_from_slice(&final_vec);

    secure_zero(&mut p2_b[..]);
    secure_zero(&mut combo[..]);
    secure_zero(&mut salt[..]);
    final_vec.zeroize();

    Ok(final_key)
}
