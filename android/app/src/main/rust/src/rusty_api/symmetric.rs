use argon2::{Argon2, Algorithm, Version, Params};
use serpent::{Serpent, cipher::{BlockEncrypt, BlockDecrypt}};
use serpent::cipher::generic_array::GenericArray;

use super::constants_errors::*;

// MARK: argon2id_hash
#[inline]
pub fn argon2id_hash(
    password: &[u8],
    salt: &[u8; 32],
    output_len: usize,
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, CryptoError> {
    if output_len == 0 || output_len > 1024 {
        return Err(CryptoError::InvalidParameters);
    }
    
    let params = Params::new(memory_kb, iterations, parallelism, Some(output_len))
        .map_err(|_| CryptoError::InvalidParameters)?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash_output = vec![0u8; output_len];
    
    argon2.hash_password_into(password, salt, &mut hash_output)
        .map_err(|_| CryptoError::HashingFailed)?;
    
    Ok(hash_output)
}

// MARK: serpent_encrypt_inplace
#[inline(always)]
pub fn serpent_encrypt_inplace(
    cipher: &Serpent,
    block: &mut [u8; 16]
) {
    let block_ga = GenericArray::from_mut_slice(block);
    cipher.encrypt_block(block_ga);
}

// MARK: serpent_decrypt_inplace
#[inline(always)]
pub fn serpent_decrypt_inplace(
    cipher: &Serpent,
    block: &mut [u8; 16]
) {
    let block_ga = GenericArray::from_mut_slice(block);
    cipher.decrypt_block(block_ga);
}
