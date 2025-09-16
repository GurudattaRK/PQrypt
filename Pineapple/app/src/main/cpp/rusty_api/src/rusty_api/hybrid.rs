use super::constants_errors::*;
use super::asymmetric::{crypto_kyber1024_keypair, crypto_kyber1024_encaps, crypto_kyber1024_decaps, crypto_hqc256_keypair, crypto_hqc256_encaps, crypto_hqc256_decaps, crypto_x448_keypair, crypto_x448_shared_secret, crypto_p521_keypair, crypto_p521_shared_secret, crypto_slh_dsa_keypair, crypto_slh_dsa_sign, crypto_slh_dsa_verify};
use super::utils::{encrypt_key_with_shared_secret, decrypt_key_with_shared_secret};
use super::symmetric::argon2id_hash;
use zeroize::Zeroize;
use serde::{Serialize, Deserialize};
use serde_arrays::*;

// HYBRID KEY EXCHANGE TYPE DEFINITIONS

#[derive(Serialize, Deserialize)]
pub struct KyberX448SenderState(
    #[serde(with = "serde_arrays")] pub [u8; KYBER_SECRETKEYBYTES], 
    #[serde(with = "serde_arrays")] pub [u8; X448_KEY_SIZE], 
    #[serde(with = "serde_arrays")] pub [u8; X448_KEY_SIZE]
);

#[derive(Serialize, Deserialize)]
pub struct KyberX448ReceiverState(
    #[serde(with = "serde_arrays")] pub [u8; KYBER_SECRETKEYBYTES], 
    #[serde(with = "serde_arrays")] pub [u8; X448_KEY_SIZE]
);

#[derive(Serialize, Deserialize)]
pub struct HqcP521SenderState(
    #[serde(with = "serde_arrays")] pub [u8; HQC256_SECRETKEYBYTES], 
    #[serde(with = "serde_arrays")] pub [u8; P521_KEY_SIZE], 
    #[serde(with = "serde_arrays")] pub [u8; P521_SECRET_SIZE]
);

#[derive(Serialize, Deserialize)]
pub struct HqcP521ReceiverState(
    #[serde(with = "serde_arrays")] pub [u8; HQC256_SECRETKEYBYTES], 
    #[serde(with = "serde_arrays")] pub [u8; P521_SECRET_SIZE]
);

#[derive(Serialize, Deserialize)]
pub struct HybridSenderState(
    pub KyberX448SenderState,
    pub HqcP521SenderState,
    #[serde(with = "serde_arrays")] pub [u8; SLH_DSA_SECRETKEYBYTES],
    #[serde(with = "serde_arrays")] pub [u8; SLH_DSA_PUBKEYBYTES]
);

#[derive(Serialize, Deserialize)]
pub struct HybridReceiverState(
    pub KyberX448ReceiverState,
    pub HqcP521ReceiverState,
    #[serde(with = "serde_arrays")] pub [u8; SLH_DSA_SECRETKEYBYTES],
    #[serde(with = "serde_arrays")] pub [u8; SLH_DSA_PUBKEYBYTES]
);

// AAD for SLH-DSA domain separation in this protocol
const SLH_DSA_AAD: &[u8] = b"PQrypt:PQC4:SLH-DSA:v1";

// Helper: Pack content into a signed .key file with header + content + signature + signer public key
fn pack_signed_keyfile(
    content: &[u8],
    signer_sk: &[u8; SLH_DSA_SECRETKEYBYTES],
    signer_pk: &[u8; SLH_DSA_PUBKEYBYTES]
) -> Result<Vec<u8>, CryptoError> {
    let signature = crypto_slh_dsa_sign(signer_sk, content, SLH_DSA_AAD, true)?;
    if signature.len() != SLH_DSA_SIGNATUREBYTES {
        return Err(CryptoError::PqcOperationFailed);
    }
    let mut out = Vec::with_capacity(SLH_DSA_HEADER_SIZE + content.len() + signature.len() + signer_pk.len());
    out.extend_from_slice(&SLH_DSA_HEADER_MAGIC);
    out.extend_from_slice(&(content.len() as u64).to_le_bytes());
    out.extend_from_slice(&(signature.len() as u64).to_le_bytes());
    out.extend_from_slice(&(signer_pk.len() as u64).to_le_bytes());
    out.extend_from_slice(content);
    out.extend_from_slice(&signature);
    out.extend_from_slice(signer_pk);
    Ok(out)
}

// Helper: Unpack and verify a signed .key file; returns the inner content
fn unpack_and_verify_keyfile(signed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if signed.len() < SLH_DSA_HEADER_SIZE { return Err(CryptoError::InvalidInput); }
    if &signed[0..8] != &SLH_DSA_HEADER_MAGIC { return Err(CryptoError::InvalidInput); }
    let content_len = u64::from_le_bytes(signed[8..16].try_into().unwrap()) as usize;
    let sig_len = u64::from_le_bytes(signed[16..24].try_into().unwrap()) as usize;
    let pk_len = u64::from_le_bytes(signed[24..32].try_into().unwrap()) as usize;
    let header_end = SLH_DSA_HEADER_SIZE;
    let total_needed = header_end
        .checked_add(content_len).ok_or(CryptoError::IntegerOverflow)?
        .checked_add(sig_len).ok_or(CryptoError::IntegerOverflow)?
        .checked_add(pk_len).ok_or(CryptoError::IntegerOverflow)?;
    if signed.len() != total_needed { return Err(CryptoError::InvalidInput); }
    if sig_len != SLH_DSA_SIGNATUREBYTES || pk_len != SLH_DSA_PUBKEYBYTES { return Err(CryptoError::InvalidInput); }
    let content_start = header_end;
    let sig_start = content_start + content_len;
    let pk_start = sig_start + sig_len;
    let content = &signed[content_start..sig_start];
    let signature = &signed[sig_start..pk_start];
    let signer_pk: [u8; SLH_DSA_PUBKEYBYTES] = signed[pk_start..].try_into().map_err(|_| CryptoError::InvalidInput)?;
    let verified = crypto_slh_dsa_verify(&signer_pk, content, signature, SLH_DSA_AAD)?;
    if !verified { return Err(CryptoError::AuthenticationFailed); }
    Ok(content.to_vec())
}

//MARK: KYBER+X448 HYBRID KEY EXCHANGE

/// Initialize Kyber+X448 key exchange
pub fn mlkem_x448_init() -> Result<([u8; KYBER_PUBLICKEYBYTES], KyberX448SenderState), CryptoError> {
    let (sender_kyber_pk, sender_kyber_sk) = crypto_kyber1024_keypair()?;
    let (sender_x448_pk, sender_x448_sk) = crypto_x448_keypair()?;
    let sender_state = KyberX448SenderState(sender_kyber_sk, sender_x448_pk, sender_x448_sk);
    Ok((sender_kyber_pk, sender_state))
}

/// Kyber+X448 receiver response with secure key encryption
pub fn mlkem_x448_recv(
    sender_kyber_pk: &[u8; KYBER_PUBLICKEYBYTES]
) -> Result<(Vec<u8>, KyberX448ReceiverState), CryptoError> {
    let (receiver_kyber_pk, receiver_kyber_sk) = crypto_kyber1024_keypair()?;
    let (receiver_x448_pk, receiver_x448_sk) = crypto_x448_keypair()?;
    
    // Encapsulate with sender's Kyber public key
    let (kyber_ciphertext, kyber_shared_secret) = crypto_kyber1024_encaps(sender_kyber_pk)?;
    
    // Encrypt receiver's X448 public key using Kyber shared secret
    let encrypted_x448_pk = encrypt_key_with_shared_secret(&receiver_x448_pk, &kyber_shared_secret)?;
    
    // Bundle: encrypted_x448_pk_len(4) + encrypted_x448_pk + kyber_ciphertext + receiver_kyber_pk
    let mut bundled_data = Vec::new();
    bundled_data.extend_from_slice(&(encrypted_x448_pk.len() as u32).to_le_bytes());
    bundled_data.extend_from_slice(&encrypted_x448_pk);
    bundled_data.extend_from_slice(&kyber_ciphertext);
    bundled_data.extend_from_slice(&receiver_kyber_pk);
    
    let receiver_state = KyberX448ReceiverState(receiver_kyber_sk, receiver_x448_sk);
    Ok((bundled_data, receiver_state))
}

/// Complete Kyber+X448 exchange with security validation
pub fn mlkem_x448_snd_final(
    receiver_bundle: &[u8],
    sender_state: &KyberX448SenderState
) -> Result<([u8; X448_KEY_SIZE], Vec<u8>), CryptoError> {
    let KyberX448SenderState(sender_kyber_sk, sender_x448_pk, sender_x448_sk) = sender_state;
    
    if receiver_bundle.len() < 4 {
        return Err(CryptoError::InvalidInput);
    }
    
    // Parse bundle
    let encrypted_x448_len = u32::from_le_bytes([
        receiver_bundle[0], receiver_bundle[1], receiver_bundle[2], receiver_bundle[3]
    ]) as usize;
    
    let expected_bundle_size = 4 + encrypted_x448_len + KYBER_CIPHERTEXTBYTES + KYBER_PUBLICKEYBYTES;
    if receiver_bundle.len() != expected_bundle_size {
        return Err(CryptoError::InvalidInput);
    }
    
    let encrypted_receiver_x448_pk = &receiver_bundle[4..4 + encrypted_x448_len];
    let kyber_ciphertext: [u8; KYBER_CIPHERTEXTBYTES] = receiver_bundle[4 + encrypted_x448_len..4 + encrypted_x448_len + KYBER_CIPHERTEXTBYTES]
        .try_into()
        .map_err(|_| CryptoError::InvalidInput)?;
    let receiver_kyber_pk: [u8; KYBER_PUBLICKEYBYTES] = receiver_bundle[4 + encrypted_x448_len + KYBER_CIPHERTEXTBYTES..]
        .try_into()
        .map_err(|_| CryptoError::InvalidInput)?;
    
    // Decrypt receiver's X448 public key
    let kyber_shared_secret = crypto_kyber1024_decaps(&kyber_ciphertext, sender_kyber_sk)?;
    let receiver_x448_pk_bytes = decrypt_key_with_shared_secret(encrypted_receiver_x448_pk, &kyber_shared_secret)?;
    
    if receiver_x448_pk_bytes.len() != X448_KEY_SIZE {
        return Err(CryptoError::InvalidInput);
    }
    
    let receiver_x448_pk: [u8; X448_KEY_SIZE] = receiver_x448_pk_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidInput)?;
    
    // Generate sender's response
    let (sender_kyber_ciphertext, sender_kyber_shared_secret) = crypto_kyber1024_encaps(&receiver_kyber_pk)?;
    let encrypted_sender_x448_pk = encrypt_key_with_shared_secret(sender_x448_pk, &sender_kyber_shared_secret)?;
    
    // Create sender's final bundle
    let mut sender_final_bundle = Vec::new();
    sender_final_bundle.extend_from_slice(&(encrypted_sender_x448_pk.len() as u32).to_le_bytes());
    sender_final_bundle.extend_from_slice(&encrypted_sender_x448_pk);
    sender_final_bundle.extend_from_slice(&sender_kyber_ciphertext);
    
    // Compute final shared secret
    let final_shared_secret = crypto_x448_shared_secret(&receiver_x448_pk, sender_x448_sk)?;
    
    Ok((final_shared_secret, sender_final_bundle))
}

/// Finalize Kyber+X448 exchange
pub fn mlkem_x448_recv_final(
    sender_final_bundle: &[u8],
    receiver_state: &KyberX448ReceiverState
) -> Result<[u8; X448_KEY_SIZE], CryptoError> {
    let KyberX448ReceiverState(receiver_kyber_sk, receiver_x448_sk) = receiver_state;
    
    if sender_final_bundle.len() < 4 {
        return Err(CryptoError::InvalidInput);
    }
    
    let encrypted_x448_len = u32::from_le_bytes([
        sender_final_bundle[0], sender_final_bundle[1], 
        sender_final_bundle[2], sender_final_bundle[3]
    ]) as usize;
    
    let expected_size = 4 + encrypted_x448_len + KYBER_CIPHERTEXTBYTES;
    if sender_final_bundle.len() != expected_size {
        return Err(CryptoError::InvalidInput);
    }
    
    let encrypted_sender_x448_pk = &sender_final_bundle[4..4 + encrypted_x448_len];
    let sender_kyber_ciphertext: [u8; KYBER_CIPHERTEXTBYTES] = sender_final_bundle[4 + encrypted_x448_len..]
        .try_into()
        .map_err(|_| CryptoError::InvalidInput)?;
    
    // Decrypt sender's X448 public key
    let sender_kyber_shared_secret = crypto_kyber1024_decaps(&sender_kyber_ciphertext, receiver_kyber_sk)?;
    let sender_x448_pk_bytes = decrypt_key_with_shared_secret(encrypted_sender_x448_pk, &sender_kyber_shared_secret)?;
    
    if sender_x448_pk_bytes.len() != X448_KEY_SIZE {
        return Err(CryptoError::InvalidInput);
    }
    
    let sender_x448_pk: [u8; X448_KEY_SIZE] = sender_x448_pk_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidInput)?;
    
    // Compute final shared secret
    crypto_x448_shared_secret(&sender_x448_pk, receiver_x448_sk)
}

//MARK: HQC+P521 HYBRID KEY EXCHANGE

/// Initialize HQC+P521 key exchange
pub fn hqc_p521_init() -> Result<([u8; HQC256_PUBLICKEYBYTES], HqcP521SenderState), CryptoError> {
    let (sender_hqc_pk, sender_hqc_sk) = crypto_hqc256_keypair()?;
    let (sender_p521_pk, sender_p521_sk) = crypto_p521_keypair()?;
    let sender_state = HqcP521SenderState(sender_hqc_sk, sender_p521_pk, sender_p521_sk);
    Ok((sender_hqc_pk, sender_state))
}

/// HQC+P521 receiver response with secure key encryption
pub fn hqc_p521_recv(
    sender_hqc_pk: &[u8]
) -> Result<(Vec<u8>, HqcP521ReceiverState), CryptoError> {
    let (receiver_hqc_pk, receiver_hqc_sk) = crypto_hqc256_keypair()?;
    let (receiver_p521_pk, receiver_p521_sk) = crypto_p521_keypair()?;
    
    // Encapsulate with sender's HQC public key
    let (hqc_ciphertext, hqc_shared_secret) = crypto_hqc256_encaps(sender_hqc_pk)?;
    
    // Encrypt receiver's P521 public key using HQC shared secret
    let encrypted_p521_pk = encrypt_key_with_shared_secret(&receiver_p521_pk, &hqc_shared_secret)?;
    
    // Bundle: encrypted_p521_pk_len(4) + encrypted_p521_pk + hqc_ciphertext + receiver_hqc_pk
    let mut bundled_data = Vec::new();
    bundled_data.extend_from_slice(&(encrypted_p521_pk.len() as u32).to_le_bytes());
    bundled_data.extend_from_slice(&encrypted_p521_pk);
    bundled_data.extend_from_slice(&hqc_ciphertext);
    bundled_data.extend_from_slice(&receiver_hqc_pk);
    
    let receiver_state = HqcP521ReceiverState(receiver_hqc_sk, receiver_p521_sk);
    Ok((bundled_data, receiver_state))
}

/// Complete HQC+P521 exchange
pub fn hqc_p521_snd_final(
    receiver_bundle: &[u8],
    sender_state: &HqcP521SenderState
) -> Result<([u8; P521_SECRET_SIZE], Vec<u8>), CryptoError> {
    let HqcP521SenderState(sender_hqc_sk, sender_p521_pk, sender_p521_sk) = sender_state;
    
    if receiver_bundle.len() < 4 {
        return Err(CryptoError::InvalidInput);
    }
    
    // Parse bundle
    let encrypted_p521_len = u32::from_le_bytes([
        receiver_bundle[0], receiver_bundle[1], receiver_bundle[2], receiver_bundle[3]
    ]) as usize;
    
    if receiver_bundle.len() < 4 + encrypted_p521_len + HQC256_PUBLICKEYBYTES {
        return Err(CryptoError::InvalidInput);
    }
    
    let encrypted_receiver_p521_pk = &receiver_bundle[4..4 + encrypted_p521_len];
    let remaining = &receiver_bundle[4 + encrypted_p521_len..];
    
    let hqc_ciphertext = &remaining[..remaining.len() - HQC256_PUBLICKEYBYTES];
    let receiver_hqc_pk = &remaining[remaining.len() - HQC256_PUBLICKEYBYTES..];
    
    // Decrypt receiver's P521 public key
    let hqc_shared_secret = crypto_hqc256_decaps(hqc_ciphertext, sender_hqc_sk)?;
    let receiver_p521_pk_bytes = decrypt_key_with_shared_secret(encrypted_receiver_p521_pk, &hqc_shared_secret)?;
    
    if receiver_p521_pk_bytes.len() != P521_KEY_SIZE {
        return Err(CryptoError::InvalidInput);
    }
    
    let receiver_p521_pk: [u8; P521_KEY_SIZE] = receiver_p521_pk_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidInput)?;
    
    // Generate sender's response
    let (sender_hqc_ciphertext, sender_hqc_shared_secret) = crypto_hqc256_encaps(receiver_hqc_pk)?;
    let encrypted_sender_p521_pk = encrypt_key_with_shared_secret(sender_p521_pk, &sender_hqc_shared_secret)?;
    
    let mut sender_final_bundle = Vec::new();
    sender_final_bundle.extend_from_slice(&(encrypted_sender_p521_pk.len() as u32).to_le_bytes());
    sender_final_bundle.extend_from_slice(&encrypted_sender_p521_pk);
    sender_final_bundle.extend_from_slice(&sender_hqc_ciphertext);
    
    // Compute final shared secret
    let final_secret = crypto_p521_shared_secret(&receiver_p521_pk, sender_p521_sk)?;
    
    Ok((final_secret, sender_final_bundle))
}

/// Finalize HQC+P521 exchange
pub fn hqc_p521_recv_final(
    sender_final_bundle: &[u8],
    receiver_state: &HqcP521ReceiverState
) -> Result<[u8; P521_SECRET_SIZE], CryptoError> {
    let HqcP521ReceiverState(receiver_hqc_sk, receiver_p521_sk) = receiver_state;
    
    if sender_final_bundle.len() < 4 {
        return Err(CryptoError::InvalidInput);
    }
    
    // Parse bundle
    let encrypted_p521_len = u32::from_le_bytes([
        sender_final_bundle[0], sender_final_bundle[1], sender_final_bundle[2], sender_final_bundle[3]
    ]) as usize;
    
    if sender_final_bundle.len() < 4 + encrypted_p521_len {
        return Err(CryptoError::InvalidInput);
    }
    
    let encrypted_sender_p521_pk = &sender_final_bundle[4..4 + encrypted_p521_len];
    let sender_hqc_ciphertext = &sender_final_bundle[4 + encrypted_p521_len..];
    
    // Decrypt sender's P521 public key
    let sender_hqc_shared_secret = crypto_hqc256_decaps(sender_hqc_ciphertext, receiver_hqc_sk)?;
    let sender_p521_pk_bytes = decrypt_key_with_shared_secret(encrypted_sender_p521_pk, &sender_hqc_shared_secret)?;
    
    if sender_p521_pk_bytes.len() != P521_KEY_SIZE {
        return Err(CryptoError::InvalidInput);
    }
    
    let sender_p521_pk: [u8; P521_KEY_SIZE] = sender_p521_pk_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidInput)?;
    
    // Compute final shared secret
    crypto_p521_shared_secret(&sender_p521_pk, receiver_p521_sk)
}

/// Initialize layered hybrid key exchange
pub fn pqc_4hybrid_init() -> Result<(Vec<u8>, HybridSenderState), CryptoError> {
    let (impl1_kyber_pk, impl1_sender_state) = mlkem_x448_init()?;
    let (impl2_hqc_pk, impl2_sender_state) = hqc_p521_init()?;

    // Prepare unsigned content of 1.key  => [KyberPK | HQCPK]
    let mut hybrid_1_content = Vec::new();
    hybrid_1_content.extend_from_slice(&impl1_kyber_pk);
    hybrid_1_content.extend_from_slice(&impl2_hqc_pk);

    // Generate Alice's SLH-DSA keypair and sign 1.key content
    let (alice_slh_pk, alice_slh_sk) = crypto_slh_dsa_keypair()?;
    let hybrid_1_signed = pack_signed_keyfile(&hybrid_1_content, &alice_slh_sk, &alice_slh_pk)?;

    let hybrid_sender_state = HybridSenderState(impl1_sender_state, impl2_sender_state, alice_slh_sk, alice_slh_pk);
    Ok((hybrid_1_signed, hybrid_sender_state))
}

/// Layered hybrid receiver response
pub fn pqc_4hybrid_recv(
    hybrid_1_key: &[u8]
) -> Result<(Vec<u8>, HybridReceiverState), CryptoError> {
    // Verify and extract content from signed 1.key
    let content = unpack_and_verify_keyfile(hybrid_1_key)?;
    if content.len() != KYBER_PUBLICKEYBYTES + HQC256_PUBLICKEYBYTES {
        return Err(CryptoError::InvalidInput);
    }
    let impl1_kyber_pk: [u8; KYBER_PUBLICKEYBYTES] = content[0..KYBER_PUBLICKEYBYTES]
        .try_into()
        .map_err(|_| CryptoError::InvalidInput)?;
    let impl2_hqc_pk = &content[KYBER_PUBLICKEYBYTES..];
    
    // Process first implementation (Kyber+X448)
    let (impl1_bundle, impl1_receiver_state) = mlkem_x448_recv(&impl1_kyber_pk)?;
    println!("DEBUG: impl1_bundle size: {}", impl1_bundle.len());
    
    // Process second implementation (HQC+P521) 
    let (impl2_bundle, impl2_receiver_state) = hqc_p521_recv(impl2_hqc_pk)?;
    println!("DEBUG: impl2_bundle size: {}", impl2_bundle.len());
    
    // Combine both bundles into content
    let mut hybrid_2_content = Vec::new();
    hybrid_2_content.extend_from_slice(&(impl1_bundle.len() as u32).to_le_bytes());
    hybrid_2_content.extend_from_slice(&impl1_bundle);
    hybrid_2_content.extend_from_slice(&impl2_bundle);

    // Generate Bob's SLH-DSA keypair and sign 2.key content
    let (bob_slh_pk, bob_slh_sk) = crypto_slh_dsa_keypair()?;
    let hybrid_2_signed = pack_signed_keyfile(&hybrid_2_content, &bob_slh_sk, &bob_slh_pk)?;

    let hybrid_receiver_state = HybridReceiverState(impl1_receiver_state, impl2_receiver_state, bob_slh_sk, bob_slh_pk);
    Ok((hybrid_2_signed, hybrid_receiver_state))
}

pub fn pqc_4hybrid_snd_final(
    hybrid_2_key: &[u8],
    hybrid_sender_state: &HybridSenderState
) -> Result<([u8; 128], Vec<u8>), CryptoError> {
    let impl1_sender_state = &hybrid_sender_state.0;
    let impl2_sender_state = &hybrid_sender_state.1;
    let alice_slh_sk = &hybrid_sender_state.2;
    let alice_slh_pk = &hybrid_sender_state.3;

    // Verify and extract content from signed 2.key
    let content = unpack_and_verify_keyfile(hybrid_2_key)?;
    if content.len() < 4 { return Err(CryptoError::InvalidInput); }

    // Parse impl1 bundle
    let impl1_bundle_len = u32::from_le_bytes([
        content[0], content[1], content[2], content[3]
    ]) as usize;
    if content.len() < 4 + impl1_bundle_len { return Err(CryptoError::InvalidInput); }
    let impl1_bundle = &content[4..4 + impl1_bundle_len];
    let impl2_bundle = &content[4 + impl1_bundle_len..];
    
    // Complete both exchanges
    let (impl1_final_secret, impl1_final_bundle) = mlkem_x448_snd_final(impl1_bundle, impl1_sender_state)?;
    let (impl2_final_secret, impl2_final_bundle) = hqc_p521_snd_final(impl2_bundle, impl2_sender_state)?;
    
    // Securely combine secrets using Argon2 (122 -> 128 bytes)
    let mut combined_secrets = [0u8; 122];
    combined_secrets[0..56].copy_from_slice(&impl1_final_secret);
    combined_secrets[56..122].copy_from_slice(&impl2_final_secret);

    // Use the exact same salt as rustUI for deterministic compatibility
    let salt: [u8; 32] = [
        0x7c, 0x3f, 0xa8, 0x51, 0x94, 0x2b, 0xe6, 0x79,
        0x1d, 0x45, 0x82, 0x36, 0xf9, 0x5a, 0x17, 0xc4,
        0x68, 0x9e, 0x23, 0xd7, 0x4f, 0x85, 0x31, 0xb2,
        0x76, 0x19, 0xac, 0x58, 0x93, 0x27, 0xe4, 0x6b
    ];

    let final_key = argon2id_hash(&combined_secrets, &salt, 128, 10240, 1, 1)?;
    
    let final_key_array: [u8; 128] = final_key
        .try_into()
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    
    // Combine final bundles and sign 3.key with Alice's SLH-DSA
    let mut hybrid_3_content = Vec::new();
    hybrid_3_content.extend_from_slice(&(impl1_final_bundle.len() as u32).to_le_bytes());
    hybrid_3_content.extend_from_slice(&impl1_final_bundle);
    hybrid_3_content.extend_from_slice(&impl2_final_bundle);

    // Zeroize intermediate secrets
    let mut combined_secrets_mut = combined_secrets;
    combined_secrets_mut.zeroize();

    let hybrid_3_signed = pack_signed_keyfile(&hybrid_3_content, alice_slh_sk, alice_slh_pk)?;
    Ok((final_key_array, hybrid_3_signed))
}

/// Finalize layered hybrid exchange  
pub fn pqc_4hybrid_recv_final(
    hybrid_3_key: &[u8],
    hybrid_receiver_state: &HybridReceiverState
) -> Result<[u8; 128], CryptoError> {
    let impl1_receiver_state = &hybrid_receiver_state.0;
    let impl2_receiver_state = &hybrid_receiver_state.1;
    let _bob_slh_sk = &hybrid_receiver_state.2;
    let _bob_slh_pk = &hybrid_receiver_state.3;

    // Verify and extract content from signed 3.key
    let content = unpack_and_verify_keyfile(hybrid_3_key)?;
    if content.len() < 4 { return Err(CryptoError::InvalidInput); }

    // Parse impl1 final bundle
    let impl1_final_bundle_len = u32::from_le_bytes([
        content[0], content[1], content[2], content[3]
    ]) as usize;
    if content.len() < 4 + impl1_final_bundle_len { return Err(CryptoError::InvalidInput); }
    let impl1_final_bundle = &content[4..4 + impl1_final_bundle_len];
    let impl2_final_bundle = &content[4 + impl1_final_bundle_len..];
    
    // Finalize both exchanges
    let impl1_final_secret = mlkem_x448_recv_final(impl1_final_bundle, impl1_receiver_state)?;
    let impl2_final_secret = hqc_p521_recv_final(impl2_final_bundle, impl2_receiver_state)?;
    
    // Securely combine secrets using Argon2 (122 -> 128 bytes)
    let mut combined_secrets = [0u8; 122];
    combined_secrets[0..56].copy_from_slice(&impl1_final_secret);
    combined_secrets[56..122].copy_from_slice(&impl2_final_secret);
    
    // Use the exact same salt as rustUI for deterministic compatibility
    let salt: [u8; 32] = [
        0x7c, 0x3f, 0xa8, 0x51, 0x94, 0x2b, 0xe6, 0x79,
        0x1d, 0x45, 0x82, 0x36, 0xf9, 0x5a, 0x17, 0xc4,
        0x68, 0x9e, 0x23, 0xd7, 0x4f, 0x85, 0x31, 0xb2,
        0x76, 0x19, 0xac, 0x58, 0x93, 0x27, 0xe4, 0x6b
    ];
    
    let final_key = argon2id_hash(&combined_secrets, &salt, 128, 10240, 1, 1)?;
    
    let final_key_array: [u8; 128] = final_key
        .try_into()
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    
    // Zeroize intermediate secrets
    let mut combined_secrets_mut = combined_secrets;
    combined_secrets_mut.zeroize();
    
    Ok(final_key_array)
}
