pub mod openssl_ffi;
pub mod hybrids;

// Re-export key functions for easier access
pub use openssl_ffi::{
    argon2id_derive, secure_zero,
    chacha20_encrypt, chacha20_decrypt,
    aes_encrypt_with_aad, aes_decrypt_with_aad,
    x448mlkem1024_keygen, x448mlkem1024_encaps, x448mlkem1024_decaps,
    hqc_p521_keygen, hqc_p521_encaps, hqc_p521_decaps,
    slhdsa_keygen, slhdsa_sign, slhdsa_verify,
};
pub use hybrids::{double_encrypt, double_decrypt, sender_init, receiver, sender_final};
