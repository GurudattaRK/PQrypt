#ifndef SIMPLE_CFFI_H
#define SIMPLE_CFFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Return codes
#define CRYPTO_SUCCESS 0
#define CRYPTO_ERROR_NULL_POINTER -1
#define CRYPTO_ERROR_HASHING_FAILED -6
#define CRYPTO_ERROR_ENCRYPTION_FAILED -7
#define CRYPTO_ERROR_DECRYPTION_FAILED -3
#define CRYPTO_ERROR_KEY_GENERATION_FAILED -8
#define CRYPTO_ERROR_INVALID_INPUT -4
#define CRYPTO_ERROR_MEMORY_ALLOCATION -5

// Core cryptographic functions
int argon2_hash_c(
    const unsigned char* password,
    size_t password_len,
    const unsigned char* salt,
    size_t salt_len,
    unsigned char* output,
    size_t output_len
);

int triple_encrypt_c(
    const unsigned char* key,
    const unsigned char* plaintext,
    size_t plaintext_len,
    unsigned char* output,
    size_t* output_len
);

int triple_decrypt_c(
    const unsigned char* key,
    const unsigned char* ciphertext,
    size_t ciphertext_len,
    unsigned char* output,
    size_t* output_len
);

int generate_password_c(
    unsigned char mode,
    const unsigned char* hash_bytes,
    size_t hash_len,
    size_t desired_len,
    const unsigned char* enabled_sets,
    char* output,
    size_t* output_len
);

// Unified 128-byte password derivation
int derive_password_hash_unified_128_c(
    const unsigned char* app_name,
    size_t app_name_len,
    const unsigned char* app_password,
    size_t app_password_len,
    const unsigned char* master_password,
    size_t master_password_len,
    unsigned char* out,
    size_t out_len
);

// Basic key generation functions
int kyber_keypair_c(
    unsigned char* public_key,
    unsigned char* secret_key
);

int x448_keypair_c(
    unsigned char* public_key,
    unsigned char* private_key
);

// PQC 4-Algorithm Hybrid Key Exchange Functions
int pqc_4hybrid_init_c(
    unsigned char* hybrid_1_key,
    size_t* hybrid_1_key_len,
    unsigned char* sender_state,
    size_t* sender_state_len
);

int pqc_4hybrid_recv_c(
    const unsigned char* hybrid_1_key,
    size_t hybrid_1_key_len,
    unsigned char* hybrid_2_key,
    size_t* hybrid_2_key_len,
    unsigned char* receiver_state,
    size_t* receiver_state_len
);

int pqc_4hybrid_snd_final_c(
    const unsigned char* hybrid_2_key,
    size_t hybrid_2_key_len,
    const unsigned char* sender_state,
    size_t sender_state_len,
    unsigned char* final_key,
    unsigned char* hybrid_3_key,
    size_t* hybrid_3_key_len
);

int pqc_4hybrid_recv_final_c(
    const unsigned char* hybrid_3_key,
    size_t hybrid_3_key_len,
    const unsigned char* receiver_state,
    size_t receiver_state_len,
    unsigned char* final_key
);

#ifdef __cplusplus
}
#endif

#endif // C_FFI_H
