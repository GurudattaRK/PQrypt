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
#define CRYPTO_ERROR_HASHING_FAILED -2
#define CRYPTO_ERROR_ENCRYPTION_FAILED -3
#define CRYPTO_ERROR_DECRYPTION_FAILED -4
#define CRYPTO_ERROR_KEY_GENERATION_FAILED -5
#define CRYPTO_ERROR_INVALID_INPUT -6
#define CRYPTO_ERROR_MEMORY_ALLOCATION -7
// Extended errors
#define CRYPTO_ERROR_IO -10
#define CRYPTO_ERROR_FORMAT -11
#define CRYPTO_ERROR_UNSUPPORTED -12

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

// Unified password generator (one-shot) with bitmask flags (lowercase/uppercase/digits always included)
int generate_password_unified_c(
    const unsigned char* app_name,
    size_t app_name_len,
    const unsigned char* app_password,
    size_t app_password_len,
    const unsigned char* master_password,
    size_t master_password_len,
    size_t desired_len,
    unsigned int enabled_sets_mask,
    char* output,
    size_t* output_len
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

// New: FD-based file encryption/decryption (PQRYPT2, streaming)
int triple_encrypt_fd_c(
    const unsigned char* secret,
    unsigned long secret_len,  
    int is_keyfile,
    int in_fd,
    int out_fd
);

int triple_decrypt_fd_c(
    const unsigned char* secret,
    unsigned long secret_len,  
    int is_keyfile,
    int in_fd,
    int out_fd
);


#ifdef __cplusplus
}
#endif

#endif // C_FFI_H
