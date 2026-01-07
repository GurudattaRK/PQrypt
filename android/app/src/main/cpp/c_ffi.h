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

// Unified 64-byte password derivation (UPDATED)
int derive_password_hash_unified_64_c(
    const unsigned char* app_name,
    size_t app_name_len,
    const unsigned char* app_password,
    size_t app_password_len,
    const unsigned char* master_password,
    size_t master_password_len,
    unsigned char* out,
    size_t out_len
);

// Generate password from already-derived hash
int generate_password_from_hash_c(
    const unsigned char* hash_64,  // UPDATED: now 64 bytes
    size_t hash_len,
    size_t desired_len,
    unsigned int enabled_sets_mask,
    char* output,
    size_t* output_len
);

// Hybrid Key Exchange Functions (UPDATED - 3 functions instead of 4)
int hybrid_sender_init_c(
    unsigned char* package1,
    size_t* package1_len
);

int hybrid_receiver_c(
    const unsigned char* package1,
    size_t package1_len,
    unsigned char* derived_hash,
    unsigned char* package2,
    size_t* package2_len
);

int hybrid_sender_final_c(
    const unsigned char* package2,
    size_t package2_len,
    unsigned char* derived_hash
);

// Dual mutual exchange
int hybrid_receiver_dual_c(
    const unsigned char* package1,
    size_t package1_len,
    unsigned char* package2_bundle,
    size_t* package2_bundle_len
);

int hybrid_sender_third_c(
    const unsigned char* package2_bundle,
    size_t package2_bundle_len,
    unsigned char* package3_out,
    size_t* package3_out_len,
    unsigned char* final_hash_out
);

int hybrid_receiver_final_dual_c(
    const unsigned char* package3,
    size_t package3_len,
    unsigned char* final_hash_out
);

// New: Double encryption (ChaCha20 + AES-GCM) (UPDATED)
int double_encrypt_fd_c(
    const unsigned char* secret,
    unsigned long secret_len,
    int is_keyfile,
    int in_fd,
    int out_fd
);

int double_decrypt_fd_c(
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
