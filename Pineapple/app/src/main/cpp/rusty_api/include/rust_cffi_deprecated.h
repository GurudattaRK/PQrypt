/**
 * Cryptographic Library - C Interface

 * 
 * This header provides C-compatible bindings for use from C/C++, Objective-C,
 * Java (via JNI), Kotlin Native, and other languages that can call C libraries.

 */

#ifndef PINEAPPLE_CRYPTO_H
#define PINEAPPLE_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// CONSTANTS
// ============================================================================

/** AES-256-GCM key size in bytes */
#define AES256_KEY_SIZE 32

/** AES-256-GCM IV size in bytes */
#define AES256_IV_SIZE 12

/** AES-256-GCM authentication tag size in bytes */
#define AES256_TAG_SIZE 16

/** Serpent-256 key size in bytes */
#define SERPENT_KEY_SIZE 32

/** Serpent block size in bytes */
#define SERPENT_BLOCK_SIZE 16

/** X448 key size in bytes */
#define X448_KEY_SIZE 56

/** Kyber-1024 public key size in bytes */
#define KYBER_PUBLICKEYBYTES 1568

/** Kyber-1024 secret key size in bytes */
#define KYBER_SECRETKEYBYTES 3168

/** Kyber-1024 ciphertext size in bytes */
#define KYBER_CIPHERTEXTBYTES 1568

/** Argon2ID salt size in bytes */
#define ARGON2_SALT_SIZE 16

/** Argon2ID hash output size in bytes */
#define ARGON2_HASH_SIZE 32

// ============================================================================
// ERROR CODES
// ============================================================================

/** Operation completed successfully */
#define CRYPTO_SUCCESS 0

/** Null pointer passed as argument */
#define CRYPTO_ERROR_NULL_POINTER -1

/** Invalid length parameter */
#define CRYPTO_ERROR_INVALID_LENGTH -2

/** Decryption failed (authentication failure) */
#define CRYPTO_ERROR_DECRYPTION_FAILED -3

/** Invalid input data */
#define CRYPTO_ERROR_INVALID_INPUT -4

/** Memory allocation failed */
#define CRYPTO_ERROR_MEMORY_ALLOCATION -5

// ============================================================================
// ARGON2ID PASSWORD HASHING
// ============================================================================

/**
 * @brief Hash a password using Argon2ID
 * 
 * @param password Input password bytes
 * @param password_len Length of password in bytes
 * @param salt 16-byte salt (ARGON2_SALT_SIZE)
 * @param hash_out Output buffer for 32-byte hash (ARGON2_HASH_SIZE)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_argon2id_hash_c(
    const unsigned char* password,
    size_t password_len,
    const unsigned char* salt,
    unsigned char* hash_out
);

// ============================================================================
// AES-256-GCM ENCRYPTION
// ============================================================================

/**
 * @brief Encrypt data using AES-256-GCM
 * 
 * @param key 32-byte encryption key (AES256_KEY_SIZE)
 * @param iv 12-byte initialization vector (AES256_IV_SIZE)
 * @param plaintext Input data to encrypt
 * @param plaintext_len Length of plaintext in bytes
 * @param ciphertext_out Output buffer for encrypted data (must be at least plaintext_len)
 * @param tag_out Output buffer for 16-byte authentication tag (AES256_TAG_SIZE)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_aes256_gcm_encrypt_c(
    const unsigned char* key,
    const unsigned char* iv,
    const unsigned char* plaintext,
    size_t plaintext_len,
    unsigned char* ciphertext_out,
    unsigned char* tag_out
);

/**
 * @brief Decrypt data using AES-256-GCM
 * 
 * @param key 32-byte decryption key (AES256_KEY_SIZE)
 * @param iv 12-byte initialization vector (AES256_IV_SIZE)
 * @param ciphertext Encrypted data
 * @param ciphertext_len Length of ciphertext in bytes
 * @param tag 16-byte authentication tag (AES256_TAG_SIZE)
 * @param plaintext_out Output buffer for decrypted data (must be at least ciphertext_len)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_aes256_gcm_decrypt_c(
    const unsigned char* key,
    const unsigned char* iv,
    const unsigned char* ciphertext,
    size_t ciphertext_len,
    const unsigned char* tag,
    unsigned char* plaintext_out
);

// ============================================================================
// SERPENT-256 ENCRYPTION
// ============================================================================

/**
 * @brief Encrypt a 16-byte block using Serpent-256
 * 
 * @param key 32-byte encryption key (SERPENT_KEY_SIZE)
 * @param plaintext 16-byte plaintext block (SERPENT_BLOCK_SIZE)
 * @param ciphertext_out 16-byte output buffer for ciphertext (SERPENT_BLOCK_SIZE)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_serpent_encrypt_c(
    const unsigned char* key,
    const unsigned char* plaintext,
    unsigned char* ciphertext_out
);

/**
 * @brief Decrypt a 16-byte block using Serpent-256
 * 
 * @param key 32-byte decryption key (SERPENT_KEY_SIZE)
 * @param ciphertext 16-byte ciphertext block (SERPENT_BLOCK_SIZE)
 * @param plaintext_out 16-byte output buffer for plaintext (SERPENT_BLOCK_SIZE)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_serpent_decrypt_c(
    const unsigned char* key,
    const unsigned char* ciphertext,
    unsigned char* plaintext_out
);

// ============================================================================
// 1024-BIT CIPHER (Custom Implementation)
// ============================================================================

/**
 * @brief Encrypt using custom 1024-bit cipher
 * 
 * @param data Input data as 32 uint32_t values (1024 bits)
 * @param key Encryption key as 32 uint32_t values (1024 bits)
 * @param output Output buffer for 32 uint32_t values (1024 bits)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_encrypt_1024bit_c(
    const uint32_t* data,
    const uint32_t* key,
    uint32_t* output
);

/**
 * @brief Decrypt using custom 1024-bit cipher
 * 
 * @param data Input data as 32 uint32_t values (1024 bits)
 * @param key Decryption key as 32 uint32_t values (1024 bits)
 * @param output Output buffer for 32 uint32_t values (1024 bits)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_decrypt_1024bit_c(
    const uint32_t* data,
    const uint32_t* key,
    uint32_t* output
);

// ============================================================================
// KYBER-1024 POST-QUANTUM CRYPTOGRAPHY
// ============================================================================

/**
 * @brief Generate Kyber-1024 keypair
 * 
 * @param public_key_out Output buffer for public key (KYBER_PUBLICKEYBYTES)
 * @param secret_key_out Output buffer for secret key (KYBER_SECRETKEYBYTES)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_kyber1024_keypair_c(
    unsigned char* public_key_out,
    unsigned char* secret_key_out
);

/**
 * @brief Kyber-1024 encapsulation (generate shared secret and ciphertext)
 * 
 * @param public_key Public key (KYBER_PUBLICKEYBYTES)
 * @param ciphertext_out Output buffer for ciphertext (KYBER_CIPHERTEXTBYTES)
 * @param shared_secret_out Output buffer for 32-byte shared secret
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_kyber1024_encaps_c(
    const unsigned char* public_key,
    unsigned char* ciphertext_out,
    unsigned char* shared_secret_out
);

/**
 * @brief Kyber-1024 decapsulation (recover shared secret from ciphertext)
 * 
 * @param ciphertext Ciphertext (KYBER_CIPHERTEXTBYTES)
 * @param secret_key Secret key (KYBER_SECRETKEYBYTES)
 * @param shared_secret_out Output buffer for 32-byte shared secret
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_kyber1024_decaps_c(
    const unsigned char* ciphertext,
    const unsigned char* secret_key,
    unsigned char* shared_secret_out
);

// ============================================================================
// X448 KEY EXCHANGE
// ============================================================================

/**
 * @brief Generate X448 keypair
 * 
 * @param public_key_out Output buffer for public key (X448_KEY_SIZE)
 * @param private_key_out Output buffer for private key (X448_KEY_SIZE)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_x448_keypair_c(
    unsigned char* public_key_out,
    unsigned char* private_key_out
);

/**
 * @brief Compute X448 shared secret
 * 
 * @param their_public Their public key (X448_KEY_SIZE)
 * @param my_private My private key (X448_KEY_SIZE)
 * @param shared_secret_out Output buffer for shared secret (X448_KEY_SIZE)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_x448_shared_secret_c(
    const unsigned char* their_public,
    const unsigned char* my_private,
    unsigned char* shared_secret_out
);

// ============================================================================
// PASSWORD GENERATION
// ============================================================================

/**
 * @brief Generate password from hash bytes
 * 
 * @param mode Password generation mode (0 = BASE93, 1 = character sets)
 * @param hash_bytes Input hash bytes
 * @param hash_len Length of hash bytes
 * @param desired_len Desired password length
 * @param enabled_symbol_sets Array of 3 bytes representing boolean flags for symbol set enablement
 * @param password_out Output buffer for null-terminated password string (must be at least desired_len + 1)
 * @param password_len_out Actual length of generated password (excluding null terminator)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int generate_password_c(
    unsigned char mode,
    const unsigned char* hash_bytes,
    size_t hash_len,
    size_t desired_len,
    const unsigned char* enabled_symbol_sets,
    char* password_out,
    size_t* password_len_out
);

// ============================================================================
// LAYERED SYMMETRIC ENCRYPTION
// ============================================================================

/**
 * @brief Double encryption (streaming layout): IV(12) || ciphertext(padded to 128B chunks) || TAG(16 zeroes)
 *
 * @param master_key 128-byte master key
 * @param plaintext Pointer to plaintext bytes
 * @param plaintext_len Length of plaintext in bytes
 * @param output Output buffer for serialized result (must be large enough)
 * @param output_len_out Receives number of bytes written to output
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int double_encrypt_c(
    const unsigned char* master_key,
    const unsigned char* plaintext,
    size_t plaintext_len,
    unsigned char* output,
    size_t* output_len_out
);

/**
 * @brief Double decryption counterpart. Returns padded plaintext (original length not embedded).
 *
 * @param master_key 128-byte master key
 * @param input Pointer to serialized input buffer (IV||ciphertext||TAG)
 * @param input_len Length of input in bytes
 * @param plaintext_out Output buffer for padded plaintext
 * @param plaintext_len_out Receives number of bytes written to plaintext_out
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int double_decrypt_c(
    const unsigned char* master_key,
    const unsigned char* input,
    size_t input_len,
    unsigned char* plaintext_out,
    size_t* plaintext_len_out
);

/**
 * @brief Triple encryption (AES-256-GCM streaming): IV(12) || ciphertext(padded 128B chunks) || TAG(16)
 *
 * @param master_key 128-byte master key
 * @param plaintext Pointer to plaintext bytes
 * @param plaintext_len Length of plaintext in bytes
 * @param output Output buffer for serialized result (must be large enough)
 * @param output_len_out Receives number of bytes written to output
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int triple_encrypt_c(
    const unsigned char* master_key,
    const unsigned char* plaintext,
    size_t plaintext_len,
    unsigned char* output,
    size_t* output_len_out
);

/**
 * @brief Triple decryption counterpart. Returns padded plaintext; authentication is enforced by AES-GCM.
 *
 * @param master_key 128-byte master key
 * @param input Pointer to serialized input buffer (IV||ciphertext||TAG)
 * @param input_len Length of input in bytes
 * @param plaintext_out Output buffer for padded plaintext
 * @param plaintext_len_out Receives number of bytes written to plaintext_out
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int triple_decrypt_c(
    const unsigned char* master_key,
    const unsigned char* input,
    size_t input_len,
    unsigned char* plaintext_out,
    size_t* plaintext_len_out
);

// ============================================================================
// LAYERED ASYMMETRIC ENCRYPTION (Kyber-1024 + X448)
// ============================================================================

/**
 * @brief Layered sender initialization - generates all keys for sender
 * 
 * Step 1 of 4 in the layered key exchange protocol.
 * Generates both Kyber-1024 and X448 keypairs for the sender.
 * 
 * @param sender_kyber_pk_out Output buffer for sender's Kyber public key (KYBER_PUBLICKEYBYTES)
 * @param sender_kyber_sk_out Output buffer for sender's Kyber secret key (KYBER_SECRETKEYBYTES)
 * @param sender_x448_pk_out Output buffer for sender's X448 public key (X448_KEY_SIZE)
 * @param sender_x448_sk_out Output buffer for sender's X448 secret key (X448_KEY_SIZE)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_layered_sender_init_c(
    unsigned char* sender_kyber_pk_out,
    unsigned char* sender_kyber_sk_out,
    unsigned char* sender_x448_pk_out,
    unsigned char* sender_x448_sk_out
);

/**
 * @brief Layered receiver response - processes sender's Kyber public key and creates response bundle
 * 
 * Step 2 of 4 in the layered key exchange protocol.
 * Takes sender's Kyber public key and creates a bundled response containing encrypted data.
 * 
 * @param sender_kyber_pk Sender's Kyber public key from init step (KYBER_PUBLICKEYBYTES)
 * @param bundled_data_out Output buffer for bundled response data (approximately 3192 bytes)
 * @param bundled_data_len_out Actual length of bundled data
 * @param receiver_kyber_sk_out Output buffer for receiver's Kyber secret key (KYBER_SECRETKEYBYTES)
 * @param receiver_x448_sk_out Output buffer for receiver's X448 secret key (X448_KEY_SIZE)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_layered_receiver_response_c(
    const unsigned char* sender_kyber_pk,
    unsigned char* bundled_data_out,
    size_t* bundled_data_len_out,
    unsigned char* receiver_kyber_sk_out,
    unsigned char* receiver_x448_sk_out
);

/**
 * @brief Layered sender final step - processes receiver's bundle and creates final bundle
 * 
 * Step 3 of 4 in the layered key exchange protocol.
 * Processes receiver's bundled response and creates final bundle for receiver.
 * 
 * @param receiver_bundle Receiver's bundled data from response step
 * @param receiver_bundle_len Length of receiver's bundle
 * @param sender_kyber_sk Sender's Kyber secret key from init step (KYBER_SECRETKEYBYTES)
 * @param sender_x448_pk Sender's X448 public key from init step (X448_KEY_SIZE)
 * @param sender_x448_sk Sender's X448 secret key from init step (X448_KEY_SIZE)
 * @param final_bundle_out Output buffer for final bundle (approximately 1624 bytes)
 * @param final_bundle_len_out Actual length of final bundle
 * @param sender_shared_secret_out Output buffer for sender's final shared secret (X448_KEY_SIZE)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_layered_sender_final_c(
    const unsigned char* receiver_bundle,
    size_t receiver_bundle_len,
    const unsigned char* sender_kyber_sk,
    const unsigned char* sender_x448_pk,
    const unsigned char* sender_x448_sk,
    unsigned char* final_bundle_out,
    size_t* final_bundle_len_out,
    unsigned char* sender_shared_secret_out
);

/**
 * @brief Layered receiver final step - processes sender's final bundle
 * 
 * Step 4 of 4 in the layered key exchange protocol.
 * Processes sender's final bundle to derive the final shared secret.
 * 
 * @param sender_final_bundle Sender's final bundle from sender final step
 * @param sender_final_bundle_len Length of sender's final bundle
 * @param receiver_kyber_sk Receiver's Kyber secret key from response step (KYBER_SECRETKEYBYTES)
 * @param receiver_x448_sk Receiver's X448 secret key from response step (X448_KEY_SIZE)
 * @param receiver_shared_secret_out Output buffer for receiver's final shared secret (X448_KEY_SIZE)
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int crypto_layered_receiver_final_c(
    const unsigned char* sender_final_bundle,
    size_t sender_final_bundle_len,
    const unsigned char* receiver_kyber_sk,
    const unsigned char* receiver_x448_sk,
    unsigned char* receiver_shared_secret_out
);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Convert 128 bytes to 32 uint32_t array (for 1024-bit cipher)
 * 
 * @param bytes Input bytes (128 bytes)
 * @param output Output buffer for 32 uint32_t values
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int bytes_to_u32_array_c(
    const unsigned char* bytes,
    uint32_t* output
);

/**
 * @brief Convert 32 uint32_t array to 128 bytes (for 1024-bit cipher)
 * 
 * @param data Input data as 32 uint32_t values
 * @param output Output buffer for 128 bytes
 * @return CRYPTO_SUCCESS on success, error code on failure
 */
int u32_array_to_bytes_c(
    const uint32_t* data,
    unsigned char* output
);

#ifdef __cplusplus
}
#endif

#endif /* PINEAPPLE_CRYPTO_H */
