#include <jni.h>
#include <android/log.h>
#include <cstring>
#include "c_ffi.h"

#define LOG_TAG "RustyCrypto"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Constants
#define ARGON2_SALT_SIZE 32
#define KYBER_PUBLICKEYBYTES 1568
#define KYBER_SECRETKEYBYTES 3168
#define X448_KEY_SIZE 56

// Global JavaVM pointer for thread attachment
static JavaVM* g_jvm = nullptr;

// JNI OnLoad function to cache JavaVM
extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

// (moved below helper functions)

// Helper to get JNIEnv for current thread
static JNIEnv* getEnv() {
    JNIEnv* env = nullptr;
    if (g_jvm) {
        int status = g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
            // Attach current thread
            if (g_jvm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
                return nullptr;
            }
        }
    }
    return env;
}

// Helper functions
static uint8_t* jbyteArrayToBytes(JNIEnv *env, jbyteArray array, jsize *length) {
    if (!array) {
        *length = 0;
        return nullptr;
    }
    
    *length = env->GetArrayLength(array);
    jbyte *bytes = env->GetByteArrayElements(array, nullptr);
    if (!bytes) {
        *length = 0;
        return nullptr;
    }
    
    uint8_t *result = new uint8_t[*length];
    memcpy(result, bytes, *length);
    env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    
    return result;
}

static jbyteArray bytesToJbyteArray(JNIEnv *env, const uint8_t *bytes, jsize length) {
    if (!bytes || length <= 0) {
        return nullptr;
    }
    
    jbyteArray result = env->NewByteArray(length);
    if (result) {
        env->SetByteArrayRegion(result, 0, length, reinterpret_cast<const jbyte*>(bytes));
    }
    
    return result;
}

// Unified 128-byte password derivation JNI (placed after helper functions)
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_pineapple_app_RustyCrypto_derivePasswordHashUnified128(JNIEnv *env, jclass clazz, jbyteArray appName, jbyteArray appPassword, jbyteArray masterPassword) {
    if (!appName || !masterPassword) {
        return nullptr;
    }

    jsize appLen = 0, pwdLen = 0, masterLen = 0;
    uint8_t *appBytes = jbyteArrayToBytes(env, appName, &appLen);
    uint8_t *pwdBytes = jbyteArrayToBytes(env, appPassword, &pwdLen);
    uint8_t *masterBytes = jbyteArrayToBytes(env, masterPassword, &masterLen);

    if (!appBytes || !masterBytes) {
        if (appBytes) delete[] appBytes;
        if (pwdBytes) delete[] pwdBytes;
        if (masterBytes) delete[] masterBytes;
        return nullptr;
    }

    uint8_t out[128];
    size_t out_len = 128;
    int res = derive_password_hash_unified_128_c(appBytes, appLen,
                                                 pwdBytes, pwdLen,
                                                 masterBytes, masterLen,
                                                 out, out_len);

    delete[] appBytes;
    delete[] pwdBytes;
    delete[] masterBytes;

    if (res != CRYPTO_SUCCESS) {
        return nullptr;
    }

    return bytesToJbyteArray(env, out, 128);
}

// Core JNI functions - simplified names
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_pineapple_app_RustyCrypto_argon2Hash(JNIEnv *env, jclass clazz, jbyteArray password, jbyteArray salt, jint outputLength) {
    jsize passwordLen, saltLen;
    uint8_t *passwordBytes = jbyteArrayToBytes(env, password, &passwordLen);
    uint8_t *saltBytes = jbyteArrayToBytes(env, salt, &saltLen);
    
    if (!passwordBytes) {
        delete[] passwordBytes;
        delete[] saltBytes;
        return nullptr;
    }
    
    // Use default salt if none provided
    uint8_t defaultSalt[ARGON2_SALT_SIZE] = {0};
    const uint8_t* saltPtr = (saltBytes && saltLen > 0) ? saltBytes : defaultSalt;
    size_t saltSize = (saltBytes && saltLen > 0) ? saltLen : ARGON2_SALT_SIZE;
    
    jsize outLen = outputLength > 0 ? outputLength : 32;
    uint8_t *hashBuf = new uint8_t[outLen];
    int result = argon2_hash_c(passwordBytes, passwordLen, saltPtr, saltSize, hashBuf, outLen);
    
    delete[] passwordBytes;
    delete[] saltBytes;
    
    if (result != CRYPTO_SUCCESS) {
        delete[] hashBuf;
        return nullptr;
    }
    
    jbyteArray resultArray = bytesToJbyteArray(env, hashBuf, outLen);
    delete[] hashBuf;
    return resultArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_pineapple_app_RustyCrypto_tripleEncrypt(JNIEnv *env, jclass clazz, jbyteArray masterKey, jbyteArray plaintext) {
    jsize masterKeyLen, plaintextLen;
    uint8_t *masterKeyBytes = jbyteArrayToBytes(env, masterKey, &masterKeyLen);
    uint8_t *plaintextBytes = jbyteArrayToBytes(env, plaintext, &plaintextLen);

    if (!masterKeyBytes || !plaintextBytes || masterKeyLen != 128) {
        delete[] masterKeyBytes;
        delete[] plaintextBytes;
        return nullptr;
    }

    // Calculate proper output size: padded input + IV + tag + safety margin
    size_t chunk_size = 128;
    size_t padded_len = ((plaintextLen + chunk_size - 1) / chunk_size) * chunk_size;
    size_t out_len = padded_len + 32 + 16 + 64; // padded + IV + tag + margin
    uint8_t *output = new uint8_t[out_len];
    size_t written = 0;

    int res = triple_encrypt_c(masterKeyBytes, plaintextBytes, plaintextLen, output, &written);

    delete[] masterKeyBytes;
    delete[] plaintextBytes;

    if (res != CRYPTO_SUCCESS || written == 0) {
        delete[] output;
        return nullptr;
    }

    jbyteArray outArray = bytesToJbyteArray(env, output, (jsize)written);
    delete[] output;
    return outArray;
}


extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_pineapple_app_RustyCrypto_tripleDecrypt(JNIEnv *env, jclass clazz, jbyteArray masterKey, jbyteArray input) {
    jsize masterKeyLen, inputLen;
    uint8_t *masterKeyBytes = jbyteArrayToBytes(env, masterKey, &masterKeyLen);
    uint8_t *inputBytes = jbyteArrayToBytes(env, input, &inputLen);

    if (!masterKeyBytes || !inputBytes || masterKeyLen != 128) {
        delete[] masterKeyBytes;
        delete[] inputBytes;
        return nullptr;
    }

    // Allocate sufficient buffer for decrypted output (input size should be enough)
    size_t plaintext_len = inputLen + 128; // Add safety margin
    uint8_t *plaintext = new uint8_t[plaintext_len];
    size_t written = 0;

    __android_log_print(ANDROID_LOG_DEBUG, "JNI_DEBUG", "Calling triple_decrypt_c with inputLen: %d", inputLen);
    __android_log_print(ANDROID_LOG_DEBUG, "JNI_DEBUG", "masterKeyBytes ptr: %p, inputBytes ptr: %p, plaintext ptr: %p", masterKeyBytes, inputBytes, plaintext);
    int res = triple_decrypt_c(masterKeyBytes, inputBytes, inputLen, plaintext, &written);
    __android_log_print(ANDROID_LOG_DEBUG, "JNI_DEBUG", "triple_decrypt_c result: %d, written: %zu, inputLen: %d", res, written, inputLen);

    delete[] masterKeyBytes;
    delete[] inputBytes;

    if (res != CRYPTO_SUCCESS || written == 0) {
        __android_log_print(ANDROID_LOG_ERROR, "JNI_DEBUG", "Decryption failed - res: %d, written: %zu", res, written);
        delete[] plaintext;
        return nullptr;
    }

    jbyteArray outArray = bytesToJbyteArray(env, plaintext, (jsize)written);
    delete[] plaintext;
    return outArray;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_pineapple_app_RustyCrypto_generatePasswordSecure(JNIEnv *env, jclass clazz, jint mode, jbyteArray hashBytes, jint length, jbooleanArray enabledSets, jstring userId) {
    LOGI("JNI generatePasswordSecure: START - mode=%d, length=%d", mode, length);
    
    jsize hashLen = env->GetArrayLength(hashBytes);
    jsize enabledSetsLen = env->GetArrayLength(enabledSets);
    
    LOGI("JNI generatePasswordSecure: hashLen=%d, enabledSetsLen=%d", hashLen, enabledSetsLen);
    
    if (enabledSetsLen != 3) {
        LOGE("JNI generatePasswordSecure: ERROR - enabledSetsLen != 3");
        return nullptr;
    }
    
    uint8_t *hashBytesPtr = jbyteArrayToBytes(env, hashBytes, &hashLen);
    jboolean *enabledSetsPtr = env->GetBooleanArrayElements(enabledSets, nullptr);
    
    if (!hashBytesPtr || !enabledSetsPtr) {
        LOGE("JNI generatePasswordSecure: ERROR - null pointers: hash=%p, sets=%p", hashBytesPtr, enabledSetsPtr);
        if (hashBytesPtr) delete[] hashBytesPtr;
        if (enabledSetsPtr) env->ReleaseBooleanArrayElements(enabledSets, enabledSetsPtr, JNI_ABORT);
        return nullptr;
    }
    
    // userId parameter is ignored for backward compatibility
    if (userId) {
        const char *userIdStr = env->GetStringUTFChars(userId, nullptr);
        if (userIdStr) env->ReleaseStringUTFChars(userId, userIdStr);
    }
    
    unsigned char enabledSymbolSets[3];
    for (int i = 0; i < 3; i++) {
        enabledSymbolSets[i] = enabledSetsPtr[i] ? 1 : 0;
    }
    
    char passwordOut[257];
    size_t passwordLenOut = 0;
    
    LOGI("JNI generatePasswordSecure: About to call generate_password_c");
    
    int result = generate_password_c((unsigned char)mode, hashBytesPtr, hashLen, length,
                                           enabledSymbolSets, passwordOut, &passwordLenOut);
    
    LOGI("JNI generatePasswordSecure: generate_password_c returned %d, passwordLenOut=%zu", result, passwordLenOut);
    
    delete[] hashBytesPtr;
    env->ReleaseBooleanArrayElements(enabledSets, enabledSetsPtr, JNI_ABORT);
    
    if (result != CRYPTO_SUCCESS) {
        LOGE("JNI generatePasswordSecure: ERROR - generate_password_c failed with code %d", result);
        return nullptr;
    }
    
    LOGI("JNI generatePasswordSecure: SUCCESS - returning password");
    return env->NewStringUTF(passwordOut);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_pineapple_app_RustyCrypto_kyberKeypair(JNIEnv *env, jclass clazz) {
    uint8_t publicKey[KYBER_PUBLICKEYBYTES];
    uint8_t secretKey[KYBER_SECRETKEYBYTES];
    
    int result = kyber_keypair_c(publicKey, secretKey);
    
    if (result != CRYPTO_SUCCESS) {
        return nullptr;
    }
    
    jclass byteArrayClass = env->FindClass("[B");
    if (!byteArrayClass) {
        return nullptr;
    }
    jobjectArray resultArray = env->NewObjectArray(2, byteArrayClass, nullptr);
    env->SetObjectArrayElement(resultArray, 0, bytesToJbyteArray(env, publicKey, KYBER_PUBLICKEYBYTES));
    env->SetObjectArrayElement(resultArray, 1, bytesToJbyteArray(env, secretKey, KYBER_SECRETKEYBYTES));
    
    return resultArray;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_pineapple_app_RustyCrypto_x448Keypair(JNIEnv *env, jclass clazz) {
    uint8_t publicKey[X448_KEY_SIZE];
    uint8_t privateKey[X448_KEY_SIZE];
    
    int result = x448_keypair_c(publicKey, privateKey);
    
    if (result != CRYPTO_SUCCESS) {
        return nullptr;
    }
    
    jclass byteArrayClass = env->FindClass("[B");
    if (!byteArrayClass) {
        return nullptr;
    }
    jobjectArray resultArray = env->NewObjectArray(2, byteArrayClass, nullptr);
    env->SetObjectArrayElement(resultArray, 0, bytesToJbyteArray(env, publicKey, X448_KEY_SIZE));
    env->SetObjectArrayElement(resultArray, 1, bytesToJbyteArray(env, privateKey, X448_KEY_SIZE));
    
    return resultArray;
}

// PQC 4-Algorithm Hybrid Key Exchange Functions

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_pineapple_app_RustyCrypto_pqc4HybridInit(JNIEnv *env, jclass clazz) {
    uint8_t hybrid1Key[131072]; // Large buffer for signed hybrid key (1.key)
    size_t hybrid1KeyLen = 0;
    uint8_t senderState[65536]; // Large buffer for sender state (includes SLH-DSA keys)
    size_t senderStateLen = 0;
    
    int status = pqc_4hybrid_init_c(hybrid1Key, &hybrid1KeyLen, senderState, &senderStateLen);
    
    if (status != CRYPTO_SUCCESS) {
        return nullptr;
    }
    
    jclass byteArrayClass = env->FindClass("[B");
    if (!byteArrayClass) {
        return nullptr;
    }
    
    jobjectArray resultArray = env->NewObjectArray(2, byteArrayClass, nullptr);
    if (!resultArray) {
        return nullptr;
    }
    
    jbyteArray j_hybrid1Key = bytesToJbyteArray(env, hybrid1Key, (jsize)hybrid1KeyLen);
    jbyteArray j_senderState = bytesToJbyteArray(env, senderState, (jsize)senderStateLen);
    
    if (!j_hybrid1Key || !j_senderState) {
        return nullptr;
    }
    
    env->SetObjectArrayElement(resultArray, 0, j_hybrid1Key);
    env->SetObjectArrayElement(resultArray, 1, j_senderState);
    
    env->DeleteLocalRef(j_hybrid1Key);
    env->DeleteLocalRef(j_senderState);
    
    return resultArray;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_pineapple_app_RustyCrypto_pqc4HybridRecv(JNIEnv *env, jclass clazz, jbyteArray hybrid1Key) {
    LOGI("pqc4HybridRecv: ENTRY - Function called");
    jsize hybrid1KeyLen;
    uint8_t *hybrid1KeyBytes = jbyteArrayToBytes(env, hybrid1Key, &hybrid1KeyLen);
    
    LOGI("pqc4HybridRecv: hybrid1KeyLen=%d", hybrid1KeyLen);
    
    if (!hybrid1KeyBytes) {
        LOGE("pqc4HybridRecv: hybrid1Key is null");
        return nullptr;
    }
    
    uint8_t hybrid2Key[131072]; // Increased buffer for signed hybrid2 key (2.key)
    size_t hybrid2KeyLen = 0;
    uint8_t receiverState[65536]; // Increased buffer for receiver state (includes SLH-DSA keys)
    size_t receiverStateLen = 0;
    
    int result = pqc_4hybrid_recv_c(hybrid1KeyBytes, hybrid1KeyLen, hybrid2Key, &hybrid2KeyLen, receiverState, &receiverStateLen);
    
    LOGI("pqc4HybridRecv: pqc_4hybrid_recv_c returned %d, hybrid2KeyLen=%zu, receiverStateLen=%zu", result, hybrid2KeyLen, receiverStateLen);
    
    delete[] hybrid1KeyBytes;
    
    if (result != CRYPTO_SUCCESS) {
        LOGE("pqc4HybridRecv: pqc_4hybrid_recv_c failed with error %d", result);
        return nullptr;
    }
    
    jclass byteArrayClass = env->FindClass("[B");
    if (!byteArrayClass) {
        LOGE("pqc4HybridRecv: Failed to find byte array class");
        return nullptr;
    }
    
    jobjectArray resultArray = env->NewObjectArray(2, byteArrayClass, nullptr);
    if (!resultArray) {
        LOGE("pqc4HybridRecv: Failed to create result array");
        return nullptr;
    }
    
    jbyteArray j_hybrid2Key = bytesToJbyteArray(env, hybrid2Key, (jsize)hybrid2KeyLen);
    jbyteArray j_receiverState = bytesToJbyteArray(env, receiverState, (jsize)receiverStateLen);
    
    if (!j_hybrid2Key || !j_receiverState) {
        LOGE("pqc4HybridRecv: Failed to create byte arrays");
        return nullptr;
    }
    
    env->SetObjectArrayElement(resultArray, 0, j_hybrid2Key);
    env->SetObjectArrayElement(resultArray, 1, j_receiverState);
    
    env->DeleteLocalRef(j_hybrid2Key);
    env->DeleteLocalRef(j_receiverState);
    
    LOGI("pqc4HybridRecv: Successfully returning result array");
    return resultArray;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_pineapple_app_RustyCrypto_pqc4HybridSndFinal(JNIEnv *env, jclass clazz, jbyteArray hybrid2Key, jbyteArray senderState) {
    jsize hybrid2KeyLen, senderStateLen;
    uint8_t *hybrid2KeyBytes = jbyteArrayToBytes(env, hybrid2Key, &hybrid2KeyLen);
    uint8_t *senderStateBytes = jbyteArrayToBytes(env, senderState, &senderStateLen);
    
    LOGI("pqc4HybridSndFinal: hybrid2KeyLen=%d, senderStateLen=%d", hybrid2KeyLen, senderStateLen);
    
    if (!hybrid2KeyBytes || !senderStateBytes) {
        LOGE("pqc4HybridSndFinal: Input arrays are null");
        delete[] hybrid2KeyBytes;
        delete[] senderStateBytes;
        return nullptr;
    }
    
    uint8_t finalKey[128]; // 128-byte final key
    uint8_t hybrid3Key[131072]; // Increased buffer for signed hybrid3 key (3.key)
    size_t hybrid3KeyLen = 0;
    
    int result = pqc_4hybrid_snd_final_c(hybrid2KeyBytes, hybrid2KeyLen, senderStateBytes, senderStateLen, finalKey, hybrid3Key, &hybrid3KeyLen);
    
    LOGI("pqc4HybridSndFinal: pqc_4hybrid_snd_final_c returned %d, hybrid3KeyLen=%zu", result, hybrid3KeyLen);
    
    delete[] hybrid2KeyBytes;
    delete[] senderStateBytes;
    
    if (result != CRYPTO_SUCCESS) {
        LOGE("pqc4HybridSndFinal: pqc_4hybrid_snd_final_c failed with error %d", result);
        return nullptr;
    }
    
    jclass byteArrayClass = env->FindClass("[B");
    if (!byteArrayClass) {
        LOGE("pqc4HybridSndFinal: Failed to find byte array class");
        return nullptr;
    }
    
    jobjectArray resultArray = env->NewObjectArray(2, byteArrayClass, nullptr);
    if (!resultArray) {
        LOGE("pqc4HybridSndFinal: Failed to create result array");
        return nullptr;
    }
    
    jbyteArray j_finalKey = bytesToJbyteArray(env, finalKey, 128);
    jbyteArray j_hybrid3Key = bytesToJbyteArray(env, hybrid3Key, (jsize)hybrid3KeyLen);
    
    if (!j_finalKey || !j_hybrid3Key) {
        LOGE("pqc4HybridSndFinal: Failed to create byte arrays");
        return nullptr;
    }
    
    env->SetObjectArrayElement(resultArray, 0, j_finalKey);
    env->SetObjectArrayElement(resultArray, 1, j_hybrid3Key);
    
    env->DeleteLocalRef(j_finalKey);
    env->DeleteLocalRef(j_hybrid3Key);
    
    LOGI("pqc4HybridSndFinal: Successfully returning result array");
    return resultArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_pineapple_app_RustyCrypto_pqc4HybridRecvFinal(JNIEnv *env, jclass clazz, jbyteArray hybrid3Key, jbyteArray receiverState) {
    jsize hybrid3KeyLen, receiverStateLen;
    uint8_t *hybrid3KeyBytes = jbyteArrayToBytes(env, hybrid3Key, &hybrid3KeyLen);
    uint8_t *receiverStateBytes = jbyteArrayToBytes(env, receiverState, &receiverStateLen);
    
    if (!hybrid3KeyBytes || !receiverStateBytes) {
        delete[] hybrid3KeyBytes;
        delete[] receiverStateBytes;
        return nullptr;
    }
    
    uint8_t finalKey[128]; // 128-byte final key
    
    int result = pqc_4hybrid_recv_final_c(hybrid3KeyBytes, hybrid3KeyLen, receiverStateBytes, receiverStateLen, finalKey);
    
    delete[] hybrid3KeyBytes;
    delete[] receiverStateBytes;
    
    if (result != CRYPTO_SUCCESS) {
        return nullptr;
    }
    
    return bytesToJbyteArray(env, finalKey, 128);
}
