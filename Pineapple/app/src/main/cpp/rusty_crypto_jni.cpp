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

// =============================
// New FD-based file crypto APIs
// =============================

extern "C" JNIEXPORT jint JNICALL
Java_com_pineapple_app_RustyCrypto_tripleEncryptFd(JNIEnv *env, jclass, jbyteArray secret, jboolean isKeyFile, jint inFd, jint outFd) {
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "JNI tripleEncryptFd: ENTRY - inFd=%d, outFd=%d, isKeyFile=%d", (int)inFd, (int)outFd, (int)isKeyFile);
    
    if (!secret || inFd < 0 || outFd < 0) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "JNI tripleEncryptFd: Invalid input parameters");
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    jsize secretLen = env->GetArrayLength(secret);
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "JNI tripleEncryptFd: secretLen=%d", (int)secretLen);
    
    jbyte* secretBytes = env->GetByteArrayElements(secret, nullptr);
    if (!secretBytes || secretLen <= 0) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "JNI tripleEncryptFd: Failed to get secret bytes");
        if (secretBytes) env->ReleaseByteArrayElements(secret, secretBytes, JNI_ABORT);
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    // Copy to native buffer
    uint8_t* secretCopy = new uint8_t[secretLen];
    memcpy(secretCopy, secretBytes, secretLen);
    // Zero Java array in-place and commit
    memset(secretBytes, 0, secretLen);
    env->ReleaseByteArrayElements(secret, secretBytes, 0);

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "JNI tripleEncryptFd: About to call triple_encrypt_fd_c");
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "JNI tripleEncryptFd: Parameters - secretCopy=%p, secretLen=%d, isKeyFile=%d, inFd=%d, outFd=%d", 
                       secretCopy, (int)secretLen, isKeyFile ? 1 : 0, (int)inFd, (int)outFd);
    
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "JNI tripleEncryptFd: CALLING triple_encrypt_fd_c NOW");
    int res = triple_encrypt_fd_c(secretCopy, (unsigned long)secretLen, isKeyFile ? 1 : 0, (int)inFd, (int)outFd);
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "JNI tripleEncryptFd: triple_encrypt_fd_c returned %d", res);
    
    // Zero and free native buffer
    memset(secretCopy, 0, secretLen);
    delete [] secretCopy;
    return res;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_pineapple_app_RustyCrypto_tripleDecryptFd(JNIEnv *env, jclass, jbyteArray secret, jboolean isKeyFile, jint inFd, jint outFd) {
    if (!secret || inFd < 0 || outFd < 0) return CRYPTO_ERROR_INVALID_INPUT;

    jsize secretLen = env->GetArrayLength(secret);
    jbyte* secretBytes = env->GetByteArrayElements(secret, nullptr);
    if (!secretBytes || secretLen <= 0) {
        if (secretBytes) env->ReleaseByteArrayElements(secret, secretBytes, JNI_ABORT);
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    // Copy to native buffer
    uint8_t* secretCopy = new uint8_t[secretLen];
    memcpy(secretCopy, secretBytes, secretLen);
    // Zero Java array in-place and commit
    memset(secretBytes, 0, secretLen);
    env->ReleaseByteArrayElements(secret, secretBytes, 0);

    int res = triple_decrypt_fd_c(secretCopy, (size_t)secretLen, isKeyFile ? 1 : 0, (int)inFd, (int)outFd);
    // Zero and free native buffer
    memset(secretCopy, 0, secretLen);
    delete [] secretCopy;
    return res;
}

// =====================================
// Unified password generator (bitmask)
// =====================================

extern "C" JNIEXPORT jstring JNICALL
Java_com_pineapple_app_RustyCrypto_generatePasswordUnified(JNIEnv *env, jclass, jbyteArray appName, jbyteArray appPassword, jbyteArray masterPassword, jint desiredLen, jint enabledSetsMask) {
    if (!appName || !masterPassword || desiredLen <= 0) return nullptr;

    jsize appLen = env->GetArrayLength(appName);
    jsize pwdLen = appPassword ? env->GetArrayLength(appPassword) : 0;
    jsize mstLen = env->GetArrayLength(masterPassword);

    jbyte* appBytes = env->GetByteArrayElements(appName, nullptr);
    jbyte* pwdBytes = appPassword ? env->GetByteArrayElements(appPassword, nullptr) : nullptr;
    jbyte* mstBytes = env->GetByteArrayElements(masterPassword, nullptr);
    if (!appBytes || !mstBytes) {
        if (appBytes) env->ReleaseByteArrayElements(appName, appBytes, JNI_ABORT);
        if (pwdBytes) env->ReleaseByteArrayElements(appPassword, pwdBytes, JNI_ABORT);
        if (mstBytes) env->ReleaseByteArrayElements(masterPassword, mstBytes, JNI_ABORT);
        return nullptr;
    }

    char outBuf[257];
    size_t outLen = 0;
    int res = generate_password_unified_c(
        reinterpret_cast<const unsigned char*>(appBytes), (size_t)appLen,
        reinterpret_cast<const unsigned char*>(pwdBytes), (size_t)pwdLen,
        reinterpret_cast<const unsigned char*>(mstBytes), (size_t)mstLen,
        (size_t)desiredLen, (unsigned int)enabledSetsMask,
        outBuf, &outLen);

    // Zero Java arrays in-place
    memset(appBytes, 0, appLen);
    env->ReleaseByteArrayElements(appName, appBytes, 0);
    if (pwdBytes) { memset(pwdBytes, 0, pwdLen); env->ReleaseByteArrayElements(appPassword, pwdBytes, 0); }
    memset(mstBytes, 0, mstLen);
    env->ReleaseByteArrayElements(masterPassword, mstBytes, 0);

    if (res != CRYPTO_SUCCESS) return nullptr;
    return env->NewStringUTF(outBuf);
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
    // This function is deprecated - use derivePasswordHashUnified128 instead
    // For backward compatibility, we'll implement a simple fallback
    jsize passwordLen;
    uint8_t *passwordBytes = jbyteArrayToBytes(env, password, &passwordLen);
    
    if (!passwordBytes) {
        return nullptr;
    }
    
    jsize outLen = outputLength > 0 ? outputLength : 32;
    uint8_t *hashBuf = new uint8_t[outLen];
    
    // Use the unified derivation with empty app name and app password
    int result = derive_password_hash_unified_128_c(
        (const unsigned char*)"", 0,  // empty app name
        (const unsigned char*)"", 0,  // empty app password
        passwordBytes, passwordLen,    // master password = input password
        hashBuf, outLen
    );
    
    delete[] passwordBytes;
    
    if (result != CRYPTO_SUCCESS) {
        delete[] hashBuf;
        return nullptr;
    }
    
    jbyteArray resultArray = bytesToJbyteArray(env, hashBuf, outLen);
    delete[] hashBuf;
    return resultArray;
}

// Removed tripleDecrypt - use tripleDecryptFd instead

// Removed generatePasswordSecure - use generatePasswordUnified instead


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
