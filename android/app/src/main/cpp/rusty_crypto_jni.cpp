#include <jni.h>
#include <android/log.h>
#include <cstring>
#include <vector>
#include "c_ffi.h"


static JavaVM* g_jvm = nullptr;

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}


extern "C" JNIEXPORT jint JNICALL
Java_com_pqrypt_app_RustyCrypto_doubleEncryptFd(JNIEnv *env, jclass, jbyteArray secret, jboolean isKeyFile, jint inFd, jint outFd) {
    if (!secret || inFd < 0 || outFd < 0) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    jsize secretLen = env->GetArrayLength(secret);
    jbyte* secretBytes = env->GetByteArrayElements(secret, nullptr);
    if (!secretBytes || secretLen <= 0) {
        if (secretBytes) env->ReleaseByteArrayElements(secret, secretBytes, JNI_ABORT);
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    // Copy to native buffer
    uint8_t* secretCopy = new uint8_t[secretLen];
    memcpy(secretCopy, secretBytes, secretLen);
    
    // Do not modify the Java array in-place; release without committing native changes
    env->ReleaseByteArrayElements(secret, secretBytes, JNI_ABORT);

    int res = double_encrypt_fd_c(secretCopy, (unsigned long)secretLen, isKeyFile ? 1 : 0, (int)inFd, (int)outFd);
    
    // Zero and free native buffer
    memset(secretCopy, 0, secretLen);
    delete [] secretCopy;
    return res;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_pqrypt_app_RustyCrypto_doubleDecryptFd(JNIEnv *env, jclass, jbyteArray secret, jboolean isKeyFile, jint inFd, jint outFd) {
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
    
    // Do not modify the Java array in-place; release without committing native changes
    env->ReleaseByteArrayElements(secret, secretBytes, JNI_ABORT);

    int res = double_decrypt_fd_c(secretCopy, (size_t)secretLen, isKeyFile ? 1 : 0, (int)inFd, (int)outFd);
    
    // Zero and free native buffer
    memset(secretCopy, 0, secretLen);
    delete [] secretCopy;
    return res;
}


extern "C" JNIEXPORT jstring JNICALL
Java_com_pqrypt_app_RustyCrypto_generatePasswordFromHash(JNIEnv *env, jclass, jbyteArray hash64, jint desiredLen, jint enabledSetsMask) {
    if (!hash64 || desiredLen <= 0) return nullptr;

    jsize hashLen = env->GetArrayLength(hash64);
    if (hashLen != 64) return nullptr;

    jbyte* hashBytes = env->GetByteArrayElements(hash64, nullptr);
    if (!hashBytes) return nullptr;

    char outBuf[257];
    size_t outLen = 0;
    int res = generate_password_from_hash_c(
        reinterpret_cast<const unsigned char*>(hashBytes), 64,
        (size_t)desiredLen, (unsigned int)enabledSetsMask,
        outBuf, &outLen);

    memset(hashBytes, 0, hashLen);
    env->ReleaseByteArrayElements(hash64, hashBytes, 0);

    if (res != CRYPTO_SUCCESS) return nullptr;
    return env->NewStringUTF(outBuf);
}


static JNIEnv* getEnv() {
    JNIEnv* env = nullptr;
    if (g_jvm) {
        int status = g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
            if (g_jvm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
                return nullptr;
            }
        }
    }
    return env;
}

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

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_pqrypt_app_RustyCrypto_derivePasswordHashUnified64(JNIEnv *env, jclass clazz, jbyteArray appName, jbyteArray appPassword, jbyteArray masterPassword) {
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

    uint8_t out[64];
    size_t out_len = 64;
    int res = derive_password_hash_unified_64_c(appBytes, appLen,
                                                 pwdBytes, pwdLen,
                                                 masterBytes, masterLen,
                                                 out, out_len);

    delete[] appBytes;
    delete[] pwdBytes;
    delete[] masterBytes;

    if (res != CRYPTO_SUCCESS) {
        return nullptr;
    }

    return bytesToJbyteArray(env, out, 64);
}

// argon2Hash JNI bridge removed: KDF is handled internally in Rust.


extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_pqrypt_app_RustyCrypto_hybridSenderInit(JNIEnv *env, jclass clazz) {
    // PACKAGE1_SIZE = SLHDSA_SIGNATURE_SIZE + (MLKEM1024_PUBLIC_SIZE + X448_PUBLIC_SIZE + HQC256_PUBLIC_SIZE + P521_PUBLIC_SIZE) + SLHDSA_PUBLIC_SIZE
    const size_t PACKAGE1_SIZE = 49856 + (1568 + 56 + 7245 + 133) + 64;
    std::vector<uint8_t> package1(PACKAGE1_SIZE);
    size_t package1Len = 0;

    int status = hybrid_sender_init_c(package1.data(), &package1Len);

    if (status != CRYPTO_SUCCESS) {
        return nullptr;
    }

    return bytesToJbyteArray(env, package1.data(), (jsize)package1Len);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_pqrypt_app_RustyCrypto_hybridReceiver(JNIEnv *env, jclass clazz, jbyteArray package1) {
    jsize package1Len;
    uint8_t *package1Bytes = jbyteArrayToBytes(env, package1, &package1Len);

    if (!package1Bytes) {
        return nullptr;
    }

    uint8_t derivedHash[64];
    // PACKAGE2_SIZE = SLHDSA_SIGNATURE_SIZE + (MLKEM1024_CIPHERTEXT_SIZE + X448_PUBLIC_SIZE + HQC256_CIPHERTEXT_SIZE + P521_PUBLIC_SIZE) + SLHDSA_PUBLIC_SIZE
    const size_t PACKAGE2_SIZE = 49856 + (1568 + 56 + 14421 + 133) + 64;
    std::vector<uint8_t> package2(PACKAGE2_SIZE);
    size_t package2Len = 0;

    int result = hybrid_receiver_c(package1Bytes, package1Len, derivedHash, package2.data(), &package2Len);

    delete[] package1Bytes;

    if (result != CRYPTO_SUCCESS) {
        return nullptr;
    }

    // Return combined result: derivedHash + package2
    jclass byteArrayClass = env->FindClass("[B");
    if (!byteArrayClass) {
        return nullptr;
    }

    jobjectArray resultArray = env->NewObjectArray(2, byteArrayClass, nullptr);
    if (!resultArray) {
        return nullptr;
    }

    jbyteArray j_derivedHash = bytesToJbyteArray(env, derivedHash, 64);
    jbyteArray j_package2 = bytesToJbyteArray(env, package2.data(), (jsize)package2Len);

    if (!j_derivedHash || !j_package2) {
        return nullptr;
    }

    env->SetObjectArrayElement(resultArray, 0, j_package2);
    env->SetObjectArrayElement(resultArray, 1, j_derivedHash);

    env->DeleteLocalRef(j_derivedHash);
    env->DeleteLocalRef(j_package2);

    return resultArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_pqrypt_app_RustyCrypto_hybridSenderFinal(JNIEnv *env, jclass clazz, jbyteArray package2) {
    jsize package2Len;
    uint8_t *package2Bytes = jbyteArrayToBytes(env, package2, &package2Len);

    if (!package2Bytes) {
        return nullptr;
    }

    uint8_t derivedHash[64];

    int result = hybrid_sender_final_c(package2Bytes, package2Len, derivedHash);

    delete[] package2Bytes;

    if (result != CRYPTO_SUCCESS) {
        return nullptr;
    }

    return bytesToJbyteArray(env, derivedHash, 64);
}

// ===== Dual mutual exchange JNI wrappers =====
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_pqrypt_app_RustyCrypto_hybridReceiverDual(JNIEnv *env, jclass, jbyteArray package1) {
    jsize package1Len;
    uint8_t *package1Bytes = jbyteArrayToBytes(env, package1, &package1Len);
    if (!package1Bytes) return nullptr;

    const size_t PACKAGE1_SIZE = 49856 + (1568 + 56 + 7245 + 133) + 64;
    const size_t PACKAGE2_SIZE = 49856 + (1568 + 56 + 14421 + 133) + 64;
    const size_t BUNDLE_SIZE = PACKAGE2_SIZE + PACKAGE1_SIZE;

    std::vector<uint8_t> bundle(BUNDLE_SIZE);
    size_t bundleLen = 0;
    int res = hybrid_receiver_dual_c(package1Bytes, (size_t)package1Len, bundle.data(), &bundleLen);
    delete[] package1Bytes;
    if (res != CRYPTO_SUCCESS) return nullptr;
    return bytesToJbyteArray(env, bundle.data(), (jsize)bundleLen);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_pqrypt_app_RustyCrypto_hybridSenderThird(JNIEnv *env, jclass, jbyteArray package2Bundle) {
    jsize bundleLen;
    uint8_t *bundleBytes = jbyteArrayToBytes(env, package2Bundle, &bundleLen);
    if (!bundleBytes) return nullptr;

    const size_t PACKAGE2_SIZE = 49856 + (1568 + 56 + 14421 + 133) + 64;
    std::vector<uint8_t> package3(PACKAGE2_SIZE);
    size_t package3Len = 0;
    uint8_t finalHash[64];

    int res = hybrid_sender_third_c(bundleBytes, (size_t)bundleLen, package3.data(), &package3Len, finalHash);
    delete[] bundleBytes;
    if (res != CRYPTO_SUCCESS) return nullptr;

    jclass byteArrayClass = env->FindClass("[B");
    if (!byteArrayClass) return nullptr;
    jobjectArray resultArray = env->NewObjectArray(2, byteArrayClass, nullptr);
    if (!resultArray) return nullptr;

    jbyteArray j_package3 = bytesToJbyteArray(env, package3.data(), (jsize)package3Len);
    jbyteArray j_finalHash = bytesToJbyteArray(env, finalHash, 64);
    if (!j_package3 || !j_finalHash) return nullptr;
    env->SetObjectArrayElement(resultArray, 0, j_package3);
    env->SetObjectArrayElement(resultArray, 1, j_finalHash);
    env->DeleteLocalRef(j_package3);
    env->DeleteLocalRef(j_finalHash);
    return resultArray;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_pqrypt_app_RustyCrypto_hybridReceiverFinalDual(JNIEnv *env, jclass, jbyteArray package3) {
    jsize p3Len;
    uint8_t *p3Bytes = jbyteArrayToBytes(env, package3, &p3Len);
    if (!p3Bytes) return nullptr;
    uint8_t finalHash[64];
    int res = hybrid_receiver_final_dual_c(p3Bytes, (size_t)p3Len, finalHash);
    delete[] p3Bytes;
    if (res != CRYPTO_SUCCESS) return nullptr;
    return bytesToJbyteArray(env, finalHash, 64);
}
