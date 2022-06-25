#include "dev_asmed_encryption_provider_AesProvider.h"

#include "base64.h"

using namespace std;

string encrypt(string, string, string);
string decrypt(string, string, string);
string convert(JNIEnv*, jstring);
string decodeBase(string);

JNIEXPORT jstring JNICALL Java_dev_asmed_encryption_provider_AesProvider_encrypt
(JNIEnv* env, jobject, jstring plain, jstring key, jstring iv) {
    if (!plain || !key || !iv) return env->NewStringUTF("Error");
    string convertedPlain = convert(env, plain);
    string convertedKey = convert(env, key);
    string convertedIv = convert(env, iv);
    return env->NewStringUTF(encrypt(convertedKey, convertedPlain, convertedIv).c_str());  
}

JNIEXPORT jstring JNICALL Java_dev_asmed_encryption_provider_AesProvider_decrypt
(JNIEnv* env, jobject, jstring plain, jstring key, jstring iv) {
    if (!plain || !key || !iv) return env->NewStringUTF("Error");
    string convertedPlain = convert(env, plain);
    string convertedKey = convert(env, key);
    string convertedIv = convert(env, iv);
    return env->NewStringUTF(decrypt(convertedKey, convertedPlain, convertedIv).c_str());  
}

string encrypt(string rawKey, string plain, string iv) {
    string cipher;
    CryptoPP::AES::Encryption aesEncryption((CryptoPP::byte*) rawKey.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, (CryptoPP::byte*)iv.c_str());
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(cipher)));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plain.c_str()), plain.length());
    stfEncryptor.MessageEnd();
    return cipher;
}

string decrypt(string rawKey, string plainDecoded, string iv) {
    string plain = decodeBase(plainDecoded);
    string end;
    CryptoPP::AES::Decryption aesDecryption((CryptoPP::byte*)rawKey.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (CryptoPP::byte*)iv.c_str());
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(end));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plain.c_str()), plain.size());
    stfDecryptor.MessageEnd();
    return end;
}

string convert(JNIEnv* env, jstring jStr) {

    const jclass stringClass = env->GetObjectClass(jStr);
    const jmethodID getBytes = env->GetMethodID(stringClass, "getBytes", "(Ljava/lang/String;)[B");
    const jbyteArray stringJbytes = (jbyteArray)env->CallObjectMethod(jStr, getBytes, env->NewStringUTF("UTF-8"));

    size_t length = (size_t)env->GetArrayLength(stringJbytes);
    jbyte* pBytes = env->GetByteArrayElements(stringJbytes, NULL);

    string ret = string((char*)pBytes, length);
    env->ReleaseByteArrayElements(stringJbytes, pBytes, JNI_ABORT);

    env->DeleteLocalRef(stringJbytes);
    env->DeleteLocalRef(stringClass);
    return ret;
}

string decodeBase(std::string encoded) {
    std::string decoded;
    CryptoPP::Base64Decoder decoder;
    decoder.Put((CryptoPP::byte*) encoded.data(), encoded.size());
    decoder.MessageEnd();

    CryptoPP::word64 size = decoder.MaxRetrievable();
    if (size && size <= SIZE_MAX)
    {
        decoded.resize(size);
        decoder.Get((CryptoPP::byte*)&decoded[0], decoded.size());
    }
    return decoded;
}