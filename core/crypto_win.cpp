// crypto.h on Windows: BCrypt (CNG)
#include "crypto.h"

#include <windows.h>
#include <bcrypt.h>

namespace crypto {
namespace {
std::string hash(const std::string* key, const std::string& data) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    std::string out(32, '\0');
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, key ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
    BCryptCreateHash(alg, &h, nullptr, 0, key ? (PUCHAR)key->data() : nullptr, key ? (ULONG)key->size() : 0, 0);
    BCryptHashData(h, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BCryptFinishHash(h, (PUCHAR)out.data(), 32, 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}
}  // namespace

std::string random(size_t n) {
    std::string out(n, '\0');
    BCryptGenRandom(nullptr, (PUCHAR)out.data(), (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return out;
}
std::string sha256(const std::string& data) { return hash(nullptr, data); }
std::string hmac(const std::string& key, const std::string& data) { return hash(&key, data); }
void aesEcb(const std::string& key32, const unsigned char* in, unsigned char* out, size_t blocks) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE k = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    BCryptGenerateSymmetricKey(alg, &k, nullptr, 0, (PUCHAR)key32.data(), 32, 0);
    ULONG done = 0;
    BCryptEncrypt(k, (PUCHAR)in, (ULONG)(blocks * 16), nullptr, nullptr, 0, out, (ULONG)(blocks * 16), &done, 0);
    BCryptDestroyKey(k);
    BCryptCloseAlgorithmProvider(alg, 0);
}
}  // namespace crypto
