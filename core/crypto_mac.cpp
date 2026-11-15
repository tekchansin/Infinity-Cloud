// crypto.h on macOS: CommonCrypto + the system's random source
#include "crypto.h"

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>

#include <cstdlib>

namespace crypto {
std::string random(size_t n) {
    std::string out(n, '\0');
    arc4random_buf(out.data(), n);
    return out;
}
std::string sha256(const std::string& data) {
    std::string out(CC_SHA256_DIGEST_LENGTH, '\0');
    CC_SHA256(data.data(), (CC_LONG)data.size(), (unsigned char*)out.data());
    return out;
}
std::string hmac(const std::string& key, const std::string& data) {
    std::string out(CC_SHA256_DIGEST_LENGTH, '\0');
    CCHmac(kCCHmacAlgSHA256, key.data(), key.size(), data.data(), data.size(), out.data());
    return out;
}
void aesEcb(const std::string& key32, const unsigned char* in, unsigned char* out, size_t blocks) {
    size_t done = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, key32.data(), kCCKeySizeAES256, nullptr, in, blocks * 16, out, blocks * 16, &done);
}
}  // namespace crypto
