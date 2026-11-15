// The little cryptography Remote access needs (remote.cpp; the browser's side: ui/shared/remote-crypto.ts, the spec),
// on the system's own primitives: CommonCrypto (crypto_mac.cpp), BCrypt (crypto_win.cpp). Bytes = std::string.
#pragma once
#include <string>

namespace crypto {
std::string random(size_t n);
std::string sha256(const std::string& data);
std::string hmac(const std::string& key, const std::string& data);  // HMAC-SHA-256
// AES-256 in counter mode, the whole 128-bit block counting up big-endian (WebCrypto AES-CTR, length 128); both ways
std::string aesCtr(const std::string& key32, const std::string& iv16, const std::string& data);
bool same(const std::string& a, const std::string& b);  // in constant time
std::string hex(const std::string& b);
std::string unhex(const std::string& h);  // "" if it is not hex
std::string b64(const std::string& b);
bool unb64(const std::string& s, std::string& out);
// one AES-256 block function over whole blocks (ECB): the platform's part of aesCtr
void aesEcb(const std::string& key32, const unsigned char* in, unsigned char* out, size_t blocks);
}  // namespace crypto
