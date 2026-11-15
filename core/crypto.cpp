// crypto.h: what is the same everywhere — counter mode over the platform's AES block, hex, base64, comparison
#include "crypto.h"

#include <cstring>
#include <vector>

namespace crypto {
std::string aesCtr(const std::string& key32, const std::string& iv16, const std::string& data) {
    const size_t blocks = (data.size() + 15) / 16;
    std::vector<unsigned char> ctr(blocks * 16), ks(blocks * 16);
    unsigned char c[16];
    for (int i = 0; i < 16; i++) c[i] = (unsigned char)iv16[i];
    for (size_t b = 0; b < blocks; b++) {
        std::copy(c, c + 16, ctr.begin() + (long)(b * 16));
        for (int i = 15; i >= 0 && ++c[i] == 0; i--) {}  // +1, big-endian over all 128 bits
    }
    if (blocks) aesEcb(key32, ctr.data(), ks.data(), blocks);
    std::string out(data);
    for (size_t i = 0; i < out.size(); i++) out[i] = (char)(out[i] ^ ks[i]);
    return out;
}

bool same(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char d = 0;
    for (size_t i = 0; i < a.size(); i++) d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

std::string hex(const std::string& b) {
    static const char* x = "0123456789abcdef";
    std::string out;
    for (unsigned char c : b) { out += x[c >> 4]; out += x[c & 15]; }
    return out;
}
std::string unhex(const std::string& h) {
    if (h.size() % 2) return "";
    auto v = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; };
    std::string out;
    for (size_t i = 0; i < h.size(); i += 2) {
        const int a = v(h[i]), b = v(h[i + 1]);
        if (a < 0 || b < 0) return "";
        out += (char)(a * 16 + b);
    }
    return out;
}

static const char* kB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string b64(const std::string& b) {
    std::string out;
    size_t i = 0;
    for (; i + 2 < b.size(); i += 3) {
        const unsigned n = ((unsigned char)b[i] << 16) | ((unsigned char)b[i + 1] << 8) | (unsigned char)b[i + 2];
        out += kB64[n >> 18]; out += kB64[(n >> 12) & 63]; out += kB64[(n >> 6) & 63]; out += kB64[n & 63];
    }
    if (i + 1 == b.size()) {
        const unsigned n = (unsigned char)b[i] << 16;
        out += kB64[n >> 18]; out += kB64[(n >> 12) & 63]; out += "==";
    } else if (i + 2 == b.size()) {
        const unsigned n = ((unsigned char)b[i] << 16) | ((unsigned char)b[i + 1] << 8);
        out += kB64[n >> 18]; out += kB64[(n >> 12) & 63]; out += kB64[(n >> 6) & 63]; out += '=';
    }
    return out;
}
bool unb64(const std::string& s, std::string& out) {
    out.clear();
    unsigned n = 0;
    int bits = 0;
    for (char ch : s) {
        if (ch == '=') break;
        const char* p = strchr(kB64, ch);
        if (!p || !ch) return false;
        n = (n << 6) | (unsigned)(p - kB64);
        bits += 6;
        if (bits >= 8) { bits -= 8; out += (char)((n >> bits) & 0xff); }
    }
    return true;
}
}  // namespace crypto
