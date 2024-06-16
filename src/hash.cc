#include <iomanip>
#include <sstream>
#include <string_view>
#include "common.hpp"
#include "hash.hpp"
#include "sha1.hpp"

namespace hash {

// Assumes `out_padded` is already zero-initialized, shouldn't be used outside of testing.
void pad_key(const char* key, u32 out_padded[16]) {
    u64 len = std::strlen(key);

    if (len > 64)
        error("shouldn't pass pmkid(..) pmk's that are larger than 64 characters");

    u8 *out_bytes_padded = reinterpret_cast<u8*>(out_padded);

    // Fill the array with the message data.
    for (u64 idx = 0; idx < len; idx++)
        out_bytes_padded[idx] = key[idx];
}

void hmac_sha1_128_init(u32 ipad[16], u32 opad[16], const u32 key[16]) {
    for (u32 idx = 0; idx < 16; idx++) {
        u32 val = (idx * 4) | ((idx * 4 + 1) << 8) | ((idx * 4 + 2) << 16) | ((idx * 4 + 3) << 24);

        ipad[idx] = val ^ 0x36363636;
        opad[idx] = val ^ 0x5c5c5c5c;

        ipad[idx] ^= key[idx];
        opad[idx] ^= key[idx];
    }
}

inline void hmac_sha1_128(const u32 key[16], const u32 msg[5], u32 out_hash[5]) {
    u32 ipad[21];
    u32 opad[21];
    hmac_sha1_128_init(ipad, opad, key);

    SHA1_CTX ctx;

    u32 inner_hash[5];
    memcpy(&ipad[16], msg, 5 * sizeof(u32));
    SHA1DCInit(&ctx);
    SHA1DCUpdate(&ctx, reinterpret_cast<const char*>(ipad), sizeof(ipad));
    SHA1DCFinal(reinterpret_cast<unsigned char*>(inner_hash), &ctx);

    memcpy(&opad[16], inner_hash, 5 * sizeof(u32));
    SHA1DCInit(&ctx);
    SHA1DCUpdate(&ctx, reinterpret_cast<const char*>(opad), sizeof(opad));
    SHA1DCFinal(reinterpret_cast<unsigned char*>(out_hash), &ctx);
}

void pmkid(const char* pmk, const u8 mac_ap[6], const u8 mac_sta[6], u32 out_hash[5]) {
    u8 msg[20]; // = "PMK Name" + mac_ap + mac_sta

    memcpy(msg, "PMK Name", 8);

    for (u64 idx = 0; idx < 6; idx++)
        msg[idx + 8] = mac_ap[idx];

    for (u64 idx = 0; idx < 6; idx++)
        msg[idx + 14] = mac_sta[idx];

    u32 padded_key[16] = {0};
    pad_key(pmk, padded_key);

    hmac_sha1_128(padded_key, reinterpret_cast<u32*>(msg), out_hash);
}

void mac_to_bytes(std::string_view mac, u8 out_mac[6]) {
    std::istringstream ss{std::string(mac)};
    std::string token;

    while (std::getline(ss, token, ':')) {
        u8 byte = static_cast<u8>(std::stoi(token, nullptr, 16));
        *out_mac++ = byte;
    }
}

std::string bytes_to_digest(const u8* bytes, u64 len) {
    std::ostringstream oss;
    for (u64 idx = 0; idx < len; ++idx) {
        auto byte = static_cast<int>(bytes[idx]);
        oss << std::setw(2) << std::setfill('0') << std::hex << byte;
    }

    return oss.str();
}

}
