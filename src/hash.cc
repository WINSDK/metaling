#include "hash.hpp"
#include <functional>
#include <iomanip>
#include <sstream>
#include <string_view>
#include "common.hpp"
#include "sha1.hpp"

namespace hash {

// Assumption we make when casting strings.
static_assert(sizeof(char) == sizeof(u8));

void hmac_sha1_128_init(u32 ipad[16], u32 opad[16], const u32 key[16]) {
    for (u32 idx = 0; idx < 16; idx++) {
        u32 val = (idx * 4) | ((idx * 4 + 1) << 8) | ((idx * 4 + 2) << 16) | ((idx * 4 + 3) << 24);

        ipad[idx] = val ^ 0x36363636;
        opad[idx] = val ^ 0x5c5c5c5c;

        ipad[idx] ^= key[idx];
        opad[idx] ^= key[idx];
    }
}

thread_local SHA1_CTX ctx;

inline void hmac_sha1_128(const u32 key[16], const u32 msg[5], u32 out_hash[5]) {
    u32 ipad[21];
    u32 opad[21];
    hmac_sha1_128_init(ipad, opad, key);

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

// Must have `pmk` zero initialized for any unused bytes.
void pmkid(const u8 pmk[64], const u8 mac_ap[6], const u8 mac_sta[6], u32 out_hash[5]) {
    u8 msg[20]; // = "PMK Name" + mac_ap + mac_sta

    memcpy(msg, "PMK Name", 8);

    for (u64 idx = 0; idx < 6; idx++)
        msg[idx + 8] = mac_ap[idx];

    for (u64 idx = 0; idx < 6; idx++)
        msg[idx + 14] = mac_sta[idx];

    hmac_sha1_128(reinterpret_cast<const u32*>(pmk), reinterpret_cast<u32*>(msg), out_hash);
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

void generate_example(const char* pmk, const u8 mac_ap[6], const u8 mac_sta[6], u32 out_hash[5]) {
    u8 pmk_padded[64] = {0};
    u64 pmk_len = std::strlen(pmk);
    std::strncpy(reinterpret_cast<char*>(pmk_padded), pmk, pmk_len);
    hash::pmkid(pmk_padded, mac_ap, mac_sta, out_hash);
}

#define DIGITS "0123456789"
#define LOWERCASE "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define ALPHA LOWERCASE UPPERCASE
#define ANY ALPHA "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

void generate_permutations(std::string_view pattern, std::function<bool(const u8[64])> callback) {
    u64 len = pattern.size();
    u8 current[64] = {0};

    if (len > 64)
        error("Support for patterns great than 64 characters isn't supported");

    // Precompute character sets for each position in the pattern.
    const char* char_sets[len];
    u32 set_sizes[len];

    for (u64 idx = 0; idx < len; idx++) {
        switch (pattern[idx]) {
            case 'd':
                char_sets[idx] = DIGITS;
                set_sizes[idx] = std::strlen(DIGITS);
                break;
            case 'l':
                char_sets[idx] = LOWERCASE;
                set_sizes[idx] = std::strlen(LOWERCASE);
                break;
            case 'u':
                char_sets[idx] = UPPERCASE;
                set_sizes[idx] = std::strlen(UPPERCASE);
                break;
            case 'a':
                char_sets[idx] = ALPHA;
                set_sizes[idx] = std::strlen(ALPHA);
                break;
            case '?':
                char_sets[idx] = ANY;
                set_sizes[idx] = std::strlen(ANY);
                break;
            default:
                error("invalid pattern character '%c'", pattern[idx]);
        }
    }

    u32 indices[len];
    memset(indices, 0, sizeof(u32) * len);

    while (true) {
        // Construct the current permutation based on indices.
        for (u64 idx = 0; idx < len; idx++)
            current[idx] = char_sets[idx][indices[idx]];

        if (!callback(current))
            return;

        // Increment indices from right to left.
        i64 pos = len - 1;
        while (pos >= 0) {
            if (indices[pos] < set_sizes[pos] - 1) {
                indices[pos]++;
                break;
            } else {
                indices[pos] = 0;
                pos--;
            }
        }

        // All permutations generated.
        if (pos < 0)
            break;
    }
}

} // namespace hash
