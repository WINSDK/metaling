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

u8 DIGITS[] =
    "\0"
    " "
    "0123456789";
u8 LOWERCASE[] =
    "\0"
    " "
    "abcdefghijklmnopqrstuvwxyz";
u8 UPPERCASE[] =
    "\0"
    " "
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
u8 ALPHA[] =
    "\0"
    " "
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
u8 ALPHA_NUM[] =
    "\0"
    " "
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
u8 ANY[] =
    "\0"
    " "
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

u64 calculate_total_hashes(std::string_view pattern) {
    u64 perms = 1;

    for (u64 idx = 0; idx < pattern.length(); idx++) {
        switch (pattern[idx]) {
            case 'd':
                perms *= sizeof(DIGITS);
                break;
            case 'l':
                perms *= sizeof(LOWERCASE);
                break;
            case 'u':
                perms *= sizeof(UPPERCASE);
                break;
            case 'a':
                perms *= sizeof(ALPHA);
                break;
            case 'n':
                perms *= sizeof(ALPHA_NUM);
                break;
            case '?':
                perms *= sizeof(ANY);
                break;
            default:
                error("invalid pattern character '%c'\n", pattern[idx]);
        }
    }

    return perms;
}

void generate_permutations(
    std::string_view pattern,
    u64 chunk_idx,
    u64 chunk_count,
    std::function<bool(const u8[64])> callback) {
    u64 len = pattern.length();
    u8 current[64] = {0};

    if (chunk_idx >= chunk_count)
        error("idx %lld, is out of range of chunk count %lld\n", chunk_idx, chunk_count);

    if (chunk_count == 0)
        error("chunk count of 0 is not supported.\n");

    if (len > 64)
        error("support for patterns great than 64 characters isn't supported\n");

    // Precompute character sets for each position in the pattern.
    const u8* char_sets[len];
    u32 set_sizes[len];

    for (u64 idx = 0; idx < len; idx++) {
        switch (pattern[idx]) {
            case 'd':
                char_sets[idx] = DIGITS;
                set_sizes[idx] = sizeof(DIGITS);
                break;
            case 'l':
                char_sets[idx] = LOWERCASE;
                set_sizes[idx] = sizeof(LOWERCASE);
                break;
            case 'u':
                char_sets[idx] = UPPERCASE;
                set_sizes[idx] = sizeof(UPPERCASE);
                break;
            case 'a':
                char_sets[idx] = ALPHA;
                set_sizes[idx] = sizeof(ALPHA);
                break;
            case 'n':
                char_sets[idx] = ALPHA_NUM;
                set_sizes[idx] = sizeof(ALPHA_NUM);
                break;
            case '?':
                char_sets[idx] = ANY;
                set_sizes[idx] = sizeof(ANY);
                break;
            default:
                error("invalid pattern character '%c'\n", pattern[idx]);
        }
    }

    // Calculate the total number of permutations.
    u64 perms = 1;
    for (u64 idx = 0; idx < len; ++idx)
        perms *= set_sizes[idx];

    // Calculate the range of permutations this chunk will handle.
    u64 chunk_size = (perms + chunk_count - 1) / chunk_count; // Ceiling division.
    u64 start_idx = chunk_idx * chunk_size;
    u64 end_idx = std::min(start_idx + chunk_size, perms);

    // Initialize indices to start at start_index.
    u32 indices[len];
    u32 current_idx = start_idx;
    for (u64 idx = 0; idx < len; ++idx) {
        u32 set_size = set_sizes[idx];
        indices[idx] = current_idx % set_size;
        current_idx /= set_size;
    }

    while (start_idx < end_idx) {
        // Construct the current permutation based on indices.
        for (u64 idx = 0; idx < len; idx++)
            current[idx] = char_sets[idx][indices[idx]];

        if (!callback(current))
            return;

        // Increment indices from left to right.
        u64 pos = 0;
        while (pos < len) {
            if (indices[pos] < set_sizes[pos] - 1) {
                indices[pos]++;
                break;
            } else {
                indices[pos] = 0;
                pos++;
            }
        }

        // All permutations generated
        if (pos == len)
            break;

        start_idx++;
    }
}

} // namespace hash
