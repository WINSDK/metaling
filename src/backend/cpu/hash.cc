#include <functional>

#include "src/common.hpp"
#include "src/backend/cpu/hash.hpp"
#include "src/backend/cpu/sha1.hpp"

namespace cpu::hash {

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

// Function to initialize indices based on a given index.
inline void initialize_indices(u64 current_idx, u32 indices[], const u32 set_sizes[], u64 len) {
    for (u64 idx = 0; idx < len; idx++) {
        u32 set_size = set_sizes[idx];
        indices[idx] = current_idx % set_size;
        current_idx /= set_size;
    }
}

#define MAX_LEN 64

void generate_permutations(
    const u8 pattern[MAX_LEN],
    u64 len,
    u64 chunk_idx,
    u64 chunk_count,
    std::function<bool(const u8[MAX_LEN])> callback) {
    u8 current[MAX_LEN] = {0};

    if (chunk_idx >= chunk_count)
        error("idx %lld, is out of range of chunk count %lld\n", chunk_idx, chunk_count);

    if (chunk_count == 0)
        error("chunk count of 0 is not supported.\n");

    // Precompute character sets for each position in the pattern.
    const char* char_sets[MAX_LEN];
    u32 set_sizes[MAX_LEN];

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
    for (u64 idx = 0; idx < len; idx++)
        perms *= set_sizes[idx];

    // Calculate the range of permutations this chunk will handle.
    u64 stride = 1024 * 64;
    u64 start_idx = chunk_idx * stride;
    u64 end_idx = perms;

    // Initialize indices to start at start_index.
    u32 indices[MAX_LEN];
    initialize_indices(start_idx, indices, set_sizes, len);

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

        // If we've completed a stride, move to the next chunk's corresponding stride.
        if (start_idx % stride == 0) {
            start_idx += (chunk_count - 1) * stride;
            initialize_indices(start_idx, indices, set_sizes, len);
        }
    }
}

} // namespace hash
