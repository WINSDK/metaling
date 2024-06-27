#include <metal_stdlib>
using namespace metal;

// #import "sha1.metal"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef float f32;

struct GlobalContext {
    u8 mac_ap[6];
    u8 mac_sta[6];
    u32 target_hash[5];

    u8 pattern[64];
    u64 pattern_len;

    u64 thread_count;
    u64 hashes_to_check;

    u8 passphrase[64];
    bool found_passphrase;
    // device atomic<ulong> *total_hash_count;
};

void hmac_sha1_128_init(u32 ipad[16], u32 opad[16], const u32 key[16]) {
    for (u32 idx = 0; idx < 16; idx++) {
        u32 val = (idx * 4) | ((idx * 4 + 1) << 8) | ((idx * 4 + 2) << 16) | ((idx * 4 + 3) << 24);

        ipad[idx] = val ^ 0x36363636;
        opad[idx] = val ^ 0x5c5c5c5c;

        ipad[idx] ^= key[idx];
        opad[idx] ^= key[idx];
    }
}

// thread_local SHA1_CTX ctx;

inline void hmac_sha1_128(const u32 key[16], const u32 msg[5], u32 out_hash[5]) {
    u32 ipad[21];
    u32 opad[21];
    hmac_sha1_128_init(ipad, opad, key);

    u32 inner_hash[5];

    for (u64 idx = 0; idx < 5; idx++)
        ipad[16 + idx] = msg[idx];

    // SHA1DCInit(&ctx);
    // SHA1DCUpdate(&ctx, reinterpret_cast<const char*>(ipad), sizeof(ipad));
    // SHA1DCFinal(reinterpret_cast<unsigned char*>(inner_hash), &ctx);

    for (u64 idx = 0; idx < 5; idx++)
        opad[16 + idx] = inner_hash[idx];

    // SHA1DCInit(&ctx);
    // SHA1DCUpdate(&ctx, reinterpret_cast<const char*>(opad), sizeof(opad));
    // SHA1DCFinal(reinterpret_cast<unsigned char*>(out_hash), &ctx);
}

// = "PMK Name" + mac_ap + mac_sta
void pmkid_msg_init(u8 msg[20], device const u8 mac_ap[6], device const u8 mac_sta[6]) {
    msg[0] = 'P';
    msg[1] = 'M';
    msg[2] = 'K';
    msg[3] = ' ';
    msg[4] = 'N';
    msg[5] = 'a';
    msg[6] = 'm';
    msg[7] = 'e';

    for (u64 idx = 0; idx < 6; idx++)
        msg[idx + 8] = mac_ap[idx];

    for (u64 idx = 0; idx < 6; idx++)
        msg[idx + 14] = mac_sta[idx];
}

#define STAT_REPORT_INTERVAL 10000

bool pmkid(device GlobalContext *ctx, u32 hash[5], thread u64 &hash_count, u8 msg[20], thread const u8 current[64]) {
    hmac_sha1_128(
        reinterpret_cast<thread const u32*>(current),
        reinterpret_cast<thread u32*>(msg),
        hash
    );

    hash_count++;

    if (hash_count == STAT_REPORT_INTERVAL) {
        // u64 total_hash_count = atomic_load_explicit(ctx->total_hash_count, memory_order_relaxed);
        // atomic_store_explicit(ctx->total_hash_count, total_hash_count + hash_count, memory_order_relaxed);
        // atomic_fence();

        hash_count = 0;
    }

    for (u64 jdx = 0; jdx < 5; jdx++)
        if (hash[jdx] != ctx->target_hash[jdx])
            // Keep looking for matching hashes.
            return true;

    // Notify CPU of the passphrase we found.
    for (u64 idx = 0; idx < 64; idx++)
        ctx->passphrase[idx] = current[idx];
    ctx->found_passphrase = true;

    return false;
}

constant u8 DIGITS[] =
    "\0"
    " "
    "0123456789";
constant u8 LOWERCASE[] =
    "\0"
    " "
    "abcdefghijklmnopqrstuvwxyz";
constant u8 UPPERCASE[] =
    "\0"
    " "
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constant u8 ALPHA[] =
    "\0"
    " "
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constant u8 ALPHA_NUM[] =
    "\0"
    " "
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constant u8 ANY[] =
    "\0"
    " "
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

// Function to initialize indices based on a given index.
inline void initialize_indices(u64 current_idx, u32 indices[], const u32 set_sizes[], u64 len) {
    for (u64 idx = 0; idx < len; idx++) {
        u32 set_size = set_sizes[idx];
        indices[idx] = current_idx % set_size;
        current_idx /= set_size;
    }
}

template <uint LEN>
kernel void hash_and_generate_permutations(
        device GlobalContext* ctx,
        uint id [[thread_position_in_grid]]) {
    u8 current[LEN] = {0};
    u64 len = ctx->pattern_len;
    u64 chunk_count = ctx->thread_count;

    if (id >= chunk_count)
        return; // this is an error

    // Precompute character sets for each position in the pattern.
    constant u8* char_sets[LEN];
    u32 set_sizes[LEN];

    for (u64 idx = 0; idx < len; idx++) {
        switch (ctx->pattern[idx]) {
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
                return; // this is an error
        }
    }

    // Calculate the total number of permutations.
    u64 perms = 1;
    for (u64 idx = 0; idx < len; ++idx)
        perms *= set_sizes[idx];

    // Calculate the range of permutations this chunk will handle.
    u64 stride = 1024 * 64;
    u64 start_idx = id * stride;
    u64 end_idx = perms;

    // Initialize indices to start at start_index.
    u32 indices[LEN];
    initialize_indices(start_idx, indices, set_sizes, len);

    u32 hash[5];
    u64 hash_count = 0;

    u8 pmk_msg[20];
    pmkid_msg_init(pmk_msg, ctx->mac_ap, ctx->mac_sta);

    while (start_idx < end_idx) {
        // Construct the current permutation based on indices.
        for (u64 idx = 0; idx < len; idx++)
            current[idx] = char_sets[idx][indices[idx]];

        if (!single_iter_hash(ctx, hash, hash_count, pmk_msg, current))
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
