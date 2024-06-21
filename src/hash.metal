#include <metal_stdlib>
using namespace metal;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

asd
typedef float f32;

struct GlobalContext {
    u8 mac_ap[6];
    u8 mac_sta[6];
    u32 target_hash[5];

    u8 pattern[64];
    u64 pattern_len;

    u64 thread_count;
    u64 hashes_to_check;

    atomic<bool> found_match;
    atomic<u64> total_hash_count;
};

#define STAT_REPORT_INTERVAL 10000

bool do_hashing(device GlobalContext *ctx, u64 hash_count, thread const u8 tc[64], thread u32 hash[5]) {
    pmkid(tc, ctx->mac_ap, ctx->mac_sta, hash);

    if (hash_count == STAT_REPORT_INTERVAL) {
        u64 total_hash_count = atomic_load_explicit(ctx->total_hash_count, memory_order_acquire);
        atomic_store_explicit(ctx->total_hash_count, total_hash_count + hash_count, memory_order_release);
        hash_count = 0;
    }

    for (u64 jdx = 0; jdx < 5; jdx++)
        if (hash[jdx] != ctx->target_hash[jdx])
            // Keep looking for matching hashes.
            return true;

    // std::string out = hash::bytes_to_digest(reinterpret_cast<u8*>(hash), 20);
    // printf("\nfound matching hash: %s\n", out.c_str());
    // printf("passphrase is: %s\n", tc);

    atomic_store_explicit(ctx->found_match, true, memory_order_relaxed);
    return false;
}

#define DIGITS                           \
    "\0"                                 \
    " "                                  \
    "0123456789"
#define LOWERCASE                        \
    "\0"                                 \
    " "                                  \
    "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE                        \
    "\0"                                 \
    " "                                  \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define ALPHA                            \
    "\0"                                 \
    " "                                  \
    "abcdefghijklmnopqrstuvwxyz"         \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define ALPHA_NUM                        \
    "\0"                                 \
    " "                                  \
    "0123456789"                         \
    "abcdefghijklmnopqrstuvwxyz"         \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define ANY                              \
    "\0"                                 \
    " "                                  \
    "0123456789"                         \
    "abcdefghijklmnopqrstuvwxyz"         \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"         \
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

// Function to initialize indices based on a given index.
inline void initialize_indices(u64 current_idx, u32 indices[], const u32 set_sizes[], u64 len) {
    for (u64 idx = 0; idx < len; idx++) {
        u32 set_size = set_sizes[idx];
        indices[idx] = current_idx % set_size;
        current_idx /= set_size;
    }
}

void generate_permutations(device const char* pattern, u64 chunk_idx, u64 chunk_count) {
    u64 len = strlen(pattern);
    u8 current[64] = {0};

    // if (chunk_idx >= chunk_count)
    //     error("idx %lld, is out of range of chunk count %lld\n", chunk_idx, chunk_count);

    // if (chunk_count == 0)
    //     error("chunk count of 0 is not supported.\n");

    // if (len > 64)
    //     error("support for patterns great than 64 characters isn't supported\n");

    // Precompute character sets for each position in the pattern.
    const u8* char_sets[len];
    u32 *set_sizes[len];

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
                break;
                // error("invalid pattern character '%c'\n", pattern[idx]);
        }
    }

    // Calculate the total number of permutations.
    u64 perms = 1;
    for (u64 idx = 0; idx < len; ++idx)
        perms *= set_sizes[idx];

    // Calculate the range of permutations this chunk will handle.
    u64 stride = 1024 * 64;
    u64 start_idx = chunk_idx * stride;
    u64 end_idx = perms;

    // Initialize indices to start at start_index.
    u32 indices[len];
    initialize_indices(start_idx, indices, set_sizes, len);

    u32 hash[5];

    while (start_idx < end_idx) {
        // Construct the current permutation based on indices.
        for (u64 idx = 0; idx < len; idx++)
            current[idx] = char_sets[idx][indices[idx]];

        // if (!callback(current))
        //     return;
        hash_count++;
        do_hashing(ctx, hash_count, current, hash);

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


kernel void entry(device GlobalContext* ctx, uint id [[thread_position_in_grid]]) {
    u64 stat_report_interval = 10000;
    u32 hash[5];
    u64 hash_count = 0;

    generate_permutations(ctx, id);

    generate_permutations(ctx->pattern, id, ctx->thread_count, [&](const u8 tc[64]) {
        pmkid(tc, ctx->mac_ap, ctx->mac_sta, hash);
        hash_count++;

        if (hash_count == STAT_REPORT_INTERVAL) {
            u64 total_hash_count = ctx->total_hash_count.load(std::memory_order_acquire);
            ctx->total_hash_count.store(total_hash_count + hash_count, std::memory_order_release);
            hash_count = 0;
        }

        for (u64 jdx = 0; jdx < 5; jdx++)
            if (hash[jdx] != ctx->target_hash[jdx])
                // Keep looking for matching hashes.
                return true;

        // std::string out = hash::bytes_to_digest(reinterpret_cast<u8*>(hash), 20);
        // printf("\nfound matching hash: %s\n", out.c_str());
        // printf("passphrase is: %s\n", tc);

        ctx->found_match.store(true);
        return false;
    });
}
