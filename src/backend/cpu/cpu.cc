#include "src/common.hpp"
#include "src/hash.hpp"
#include "src/backend/cpu/hash.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <thread>

using namespace std::chrono;

namespace cpu {

const char* PBSTR = "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||";
const u64 PBWIDTH = 60;

void print_progress(double rate, double percentage) {
    int val = (int)(percentage * 100);
    int lpad = (int)(percentage * PBWIDTH);
    int rpad = PBWIDTH - lpad;
    printf("\r  %.1f KH/s %3d%% [%.*s%*s]", rate, val, lpad, PBSTR, rpad, "");
    fflush(stdout);
}

struct GlobalContext {
    u8 mac_ap[6];
    u8 mac_sta[6];
    u32 target_hash[5];

    u8 pattern[64];
    u64 pattern_len;

    u64 thread_count;
    u64 hashes_to_check;

    u8 passphrase[64];
    std::atomic<bool> *found_passphrase;
    std::atomic<u64> *total_hash_count;
};

struct ThreadContext {
    u64 idx;
    std::thread thread;
};

const u64 PRINT_INTERVAL = 500000;

void worker(GlobalContext* gctx, ThreadContext* tctx) {
    u32 hash[5];
    u64 hash_count = 0;
    std::chrono::time_point<std::chrono::high_resolution_clock> start;

    // Only the main thread has to record time for showing the progress.
    if (tctx->idx == 0)
        start = high_resolution_clock::now();

    hash::generate_permutations(
        gctx->pattern, gctx->pattern_len, tctx->idx, gctx->thread_count, [&](const u8 tc[64]) {
            hash::pmkid(tc, gctx->mac_ap, gctx->mac_sta, hash);
            hash_count++;

            if (hash_count == PRINT_INTERVAL) {
                // Early return if match is found by different thread.
                if (gctx->found_passphrase->load())
                    return false;

                u64 total_hash_count = gctx->total_hash_count->load(std::memory_order_acquire);
                gctx->total_hash_count->store(
                    total_hash_count + hash_count, std::memory_order_release);

                // Only the main thread updates the progress.
                if (tctx->idx == 0) {
                    auto now = high_resolution_clock::now();
                    auto duration = duration_cast<milliseconds>(now - start);
                    double hps = ((double)hash_count / (double)duration.count()) * 1000;
                    double progress = (double)total_hash_count / (double)gctx->hashes_to_check;

                    // It isn't entirely correct to just multiply the local hash count by the
                    // #thread.
                    print_progress(hps * (double)gctx->thread_count / 1024.0, progress);

                    start = now;
                }

                hash_count = 0;
            }

            for (u64 jdx = 0; jdx < 5; jdx++)
                if (hash[jdx] != gctx->target_hash[jdx])
                    // Keep looking for matching hashes.
                    return true;

            memcpy(gctx->passphrase, tc, 64);
            gctx->found_passphrase->store(true);
            return false;
        });
}

void main(const char* pattern) {
    u64 pattern_len = std::strlen(pattern);

    if (pattern_len > 63)
        error("input patterns must be less than 63 characters");

    u64 hashes_to_check = 100; // broken
    printf("hashes to check: %lld\n", hashes_to_check);

    u64 thread_count = std::thread::hardware_concurrency();
    printf("detected %lld threads\n", thread_count);

    std::atomic<bool> found_passphrase = false;
    std::atomic<u64> total_hash_count = 0;
    GlobalContext gctx = GlobalContext{
        .pattern = {0},
        .pattern_len = pattern_len,
        .thread_count = thread_count,
        .hashes_to_check = hashes_to_check,
        .found_passphrase = &found_passphrase,
        .total_hash_count = &total_hash_count,
    };

    // Copy over pattern, the rest of the characters are '\0's.
    std::strcpy((char*)gctx.pattern, pattern);

    // Example packet.
    ::hash::mac_to_bytes("00:11:22:33:44:55", gctx.mac_ap);
    ::hash::mac_to_bytes("66:77:88:99:AA:BB", gctx.mac_sta);
    ::hash::generate_example("lola1", gctx.mac_ap, gctx.mac_sta, gctx.target_hash);

    ThreadContext threads[thread_count];

    for (u64 idx = 0; idx < thread_count; idx++) {
        ThreadContext* tctx = &threads[idx];
        tctx->idx = idx;
        tctx->thread = std::thread(worker, &gctx, tctx);
    }

    for (u64 idx = 0; idx < thread_count; idx++)
        threads[idx].thread.join();

    // We showed the progress bar, so print a newline.
    if (gctx.total_hash_count->load() >= PRINT_INTERVAL)
        printf("\n");

    if (gctx.found_passphrase->load()) {
        printf("passphrase is: %s\n", gctx.passphrase);
    } else {
        printf("didn't find a passphrase with the given pattern\n");
    }
}

}
