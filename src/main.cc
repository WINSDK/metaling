#include <cassert>
#include <cstring>
#include <string>
#include <chrono>
#include <thread>
#include <atomic>

#include "common.hpp"
#include "metal.hpp"
#include "hash.hpp"

using namespace std::chrono;

void buf_cmp(const char* fn, float* got, float* exp, u64 len) {
    for (u64 idx = 0; idx < len; idx++) {
        if (abs(got[idx] - exp[idx]) > 0.005) {
            fputc('\n', stderr);
            error(
                "%s(): arr[%d] is incorrect: expected %.2f, got %.2f\n",
                fn,
                idx,
                exp[idx],
                got[idx]);
        }
    }

    printf("\t%s() works\n", fn);
}

void example_add(ComputeKernel* kern) {
    ComputeFunction add = kern->get_function("add");

    float A[] = {1, 2, 3, 4, 5, 6};
    float B[] = {1, 2, 3, 4, 5, 6};
    float C[] = {0, 0, 0, 0, 0, 0};
    float exp[] = {2, 4, 6, 8, 10, 12};
    u64 buf_len = sizeof(C) / sizeof(float);

    add.append_arg_buf_inout(kern, A, sizeof(A));
    add.append_arg_buf_inout(kern, B, sizeof(A));
    add.append_arg_buf_out(kern, C, sizeof(A));
    add.linear_buf_len = buf_len;

    add.execute(kern);
    buf_cmp(__func__, C, exp, buf_len);
}

void example_mul_buffered(ComputeKernel* kern) {
    ComputeFunction mul = kern->get_function("mul_buffered");

    float in[] = {1, 2, 3, 4, 5, 6};
    float out[] = {0, 0, 0, 0, 0, 0};
    float exp[] = {2, 4, 6, 8, 10, 12};
    float factor = 2.0;
    u64 buf_len = sizeof(in) / sizeof(float);

    mul.append_arg_buf_inout(kern, in, sizeof(in));
    mul.append_arg_buf_out(kern, out, sizeof(out));
    mul.append_arg_val(kern, &factor, sizeof(factor));
    mul.linear_buf_len = buf_len;

    mul.execute(kern);
    buf_cmp(__func__, out, exp, buf_len);
}

void example_mul(ComputeKernel* kern) {
    ComputeFunction mul = kern->get_function("mul");

    float in[] = {1, 2, 3, 4, 5, 6};
    float exp[] = {2, 4, 6, 8, 10, 12};
    float factor = 2.0;
    u64 buf_len = sizeof(in) / sizeof(float);

    mul.append_arg_buf_inout(kern, in, sizeof(in));
    mul.append_arg_val(kern, &factor, sizeof(factor));
    mul.linear_buf_len = buf_len;

    mul.execute(kern);
    buf_cmp(__func__, in, exp, buf_len);
}

const char* PBSTR = "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||";
const u64 PBWIDTH = 60;

void print_progress(double rate, double percentage) {
    int val = (int) (percentage * 100);
    int lpad = (int) (percentage * PBWIDTH);
    int rpad = PBWIDTH - lpad;
    printf("\r  %.1f KH/s %3d%% [%.*s%*s]", rate, val, lpad, PBSTR, rpad, "");
    fflush(stdout);
}

struct GlobalContext {
    std::atomic<bool> found_match;
    std::atomic<u64> total_hash_count;
};

struct ThreadContext {
    u8 *mac_ap;
    u8 *mac_sta;
    u32 *target_hash;
    std::string_view pattern;

    u64 idx;
    u64 thread_count;
    u64 hashes_to_check;
    std::thread thread;
};

void worker(GlobalContext *gctx, ThreadContext *tctx) {
    u32 hash[5];
    u64 hash_count = 0;
    auto start = high_resolution_clock::now();

    hash::generate_permutations(tctx->pattern, tctx->idx, tctx->thread_count, [&](const u8 test_case[64]) {
        hash::pmkid(test_case, tctx->mac_ap, tctx->mac_sta, hash);
        hash_count++;

        if (hash_count == 500000) {
            // Early return if match is found by different thread.
            if (gctx->found_match.load())
                return false;

            u64 total_hash_count = gctx->total_hash_count.load(std::memory_order_acquire);
            gctx->total_hash_count.store(total_hash_count + hash_count, std::memory_order_release);

            auto now = high_resolution_clock::now();
            auto duration = duration_cast<milliseconds>(now - start);
            double hps = ((double)hash_count / (double)duration.count()) * 1000;
            double progress = (double)total_hash_count / (double)tctx->hashes_to_check;
            print_progress(hps / 1024.0, progress);

            start = now;
            hash_count = 0;
        }

        for (u64 jdx = 0; jdx < 5; jdx++)
            if (hash[jdx] != tctx->target_hash[jdx])
                // Keep looking for matching hashes.
                return true;

        std::string out = hash::bytes_to_digest(reinterpret_cast<u8*>(hash), 20);
        printf("\nfound matching hash: %s\n", out.c_str());
        printf("passphrase is: %s\n", test_case);
        gctx->found_match.store(true);
        return false;
    });
}

int main(int argc, const char* argv[]) {
    auto kern_path = std::string(ROOT_DIR) + "/src/math.metal";
    ComputeKernel kern = ComputeKernel(kern_path);

    // printf("tests:\n");
    // example_add(&kern);
    // example_mul_buffered(&kern);
    // example_mul(&kern);

    if (argc < 2)
        error("failed to provide pattern, usage: ./metaling {d|l|u|a|?}*\n");

    const char *pattern = argv[1];

    // Example packet.
    u8 mac_ap[6];
    hash::mac_to_bytes("00:11:22:33:44:55", mac_ap);

    u8 mac_sta[6];
    hash::mac_to_bytes("66:77:88:99:AA:BB", mac_sta);

    u32 target_hash[5];
    hash::generate_example("lola", mac_ap, mac_sta, target_hash);
    // End of example hash.

    u64 hashes_to_check = hash::calculate_total_hashes(pattern);
    printf("hashes to check: %lld\n", hashes_to_check);

    u64 thread_count = std::thread::hardware_concurrency();
    printf("detected %lld threads\n", thread_count);

    ThreadContext threads[thread_count];
    GlobalContext gctx = GlobalContext {
        .found_match = false,
        .total_hash_count = 0,
    };

    for (u64 idx = 0; idx < thread_count; idx++) {
        ThreadContext* tctx = &threads[idx];

        tctx->mac_ap = mac_ap;
        tctx->mac_sta = mac_sta;
        tctx->target_hash = target_hash;
        tctx->pattern = pattern;

        tctx->idx = idx;
        tctx->thread_count = thread_count;
        tctx->hashes_to_check = hashes_to_check;
        tctx->thread = std::thread(worker, &gctx, tctx);
    }

    for (u64 idx = 0; idx < thread_count; idx++)
        threads[idx].thread.join();

    // We showed the progress bar, so print a newline.
    if (gctx.total_hash_count.load() >= 0xfffff) {
        printf("\n");
    }

    return 0;
}
