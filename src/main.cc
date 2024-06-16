#include <cassert>
#include <cstring>
#include <string>
#include "common.hpp"
#include "metal.hpp"
#include "hash.hpp"

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

    // example hash
    u8 mac_ap[6];
    hash::mac_to_bytes("00:11:22:33:44:55", mac_ap);

    u8 mac_sta[6];
    hash::mac_to_bytes("66:77:88:99:AA:BB", mac_sta);

    u32 target_hash[5];
    hash::generate_example("lol", mac_ap, mac_sta, target_hash);
    // end of example hash

    u32 hash[5];
    bool found_match = false;
    hash::generate_permutations(pattern, [&](const u8 test_case[64]) {
        hash::pmkid(test_case, mac_ap, mac_sta, hash);

        for (u64 idx = 0; idx < 5; idx++)
            if (hash[idx] != target_hash[idx])
                // keep looking for matching hashes
                return true;

        found_match = true;
        return false;
    });

    if (found_match) {
        std::string out = hash::bytes_to_digest(reinterpret_cast<u8*>(hash), 20);
        printf("found matching hash: %s\n", out.c_str());
    } else {
        printf("failed to find match hash with given pattern\n");
    }


    return 0;
}
