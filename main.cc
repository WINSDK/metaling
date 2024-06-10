#include <cstdio>
#include <cassert>
#include <cstdint>
#include "metal.h"
#include "common.h"

void example_matmul() {
    ComputeKernel kern = ComputeKernel("./math.metal");
    ComputeFunction func = kern.get_kernel_func("matmul");

    float A[] = {1, 2, 3, 4, 5, 6};
    float B[] = {7, 8, 9, 10, 11, 12};
    
    uint32_t width_A = 3;
    uint32_t width_B = 2;
    uint32_t size_C = 4 * sizeof(float);

    func.push_arg(&kern, A, sizeof(A));
    func.push_arg(&kern, B, sizeof(B));
    func.push_arg_output(&kern, size_C);
    func.push_arg(&kern, &width_A, sizeof(width_A));
    func.push_arg(&kern, &width_B, sizeof(width_B));
    func.execute_on_gpu(&kern);

    auto C = (float*)func.pop_arg_output(&kern, size_C);
    float expected_C[] = {58, 64, 139, 154};

    for (int i = 0; i < 4; ++i) {
        assert(C[i] == expected_C[i]);
        if (C[i] == expected_C[i]) {
            printf("C[%d] is correct: %f\n", i, C[i]);
        } else {
            error("C[%d] is incorrect: expected %f, got %f\n", i, expected_C[i], C[i]);
        }
    }
}

int main(int argc, const char * argv[]) {
    example_matmul();

    return 0;
}
