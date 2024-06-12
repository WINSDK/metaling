#include <cassert>
#include "metal.hpp"
#include "common.hpp"

void example_add() {
    ComputeKernel kern = ComputeKernel("./math.metal");
    ComputeFunction add = kern.get_kernel_func("add");

    float A[] = {1, 2, 3, 4, 5, 6};
    float B[] = {1, 2, 3, 4, 5, 6};
    float C[] = {0, 0, 0, 0, 0, 0};
    float expected_C[] = {2, 4, 6, 8, 10, 12};

    add.append_arg_buf_inout(&kern, A, sizeof(A));
    add.append_arg_buf_inout(&kern, B, sizeof(A));
    add.append_arg_buf_out(&kern, C, sizeof(A));

    add.execute(&kern);

    for (u64 idx = 0; idx < sizeof(C) / sizeof(float); idx++)
        if (abs(C[idx] - expected_C[idx]) > 0.005)
            error("C[%d] is incorrect: expected %.2f, got %.2f\n", idx, expected_C[idx], C[idx]);

    printf("%s() works\n", __func__);
}

void example_mul() {
    ComputeKernel kern = ComputeKernel("./math.metal");
    ComputeFunction add = kern.get_kernel_func("mul");

    float in[] = {1, 2, 3, 4, 5, 6};
    float expected_out[] = {2, 4, 6, 8, 10, 12};
    float factor = 2.0;

    add.append_arg_buf_inout(&kern, in, sizeof(in));
    add.append_arg_val(&kern, &factor, sizeof(factor));
    add.execute(&kern);

    for (u64 idx = 0; idx < sizeof(in) / sizeof(float); idx++)
        if (abs(in[idx] - expected_out[idx]) > 0.005)
            error("C[%d] is incorrect: expected %.2f, got %.2f\n", idx, expected_out[idx], in[idx]);

    printf("%s() works\n", __func__);
}

int main(int argc, const char * argv[]) {
    example_add();
    example_mul();
    return 0;
}
