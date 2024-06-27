#include <metal_stdlib>
using namespace metal;

kernel void add(
        device const float *A,
        device const float *B,
        device float *out,
        uint id [[thread_position_in_grid]]) {
    out[id] = A[id] + B[id];
}

kernel void mul(
        device float *in,
        device const float &factor,
        uint id [[thread_position_in_grid]]) {
    in[id] *= factor;
}

kernel void mul_buffered(
        device const float *in,
        device float *out,
        device const float &factor,
        uint id [[thread_position_in_grid]]) {
    out[id] = in[id] * factor;
}
