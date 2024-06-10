#include <metal_stdlib>
using namespace metal;

kernel void matmul(
        device const float *A,
        device const float *B,
        device float *C,
        device const uint &widthA,
        device const uint &widthB,
        uint id [[thread_position_in_grid]]) {
    uint row = id / widthB;
    uint col = id % widthB;
    
    float sum = 0.0;
    for (uint i = 0; i < widthA; i++) {
        sum += A[row * widthA + i] * B[i * widthB + col];
    }
    
    C[id] = sum;
}
