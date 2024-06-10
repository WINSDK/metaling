#pragma once

#include <string_view>
#include <cstdint>

struct ComputeFunction;
struct ComputeKernel;

struct ComputeFunction {
    ComputeFunction() = delete;
    ~ComputeFunction();

    void push_arg(ComputeKernel *kern, void *arg, uint64_t size);
    void push_arg_output(ComputeKernel *kern, uint64_t size);
    void* pop_arg_output(ComputeKernel *kern, uint64_t size);
    void execute_on_gpu(ComputeKernel *kern);
};

struct ComputeKernel {
    ComputeKernel(std::string_view src_path);
    ~ComputeKernel();

    ComputeFunction get_kernel_func(std::string_view name);
};
