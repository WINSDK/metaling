#pragma once

#include <string_view>
#include <cstdint>
#include <vector>

struct ComputeFunction;
struct ComputeKernel;

enum BufferType : uint32_t {
    VAL_IN,
    BUF_IN,
    BUF_OUT,
};

struct ComputeBuffer {
    void *data;
    uint64_t size;
    BufferType ty;
};

struct ComputeKernel {
    void* device;
    void* queue;
    void* lib;

    ComputeKernel(std::string_view src_path);
    ~ComputeKernel();

    ComputeFunction get_kernel_func(std::string_view name);
};

struct ComputeFunction {
    void* pipeline;
    std::vector<ComputeBuffer> bufs;

    ComputeFunction() = delete;
    ~ComputeFunction();

    void append_arg_buf_inout(ComputeKernel *kern, void *data, uint64_t size);
    void append_arg_val(ComputeKernel *kern, void *val, uint64_t size);
    void append_arg_buf_out(ComputeKernel *kern, void *data, uint64_t size);

    void execute(ComputeKernel *kern);
};

uint64_t align_size(uint64_t size);
