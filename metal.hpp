#pragma once

#include <string_view>
#include <vector>
#include "common.hpp"

struct ComputeFunction;
struct ComputeKernel;

enum BufferType {
    VAL_IN,
    BUF_IN,
    BUF_OUT,
};

struct ComputeBuffer {
    void *data;
    u64 size;
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

    void append_arg_buf_inout(ComputeKernel *kern, void *data, u64 size);
    void append_arg_val(ComputeKernel *kern, void *val, u64 size);
    void append_arg_buf_out(ComputeKernel *kern, void *data, u64 size);

    void execute(ComputeKernel *kern);
};

u64 align_size(u64 size);
