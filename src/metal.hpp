#pragma once

#include <Metal/Metal.hpp>
#include <string_view>
#include <vector>
#include "common.hpp"

struct ComputeFunction;
struct ComputeKernel;

enum BufferType {
    VAL_IN,
    BUF_INOUT,
    BUF_OUT,
};

struct ComputeBuffer {
    void* data;
    u64 size;
    BufferType ty;
    MTL::Buffer* mtl;
};

struct ComputeKernel {
    MTL::Device* device;
    MTL::CommandQueue* queue;
    MTL::Library* lib;

    ComputeKernel(std::string_view src_path);
    ~ComputeKernel();

    ComputeFunction get_function(std::string_view name);
};

struct ComputeFunction {
    MTL::ComputePipelineState* pipeline;
    std::vector<ComputeBuffer> bufs;
    u64 linear_buf_len = 0;

    ComputeFunction(MTL::Device* device, MTL::Library* lib, std::string_view name);
    ~ComputeFunction();

    void append_arg_buf_inout(ComputeKernel* kern, void* data, u64 size);
    void append_arg_val(ComputeKernel* kern, void* val, u64 size);
    void append_arg_buf_out(ComputeKernel* kern, void* data, u64 size);

    void set_buf_len(u64 len);
    void execute(ComputeKernel* kern);
};

u64 align_size(u64 size);
