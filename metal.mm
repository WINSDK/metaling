#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <vector>
#include <string>
#include <string_view>
#include <cstdio>
#include <cstdint>
#include "common.h"

struct ComputeFunction;
struct ComputeKernel;

struct ComputeBuffer {
    void *data;
    uint64_t size;
    id<MTLBuffer> buf; 
};

struct ComputeFunction {
    id<MTLComputePipelineState> pipeline;
    std::vector<ComputeBuffer> bufs;

    ComputeFunction(id<MTLDevice> device, id<MTLLibrary> lib, std::string_view name);
    ~ComputeFunction();

    void push_arg(ComputeKernel *kern, void *arg, uint64_t size);
    void push_arg_output(ComputeKernel *kern, uint64_t size);
    void* pop_arg_output(ComputeKernel *kern, uint64_t size);
    void execute_on_gpu(ComputeKernel *kern);
};

struct ComputeKernel {
    id<MTLDevice> device;
    id<MTLCommandQueue> queue;
    id<MTLLibrary> lib;

    ComputeKernel(std::string_view src_path);
    ~ComputeKernel();

    ComputeFunction get_kernel_func(std::string_view name);
};

ComputeFunction::ComputeFunction(id<MTLDevice> device, id<MTLLibrary> lib, std::string_view name) {
    NSError *err = nullptr;
    NSString *nname = [NSString stringWithUTF8String:name.data()];
    id<MTLFunction> function = [lib newFunctionWithName:nname];

    if (!function)
        error("Function '%s' not found\n", name.data());

    this->pipeline = [device newComputePipelineStateWithFunction:function error:&err];

    if (err)
        error("loading pipeline failed: %s\n", [[err description] UTF8String]);

    [function release];
    [nname release];
}

inline uint64_t align_size(uint64_t size) {
    if ((size % PAGE_SIZE) != 0)
        size += (PAGE_SIZE - (size % PAGE_SIZE));

    return size;
}

void ComputeFunction::push_arg(ComputeKernel *kern, void *arg, uint64_t size) {
    uint64_t size_aligned = align_size(size);

    id<MTLBuffer> buf = [
        kern->device
        newBufferWithBytes:arg
        length:size_aligned
        options:MTLResourceStorageModeShared
    ];

    if (!buf)
        error("Buffer of size %lld was too large for GPU to allocate\n", size_aligned);

    ComputeBuffer compute_buf {
        .data = arg,
        .size = size,
        .buf = buf,
    };

    this->bufs.push_back(compute_buf);
}

void ComputeFunction::push_arg_output(ComputeKernel *kern, uint64_t size) {
    uint64_t size_aligned = align_size(size);

    id<MTLBuffer> buf = [
        kern->device
        newBufferWithLength:size_aligned
        options:MTLResourceStorageModeShared
    ];

    if (!buf)
        error("Buffer of size %lld was too large for GPU to allocate\n", size_aligned);

    ComputeBuffer compute_buf {
        .data = nullptr,
        .size = size,
        .buf = buf,
    };

    this->bufs.push_back(compute_buf);
}

void* ComputeFunction::pop_arg_output(ComputeKernel *kern, uint64_t size) {
    auto is_output = [](const ComputeBuffer& buf) { return buf.data == nullptr; };
    auto it = std::find_if(this->bufs.rbegin(), this->bufs.rend(), is_output);
    id<MTLBuffer> buf = std::next(it)->buf;
    return [buf contents];
}

void ComputeFunction::execute_on_gpu(ComputeKernel *kern) {
    id<MTLCommandQueue> cmd_queue = [kern->device newCommandQueue];
    id<MTLCommandBuffer> cmd_buf = [cmd_queue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [cmd_buf computeCommandEncoder];
    
    [encoder setComputePipelineState:this->pipeline];
 
    for (uint64_t idx = 0; idx < this->bufs.size(); idx++) {
        [encoder setBuffer:this->bufs[idx].buf offset:0 atIndex:idx];
    }

    MTLSize tgroup_size = MTLSizeMake(1, 1, 1);
    MTLSize tgroup_count = MTLSizeMake(6 * sizeof(float), 1, 1);
    [encoder dispatchThreadgroups:tgroup_count threadsPerThreadgroup:tgroup_size];

    [encoder endEncoding];
    [cmd_buf commit];
    [cmd_buf waitUntilCompleted];
}

ComputeFunction::~ComputeFunction() {
    [this->pipeline release];
    for (ComputeBuffer& compute_buf : this->bufs)
        [compute_buf.buf release];
}

id<MTLLibrary> metal_read_lib(id<MTLDevice> device, std::string_view path) {
    NSError *err = nullptr;
    NSString *npath = [NSString stringWithUTF8String:path.data()];
    NSString *src = [
        NSString
        stringWithContentsOfFile:npath
        encoding:NSUTF8StringEncoding
        error:&err
    ];

    if (err)
        error("loading src failed: %s\n", [[err description] UTF8String]);

    err = nullptr;
    MTLCompileOptions* options = [MTLCompileOptions new];
    id<MTLLibrary> lib = [device newLibraryWithSource:src options:options error:&err];

    if (err)
        error("compiling src failed: %s\n", [[err description] UTF8String]);

    [npath release];
    [src release];
    [options release];

    return lib;
}

ComputeKernel::ComputeKernel(std::string_view src_path) {
    NSArray *devices = MTLCopyAllDevices();
    for (id<MTLDevice> device in devices) {
        printf("found device: %s\n", [[device name] UTF8String]);
    }

    this->device = devices[0];
    this->queue = [this->device newCommandQueue];
    this->lib = metal_read_lib(this->device, src_path);

    [devices release];
}

ComputeKernel::~ComputeKernel() {
    [this->device release];
    [this->queue release];
}

ComputeFunction ComputeKernel::get_kernel_func(std::string_view name) {
    return ComputeFunction(this->device, this->lib, name);
}

