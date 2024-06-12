#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <vector>
#include <string>
#include <string_view>
#include <cstdio>
#include <cstdint>
#include "common.hpp"

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
    id<MTLBuffer> mtl;
};

struct ComputeKernel {
    id<MTLDevice> device;
    id<MTLCommandQueue> queue;
    id<MTLLibrary> lib;

    ComputeKernel(std::string_view src_path);
    ~ComputeKernel();

    ComputeFunction get_kernel_func(std::string_view name);
};

struct ComputeFunction {
    id<MTLComputePipelineState> pipeline;
    std::vector<ComputeBuffer> bufs;

    ComputeFunction(id<MTLDevice> device, id<MTLLibrary> lib, std::string_view name);
    ~ComputeFunction();

    void append_arg_buf_inout(ComputeKernel *kern, void *data, uint64_t size);
    void append_arg_val(ComputeKernel *kern, void *val, uint64_t size);
    void append_arg_buf_out(ComputeKernel *kern, void *data, uint64_t size);

    void execute(ComputeKernel *kern);
};

void ComputeFunction::append_arg_buf_inout(ComputeKernel *kern, void *data, uint64_t size) {
    this->bufs.push_back(ComputeBuffer {
        .data = data,
        .size = size,
        .ty = BUF_IN,
    });
}

// More efficient for small values.
void ComputeFunction::append_arg_val(ComputeKernel *kern, void *val, uint64_t size) {
    this->bufs.push_back(ComputeBuffer {
        .data = val,
        .size = size,
        .ty = VAL_IN,
    });
}

void ComputeFunction::append_arg_buf_out(ComputeKernel *kern, void *data, uint64_t size) {
    this->bufs.push_back(ComputeBuffer {
        .data = data,
        .size = size,
        .ty = BUF_OUT,
    });
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
        error("Loading src failed: %s\n", [[err description] UTF8String]);

    err = nullptr;
    MTLCompileOptions* options = [MTLCompileOptions new];
    id<MTLLibrary> lib = [device newLibraryWithSource:src options:options error:&err];

    if (err)
        error("Compiling src failed: %s\n", [[err description] UTF8String]);

    [npath release];
    [src release];
    [options release];

    return lib;
}

ComputeKernel::ComputeKernel(std::string_view src_path) {
    NSArray *devices = MTLCopyAllDevices();
    for (id<MTLDevice> device in devices) {
        printf("Found device: %s\n", [[device name] UTF8String]);
    }

    this->device = devices[0];
    this->queue = [this->device newCommandQueue];
    this->lib = metal_read_lib(this->device, src_path);

    [devices release];
}

ComputeKernel::~ComputeKernel() {
    [this->device release];
    [this->queue release];
    [this->lib release];
}

ComputeFunction ComputeKernel::get_kernel_func(std::string_view name) {
    return ComputeFunction(this->device, this->lib, name);
}

ComputeFunction::ComputeFunction(id<MTLDevice> device, id<MTLLibrary> lib, std::string_view name) {
    NSError *err = nullptr;
    NSString *nname = [NSString stringWithUTF8String:name.data()];
    id<MTLFunction> func = [lib newFunctionWithName:nname];

    if (!func)
        error("Function '%s' not found\n", name.data());

    this->pipeline = [device newComputePipelineStateWithFunction:func error:&err];

    if (err)
        error("Loading pipeline failed: %s\n", [[err description] UTF8String]);

    [func release];
    [nname release];
}

ComputeFunction::~ComputeFunction() {
    [this->pipeline release];
    for (ComputeBuffer &buf : this->bufs)
        [buf.mtl release];
}

void ComputeFunction::execute(ComputeKernel *kern) {
    id<MTLCommandBuffer> cmd_buf = [kern->queue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [cmd_buf computeCommandEncoder];

    [encoder setComputePipelineState:this->pipeline];

    for (uint64_t idx = 0; idx < this->bufs.size(); idx++) {
        ComputeBuffer& buf = this->bufs[idx];

        if (buf.ty == VAL_IN) {
            [encoder setBytes:buf.data length:buf.size atIndex:idx];
            continue;
        }

        if (buf.ty == BUF_IN) {
            buf.mtl = [
                kern->device
                newBufferWithBytes:buf.data
                length:buf.size
                options:MTLResourceStorageModeShared
            ];
        }

        if (buf.ty == BUF_OUT) {
            buf.mtl = [
                kern->device
                newBufferWithLength:buf.size
                options:MTLResourceStorageModeManaged
            ];
        }

        if (!buf.mtl)
            error("Buffer of size %lld was too large for GPU to allocate\n", buf.size);

        [encoder setBuffer:buf.mtl offset:0 atIndex:idx];
    }

    MTLSize grid_size = MTLSizeMake(6, 1, 1);
    NSUInteger tgroup_size = this->pipeline.maxTotalThreadsPerThreadgroup;
    if (tgroup_size > 6)
        tgroup_size = 6;
    MTLSize tgroups_size = MTLSizeMake(tgroup_size, 1, 1);

    [encoder dispatchThreadgroups:tgroups_size threadsPerThreadgroup:grid_size];
    [encoder endEncoding];
    [encoder release];
    
    [cmd_buf commit];
    [cmd_buf waitUntilCompleted];
    [cmd_buf release];

    for (ComputeBuffer &buf : this->bufs) {
        if (buf.ty != BUF_OUT)
            continue;

        // Ensure the buffer contents are synchronized for reading.
        [buf.mtl didModifyRange:NSMakeRange(0, buf.size)];

        // Write back output buffers.
        memcpy(buf.data, buf.mtl.contents, buf.size);
    }
}


uint64_t align_size(uint64_t size) {
    if ((size % PAGE_SIZE) != 0)
        size += (PAGE_SIZE - (size % PAGE_SIZE));

    return size;
}
