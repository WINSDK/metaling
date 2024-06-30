#include "common.hpp"
#include "hash.hpp"
#include "metal.hpp"

namespace tests {

void sha1() {
    NS::Array* devices = MTL::CopyAllDevices();
    auto device = static_cast<MTL::Device*>(devices->object(0));
    MTL::CommandQueue* queue = device->newCommandQueue();

    std::string path = std::string(ROOT_DIR) + "/src/backend/metal/kernels/sha1_simple.metal";
    MTL::Library* lib = metal_read_lib(device, path);

    auto nname = NS::String::string("sha1", NS::UTF8StringEncoding);
    MTL::Function* func = lib->newFunction(nname);

    if (!func)
        error("function not found\n");

    NS::Error* err = nullptr;
    MTL::ComputePipelineState* kernel = device->newComputePipelineState(func, &err);

    if (!kernel)
        error_metal(err, "loading pipeline failed");

    MTL::CommandBuffer* cmd_buf = queue->commandBuffer();
    MTL::ComputeCommandEncoder* encoder =
        cmd_buf->computeCommandEncoder(MTL::DispatchTypeConcurrent);

    const char* input = "what";
    u64 input_len = std::strlen(input);
    MTL::Buffer* input_buf = device->newBuffer(input, input_len, MTL::ResourceStorageModeManaged);

    u32 hash[5];
    MTL::Buffer* hash_buf = device->newBuffer(sizeof(hash), MTL::ResourceStorageModeManaged);

    encoder->setComputePipelineState(kernel);
    encoder->setBuffer(input_buf, 0, 0);
    encoder->setBuffer(hash_buf, 0, 1);
    encoder->setBytes(&input_len, sizeof(input_len), 2);

    MTL::Size group_dims = MTL::Size(1, 1, 1);
    MTL::Size grid_dims = MTL::Size(1, 1, 1);

    encoder->dispatchThreadgroups(grid_dims, group_dims);
    encoder->endEncoding();
    encoder->release();

    cmd_buf->commit();
    cmd_buf->waitUntilCompleted();
    cmd_buf->release();

    memcpy(hash, hash_buf->contents(), sizeof(hash));

    input_buf->release();
    hash_buf->release();

    kernel->release();
    func->release();
    lib->release();
    device->release();
    devices->release();

    std::string exp = "a110e6b9a361653a042e3f5dfbac4c6105693789";
    std::string got = hash::bytes_to_digest((u8*)hash, sizeof(hash));

    if (exp != got)
        error("mismatch in hashes:\nexp: %s\ngot: %s\n", exp.c_str(), got.c_str());

    printf("\t%s() works\n", __func__);
}

void sha1_hmac() {
    NS::Array* devices = MTL::CopyAllDevices();
    auto device = static_cast<MTL::Device*>(devices->object(0));
    MTL::CommandQueue* queue = device->newCommandQueue();

    std::string path = std::string(ROOT_DIR) + "/src/backend/metal/kernels/sha1.metal";
    MTL::Library* lib = metal_read_lib(device, path);

    auto nname = NS::String::string("test_sha1_hmac", NS::UTF8StringEncoding);
    MTL::Function* func = lib->newFunction(nname);

    if (!func)
        error("function not found\n");

    NS::Error* err = nullptr;
    MTL::ComputePipelineState* kernel = device->newComputePipelineState(func, &err);

    if (!kernel)
        error_metal(err, "loading pipeline failed");

    MTL::CommandBuffer* cmd_buf = queue->commandBuffer();
    MTL::ComputeCommandEncoder* encoder =
        cmd_buf->computeCommandEncoder(MTL::DispatchTypeConcurrent);

    u32 hash[5];
    MTL::Buffer* hash_buf = device->newBuffer(sizeof(hash), MTL::ResourceStorageModeManaged);

    encoder->setComputePipelineState(kernel);
    encoder->setBuffer(hash_buf, 0, 0);

    MTL::Size group_dims = MTL::Size(1, 1, 1);
    MTL::Size grid_dims = MTL::Size(1, 1, 1);

    encoder->dispatchThreadgroups(grid_dims, group_dims);
    encoder->endEncoding();
    encoder->release();

    cmd_buf->commit();
    cmd_buf->waitUntilCompleted();
    cmd_buf->release();

    memcpy(hash, hash_buf->contents(), sizeof(hash));

    hash_buf->release();

    kernel->release();
    func->release();
    lib->release();
    device->release();
    devices->release();

    std::string exp = "f61a533909a63012da90f7e4b0924f5dcb8bd95f";
    std::string got = hash::bytes_to_digest((u8*)hash, sizeof(hash));

    if (exp != got)
        printf("mismatch in hashes:\nexp: %s\ngot: %s\n", exp.c_str(), got.c_str());
    else
        printf("\t%s() works\n", __func__);
}

void run() {
    start_capture("metaling.gputrace");

    printf("tests:\n");
    sha1();
    sha1_hmac();

    stop_capture();
}

}
