#include "src/common.hpp"
#include "src/hash.hpp"
#include "src/metal.hpp"

#include <cassert>
#include <chrono>
#include <cstring>
#include <thread>

using namespace std::chrono_literals;
using namespace std::chrono;

namespace metal {

struct GlobalContext {
    u8 mac_ap[6];
    u8 mac_sta[6];
    u32 target_hash[5];

    u8 pattern[64];
    u64 pattern_len;

    u64 hashes_to_check;

    u8 passphrase[64];
    bool found_passphrase;
    // device atomic<ulong> *total_hash_count;
};

void dispatch(GlobalContext *ctx) {
    NS::Array* devices = MTL::CopyAllDevices();
    auto device = static_cast<MTL::Device*>(devices->object(0));
    MTL::CommandQueue* queue = device->newCommandQueue();

    std::string path = std::string(ROOT_DIR) + "/src/backend/metal/kernels/sha1.metal";
    MTL::Library* lib = metal_read_lib(device, path);

    auto nname = NS::String::string("hash_and_generate_permutations", NS::UTF8StringEncoding);
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

    MTL::Buffer* ctx_buf = device->newBuffer(ctx, sizeof(GlobalContext), MTL::ResourceStorageModeManaged);

    encoder->setComputePipelineState(kernel);
    encoder->setBuffer(ctx_buf, 0, 0);

    MTL::Size group_dims = MTL::Size(1, 1, 1);
    MTL::Size grid_dims = MTL::Size(kernel->maxTotalThreadsPerThreadgroup(), 1, 1);

    encoder->dispatchThreadgroups(grid_dims, group_dims);
    encoder->endEncoding();
    // encoder->release();

    cmd_buf->commit();
    // cmd_buf->waitUntilCompleted();

    auto start = high_resolution_clock::now();

    while (true) {
        if (ctx->found_passphrase) {
            printf("passphrase is: %s\n", ctx->passphrase);
            break;
        } else {
            // printf("didn't find a passphrase with the given pattern\n");
        }

        // auto now = high_resolution_clock::now();
        // if (duration_cast<seconds>(now - start) > 1s)
        //     break;

        std::this_thread::sleep_for(10ms);
    }

    printf("found it!\n");

    cmd_buf->release();
    encoder->release();

    ctx_buf->release();

    kernel->release();
    func->release();
    lib->release();
    device->release();
    devices->release();
}

void main(const char* pattern) {
    u64 pattern_len = std::strlen(pattern);

    if (pattern_len > 63)
        error("input patterns must be less than 63 characters");

    u64 hashes_to_check = ::hash::calculate_total_hashes(pattern);
    printf("hashes to check: %lld\n", hashes_to_check);

    GlobalContext ctx = GlobalContext{
        .pattern = {0},
        .pattern_len = pattern_len,
        .hashes_to_check = hashes_to_check,
        .found_passphrase = false,
    };

    // Copy over pattern, the rest of the characters are '\0's.
    std::strcpy((char*)ctx.pattern, pattern);

    // Example packet.
    ::hash::mac_to_bytes("00:11:22:33:44:55", ctx.mac_ap);
    ::hash::mac_to_bytes("66:77:88:99:AA:BB", ctx.mac_sta);
    ::hash::generate_example("lola1", ctx.mac_ap, ctx.mac_sta, ctx.target_hash);

    start_capture("./capturing.gputrace");
    dispatch(&ctx);
    stop_capture();

    // We showed the progress bar, so print a newline.
    // if (gctx.total_hash_count->load() >= PRINT_INTERVAL)
    //     printf("\n");

}

}
