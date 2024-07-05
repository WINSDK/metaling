#include "src/backend/metal/hash.hpp"
#include "src/metal.hpp"
#include "src/common.hpp"
#include "src/hash.hpp"

#include <cassert>
#include <chrono>
#include <cstring>
#include <format>
#include <string_view>
#include <thread>
#include <filesystem>
#include <fstream>

using namespace std::chrono_literals;
using namespace std::chrono;

namespace fs = std::filesystem;

namespace metal {

// arg 0 is len
constexpr std::string_view hash_kernel_defines = R"(
#include <metal_stdlib>
using namespace metal;

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

constant u8 MAC_AP[6] = {1};
constant u8 MAC_STA[6] = {2};
constant u32 TARGET_HASH[5] = {3};
 
constant u8 PATTERN[] = "{4}";
constant u64 LEN = sizeof(PATTERN);

constant u8 CHAR_SETS[{0}][{9}] = {5};
constant u32 SET_SIZES[{0}] = {6};

constant u64 PERM_COUNT = {7};

#define PMK_MSG {8}
)";

// = "PMK Name" + mac_ap + mac_sta
void pmkid_msg_init(u8 msg[20], const u8 mac_ap[6], const u8 mac_sta[6]) {
    msg[0] = 'P';
    msg[1] = 'M';
    msg[2] = 'K';
    msg[3] = ' ';
    msg[4] = 'N';
    msg[5] = 'a';
    msg[6] = 'm';
    msg[7] = 'e';

    for (u64 idx = 0; idx < 6; idx++)
        msg[idx + 8] = mac_ap[idx];

    for (u64 idx = 0; idx < 6; idx++)
        msg[idx + 14] = mac_sta[idx];
}

void dispatch(std::string_view code, u8* passphrase, bool* found_passphrase, u64 pattern_len) {
    NS::Error* err;

    NS::Array* devices = MTL::CopyAllDevices();
    auto device = static_cast<MTL::Device*>(devices->object(0));
    MTL::CommandQueue* queue = device->newCommandQueue();

    NS::String* ncode = NS::String::string(code.data(), NS::ASCIIStringEncoding);

    auto options = MTL::CompileOptions::alloc()->init();
    options->setLanguageVersion(MTL::LanguageVersion3_1);

    err = nullptr;
    MTL::Library* lib = device->newLibrary(ncode, options, &err);

    if (!lib)
        error_metal(err, "compiling kernel failed");

    auto nname = NS::String::string("hash_and_generate_permutations", NS::UTF8StringEncoding);
    MTL::Function* func = lib->newFunction(nname);

    if (!func)
        error("function not found\n");

    err = nullptr;
    MTL::ComputePipelineState* kernel = device->newComputePipelineState(func, &err);

    if (!kernel)
        error_metal(err, "loading pipeline failed");

    MTL::CommandBuffer* cmd_buf = queue->commandBuffer();
    MTL::ComputeCommandEncoder* encoder =
        cmd_buf->computeCommandEncoder(MTL::DispatchTypeConcurrent);

    u32 total_hash_count = 0;

    MTL::Buffer* b1 = device->newBuffer(passphrase, sizeof(u8) * pattern_len, MTL::ResourceStorageModeManaged);
    MTL::Buffer* b2 = device->newBuffer(found_passphrase, sizeof(bool), MTL::ResourceStorageModeManaged);
    MTL::Buffer* b3 = device->newBuffer(&total_hash_count, sizeof(u32), MTL::ResourceStorageModeManaged);

    encoder->setComputePipelineState(kernel);
    encoder->setBuffer(b1, 0, 0);
    encoder->setBuffer(b2, 0, 1);
    encoder->setBuffer(b3, 0, 2);

    MTL::Size group_dims = MTL::Size(1, 1, 1);
    MTL::Size grid_dims = MTL::Size(1, 1, 1);

    encoder->dispatchThreadgroups(grid_dims, group_dims);
    encoder->endEncoding();
    encoder->release();

    cmd_buf->commit();
    cmd_buf->waitUntilCompleted();
    cmd_buf->release();

    // auto start = high_resolution_clock::now();

    // while (true) {
    //    if (ctx->found_passphrase) {
    //        printf("passphrase is: %s\n", ctx->passphrase);
    //        break;
    //    } else {
    //        // printf("didn't find a passphrase with the given pattern\n");
    //    }

    //    auto now = high_resolution_clock::now();
    //    if (duration_cast<seconds>(now - start) > 1s)
    //        break;

    //    std::this_thread::sleep_for(10ms);
    //}

    memcpy(passphrase, b1->contents(), sizeof(u8) * pattern_len);
    memcpy(found_passphrase, b2->contents(), sizeof(bool));
    memcpy(&total_hash_count, b3->contents(), sizeof(u32));

    b1->release();
    b2->release();
    b3->release();

    printf("checked %d hashes\n", total_hash_count);

    kernel->release();
    func->release();
    lib->release();
    device->release();
    devices->release();
}

template <typename T>
std::string format_array(const T *arr, u64 len) {
    std::string formatted_array = "{";
    for (u64 idx = 0; idx < len; idx++) {
        formatted_array += std::format("{}", arr[idx]);
        if (idx < len - 1)
            formatted_array += ", ";
    }
    formatted_array += "}";
    return formatted_array;
}

std::string format_array_str(const char **arr, u64 len) {
    std::string formatted_array = "{";
    for (u64 idx = 0; idx < len; idx++) {
        formatted_array += "\"";
        formatted_array += arr[idx];
        formatted_array += "\"";
        if (idx < len - 1)
            formatted_array += ", ";
    }
    formatted_array += "}";
    return formatted_array;
}

void main(const char* pattern) {
    u64 pattern_len = std::strlen(pattern);

    if (pattern_len > 63)
        error("input patterns must be less than 63 characters");

    u8 mac_ap[6];
    u8 mac_sta[6];
    u32 target_hash[5];

    // Example packet.
    ::hash::mac_to_bytes("00:11:22:33:44:55", mac_ap);
    ::hash::mac_to_bytes("66:77:88:99:AA:BB", mac_sta);
    ::hash::generate_example("a", mac_ap, mac_sta, target_hash);

    const char** char_sets = new const char*[pattern_len];
    u32* set_sizes = new u32[pattern_len];

    hash::generate_permutations(pattern, pattern_len, char_sets, set_sizes);

    u32 largest_set_size = 0;
    for (u64 idx = 0; idx < pattern_len; idx++)
        if (set_sizes[idx] > largest_set_size)
            largest_set_size = set_sizes[idx];

    u64 hashes_to_check = 1;
    for (u64 idx = 0; idx < pattern_len; idx++)
        hashes_to_check *= set_sizes[idx];

    printf("hashes to check: %lld\n", hashes_to_check);

    u8 pmk_msg[20];
    pmkid_msg_init(pmk_msg, mac_ap, mac_sta);

    std::string fmt_kernel_defines = std::format(
        hash_kernel_defines,
        pattern_len,
        format_array<u8>(mac_ap, 6),
        format_array<u8>(mac_sta, 6),
        format_array<u32>(target_hash, 5),
        pattern,
        format_array_str(char_sets, pattern_len),
        format_array<u32>(set_sizes, pattern_len),
        hashes_to_check,
        format_array<u8>(pmk_msg, 20),
        largest_set_size
    );

    std::string path = std::string(ROOT_DIR) + "/src/backend/metal/kernels/sha1.metal";

    if (!fs::exists(path) || !fs::is_regular_file(path))
        error("source '%s' does not exist or is not a regular file.\n", path.data());

    std::ifstream file(path.data(), std::ios::in | std::ios::binary);
    if (!file.is_open())
        error("could not open source '%s'.\n", path.data());

    std::stringstream code;
    code << fmt_kernel_defines;
    code << file.rdbuf();

    if (file.bad())
        error("incomplete read of source '%s'\n", path.data());

    file.close();

    bool found_passphrase = false;
    u8 *passphrase = new u8[pattern_len + 1];

    // metal::start_capture("sha1.gputrace");
    dispatch(code.view(), passphrase, &found_passphrase, pattern_len);
    // metal::stop_capture();

    if (found_passphrase) {
        passphrase[pattern_len] = '\0';
        printf("passphrase: %s\n", passphrase);
    } else {
        printf("found nothing...\n");
    }
    exit(0);

    // We showed the progress bar, so print a newline.
    // if (gctx.total_hash_count->load() >= PRINT_INTERVAL)
    //     printf("\n");

    delete[] char_sets;
    delete[] set_sizes;
    delete[] passphrase;
}

} // namespace metal
