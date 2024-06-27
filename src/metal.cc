#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

#define NS_PRIVATE_IMPLEMENTATION
#define CA_PRIVATE_IMPLEMENTATION
#define MTL_PRIVATE_IMPLEMENTATION

#include "common.hpp"
#include "metal.hpp"

namespace fs = std::filesystem;

constexpr auto get_metal_version() {
#if defined METAL_3_2
    return MTL::LanguageVersion3_2;
#elif defined METAL_3_1
    return MTL::LanguageVersion3_1;
#else
    return MTL::LanguageVersion3_0;
#endif
}

void ComputeFunction::append_arg_buf_inout(ComputeKernel* kern, void* data, u64 size) {
    this->bufs.push_back(ComputeBuffer{
        .data = data,
        .size = size,
        .ty = BUF_INOUT,
    });
}

// More efficient for small values.
void ComputeFunction::append_arg_val(ComputeKernel* kern, void* val, u64 size) {
    this->bufs.push_back(ComputeBuffer{
        .data = val,
        .size = size,
        .ty = VAL_IN,
    });
}

void ComputeFunction::append_arg_buf_out(ComputeKernel* kern, void* data, u64 size) {
    this->bufs.push_back(ComputeBuffer{
        .data = data,
        .size = size,
        .ty = BUF_OUT,
    });
}

MTL::Library* metal_read_lib(MTL::Device* device, std::string_view path) {
    if (!fs::exists(path) || !fs::is_regular_file(path))
        error("source '%s' does not exist or is not a regular file.\n", path.data());

    std::ifstream file(path.data(), std::ios::in | std::ios::binary);
    if (!file.is_open())
        error("could not open source '%s'.\n", path.data());

    std::stringstream code;
    code << file.rdbuf();

    if (file.bad())
        error("incomplete read of source '%s'\n", path.data());

    file.close();

    auto ncode = NS::String::string(code.str().c_str(), NS::ASCIIStringEncoding);

    NS::Error* err = nullptr;
    auto options = MTL::CompileOptions::alloc()->init();

    options->setLanguageVersion(get_metal_version());
    MTL::Library* lib = device->newLibrary(ncode, options, &err);
    options->release();

    if (!lib)
        error_metal(err, "compiling src failed");

    return lib;
}

ComputeKernel::ComputeKernel(std::string_view src_path) {
    static std::atomic<MTL::Device*> g_device = nullptr;

    this->device = g_device.load();
    if (!this->device) {
        NS::Array* devices = MTL::CopyAllDevices();
        this->device = static_cast<MTL::Device*>(devices->object(0));
        g_device.store(this->device);

        printf("found device: %s\n", this->device->name()->utf8String());
    }

    this->queue = this->device->newCommandQueue();
    this->lib = metal_read_lib(this->device, src_path);
}

ComputeKernel::~ComputeKernel() {
    this->device->release();
    this->queue->release();
    this->lib->release();
}

ComputeFunction ComputeKernel::get_function(std::string_view name) {
    return ComputeFunction(this->device, this->lib, name);
}

ComputeFunction::ComputeFunction(MTL::Device* device, MTL::Library* lib, std::string_view name) {
    auto nname = NS::String::string(name.data(), NS::UTF8StringEncoding);
    MTL::Function* func = lib->newFunction(nname);

    if (!func)
        error("function '%s' not found\n", name.data());

    NS::Error* err = nullptr;
    this->pipeline = device->newComputePipelineState(func, &err);

    if (!this->pipeline)
        error_metal(err, "loading pipeline failed");

    func->release();
    nname->release();
}

ComputeFunction::~ComputeFunction() {
    this->pipeline->release();
    for (ComputeBuffer& buf : this->bufs)
        buf.mtl->release();
}

void ComputeFunction::execute(ComputeKernel* kern) {
    MTL::CommandBuffer* cmd_buf = kern->queue->commandBuffer();
    MTL::ComputeCommandEncoder* encoder = cmd_buf->computeCommandEncoder();

    encoder->setComputePipelineState(this->pipeline);

    for (u64 idx = 0; idx < this->bufs.size(); idx++) {
        ComputeBuffer& buf = this->bufs[idx];

        if (buf.ty == VAL_IN) {
            encoder->setBytes(buf.data, buf.size, idx);
            continue;
        }

        if (buf.ty == BUF_INOUT)
            buf.mtl = kern->device->newBuffer(buf.data, buf.size, MTL::ResourceStorageModeShared);

        if (buf.ty == BUF_OUT)
            buf.mtl = kern->device->newBuffer(buf.size, MTL::ResourceStorageModeManaged);

        if (!buf.mtl)
            error("buffer of size %lld was too large for GPU to allocate\n", buf.size);

        encoder->setBuffer(buf.mtl, 0, idx);
    }

    if (this->linear_buf_len == 0)
        error("this->linear_buf_len must set to greater than 0\n");

    auto grid_size = MTL::Size(this->linear_buf_len, 1, 1);
    u64 tgroup_size = this->pipeline->maxTotalThreadsPerThreadgroup();
    if (tgroup_size > this->linear_buf_len)
        tgroup_size = this->linear_buf_len;
    auto tgroups_size = MTL::Size(tgroup_size, 1, 1);

    encoder->dispatchThreadgroups(tgroups_size, grid_size);
    encoder->endEncoding();
    encoder->release();

    cmd_buf->commit();
    cmd_buf->waitUntilCompleted();
    cmd_buf->release();

    // Write back the output buffers.
    for (ComputeBuffer& buf : this->bufs)
        if (buf.ty == BUF_OUT || buf.ty == BUF_INOUT)
            memcpy(buf.data, buf.mtl->contents(), buf.size);
}

u64 align_size(u64 size) {
    if ((size % PAGE_SIZE) != 0)
        size += (PAGE_SIZE - (size % PAGE_SIZE));
    return size;
}

void start_capture(std::string path) {
    setenv("MTL_CAPTURE_ENABLED", "1", 0);
    fs::remove_all(path);

    NS::Array* devices = MTL::CopyAllDevices();
    auto device = static_cast<MTL::Device*>(devices->object(0));

    auto descriptor = MTL::CaptureDescriptor::alloc()->init();
    descriptor->setCaptureObject(device);

    if (!path.empty()) {
        auto string = NS::String::string(path.c_str(), NS::UTF8StringEncoding);
        auto url = NS::URL::fileURLWithPath(string);
        descriptor->setDestination(MTL::CaptureDestinationGPUTraceDocument);
        descriptor->setOutputURL(url);
    }

    auto manager = MTL::CaptureManager::sharedCaptureManager();
    NS::Error* err;
    bool started = manager->startCapture(descriptor, &err);
    descriptor->release();
    if (!started)
        error_metal(err, "start capture failed");
}

void stop_capture() {
  auto manager = MTL::CaptureManager::sharedCaptureManager();
  manager->stopCapture();
}
