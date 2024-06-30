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
        auto npath = NS::String::string(path.c_str(), NS::UTF8StringEncoding);
        auto url = NS::URL::fileURLWithPath(npath);
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
