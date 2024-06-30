#pragma once

#include <Metal/Metal.hpp>
#include <string_view>
#include "common.hpp"

MTL::Library* metal_read_lib(MTL::Device* device, std::string_view path);
u64 align_size(u64 size);
void start_capture(std::string path);
void stop_capture();
