#pragma once

#include <Metal/Metal.hpp>
#include <string_view>
#include "common.hpp"

namespace metal {

std::unique_ptr<void, std::function<void(void*)>> new_scoped_memory_pool();
MTL::Library* read_lib(MTL::Device* device, std::string_view path, std::string_view header = "");
u64 align_size(u64 size);
void start_capture(std::string path);
void stop_capture();

}
