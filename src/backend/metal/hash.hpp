#pragma once

#include "src/common.hpp"

namespace metal::hash {

void generate_permutations(
    const char* pattern,
    u64 pattern_len,
    const char** char_sets,
    u32* set_sizes);

}
