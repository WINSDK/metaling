#pragma once 

#include <functional>

#include "src/common.hpp"

namespace cpu::hash {

void pmkid(const u8 pmk[64], const u8 mac_ap[6], const u8 mac_sta[6], u32 out_hash[5]);
void generate_permutations(
    const u8 pattern[64],
    u64 len,
    u64 chunk_idx,
    u64 chunk_count,
    std::function<bool(const u8[64])> callback);

} // namespace hash
