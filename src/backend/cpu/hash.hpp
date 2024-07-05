#pragma once 

#include <functional>

#include "src/common.hpp"

namespace cpu::hash {

const char DIGITS[] =
    "\0"
    " "
    "0123456789";
const char LOWERCASE[] =
    "\0"
    " "
    "abcdefghijklmnopqrstuvwxyz";
const char UPPERCASE[] =
    "\0"
    " "
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char ALPHA[] =
    "\0"
    " "
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char ALPHA_NUM[] =
    "\0"
    " "
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char ANY[] =
    "\0"
    " "
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

void pmkid(const u8 pmk[64], const u8 mac_ap[6], const u8 mac_sta[6], u32 out_hash[5]);
void generate_permutations(
    const u8 pattern[64],
    u64 len,
    u64 chunk_idx,
    u64 chunk_count,
    std::function<bool(const u8[64])> callback);

} // namespace hash
