#pragma once

#include <string_view>
#include "common.hpp"

namespace hash {

void mac_to_bytes(std::string_view mac, u8 out_mac[6]);
std::string bytes_to_digest(const u8* bytes, u64 len);
void digest_to_bytes(std::string_view digest, void* buffer, u64 len);
void generate_example(const char* pmk, const u8 mac_ap[6], const u8 mac_sta[6], u32 out_hash[5]);

}
