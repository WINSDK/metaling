#include <string_view>
#include <functional>
#include "common.hpp"

namespace hash {

void pmkid(const u8 pmk[64], const u8 mac_ap[6], const u8 mac_sta[6], u32 out_hash[5]);
void mac_to_bytes(std::string_view mac, u8 out_mac[6]);
std::string bytes_to_digest(const u8* bytes, u64 len);

u64 calculate_total_hashes(std::string_view pattern);

void generate_example(const char *pmk, const u8 mac_ap[6], const u8 mac_sta[6], u32 out_hash[5]);
void generate_permutations(std::string_view pattern, std::function<bool(const u8[64])> callback);

} // namespace hash
