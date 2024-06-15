#include <string_view>
#include "common.hpp"

namespace hash {

void pmkid(const char *pmk, const u8 mac_ap[6], const u8 mac_sta[6], u32 out_hash[5]);
void mac_to_bytes(std::string_view mac, u8 out_mac[6]);
std::string bytes_to_digest(const u8* bytes, u64 len);

}
