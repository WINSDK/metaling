#include <iomanip>
#include <string_view>
#include <sstream>

#include "src/common.hpp"
#include "src/hash.hpp"
#include "src/backend/cpu/hash.hpp"

namespace hash {

void mac_to_bytes(std::string_view mac, u8 out_mac[6]) {
    std::istringstream ss{std::string(mac)};
    std::string token;

    while (std::getline(ss, token, ':')) {
        u8 byte = static_cast<u8>(std::stoi(token, nullptr, 16));
        *out_mac++ = byte;
    }
}

std::string bytes_to_digest(const u8* bytes, u64 len) {
    std::ostringstream oss;
    for (u64 idx = 0; idx < len; idx++) {
        auto byte = static_cast<int>(bytes[idx]);
        oss << std::setw(2) << std::setfill('0') << std::hex << byte;
    }

    return oss.str();
}

void digest_to_bytes(std::string_view digest, void* buffer, u64 len) {
    if (digest.size() != len * 2)
        error("invalid digest length");

    u8* byteBuffer = static_cast<u8*>(buffer);
    for (u64 idx = 0; idx < len; idx++) {
        std::string byteString = std::string(digest.substr(idx * 2, 2));

        if (!std::isxdigit(byteString[0]) || !std::isxdigit(byteString[1]))
            error("invalid character in digest");

        byteBuffer[idx] = static_cast<u8>(std::stoul(byteString, nullptr, 16));
    }
}


void generate_example(const char* pmk, const u8 mac_ap[6], const u8 mac_sta[6], u32 out_hash[5]) {
    u8 pmk_padded[64] = {0};
    u64 pmk_len = std::strlen(pmk);
    std::strncpy(reinterpret_cast<char*>(pmk_padded), pmk, pmk_len);
    cpu::hash::pmkid(pmk_padded, mac_ap, mac_sta, out_hash);
}

}
