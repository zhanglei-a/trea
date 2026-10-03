#include "common.h"
#include <random>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/time.h>
#endif

namespace rmf {

std::string GenerateBeaconId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);

    uint8_t id[BEACON_ID_LEN];
    for (size_t i = 0; i < BEACON_ID_LEN; i += 4) {
        uint32_t v = dis(gen);
        memcpy(id + i, &v, 4);
    }
    return ToHexString(id, BEACON_ID_LEN);
}

uint64_t GetTimestampMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string ToHexString(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::vector<uint8_t> FromHexString(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

// Base64 编码表
static const char BASE64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const std::vector<uint8_t>& data) {
    std::string result;
    size_t i = 0;
    while (i < data.size()) {
        uint32_t octet_a = data[i++];
        uint32_t octet_b = (i < data.size()) ? data[i++] : 0;
        uint32_t octet_c = (i < data.size()) ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        result += BASE64_TABLE[(triple >> 18) & 0x3F];
        result += BASE64_TABLE[(triple >> 12) & 0x3F];
        result += (i > data.size() + 1) ? '=' : BASE64_TABLE[(triple >> 6) & 0x3F];
        result += (i > data.size()) ? '=' : BASE64_TABLE[triple & 0x3F];
    }
    return result;
}

std::vector<uint8_t> Base64Decode(const std::string& encoded) {
    std::vector<uint8_t> result;
    auto decode_char = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    int val = 0, bits = 0;
    for (char c : encoded) {
        if (c == '=') break;
        int d = decode_char(c);
        if (d < 0) continue;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
        }
    }
    return result;
}

} // namespace rmf
