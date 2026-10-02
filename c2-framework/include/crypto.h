#pragma once

#include "common.h"
#include <vector>
#include <string>

// ============================================================================
//  加密模块
//  注意：本实现使用 XOR 流密码作为教学演示。
//  生产环境必须替换为 AES-GCM（Windows 下使用 BCrypt API）。
// ============================================================================

namespace rmf {

class Crypto {
public:
    // 设置密钥（16 字节）
    static void SetKey(const std::vector<uint8_t>& key);

    // 加密/解密（XOR 流密码，对称操作）
    static std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext);
    static std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext);

    // 生成随机密钥
    static std::vector<uint8_t> GenerateKey();

    // 获取当前密钥
    static const std::vector<uint8_t>& GetKey();

private:
    static std::vector<uint8_t> key_;
};

} // namespace rmf
