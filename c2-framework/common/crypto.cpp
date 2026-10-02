#include "crypto.h"
#include <random>
#include <cstring>

namespace rmf {

std::vector<uint8_t> Crypto::key_;

void Crypto::SetKey(const std::vector<uint8_t>& key) {
    key_ = key;
    if (key_.size() < KEY_LEN) {
        key_.resize(KEY_LEN, 0);
    }
}

std::vector<uint8_t> Crypto::Encrypt(const std::vector<uint8_t>& plaintext) {
    // XOR 流密码（教学演示）
    // 生产环境请替换为 AES-GCM
    if (key_.empty()) {
        return plaintext;
    }
    std::vector<uint8_t> ciphertext(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); i++) {
        ciphertext[i] = plaintext[i] ^ key_[i % key_.size()];
    }
    return ciphertext;
}

std::vector<uint8_t> Crypto::Decrypt(const std::vector<uint8_t>& ciphertext) {
    // XOR 是对称的，加密解密相同
    return Encrypt(ciphertext);
}

std::vector<uint8_t> Crypto::GenerateKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);

    std::vector<uint8_t> key(KEY_LEN);
    for (size_t i = 0; i < KEY_LEN; i++) {
        key[i] = static_cast<uint8_t>(dis(gen));
    }
    return key;
}

const std::vector<uint8_t>& Crypto::GetKey() {
    return key_;
}

} // namespace rmf
