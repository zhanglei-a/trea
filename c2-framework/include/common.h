#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>

// ============================================================================
//  通用定义 - Remote Management Framework
//  仅用于授权的远程运维/安全研究场景
// ============================================================================

namespace rmf {

// 协议版本
constexpr uint32_t PROTOCOL_VERSION = 0x00000001;

// 默认端口
constexpr uint16_t DEFAULT_PORT = 4444;

// 默认心跳间隔（毫秒）
constexpr uint32_t DEFAULT_HEARTBEAT_MS = 5000;

// 最大消息长度（16 MB）
constexpr uint32_t MAX_MESSAGE_SIZE = 16 * 1024 * 1024;

// Beacon ID 长度（8 字节）
constexpr size_t BEACON_ID_LEN = 8;

// 加密密钥长度（AES-128）
constexpr size_t KEY_LEN = 16;

// 消息类型
enum class MsgType : uint32_t {
    HELLO     = 0x01,  // Beacon 注册
    HEARTBEAT = 0x02,  // 心跳
    TASK      = 0x03,  // 任务下发
    RESULT    = 0x04,  // 结果回传
    ERROR     = 0x05,  // 错误
};

// 任务类型
enum class TaskType : uint32_t {
    CMD_EXEC    = 0x01,  // 执行命令
    POWERSHELL  = 0x02,  // 执行 PowerShell
    SYSINFO     = 0x03,  // 系统信息
    SLEEP       = 0x04,  // 修改心跳间隔
    UPLOAD      = 0x05,  // 上传文件到目标
    DOWNLOAD    = 0x06,  // 从目标下载文件
    SHELLCODE   = 0x07,  // 执行 Shellcode（安全研究用）
    EXIT        = 0xFF,  // 退出 Beacon
};

// Beacon 状态
enum class BeaconStatus : uint32_t {
    ACTIVE   = 0x01,
    IDLE     = 0x02,
    OFFLINE  = 0x03,
};

// 生成随机 Beacon ID
std::string GenerateBeaconId();

// 获取当前时间戳（毫秒）
uint64_t GetTimestampMs();

// 十六进制字符串转换
std::string ToHexString(const uint8_t* data, size_t len);
std::vector<uint8_t> FromHexString(const std::string& hex);

// Base64 编解码
std::string Base64Encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> Base64Decode(const std::string& encoded);

} // namespace rmf
