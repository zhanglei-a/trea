#pragma once

#include "common.h"
#include <vector>
#include <string>
#include <cstdint>

// ============================================================================
//  协议层 - 消息打包与解包
//  消息格式: [4B length][4B type][payload...]
//  payload 经过 AES-GCM 加密（本实现用 XOR 流密码演示，生产环境请替换为 AES）
// ============================================================================

namespace rmf {

// 消息头
struct MessageHeader {
    uint32_t length;   // 消息体长度（不含头）
    uint32_t type;     // 消息类型 MsgType
};

// Beacon 注册信息
struct BeaconInfo {
    std::string id;          // Beacon ID (hex)
    std::string hostname;    // 主机名
    std::string username;    // 用户名
    std::string os_version;  // 系统版本
    std::string ip;          // IP 地址
    uint32_t    pid;         // 进程 ID
    uint64_t    timestamp;   // 注册时间戳
};

// 任务结构
struct Task {
    uint32_t    id;          // 任务 ID
    TaskType    type;        // 任务类型
    std::string args;        // 任务参数（JSON 或字符串）
};

// 任务结果
struct TaskResult {
    uint32_t    task_id;     // 对应任务 ID
    bool        success;     // 是否成功
    std::string output;      // 输出内容
    uint64_t    timestamp;   // 完成时间戳
};

// 打包消息（加密后）
std::vector<uint8_t> PackMessage(MsgType type, const std::vector<uint8_t>& payload,
                                 const std::vector<uint8_t>& key);

// 解包消息（解密后），返回 {type, payload}
std::pair<MsgType, std::vector<uint8_t>> UnpackMessage(const std::vector<uint8_t>& data,
                                                       const std::vector<uint8_t>& key);

// 序列化 BeaconInfo
std::vector<uint8_t> SerializeBeaconInfo(const BeaconInfo& info);
BeaconInfo DeserializeBeaconInfo(const std::vector<uint8_t>& data);

// 序列化 Task
std::vector<uint8_t> SerializeTask(const Task& task);
Task DeserializeTask(const std::vector<uint8_t>& data);

// 序列化 TaskResult
std::vector<uint8_t> SerializeTaskResult(const TaskResult& result);
TaskResult DeserializeTaskResult(const std::vector<uint8_t>& data);

// 从 socket 读取完整消息
std::vector<uint8_t> RecvMessage(int sock);
bool SendMessage(int sock, const std::vector<uint8_t>& data);

} // namespace rmf
