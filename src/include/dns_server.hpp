#pragma once

#include "dns_processor.hpp"
#include "thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class DnsServer {
public:
    struct Config {
        std::uint16_t port = 2053;
        std::vector<std::string> upstreams;
        std::string zone_file;
        std::size_t threads = 4;
        std::size_t cache_size = 1024;
    };

    explicit DnsServer(Config config);
    ~DnsServer();
    DnsServer(const DnsServer&) = delete;
    DnsServer& operator=(const DnsServer&) = delete;
    bool start(std::string& error);
    void stop() noexcept;

private:
    struct TcpClient {
        int fd = -1;
        std::vector<std::uint8_t> input;
        std::vector<std::uint8_t> output;
        std::mutex mutex;
        std::chrono::steady_clock::time_point last_activity;
    };

    bool setup_sockets(std::string& error);
    void event_loop();
    void accept_clients();
    void read_udp();
    void read_tcp(int fd);
    void close_client(int fd);
    void dispatch_tcp_message(const std::shared_ptr<TcpClient>& client, std::vector<std::uint8_t> message);
    static bool set_nonblocking(int fd);
    static bool add_epoll(int epoll_fd, int fd, std::uint32_t events);
    static bool modify_epoll(int epoll_fd, int fd, std::uint32_t events);

    Config config_;
    int epoll_fd_ = -1;
    int udp_fd_ = -1;
    int tcp_fd_ = -1;
    int signal_fd_ = -1;
    std::atomic<bool> running_{false};
    std::unique_ptr<DnsProcessor> processor_;
    std::unique_ptr<ThreadPool> pool_;
    std::unordered_map<int, std::shared_ptr<TcpClient>> clients_;
};
