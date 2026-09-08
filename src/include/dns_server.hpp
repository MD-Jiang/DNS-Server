#pragma once

#include "dns_processor.hpp"
#include "thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <sys/eventfd.h>
#include <netinet/in.h>

class DnsServer {
public:
    struct Config {
        std::uint16_t port = 2053;
        std::vector<std::string> upstreams;
        std::string zone_file;
        std::size_t threads = 4;
        std::size_t cache_size = 1024;
        std::size_t upstream_retries = 1;
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
        std::size_t output_offset = 0;
        std::chrono::steady_clock::time_point last_activity;
    };

    struct TcpCompletion {
        enum class Kind { Response, UpstreamQuery };

        Kind kind = Kind::Response;
        bool tcp = false;
        std::weak_ptr<TcpClient> client;
        sockaddr_storage peer{};
        socklen_t peer_length = 0;
        std::vector<std::uint8_t> response;
        DnsQueryPlan plan;
    };

    struct PendingUpstream {
        std::uint16_t upstream_id = 0;
        DnsQueryPlan plan;
        sockaddr_storage peer{};
        socklen_t peer_length = 0;
        std::weak_ptr<TcpClient> client;
        std::chrono::steady_clock::time_point deadline;
        std::uint32_t retries = 0;
    };

    struct NetworkThread {
        DnsServer* server = nullptr;
        int index = 0;
        int epoll_fd = -1;
        int udp_fd = -1;
        int upstream_fd = -1;
        int wake_fd = -1;
        std::thread thread;
        std::mutex queue_mutex;
        std::queue<int> accepted_fds;
        std::queue<TcpCompletion> completions;
        std::unordered_map<int, std::shared_ptr<TcpClient>> clients;
        std::unordered_map<std::uint16_t, PendingUpstream> pending_upstreams;
        std::uint16_t next_upstream_id = 1;
        std::size_t next_upstream_index = 0;
    };

    bool setup_sockets(std::string& error);
    void resolve_upstreams();
    bool setup_network_thread(NetworkThread& network, std::string& error);
    void event_loop();
    void network_loop(NetworkThread& network);
    void accept_clients();
    void handoff_client(int fd);
    void drain_network_queue(NetworkThread& network);
    void read_udp(NetworkThread& network);
    void read_tcp(NetworkThread& network, int fd);
    void close_client(NetworkThread& network, int fd);
    void dispatch_tcp_message(NetworkThread& network,
                              const std::shared_ptr<TcpClient>& client,
                              std::vector<std::uint8_t> message);
    void drain_completions(NetworkThread& network);
    void post_completion(NetworkThread& network, TcpCompletion completion);
    void send_response(NetworkThread& network, const TcpCompletion& completion);
    void flush_tcp_output(NetworkThread& network, const std::shared_ptr<TcpClient>& client);
    void route_request(NetworkThread& network, std::vector<std::uint8_t> request, bool tcp,
                       const sockaddr_storage* peer, socklen_t peer_length,
                       const std::shared_ptr<TcpClient>& client);
    void read_upstream(NetworkThread& network);
    void expire_upstream_queries(NetworkThread& network);
    bool send_upstream(NetworkThread& network, DnsQueryPlan plan,
                       const sockaddr_storage* peer, socklen_t peer_length,
                       const std::shared_ptr<TcpClient>& client);
    static bool set_nonblocking(int fd);
    static bool add_epoll(int epoll_fd, int fd, std::uint32_t events);
    static bool modify_epoll(int epoll_fd, int fd, std::uint32_t events);

    Config config_;
    int epoll_fd_ = -1;
    int tcp_fd_ = -1;
    int signal_fd_ = -1;
    std::atomic<bool> running_{false};
    std::unique_ptr<DnsProcessor> processor_;
    std::unique_ptr<ThreadPool> pool_;
    std::vector<sockaddr_in> upstream_addresses_;
    std::vector<std::shared_ptr<NetworkThread>> network_threads_;
    std::size_t next_network_thread_ = 0;
    std::atomic<std::size_t> total_client_count_{0};
    std::mutex lifecycle_mutex_;

};
