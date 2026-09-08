#include "dns_server.hpp"
#include "upstream_address.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
constexpr std::size_t max_tcp_output_size = 1024 * 1024;
constexpr std::size_t max_tcp_input_size = 1024 * 1024;
constexpr std::size_t max_packets_per_event = 64;
constexpr std::size_t max_total_clients = 10000;

void close_fd(int& fd) {
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}

void set_query_id(std::vector<std::uint8_t>& packet, const std::uint16_t id) {
    if (packet.size() < 2) return;
    const std::uint16_t wire_id = htons(id);
    std::memcpy(packet.data(), &wire_id, sizeof(wire_id));
}
} // namespace

DnsServer::DnsServer(Config config) : config_(std::move(config)) {}
DnsServer::~DnsServer() { stop(); }

void DnsServer::resolve_upstreams() {
    upstream_addresses_.clear();
    upstream_addresses_.reserve(config_.upstreams.size());
    for (const std::string& upstream : config_.upstreams) {
        sockaddr_in address{};
        if (parse_upstream_address(upstream, address)) {
            upstream_addresses_.push_back(address);
        }
    }
}

bool DnsServer::set_nonblocking(const int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool DnsServer::add_epoll(const int epoll_fd, const int fd, const std::uint32_t events) {
    epoll_event event{};
    event.events = events;
    event.data.fd = fd;
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == 0;
}

bool DnsServer::modify_epoll(const int epoll_fd, const int fd, const std::uint32_t events) {
    epoll_event event{};
    event.events = events;
    event.data.fd = fd;
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event) == 0;
}

bool DnsServer::setup_network_thread(NetworkThread& network, std::string& error) {
    network.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    network.udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    network.wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (!config_.upstreams.empty()) {
        network.upstream_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    }
    if (network.epoll_fd < 0 || network.udp_fd < 0 || network.wake_fd < 0 ||
        (!config_.upstreams.empty() && network.upstream_fd < 0)) {
        error = "network socket creation failed: " + std::string(std::strerror(errno));
        return false;
    }
    int reuse = 1;
    if (setsockopt(network.udp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        setsockopt(network.udp_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) != 0) {
        error = "SO_REUSEPORT setup failed: " + std::string(std::strerror(errno));
        return false;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config_.port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(network.udp_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        !add_epoll(network.epoll_fd, network.udp_fd, EPOLLIN | EPOLLET) ||
        !add_epoll(network.epoll_fd, network.wake_fd, EPOLLIN)) {
        error = "UDP bind/epoll setup failed: " + std::string(std::strerror(errno));
        return false;
    }
    if (network.upstream_fd >= 0 &&
        !add_epoll(network.epoll_fd, network.upstream_fd, EPOLLIN | EPOLLET)) {
        error = "upstream epoll registration failed: " + std::string(std::strerror(errno));
        return false;
    }
    return true;
}

bool DnsServer::setup_sockets(std::string& error) {
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    tcp_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (epoll_fd_ < 0 || tcp_fd_ < 0) {
        error = "TCP socket creation failed: " + std::string(std::strerror(errno));
        return false;
    }
    int reuse = 1;
    setsockopt(tcp_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config_.port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(tcp_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(tcp_fd_, SOMAXCONN) != 0) {
        error = "TCP bind/listen failed: " + std::string(std::strerror(errno));
        return false;
    }
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &signals, nullptr) != 0) {
        error = "cannot block termination signals";
        return false;
    }
    signal_fd_ = signalfd(-1, &signals, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd_ < 0 || !add_epoll(epoll_fd_, tcp_fd_, EPOLLIN | EPOLLET) ||
        !add_epoll(epoll_fd_, signal_fd_, EPOLLIN)) {
        error = "main epoll registration failed: " + std::string(std::strerror(errno));
        return false;
    }
    const std::size_t network_count = std::max<std::size_t>(config_.threads, 1);
    network_threads_.reserve(network_count);
    for (std::size_t index = 0; index < network_count; ++index) {
        auto network = std::make_shared<NetworkThread>();
        network->server = this;
        network->index = static_cast<int>(index);
        if (!setup_network_thread(*network, error)) return false;
        network_threads_.push_back(std::move(network));
    }
    return true;
}

bool DnsServer::start(std::string& error) {
    ZoneStore zone;
    if (!config_.zone_file.empty() && !zone.load(config_.zone_file, error)) return false;
    ProcessorConfig processor_config;
    processor_config.upstreams = config_.upstreams;
    processor_ = std::make_unique<DnsProcessor>(std::move(zone), std::move(processor_config), config_.cache_size);
    resolve_upstreams();
    pool_ = std::make_unique<ThreadPool>(config_.threads, config_.threads * 1024);
    if (!setup_sockets(error)) {
        stop();
        return false;
    }
    running_.store(true);
    for (auto& network : network_threads_) {
        network->thread = std::thread(&DnsServer::network_loop, this, std::ref(*network));
    }
    event_loop();
    return true;
}

void DnsServer::stop() noexcept {
    std::lock_guard<std::mutex> lifecycle_lock(lifecycle_mutex_);
    const bool was_running = running_.exchange(false);
    if (was_running) {
        for (const auto& network : network_threads_) {
            const std::uint64_t notification = 1;
            if (network->wake_fd >= 0) (void)write(network->wake_fd, &notification, sizeof(notification));
        }
    }
    if (pool_) pool_->stop();
    for (auto& network : network_threads_) {
        if (network->thread.joinable()) network->thread.join();
        close_fd(network->wake_fd);
        close_fd(network->upstream_fd);
        close_fd(network->udp_fd);
        close_fd(network->epoll_fd);
    }
    network_threads_.clear();
    total_client_count_.store(0, std::memory_order_release);
    close_fd(signal_fd_);
    close_fd(tcp_fd_);
    close_fd(epoll_fd_);
    pool_.reset();
}

void DnsServer::accept_clients() {
    while (true) {
        const int fd = accept4(tcp_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        handoff_client(fd);
    }
}

void DnsServer::handoff_client(const int fd) {
    if (network_threads_.empty()) {
        close(fd);
        return;
    }
    NetworkThread& network = *network_threads_[next_network_thread_++ % network_threads_.size()];
    std::size_t current_clients = total_client_count_.load(std::memory_order_relaxed);
    while (current_clients < max_total_clients &&
           !total_client_count_.compare_exchange_weak(
               current_clients, current_clients + 1, std::memory_order_acq_rel,
               std::memory_order_relaxed)) {}
    if (current_clients >= max_total_clients) {
        close(fd);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(network.queue_mutex);
        network.accepted_fds.push(fd);
    }
    const std::uint64_t notification = 1;
    if (write(network.wake_fd, &notification, sizeof(notification)) < 0 && errno != EAGAIN) {
        {
            std::lock_guard<std::mutex> lock(network.queue_mutex);
            if (!network.accepted_fds.empty() && network.accepted_fds.back() == fd) {
                network.accepted_fds.pop();
            }
        }
        total_client_count_.fetch_sub(1, std::memory_order_acq_rel);
        close(fd);
    }
}

void DnsServer::drain_network_queue(NetworkThread& network) {
    std::uint64_t notification = 0;
    while (read(network.wake_fd, &notification, sizeof(notification)) > 0) {}
    std::queue<int> accepted;
    {
        std::lock_guard<std::mutex> lock(network.queue_mutex);
        accepted.swap(network.accepted_fds);
    }
    while (!accepted.empty()) {
        const int fd = accepted.front();
        accepted.pop();
        auto client = std::make_shared<TcpClient>();
        client->fd = fd;
        client->last_activity = std::chrono::steady_clock::now();
        network.clients[fd] = client;
        if (!add_epoll(network.epoll_fd, fd, EPOLLIN | EPOLLET | EPOLLRDHUP)) close_client(network, fd);
    }
}

void DnsServer::read_udp(NetworkThread& network) {
    std::array<std::uint8_t, 65535> buffer{};
    for (std::size_t count = 0; count < max_packets_per_event; ++count) {
        sockaddr_storage peer{};
        socklen_t peer_length = sizeof(peer);
        const ssize_t received = recvfrom(network.udp_fd, buffer.data(), buffer.size(), 0,
                                          reinterpret_cast<sockaddr*>(&peer), &peer_length);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        route_request(network, std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + received),
                      false, &peer, peer_length, nullptr);
    }
}

void DnsServer::dispatch_tcp_message(NetworkThread& network,
                                      const std::shared_ptr<TcpClient>& client,
                                      std::vector<std::uint8_t> message) {
    route_request(network, std::move(message), true, nullptr, 0, client);
}

void DnsServer::route_request(NetworkThread& network, std::vector<std::uint8_t> request,
                              const bool tcp, const sockaddr_storage* peer,
                              const socklen_t peer_length,
                              const std::shared_ptr<TcpClient>& client) {
    sockaddr_storage request_peer{};
    if (peer != nullptr) request_peer = *peer;
    const std::weak_ptr<TcpClient> weak_client = client;
    auto request_data = std::make_shared<const std::vector<std::uint8_t>>(std::move(request));
    const std::shared_ptr<NetworkThread> network_owner = network_threads_[network.index];
    if (!pool_->submit([this, network_owner, request_data, tcp, request_peer, peer_length, weak_client]() {
        if (!running_.load(std::memory_order_acquire)) return;
        DnsQueryPlan plan;
        std::string error;
        const bool prepared = processor_->prepare(request_data->data(), request_data->size(), tcp,
                                                  plan, error);
        TcpCompletion completion;
        completion.tcp = tcp;
        completion.peer = request_peer;
        completion.peer_length = peer_length;
        completion.client = weak_client;
        if (prepared && plan.action == DnsQueryPlan::Action::Upstream) {
            completion.kind = TcpCompletion::Kind::UpstreamQuery;
            completion.plan = std::move(plan);
        } else {
            completion.response = std::move(plan.response);
        }
        if (!completion.response.empty() || completion.kind == TcpCompletion::Kind::UpstreamQuery) {
            post_completion(*network_owner, std::move(completion));
        }
    })) return;
}

bool DnsServer::send_upstream(NetworkThread& network, DnsQueryPlan plan,
                              const sockaddr_storage* peer, const socklen_t peer_length,
                              const std::shared_ptr<TcpClient>& client) {
    if (network.upstream_fd < 0 || upstream_addresses_.empty()) return false;
    std::uint16_t upstream_id = network.next_upstream_id++;
    while (upstream_id == 0 || network.pending_upstreams.count(upstream_id) != 0) {
        upstream_id = network.next_upstream_id++;
    }
    set_query_id(plan.query, upstream_id);
    bool sent = false;
    for (std::size_t offset = 0; offset < upstream_addresses_.size(); ++offset) {
        const std::size_t index = (network.next_upstream_index + offset) % upstream_addresses_.size();
        const sockaddr_in& address = upstream_addresses_[index];
        if (sendto(network.upstream_fd, plan.query.data(), plan.query.size(), 0,
                   reinterpret_cast<const sockaddr*>(&address), sizeof(address)) >= 0) {
            sent = true;
            network.next_upstream_index = (index + 1) % upstream_addresses_.size();
            break;
        }
    }
    if (!sent) return false;
    PendingUpstream pending;
    pending.upstream_id = upstream_id;
    pending.plan = std::move(plan);
    if (peer != nullptr) {
        pending.peer = *peer;
        pending.peer_length = peer_length;
    }
    pending.client = client;
    pending.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    network.pending_upstreams.emplace(upstream_id, std::move(pending));
    return true;
}

void DnsServer::read_upstream(NetworkThread& network) {
    std::array<std::uint8_t, 65535> buffer{};
    for (std::size_t count = 0; count < max_packets_per_event; ++count) {
        const ssize_t received = recvfrom(network.upstream_fd, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        if (received < 2) continue;
        std::uint16_t wire_id = 0;
        std::memcpy(&wire_id, buffer.data(), sizeof(wire_id));
        const auto found = network.pending_upstreams.find(ntohs(wire_id));
        if (found == network.pending_upstreams.end()) continue;
        PendingUpstream pending = std::move(found->second);
        network.pending_upstreams.erase(found);
        auto packet = std::make_shared<const std::vector<std::uint8_t>>(buffer.begin(), buffer.begin() + received);
        const DnsQueryPlan plan = pending.plan;
        const std::weak_ptr<TcpClient> client = pending.client;
        const sockaddr_storage peer = pending.peer;
        const socklen_t peer_length = pending.peer_length;
        const std::shared_ptr<NetworkThread> network_owner = network_threads_[network.index];
        if (!pool_->submit([this, network_owner, plan, packet, client, peer, peer_length]() {
            if (!running_.load(std::memory_order_acquire)) return;
            auto response = processor_->finish_upstream(plan, packet->data(), packet->size());
            if (response.empty()) {
                response = processor_->overload_response(plan.query.data(), plan.query.size(), plan.tcp);
            }
            if (response.empty()) return;
            TcpCompletion completion;
            completion.tcp = plan.tcp;
            completion.client = client;
            completion.peer = peer;
            completion.peer_length = peer_length;
            completion.response = response;
            post_completion(*network_owner, std::move(completion));
        })) continue;
    }
}

void DnsServer::expire_upstream_queries(NetworkThread& network) {
    const auto now = std::chrono::steady_clock::now();
    for (auto iterator = network.pending_upstreams.begin(); iterator != network.pending_upstreams.end();) {
        PendingUpstream& pending = iterator->second;
        if (pending.deadline > now) { ++iterator; continue; }
        if (pending.retries++ < config_.upstream_retries) {
            pending.deadline = now + std::chrono::seconds(2);
            for (std::size_t offset = 0; offset < upstream_addresses_.size(); ++offset) {
                const std::size_t index = (network.next_upstream_index + offset) % upstream_addresses_.size();
                const sockaddr_in& address = upstream_addresses_[index];
                if (sendto(network.upstream_fd, pending.plan.query.data(), pending.plan.query.size(), 0,
                           reinterpret_cast<const sockaddr*>(&address), sizeof(address)) >= 0) {
                    network.next_upstream_index = (index + 1) % upstream_addresses_.size();
                    break;
                }
            }
            ++iterator;
            continue;
        }
        iterator = network.pending_upstreams.erase(iterator);
    }
}

void DnsServer::post_completion(NetworkThread& network, TcpCompletion completion) {
    if (!running_.load(std::memory_order_acquire)) return;
    {
        std::lock_guard<std::mutex> lock(network.queue_mutex);
        network.completions.push(std::move(completion));
    }
    const std::uint64_t notification = 1;
    (void)write(network.wake_fd, &notification, sizeof(notification));
}

void DnsServer::drain_completions(NetworkThread& network) {
    std::queue<TcpCompletion> completions;
    {
        std::lock_guard<std::mutex> lock(network.queue_mutex);
        completions.swap(network.completions);
    }
    while (!completions.empty()) {
        TcpCompletion completion = std::move(completions.front());
        completions.pop();
        if (completion.kind == TcpCompletion::Kind::UpstreamQuery) {
            auto client = completion.client.lock();
            if (completion.plan.tcp && !client) continue;
            (void)send_upstream(network, std::move(completion.plan), &completion.peer,
                                completion.peer_length, client);
        } else {
            send_response(network, completion);
        }
    }
}

void DnsServer::send_response(NetworkThread& network, const TcpCompletion& completion) {
    if (completion.response.empty()) return;
    if (auto client = completion.client.lock()) {
        const auto found = network.clients.find(client->fd);
        if (found == network.clients.end() || found->second != client) return;
        if (completion.response.size() > 65535 ||
            client->output.size() - client->output_offset + 2 + completion.response.size() > max_tcp_output_size) {
            close_client(network, client->fd);
            return;
        }
        const std::uint16_t length = htons(static_cast<std::uint16_t>(completion.response.size()));
        const auto* prefix = reinterpret_cast<const std::uint8_t*>(&length);
        client->output.insert(client->output.end(), prefix, prefix + 2);
        client->output.insert(client->output.end(), completion.response.begin(), completion.response.end());
        client->last_activity = std::chrono::steady_clock::now();
        modify_epoll(network.epoll_fd, client->fd, EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP);
        return;
    }
    if (completion.peer_length != 0) {
        (void)sendto(network.udp_fd, completion.response.data(), completion.response.size(), 0,
                     reinterpret_cast<const sockaddr*>(&completion.peer), completion.peer_length);
    }
}

void DnsServer::flush_tcp_output(NetworkThread& network, const std::shared_ptr<TcpClient>& client) {
    while (client->output_offset < client->output.size()) {
        const ssize_t sent = send(client->fd, client->output.data() + client->output_offset,
                                  client->output.size() - client->output_offset, MSG_NOSIGNAL);
        if (sent > 0) { client->output_offset += static_cast<std::size_t>(sent); continue; }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        close_client(network, client->fd);
        return;
    }
    if (client->output_offset == client->output.size()) {
        client->output.clear();
        client->output_offset = 0;
    }
    if (network.clients.find(client->fd) != network.clients.end()) {
        modify_epoll(network.epoll_fd, client->fd, client->output.empty()
            ? EPOLLIN | EPOLLET | EPOLLRDHUP : EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP);
    }
}

void DnsServer::read_tcp(NetworkThread& network, const int fd) {
    const auto found = network.clients.find(fd);
    if (found == network.clients.end()) return;
    const auto client = found->second;
    std::array<std::uint8_t, 8192> buffer{};
    while (true) {
        const ssize_t received = recv(fd, buffer.data(), buffer.size(), 0);
        if (received == 0) { close_client(network, fd); return; }
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            close_client(network, fd);
            return;
        }
        if (client->input.size() + static_cast<std::size_t>(received) > max_tcp_input_size) {
            close_client(network, fd);
            return;
        }
        client->input.insert(client->input.end(), buffer.begin(), buffer.begin() + received);
        client->last_activity = std::chrono::steady_clock::now();
    }
    while (client->input.size() >= 2) {
        std::uint16_t wire_length = 0;
        std::memcpy(&wire_length, client->input.data(), sizeof(wire_length));
        const std::size_t message_length = ntohs(wire_length);
        if (message_length == 0) { close_client(network, fd); return; }
        if (client->input.size() < message_length + 2) return;
        std::vector<std::uint8_t> message(client->input.begin() + 2,
                                          client->input.begin() + 2 + message_length);
        client->input.erase(client->input.begin(), client->input.begin() + 2 + message_length);
        dispatch_tcp_message(network, client, std::move(message));
    }
}

void DnsServer::close_client(NetworkThread& network, const int fd) {
    epoll_ctl(network.epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
    network.clients.erase(fd);
    total_client_count_.fetch_sub(1, std::memory_order_acq_rel);
}

void DnsServer::network_loop(NetworkThread& network) {
    std::array<epoll_event, 128> events{};
    while (running_.load()) {
        const int count = epoll_wait(network.epoll_fd, events.data(), events.size(), 250);
        if (count < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int index = 0; index < count; ++index) {
            const int fd = events[index].data.fd;
            const std::uint32_t event = events[index].events;
            if (fd == network.wake_fd) { drain_network_queue(network); continue; }
            if (fd == network.udp_fd) { read_udp(network); continue; }
            if (fd == network.upstream_fd) { read_upstream(network); continue; }
            if ((event & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
                close_client(network, fd);
                continue;
            }
            if ((event & EPOLLIN) != 0) read_tcp(network, fd);
            if ((event & EPOLLOUT) != 0) {
                const auto found = network.clients.find(fd);
                if (found != network.clients.end()) flush_tcp_output(network, found->second);
            }
        }
        drain_completions(network);
        expire_upstream_queries(network);
        processor_->cleanup_cache();
        const auto now = std::chrono::steady_clock::now();
        for (auto iterator = network.clients.begin(); iterator != network.clients.end();) {
            if (now - iterator->second->last_activity > std::chrono::seconds(30)) {
                const int fd = iterator->first;
                ++iterator;
                close_client(network, fd);
            } else {
                ++iterator;
            }
        }
    }
    for (const auto& entry : network.clients) close(entry.first);
    network.clients.clear();
}

void DnsServer::event_loop() {
    std::array<epoll_event, 16> events{};
    while (running_.load()) {
        const int count = epoll_wait(epoll_fd_, events.data(), events.size(), 1000);
        if (count < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int index = 0; index < count; ++index) {
            const int fd = events[index].data.fd;
            if (fd == signal_fd_) {
                signalfd_siginfo info{};
                (void)read(signal_fd_, &info, sizeof(info));
                running_.store(false);
            } else if (fd == tcp_fd_) {
                accept_clients();
            }
        }
    }
    stop();
}
