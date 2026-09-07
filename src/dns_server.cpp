#include "dns_server.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <array>
#include <iostream>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

void close_fd(int& fd) {
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}

bool parse_upstream_address(const std::string& value, sockaddr_in& address) {
    std::string host = value;
    std::uint16_t port = 53;
    const std::size_t separator = value.rfind(':');
    if (separator != std::string::npos && value.find(':') == separator) {
        host = value.substr(0, separator);
        try { port = static_cast<std::uint16_t>(std::stoul(value.substr(separator + 1))); }
        catch (...) { return false; }
    }
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) == 1) return true;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) return false;
    address.sin_addr = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr;
    freeaddrinfo(result);
    return true;
}

void set_query_id(std::vector<std::uint8_t>& packet, const std::uint16_t id) {
    if (packet.size() < 2) return;
    const std::uint16_t wire_id = htons(id);
    std::memcpy(packet.data(), &wire_id, sizeof(wire_id));
}

} // namespace

DnsServer::DnsServer(Config config) : config_(std::move(config)) {}

DnsServer::~DnsServer() { stop(); }

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

bool DnsServer::setup_sockets(std::string& error) {
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    udp_fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    tcp_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    completion_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (!config_.upstreams.empty()) {
        upstream_fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    }
    if (epoll_fd_ < 0 || udp_fd_ < 0 || tcp_fd_ < 0 || completion_fd_ < 0 ||
        (!config_.upstreams.empty() && upstream_fd_ < 0)) {
        error = "socket creation failed: " + std::string(std::strerror(errno));
        return false;
    }
    int reuse = 1;
    setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(tcp_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config_.port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(udp_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        bind(tcp_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(tcp_fd_, SOMAXCONN) != 0) {
        error = "bind/listen failed: " + std::string(std::strerror(errno));
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
    if (signal_fd_ < 0 || !add_epoll(epoll_fd_, udp_fd_, EPOLLIN | EPOLLET) ||
        !add_epoll(epoll_fd_, tcp_fd_, EPOLLIN | EPOLLET) ||
        !add_epoll(epoll_fd_, signal_fd_, EPOLLIN) ||
        !add_epoll(epoll_fd_, completion_fd_, EPOLLIN) ||
        (upstream_fd_ >= 0 && !add_epoll(epoll_fd_, upstream_fd_, EPOLLIN | EPOLLET))) {
        error = "epoll registration failed: " + std::string(std::strerror(errno));
        return false;
    }
    return true;
}

bool DnsServer::start(std::string& error) {
    ZoneStore zone;
    if (!config_.zone_file.empty() && !zone.load(config_.zone_file, error)) return false;
    ProcessorConfig processor_config;
    processor_config.upstreams = config_.upstreams;
    processor_ = std::make_unique<DnsProcessor>(std::move(zone), std::move(processor_config), config_.cache_size);
    pool_ = std::make_unique<ThreadPool>(config_.threads, config_.threads * 1024);
    if (!setup_sockets(error)) {
        stop();
        return false;
    }
    running_.store(true);
    event_loop();
    return true;
}

void DnsServer::stop() noexcept {
    if (!running_.exchange(false)) {
        pool_.reset();
        close_fd(signal_fd_);
        close_fd(completion_fd_);
        close_fd(upstream_fd_);
        close_fd(udp_fd_);
        close_fd(tcp_fd_);
        close_fd(epoll_fd_);
        return;
    }
    for (const auto& entry : clients_) {
        int fd = entry.first;
        close(fd);
    }
    clients_.clear();
    if (pool_) pool_->stop();
    close_fd(signal_fd_);
    close_fd(completion_fd_);
    close_fd(upstream_fd_);
    close_fd(udp_fd_);
    close_fd(tcp_fd_);
    close_fd(epoll_fd_);
}

void DnsServer::read_udp() {
    std::array<std::uint8_t, 65535> buffer{};
    while (true) {
        sockaddr_storage peer{};
        socklen_t peer_length = sizeof(peer);
        const ssize_t received = recvfrom(udp_fd_, buffer.data(), buffer.size(), 0,
                                          reinterpret_cast<sockaddr*>(&peer), &peer_length);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        route_request(std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + received),
                      false, &peer, peer_length, nullptr);
    }
}

void DnsServer::accept_clients() {
    while (true) {
        const int fd = accept4(tcp_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        auto client = std::make_shared<TcpClient>();
        client->fd = fd;
        client->last_activity = std::chrono::steady_clock::now();
        clients_[fd] = client;
        if (!add_epoll(epoll_fd_, fd, EPOLLIN | EPOLLET | EPOLLRDHUP)) close_client(fd);
    }
}

void DnsServer::dispatch_tcp_message(const std::shared_ptr<TcpClient>& client,
                                     std::vector<std::uint8_t> message) {
    route_request(std::move(message), true, nullptr, 0, client);
}

void DnsServer::route_request(std::vector<std::uint8_t> request, const bool tcp,
                              const sockaddr_storage* peer, const socklen_t peer_length,
                              const std::shared_ptr<TcpClient>& client) {
    DnsQueryPlan plan;
    std::string error;
    processor_->prepare(request.data(), request.size(), tcp, plan, error);
    if (plan.action == DnsQueryPlan::Action::Upstream) {
        if (send_upstream(std::move(plan), peer, peer_length, client)) return;
        plan.response = processor_->overload_response(request.data(), request.size(), tcp);
    }
    if (plan.response.empty()) return;
    if (!tcp) {
        sendto(udp_fd_, plan.response.data(), plan.response.size(), 0,
               reinterpret_cast<const sockaddr*>(peer), peer_length);
        return;
    }
    client->output.reserve(client->output.size() + 2 + plan.response.size());
    const std::uint16_t length = htons(static_cast<std::uint16_t>(plan.response.size()));
    const auto* prefix = reinterpret_cast<const std::uint8_t*>(&length);
    client->output.insert(client->output.end(), prefix, prefix + 2);
    client->output.insert(client->output.end(), plan.response.begin(), plan.response.end());
    modify_epoll(epoll_fd_, client->fd, EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP);
}

bool DnsServer::send_upstream(DnsQueryPlan plan, const sockaddr_storage* peer,
                              const socklen_t peer_length,
                              const std::shared_ptr<TcpClient>& client) {
    if (upstream_fd_ < 0) return false;
    std::uint16_t upstream_id = next_upstream_id_++;
    while (upstream_id == 0 || pending_upstreams_.count(upstream_id) != 0) {
        upstream_id = next_upstream_id_++;
    }
    set_query_id(plan.query, upstream_id);
    bool sent = false;
    for (const std::string& upstream : config_.upstreams) {
        sockaddr_in address{};
        if (!parse_upstream_address(upstream, address)) continue;
        if (sendto(upstream_fd_, plan.query.data(), plan.query.size(), 0,
                   reinterpret_cast<const sockaddr*>(&address), sizeof(address)) >= 0) {
            sent = true;
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
    pending.retries = 0;
    pending.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    pending_upstreams_.emplace(upstream_id, std::move(pending));
    return true;
}

void DnsServer::read_upstream() {
    std::array<std::uint8_t, 65535> buffer{};
    while (true) {
        const ssize_t received = recvfrom(upstream_fd_, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (received <= 0) return;
        if (received < 2) continue;
        std::uint16_t wire_id = 0;
        std::memcpy(&wire_id, buffer.data(), sizeof(wire_id));
        const std::uint16_t upstream_id = ntohs(wire_id);
        const auto found = pending_upstreams_.find(upstream_id);
        if (found == pending_upstreams_.end()) continue;
        PendingUpstream pending = std::move(found->second);
        pending_upstreams_.erase(found);
        const auto response = processor_->finish_upstream(pending.plan, buffer.data(),
                                                           static_cast<std::size_t>(received));
        if (response.empty()) continue;
        if (pending.plan.tcp) {
                if (pending.client == nullptr || clients_.find(pending.client->fd) == clients_.end()) continue;
            const std::uint16_t length = htons(static_cast<std::uint16_t>(response.size()));
            const auto* prefix = reinterpret_cast<const std::uint8_t*>(&length);
            pending.client->output.insert(pending.client->output.end(), prefix, prefix + 2);
            pending.client->output.insert(pending.client->output.end(), response.begin(), response.end());
            modify_epoll(epoll_fd_, pending.client->fd, EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP);
        } else {
            sendto(udp_fd_, response.data(), response.size(), 0,
                   reinterpret_cast<const sockaddr*>(&pending.peer), pending.peer_length);
        }
    }
}

void DnsServer::expire_upstream_queries() {
    const auto now = std::chrono::steady_clock::now();
    for (auto iterator = pending_upstreams_.begin(); iterator != pending_upstreams_.end();) {
        if (iterator->second.deadline > now) { ++iterator; continue; }
        PendingUpstream& pending = iterator->second;
        if (pending.retries < 1) {
            ++pending.retries;
            pending.deadline = now + std::chrono::seconds(2);
            for (const std::string& upstream : config_.upstreams) {
                sockaddr_in address{};
                if (parse_upstream_address(upstream, address)) {
                    sendto(upstream_fd_, pending.plan.query.data(), pending.plan.query.size(), 0,
                           reinterpret_cast<const sockaddr*>(&address), sizeof(address));
                }
            }
            ++iterator;
            continue;
        }
        const auto response = processor_->overload_response(pending.plan.query.data(),
                                                             pending.plan.query.size(), pending.plan.tcp);
        if (pending.plan.tcp && pending.client != nullptr) {
            if (clients_.find(pending.client->fd) == clients_.end()) {
                iterator = pending_upstreams_.erase(iterator);
                continue;
            }
            std::vector<std::uint8_t> client_response = response;
            set_query_id(client_response, pending.plan.original_id);
            const std::uint16_t length = htons(static_cast<std::uint16_t>(response.size()));
            const auto* prefix = reinterpret_cast<const std::uint8_t*>(&length);
            pending.client->output.insert(pending.client->output.end(), prefix, prefix + 2);
            pending.client->output.insert(pending.client->output.end(), client_response.begin(), client_response.end());
            modify_epoll(epoll_fd_, pending.client->fd, EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP);
        } else if (!pending.plan.tcp) {
            std::vector<std::uint8_t> client_response = response;
            set_query_id(client_response, pending.plan.original_id);
            sendto(udp_fd_, client_response.data(), client_response.size(), 0,
                   reinterpret_cast<const sockaddr*>(&pending.peer), pending.peer_length);
        }
        iterator = pending_upstreams_.erase(iterator);
    }
}

void DnsServer::drain_tcp_completions() {
    std::uint64_t notification = 0;
    while (read(completion_fd_, &notification, sizeof(notification)) > 0) {}
    std::queue<TcpCompletion> completions;
    {
        std::lock_guard<std::mutex> lock(completion_mutex_);
        completions.swap(completions_);
    }
    while (!completions.empty()) {
        TcpCompletion completion = std::move(completions.front());
        completions.pop();
        const int fd = completion.client->fd;
        const auto found = clients_.find(fd);
        if (found == clients_.end() || found->second != completion.client) continue;
        const std::uint16_t length = htons(static_cast<std::uint16_t>(completion.response.size()));
        const auto* prefix = reinterpret_cast<const std::uint8_t*>(&length);
        completion.client->output.insert(completion.client->output.end(), prefix, prefix + 2);
        completion.client->output.insert(completion.client->output.end(),
                                         completion.response.begin(), completion.response.end());
        completion.client->last_activity = std::chrono::steady_clock::now();
        modify_epoll(epoll_fd_, fd, EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP);
    }
}

void DnsServer::flush_tcp_output(const std::shared_ptr<TcpClient>& client) {
    while (client->output_offset < client->output.size()) {
        const ssize_t sent = send(client->fd, client->output.data() + client->output_offset,
                                  client->output.size() - client->output_offset, MSG_NOSIGNAL);
        if (sent > 0) {
            client->output_offset += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        close_client(client->fd);
        return;
    }
    if (client->output_offset == client->output.size()) {
        client->output.clear();
        client->output_offset = 0;
    }
    if (clients_.find(client->fd) != clients_.end()) {
        modify_epoll(epoll_fd_, client->fd, client->output.empty()
            ? EPOLLIN | EPOLLET | EPOLLRDHUP
            : EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP);
    }
}

void DnsServer::read_tcp(const int fd) {
    const auto found = clients_.find(fd);
    if (found == clients_.end()) return;
    const auto client = found->second;
    std::array<std::uint8_t, 8192> buffer{};
    while (true) {
        const ssize_t received = recv(fd, buffer.data(), buffer.size(), 0);
        if (received == 0) { close_client(fd); return; }
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            close_client(fd);
            return;
        }
        client->input.insert(client->input.end(), buffer.begin(), buffer.begin() + received);
        client->last_activity = std::chrono::steady_clock::now();
    }
    while (client->input.size() >= 2) {
        std::uint16_t wire_length = 0;
        std::memcpy(&wire_length, client->input.data(), sizeof(wire_length));
        const std::size_t message_length = ntohs(wire_length);
        if (message_length == 0 || message_length > 65535) { close_client(fd); return; }
        if (client->input.size() < message_length + 2) return;
        std::vector<std::uint8_t> message(client->input.begin() + 2,
                                          client->input.begin() + 2 + message_length);
        client->input.erase(client->input.begin(), client->input.begin() + 2 + message_length);
        dispatch_tcp_message(client, std::move(message));
    }
}

void DnsServer::close_client(const int fd) {
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
    clients_.erase(fd);
}

void DnsServer::event_loop() {
    std::array<epoll_event, 128> events{};
    while (running_.load()) {
        const int count = epoll_wait(epoll_fd_, events.data(), events.size(), 1000);
        if (count < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int index = 0; index < count; ++index) {
            const int fd = events[index].data.fd;
            const std::uint32_t event = events[index].events;
            if (fd == signal_fd_) {
                signalfd_siginfo info{};
                read(signal_fd_, &info, sizeof(info));
                running_.store(false);
                continue;
            }
            if (fd == completion_fd_) { drain_tcp_completions(); continue; }
            if (fd == upstream_fd_) { read_upstream(); continue; }
            if (fd == udp_fd_) { read_udp(); continue; }
            if (fd == tcp_fd_) { accept_clients(); continue; }
            if ((event & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
                close_client(fd);
                continue;
            }
            if ((event & EPOLLIN) != 0) read_tcp(fd);
            if ((event & EPOLLOUT) != 0) {
                const auto found = clients_.find(fd);
                if (found != clients_.end()) {
                    flush_tcp_output(found->second);
                }
            }
        }
        const auto now = std::chrono::steady_clock::now();
        expire_upstream_queries();
        for (auto iterator = clients_.begin(); iterator != clients_.end();) {
            if (now - iterator->second->last_activity > std::chrono::seconds(30)) {
                const int fd = iterator->first;
                ++iterator;
                close_client(fd);
            } else {
                ++iterator;
            }
        }
    }
    stop();
}
