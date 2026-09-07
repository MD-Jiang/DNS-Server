#include "dns_server.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <array>
#include <iostream>
#include <netinet/in.h>
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
    if (epoll_fd_ < 0 || udp_fd_ < 0 || tcp_fd_ < 0) {
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
        !add_epoll(epoll_fd_, signal_fd_, EPOLLIN)) {
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
    pool_ = std::make_unique<ThreadPool>(config_.threads);
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
        std::vector<std::uint8_t> request(buffer.begin(), buffer.begin() + received);
        auto processor = processor_.get();
        pool_->submit([processor, request = std::move(request), peer, peer_length, fd = udp_fd_]() {
            const auto response = processor->process(request.data(), request.size(), false);
            if (!response.empty()) {
                sendto(fd, response.data(), response.size(), 0,
                       reinterpret_cast<const sockaddr*>(&peer), peer_length);
            }
        });
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
    auto processor = processor_.get();
    pool_->submit([this, processor, client, message = std::move(message)]() {
        const auto response = processor->process(message.data(), message.size(), true);
        if (response.size() > 65535 || client->fd < 0) return;
        std::lock_guard<std::mutex> lock(client->mutex);
        const std::uint16_t length = htons(static_cast<std::uint16_t>(response.size()));
        const auto* prefix = reinterpret_cast<const std::uint8_t*>(&length);
        client->output.insert(client->output.end(), prefix, prefix + 2);
        client->output.insert(client->output.end(), response.begin(), response.end());
        while (!client->output.empty()) {
            const ssize_t sent = send(client->fd, client->output.data(), client->output.size(), MSG_NOSIGNAL);
            if (sent > 0) {
                client->output.erase(client->output.begin(), client->output.begin() + sent);
            } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                modify_epoll(epoll_fd_, client->fd, EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP);
                return;
            } else {
                shutdown(client->fd, SHUT_RDWR);
                return;
            }
        }
        modify_epoll(epoll_fd_, client->fd, EPOLLIN | EPOLLET | EPOLLRDHUP);
    });
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
                    std::lock_guard<std::mutex> lock(found->second->mutex);
                    while (!found->second->output.empty()) {
                        const ssize_t sent = send(fd, found->second->output.data(),
                                                  found->second->output.size(), MSG_NOSIGNAL);
                        if (sent <= 0) break;
                        found->second->output.erase(found->second->output.begin(),
                                                   found->second->output.begin() + sent);
                    }
                    modify_epoll(epoll_fd_, fd, found->second->output.empty()
                        ? EPOLLIN | EPOLLET | EPOLLRDHUP
                        : EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP);
                }
            }
        }
        const auto now = std::chrono::steady_clock::now();
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
