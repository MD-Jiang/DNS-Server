// dns_concurrency_test.cpp
//
// 针对 DNS 中继器的并发能力基准测试（UDP）。
// 覆盖三个场景：
//   1. 上游查询并发：每个请求使用唯一 qname，保证 cache miss，强制转发到真实上游
//   2. 缓存命中并发：先预热一个上游域名（写入 DnsCache），再并发重复查询同一 qname
//   3. 本地权威查询并发：查询本地 zone（example.test.）中的记录，不经过上游/缓存
//
// 用法（默认面向容器内 127.0.0.1:2053）：
//   dns_concurrency_test [--host H] [--port P] [--threads N] [--requests N]
//                        [--timeout-ms N] [--upstream-domain D] [--cache-domain D]
//                        [--local-domain D] [--qtype A|AAAA]

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeAAAA = 28;
constexpr std::uint16_t kClassIn = 1;
constexpr std::uint16_t kFlagRecursionDesired = 0x0100;
constexpr std::size_t kRecvBufSize = 65536;

// ---------------------------------------------------------------- wire format

std::string encode_name(const std::string& domain) {
    std::string normalized = domain;
    while (!normalized.empty() && normalized.back() == '.') {
        normalized.pop_back();
    }
    if (normalized.empty()) {
        return std::string(1, '\0');
    }

    std::vector<std::string> labels;
    std::size_t start = 0;
    while (start < normalized.size()) {
        const std::size_t end = normalized.find('.', start);
        const std::size_t len = (end == std::string::npos) ? normalized.size() - start : end - start;
        labels.push_back(normalized.substr(start, len));
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }

    std::string encoded;
    for (const std::string& label : labels) {
        if (label.empty() || label.size() > 63) {
            throw std::runtime_error("invalid label in domain: " + domain);
        }
        encoded.push_back(static_cast<char>(label.size()));
        encoded.append(label);
    }
    encoded.push_back('\0');
    return encoded;
}

std::vector<std::uint8_t> build_query(const std::string& domain, std::uint16_t qtype,
                                      std::uint16_t txn_id) {
    const std::string name_bytes = encode_name(domain);
    std::vector<std::uint8_t> packet;
    packet.resize(12 + name_bytes.size() + 4);

    packet[0] = static_cast<std::uint8_t>((txn_id >> 8) & 0xff);
    packet[1] = static_cast<std::uint8_t>(txn_id & 0xff);
    packet[2] = static_cast<std::uint8_t>((kFlagRecursionDesired >> 8) & 0xff);
    packet[3] = static_cast<std::uint8_t>(kFlagRecursionDesired & 0xff);
    packet[4] = 0x00;
    packet[5] = 0x01;  // QDCOUNT = 1
    packet[6] = 0x00;  // ANCOUNT = 0
    packet[7] = 0x00;
    packet[8] = 0x00;  // NSCOUNT = 0
    packet[9] = 0x00;
    packet[10] = 0x00;  // ARCOUNT = 0
    packet[11] = 0x00;

    std::memcpy(packet.data() + 12, name_bytes.data(), name_bytes.size());
    const std::size_t offset = 12 + name_bytes.size();
    packet[offset] = static_cast<std::uint8_t>((qtype >> 8) & 0xff);
    packet[offset + 1] = static_cast<std::uint8_t>(qtype & 0xff);
    packet[offset + 2] = static_cast<std::uint8_t>((kClassIn >> 8) & 0xff);
    packet[offset + 3] = static_cast<std::uint8_t>(kClassIn & 0xff);
    return packet;
}

// 检查响应：长度>=12、事务 ID 匹配、QR 位置位。输出 rcode 与 answers 数量。
bool check_response(const std::vector<std::uint8_t>& packet, std::uint16_t expected_id,
                    std::uint16_t* rcode = nullptr, std::uint16_t* answer_count = nullptr) {
    if (packet.size() < 12) {
        return false;
    }
    const std::uint16_t id = static_cast<std::uint16_t>((packet[0] << 8) | packet[1]);
    const std::uint16_t flags = static_cast<std::uint16_t>((packet[2] << 8) | packet[3]);
    if (id != expected_id) {
        return false;
    }
    if ((flags & 0x8000U) == 0) {  // QR bit
        return false;
    }
    if (rcode != nullptr) {
        *rcode = static_cast<std::uint16_t>(flags & 0x000fU);
    }
    if (answer_count != nullptr) {
        *answer_count = static_cast<std::uint16_t>((packet[6] << 8) | packet[7]);
    }
    return true;
}

// ------------------------------------------------- 每线程复用 UDP 客户端
// 非阻塞 + poll 精确 deadline；连续同步请求，靠事务 ID 过滤迟到的杂散包。
class UdpClient {
public:
    UdpClient() = default;
    UdpClient(const UdpClient&) = delete;
    UdpClient& operator=(const UdpClient&) = delete;

    ~UdpClient() { close(); }

    bool open(const std::string& host, int port) {
        fd_ = static_cast<int>(socket(AF_INET, SOCK_DGRAM, 0));
        if (fd_ < 0) {
            return false;
        }
        const int flags = fcntl(fd_, F_GETFL, 0);
        if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            close();
            return false;
        }
        std::memset(&peer_, 0, sizeof(peer_));
        peer_.sin_family = AF_INET;
        peer_.sin_port = htons(static_cast<std::uint16_t>(port));
        if (inet_pton(AF_INET, host.c_str(), &peer_.sin_addr) != 1) {
            close();
            return false;
        }
        return true;
    }

    // 发送一个查询并等待 ID 匹配的响应，最多 timeout_ms。成功返回 true。
    bool query(const std::vector<std::uint8_t>& query, std::uint16_t expect_id,
               std::vector<std::uint8_t>& out, int timeout_ms) {
        const ssize_t sent = sendto(fd_, query.data(), query.size(), 0,
                                    reinterpret_cast<const struct sockaddr*>(&peer_),
                                    sizeof(peer_));
        if (sent < 0) {
            return false;
        }

        const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
        std::uint8_t buffer[kRecvBufSize];
        while (true) {
            const auto now = Clock::now();
            if (now >= deadline) {
                return false;  // timeout
            }
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            struct pollfd poll_fd {};
            poll_fd.fd = fd_;
            poll_fd.events = POLLIN;
            const int poll_rc = poll(&poll_fd, 1, remaining <= 0 ? 1 : static_cast<int>(remaining));
            if (poll_rc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return false;
            }
            if (poll_rc == 0) {
                return false;  // timeout
            }
            const ssize_t received = recv(fd_, buffer, sizeof(buffer), 0);
            if (received < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                return false;
            }
            if (received >= 2) {
                const std::uint16_t id =
                    static_cast<std::uint16_t>((buffer[0] << 8) | buffer[1]);
                if (id == expect_id) {
                    out.assign(buffer, buffer + received);
                    return true;
                }
            }
        }
    }

    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_ = -1;
    struct sockaddr_in peer_ {};
};

// ---------------------------------------------------------------- 统计与结果

struct WorkerOut {
    std::size_t ok = 0;       // 成功（收到匹配响应且 rcode 符合场景要求）
    std::size_t timeout = 0;  // 无响应（客户端超时）
    std::size_t mismatch = 0; // 响应不匹配/报文损坏/rcode 不合预期
    std::vector<double> latencies_ms;
};

struct CaseResult {
    std::string name;
    std::size_t total = 0;
    std::size_t ok = 0;
    std::size_t timeout = 0;
    std::size_t mismatch = 0;
    std::vector<double> latencies_ms;
    double wall_sec = 0.0;
};

double percentile(std::vector<double>& sorted, double p) {
    if (sorted.empty()) {
        return 0.0;
    }
    const std::size_t index =
        static_cast<std::size_t>(std::ceil((p / 100.0) * sorted.size())) - 1;
    return sorted[std::min(index, sorted.size() - 1)];
}

// ---------------------------------------------------------------- 场景执行
//
// unique_names = true          -> 每个请求生成唯一 qname（强制 cache miss 走上游）
// require_rcode_zero = true    -> 仅 rcode==0 计为成功（缓存命中/本地权威）
// require_rcode_zero = false   -> 任何“ID 匹配 + QR 置位”的响应都算成功（上游往返，
//                                 包括上游返回的 NXDOMAIN/ServFail 等）
CaseResult run_case(const std::string& name, const std::string& host, int port,
                    const std::string& domain, std::uint16_t qtype, int thread_count,
                    int requests_per_thread, int timeout_ms, bool unique_names,
                    bool require_rcode_zero) {
    std::vector<WorkerOut> outputs(static_cast<std::size_t>(thread_count));
    std::vector<std::thread> workers;
    workers.reserve(static_cast<std::size_t>(thread_count));

    const auto wall_start = Clock::now();
    for (int tid = 0; tid < thread_count; ++tid) {
        workers.emplace_back([&outputs, host, port, domain, qtype,
                              requests_per_thread, timeout_ms, unique_names,
                              require_rcode_zero, tid]() {
            WorkerOut& mine = outputs[static_cast<std::size_t>(tid)];
            UdpClient client;
            if (!client.open(host, port)) {
                mine.timeout += static_cast<std::size_t>(requests_per_thread);
                return;
            }
            for (int request_index = 0; request_index < requests_per_thread; ++request_index) {
                std::string qname = domain;
                if (unique_names) {
                    // 唯一子域名，形如 u3x7.baidu.com.，保证不命中缓存
                    qname = "u" + std::to_string(tid) + "x" + std::to_string(request_index) +
                            "." + domain;
                }
                // 确定性、跨线程唯一的 16 位事务 ID（避开 0）
                const std::uint32_t seed =
                    1U + static_cast<std::uint32_t>(tid) * 7919U +
                    static_cast<std::uint32_t>(request_index) * 104729U;
                const std::uint16_t txn_id = static_cast<std::uint16_t>(seed & 0xffffU);

                std::vector<std::uint8_t> query;
                try {
                    query = build_query(qname, qtype, txn_id);
                } catch (const std::exception&) {
                    ++mine.mismatch;
                    continue;
                }

                const auto start = Clock::now();
                std::vector<std::uint8_t> response;
                const bool got = client.query(query, txn_id, response, timeout_ms);
                const double latency_ms =
                    std::chrono::duration<double, std::milli>(Clock::now() - start).count();
                mine.latencies_ms.push_back(latency_ms);

                if (!got) {
                    ++mine.timeout;
                    continue;
                }
                std::uint16_t rcode = 0;
                std::uint16_t answer_count = 0;
                const bool valid = check_response(response, txn_id, &rcode, &answer_count);
                if (!valid) {
                    ++mine.mismatch;
                    continue;
                }
                const bool pass = require_rcode_zero ? (rcode == 0) : true;
                if (pass) {
                    ++mine.ok;
                } else {
                    ++mine.mismatch;  // 响应有效但 rcode 不符合预期
                }
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    const double wall_sec = std::chrono::duration<double>(Clock::now() - wall_start).count();

    CaseResult result;
    result.name = name;
    result.wall_sec = wall_sec;
    for (const WorkerOut& out : outputs) {
        result.total += out.ok + out.timeout + out.mismatch;
        result.ok += out.ok;
        result.timeout += out.timeout;
        result.mismatch += out.mismatch;
        result.latencies_ms.insert(result.latencies_ms.end(), out.latencies_ms.begin(),
                                   out.latencies_ms.end());
    }
    return result;
}

void print_case(CaseResult& result) {
    std::sort(result.latencies_ms.begin(), result.latencies_ms.end());
    const std::size_t n = result.latencies_ms.size();
    double avg = 0.0;
    for (const double latency : result.latencies_ms) {
        avg += latency;
    }
    if (n > 0) {
        avg /= static_cast<double>(n);
    }

    const double qps = result.wall_sec > 0.0 ? result.total / result.wall_sec : 0.0;
    std::printf("\n[%s]\n", result.name.c_str());
    std::printf("  duration       : %.3f s\n", result.wall_sec);
    std::printf("  total requests : %zu\n", result.total);
    std::printf("  success        : %zu\n", result.ok);
    std::printf("  timeout        : %zu\n", result.timeout);
    std::printf("  bad/mismatch   : %zu\n", result.mismatch);
    std::printf("  success rate   : %.2f %%\n",
                result.total == 0 ? 0.0 : (100.0 * result.ok / result.total));
    std::printf("  throughput     : %.0f qps\n", qps);
    if (n > 0) {
        std::printf("  latency(ms)    : avg=%.3f min=%.3f p50=%.3f p90=%.3f p95=%.3f "
                    "p99=%.3f max=%.3f\n",
                    avg, result.latencies_ms.front(), percentile(result.latencies_ms, 50.0),
                    percentile(result.latencies_ms, 90.0), percentile(result.latencies_ms, 95.0),
                    percentile(result.latencies_ms, 99.0), result.latencies_ms.back());
    }
    std::fflush(stdout);
}

// 预热缓存：对真实上游域名发一次查询（写入 DnsCache）。
bool warm_up_cache(const std::string& host, int port, const std::string& domain,
                   std::uint16_t qtype, int timeout_ms) {
    UdpClient client;
    if (!client.open(host, port)) {
        std::cout << "[warm-up] cannot open socket to " << host << ':' << port << '\n';
        return false;
    }
    const std::uint16_t txn_id = 0x4d2aU;  // 固定预热事务 ID
    try {
        const std::vector<std::uint8_t> query = build_query(domain, qtype, txn_id);
        std::vector<std::uint8_t> response;
        if (!client.query(query, txn_id, response, timeout_ms)) {
            std::cout << "[warm-up] " << domain << " -> TIMEOUT\n";
            return false;
        }
        std::uint16_t rcode = 0;
        std::uint16_t answers = 0;
        if (!check_response(response, txn_id, &rcode, &answers)) {
            std::cout << "[warm-up] " << domain << " -> BAD RESPONSE\n";
            return false;
        }
        std::cout << "[warm-up] " << domain << " (type A) -> rcode=" << rcode
                  << " answers=" << answers << '\n';
        return rcode == 0 && answers > 0;
    } catch (const std::exception& error) {
        std::cout << "[warm-up] " << domain << " -> ERROR: " << error.what() << '\n';
        return false;
    }
}

void print_usage(const char* program) {
    std::cout << "Usage: " << program
              << " [--host 127.0.0.1] [--port 2053] [--threads 16] [--requests 20]\n"
                 "       [--timeout-ms 3000] [--upstream-domain baidu.com.]\n"
                 "       [--cache-domain www.baidu.com.] [--local-domain api.example.test.]\n"
                 "       [--qtype A|AAAA]\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    int port = 2053;
    int thread_count = 16;
    int requests_per_thread = 20;
    int timeout_ms = 3000;
    std::string upstream_domain = "baidu.com.";
    std::string cache_domain = "www.baidu.com.";
    std::string local_domain = "api.example.test.";
    std::uint16_t qtype = kTypeA;

    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        const auto need_value = [&](const char* name) -> const char* {
            if (index + 1 >= argc) {
                std::cerr << "missing value for " << name << '\n';
                std::exit(2);
            }
            return argv[++index];
        };
        if (argument == "--host") {
            host = need_value("--host");
        } else if (argument == "--port") {
            port = std::stoi(need_value("--port"));
        } else if (argument == "--threads") {
            thread_count = std::stoi(need_value("--threads"));
        } else if (argument == "--requests") {
            requests_per_thread = std::stoi(need_value("--requests"));
        } else if (argument == "--timeout-ms") {
            timeout_ms = std::stoi(need_value("--timeout-ms"));
        } else if (argument == "--upstream-domain") {
            upstream_domain = need_value("--upstream-domain");
        } else if (argument == "--cache-domain") {
            cache_domain = need_value("--cache-domain");
        } else if (argument == "--local-domain") {
            local_domain = need_value("--local-domain");
        } else if (argument == "--qtype") {
            const std::string type = need_value("--qtype");
            if (type == "A") {
                qtype = kTypeA;
            } else if (type == "AAAA") {
                qtype = kTypeAAAA;
            } else {
                std::cerr << "unsupported qtype: " << type << '\n';
                return 2;
            }
        } else if (argument == "--help" || argument == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "unknown argument: " << argument << '\n';
            print_usage(argv[0]);
            return 2;
        }
    }

    if (thread_count <= 0 || requests_per_thread <= 0 || port <= 0 || port > 65535) {
        std::cerr << "invalid numeric arguments\n";
        return 2;
    }

    std::cout << "DNS relay concurrency benchmark (UDP)\n";
    std::cout << "target      : " << host << ':' << port << '\n';
    std::cout << "client conc : " << thread_count << " thread(s) x " << requests_per_thread
              << " req/thread = " << (thread_count * requests_per_thread) << " requests/case\n";
    std::cout << "qtype       : " << (qtype == kTypeA ? "A" : "AAAA") << '\n';
    std::cout << "upstream dom: " << upstream_domain << " (unique subnames per request)\n";
    std::cout << "cache dom   : " << cache_domain << '\n';
    std::cout << "local dom   : " << local_domain << '\n';
    std::cout << "------------------------------------------------------------\n";

    // 场景 1：上游并发。唯一 qname -> 全部 cache miss -> 逐条转发上游。
    CaseResult upstream =
        run_case("1. UPSTREAM forwarding concurrency (unique qnames, real upstream RTT)",
                 host, port, upstream_domain, qtype, thread_count, requests_per_thread,
                 timeout_ms, /*unique_names=*/true, /*require_rcode_zero=*/false);
    print_case(upstream);

    // 场景 2：缓存命中并发。先预热真实上游域名（正向缓存），再并发打同一个名字。
    const bool warmed = warm_up_cache(host, port, cache_domain, kTypeA, timeout_ms);
    CaseResult cache_hit =
        run_case("2. CACHE HIT concurrency (same qname, answered from DnsCache)", host, port,
                 cache_domain, kTypeA, thread_count, requests_per_thread, timeout_ms,
                 /*unique_names=*/false, /*require_rcode_zero=*/true);
    print_case(cache_hit);
    if (!warmed) {
        std::cout << "[warn] cache warm-up did not get a positive answer; case 2 may have "
                     "exercised upstream instead of cache\n";
    }

    // 场景 3：本地权威并发。全部在本地 zone 内回答。
    CaseResult local =
        run_case("3. LOCAL authoritative concurrency (zone records)", host, port, local_domain,
                 qtype, thread_count, requests_per_thread, timeout_ms,
                 /*unique_names=*/false, /*require_rcode_zero=*/true);
    print_case(local);

    std::cout << "------------------------------------------------------------\n";
    std::cout << "SUMMARY\n";
    std::cout << "  upstream : success=" << upstream.ok << '/' << upstream.total
              << " rate=" << (upstream.total == 0 ? 0.0 : 100.0 * upstream.ok / upstream.total)
              << "%  qps=" << (upstream.wall_sec > 0.0 ? upstream.total / upstream.wall_sec : 0.0)
              << '\n';
    std::cout << "  cache    : success=" << cache_hit.ok << '/' << cache_hit.total
              << " rate="
              << (cache_hit.total == 0 ? 0.0 : 100.0 * cache_hit.ok / cache_hit.total)
              << "%  qps="
              << (cache_hit.wall_sec > 0.0 ? cache_hit.total / cache_hit.wall_sec : 0.0) << '\n';
    std::cout << "  local    : success=" << local.ok << '/' << local.total
              << " rate=" << (local.total == 0 ? 0.0 : 100.0 * local.ok / local.total)
              << "%  qps=" << (local.wall_sec > 0.0 ? local.total / local.wall_sec : 0.0) << '\n';
    std::fflush(stdout);

    const bool all_ok = upstream.timeout == 0 && cache_hit.timeout == 0 && local.timeout == 0;
    return all_ok ? 0 : 1;
}
