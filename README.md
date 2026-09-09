# DNS Server — 一个可观测的 C++17 DNS 服务器

零第三方库的 C++17 DNS 服务器：本地权威解析 + 上游递归转发 + TTL/LRU 缓存 + UDP/TCP 传输，并附带实时监控面板、压测工具与日志系统。

## 快速开始

```bash
# 编译 + 单测
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure

# 启动（本机直接运行，端口默认 2053）
./build/server --port 2053 --zone-file config/zone.db \
  --upstream 8.8.8.8:53,1.1.1.1:53 --threads 4 --cache-size 1024
```

> `./build/server --help` 可查看全部参数。

## 使用说明

### 命令行参数

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `--port N` | UDP/TCP 监听端口（≤65535） | `2053` |
| `--upstream IP[:PORT],...` | 上游递归 DNS，逗号分隔、可带端口 | 空（纯本地权威） |
| `--zone-file PATH` | 本地权威区文件路径 | 空 |
| `--threads N` | 工作线程数（>0） | `4` |
| `--cache-size N` | 最大缓存条目数 | `1024` |

常见运行方式：

```bash
# 1) 纯本地权威（不转发外部，适合离线/隔离网测试）
./build/server --port 2053 --zone-file config/zone.db

# 2) 本地权威 + 单上游转发
./build/server --port 2053 --zone-file config/zone.db \
  --upstream 223.5.5.5:53

# 3) 多上游容灾（任选可用），加大缓存提升命中率
./build/server --port 2053 --zone-file config/zone.db \
  --upstream 223.5.5.5:53,8.8.8.8:53,119.29.29.29:53 \
  --threads 8 --cache-size 10000
```

### 客户端查询示例

默认区文件为 `config/zone.db`（域 `example.test.`，含 router/nas/www/ns1 等记录）：

```bash
dig @127.0.0.1 -p 2053 router.example.test A      # 本地权威命中 → 192.168.1.1
dig @127.0.0.1 -p 2053 nas.example.test A         # 本地别名记录
dig @127.0.0.1 -p 2053 example.test SOA           # SOA 记录
dig @127.0.0.1 -p 2053 ns1.example.test NS        # NS 记录
dig @127.0.0.1 -p 2053 www.example.test AAAA      # 无该记录时返回 NOERROR/空
dig @127.0.0.1 -p 2053 no-such.example.test A     # 不存在的名字 → NXDOMAIN
dig @127.0.0.1 -p 2053 google.com A               # 本地未命中 → 上游转发并缓存
dig @127.0.0.1 -p 2053 google.com A +tcp          # 走 TCP（上游端口同时监听）
```

> Windows 无 `dig` 时可用 `nslookup -port=2053 router.example.test 127.0.0.1`。
> 可用 `dig +noall +answer` 只看应答区，`dig +time=2 +tries=1` 控制超时。

### 自定义区文件

按以下格式编辑 `config/zone.db`（每行 `域名 类型 数据...`），保存后重启服务生效：

```text
$ORIGIN example.test.
$TTL 300

ns1   IN A 192.168.1.10
www   IN A 192.168.1.100
@     IN A 192.168.1.100     ; 裸域（example.test.）指向主站
```

## 设计与实现

| 模块 | 职责 |
| --- | --- |
| `src/dns_message` | RFC 1035 报文解析/序列化：四区域、压缩指针、指针循环保护、多 Question |
| `src/zone` | 区文件加载与本地权威查询（A/AAAA/CNAME/MX/TXT/NS/SOA） |
| `src/dns_cache` | TTL 到期 + LRU 淘汰；正向缓存与 NXDOMAIN 负缓存 |
| `src/dns_processor` | 查询流水线：本地命中 → 缓存命中 → 上游转发；超时重试、SERVFAIL 兜底 |
| `src/dns_server` | `epoll` 事件循环 + 线程池 + UDP/TCP + 优雅停机 |
| `monitor/backend` | FastAPI + asyncio UDP 代理：旁路统计、压测、日志 |
| `monitor/frontend` | 监控面板（QPS/延迟/返回码/热门域名/进程状态） |

解析流程：

```text
请求 ──► 本地权威区? ──命中──► 直接应答
              │未命中
              ▼
        缓存? ──命中──► 应答（并恢复原事务 ID）
              │未命中
              ▼
      上游转发(UDP) ──► 应答并写入缓存（按最小 TTL）
```

监控代理会对转发请求重写内部事务 ID、响应时再还原，避免高并发下 txid 冲突导致应答错乱。

## 容器化部署（DNS + 监控一体）

```bash
docker compose up -d --build     # 构建并启动
docker compose ps                # 查看状态
docker compose logs -f dns-server    # 跟踪 DNS 服务日志
docker compose logs -f dns-monitor   # 跟踪监控服务日志
docker compose down              # 停止
```

编排文件 `docker-compose.yml` 定义了两个服务：

| 服务 | 镜像 | 对外端口 | 说明 |
| --- | --- | --- | --- |
| `dns-server` | `dns-server:latest` | UDP `2053`、TCP `15353` | C++ DNS 主服务，容器内监听 `2053` |
| `dns-monitor` | `dns-monitor:latest` | HTTP `8080`、UDP `5354` | FastAPI 监控 + DNS 观测代理 |

dns-server 容器内置启动参数：

- `--upstream 223.5.5.5:53,8.8.8.8:53,119.29.29.29:53`（国内可用上游）
- `--threads 8 --cache-size 10000`

> 说明：Windows 本地 5353 端口被 mDNS 占用，故代理对外映射为 `5354`；容器内仍是 `5353`。
> 本机有 `dig` 时，可把系统 DNS 指到 `127.0.0.1:2053` 做全局体验（注意别把权威/转发配置搞混）。

## 监控、日志与压测

### 启动监控

```bash
cd monitor/backend && pip install -r requirements.txt && python app.py
# 面板: http://localhost:8080   代理: UDP :5353 → 127.0.0.1:2053
```

> 若用 Docker 部署，监控已随 compose 启动，直接访问 `http://localhost:8080`。
> 若本机 5353 被占用，用环境变量改端口：`PROXY_PORT=5355 python app.py`（其余可用 `HTTP_PORT`、`DNS_SERVER_HOST`、`DNS_SERVER_PORT`、`DNS_PROC_NAME` 覆盖）。

### 面板与 API

面板提供实时 QPS 曲线、延迟分布、返回码分布、热门域名、进程 CPU/内存等卡片。

主要接口：

| 接口 | 作用 |
| --- | --- |
| `GET /api/stats` | 全局统计快照（总量、当前 QPS、60s 时间线、类型/返回码/热门域名、延迟 avg/p95/max） |
| `GET /api/process` | C++ `dns_server` 进程 CPU/内存/在线状态 |
| `GET /api/server/health` | 对 DNS 服务做 UDP 探测（online 布尔值） |
| `POST /api/bench` | 发起压测（见下） |

### 压测

`POST /api/bench` 请求体：

```jsonc
{
  "mode": "normal",        // 预留模式位，当前均按并发压测执行
  "concurrency": 500,      // 并发协程数（上限 500）
  "total": 50000,          // 总查询数
  "domain_set": "external" // external | local | cached
}
```

`domain_set` 三种语义：

- `external`：公网域名（如 google.com）→ 主要走上游转发链路；
- `local`：本地权威域（`*.example.test`）→ 测本地解析吞吐；
- `cached`：先串行预热缓存，再对同一批域名做热查询 → 测缓存命中场景。

```bash
# 本地权威压测（应看到较高 QPS、零超时）
curl -X POST localhost:8080/api/bench -H "Content-Type: application/json" \
  -d '{"mode":"normal","concurrency":500,"total":50000,"domain_set":"local"}'

# 外部域名压测（对比上游链路瓶颈）
curl -X POST localhost:8080/api/bench -H "Content-Type: application/json" \
  -d '{"mode":"normal","concurrency":500,"total":50000,"domain_set":"external"}'
```

返回示例（节选）：`total`、`qps`、`success/error/timeout`、`latency_ms{avg,p50,p95,p99,max}`。

### 日志

- 位置：`monitor/log/`（`dns_monitor.log`，按天轮转保留 7 天；目录已在 `.gitignore`，不会入库）。
- 记录：启动信息、慢查询/上游超时（`slow_or_timeout dns ...`）、压测起止与摘要（`benchmark_start/benchmark_summary`）。
- 用途：压测后先看 `benchmark_summary`，再按 `slow_or_timeout` 找热点域名与延迟拐点，定位瓶颈在上游还是本地。

## 测试

```bash
# 黑盒端到端（标准库实现，无需 dig/nslookup）
python tests/test_dns_server.py --skip-upstream   # 本机
python tests/test_dns_server.py --host <ip> --skip-upstream  # 局域网
```

覆盖：UDP/TCP、本地 A/AAAA/CNAME、NXDOMAIN、多 Question、上游转发（去掉 `--skip-upstream`）。

