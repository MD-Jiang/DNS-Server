# DNS Server C++

一个不依赖第三方库的 C++17 DNS 服务器，支持本地权威解析、上游递归转发、TTL/LRU 缓存，以及 UDP/TCP DNS 传输。

## 功能

- RFC 1035 Header、Question 和 Answer/Authority/Additional 四区域解析。
- DNS 域名长度检查、压缩指针解析、指针循环保护和多 Question。
- A、AAAA、CNAME、MX、TXT、NS、SOA 区文件记录。
- 未命中本地记录时，通过 UDP 向配置的上游 DNS 转发，并支持超时重试。
- 正向和 NXDOMAIN 负缓存，TTL 到期和 LRU 淘汰。
- Linux `epoll` 边缘触发事件循环、线程池、UDP 和带两字节长度前缀的 TCP。
- `SIGINT`/`SIGTERM` 优雅停止和 TCP 空闲连接清理。

## 构建

项目使用 C++17、CMake 和系统线程库，不需要 vcpkg 依赖。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

编译选项包含 `-Wall -Wextra -pedantic`。

## 启动

```bash
./build/server \
  --port 2053 \
  --zone-file config/zone.db \
  --upstream 8.8.8.8:53,1.1.1.1:53 \
  --threads 4 \
  --cache-size 1024
```

参数：

| 参数 | 说明 |
| --- | --- |
| `--port` | UDP/TCP 监听端口，默认 `2053` |
| `--upstream` | 逗号分隔的上游 IPv4 地址，可带端口 |
| `--zone-file` | 本地权威区文件路径 |
| `--threads` | 工作线程数，默认 `4` |
| `--cache-size` | 最大缓存条目数，默认 `1024` |

## 区文件

每行格式为：

```text
域名 类型 数据...
```

示例：

```text
example.com. A 8.8.8.8
example.com. AAAA 2001:4860:4860::8888
www.example.com. CNAME example.com.
example.com. MX 10 mail.example.com.
example.com. TXT dns-server-demo
example.com. NS ns1.example.com.
example.com. SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300
```

当前区文件记录使用默认 TTL 300 秒。

## Docker Compose

```bash
docker compose up -d --build
```

Compose 使用本地已有的 Debian 12 Bookworm Python Slim 镜像作为构建基础，容器内端口为 `2053`：

- UDP：主机 `2053` -> 容器 `2053`
- TCP：主机 `15353` -> 容器 `2053`

例如：

```bash
dig @127.0.0.1 -p 2053 example.com A
dig @127.0.0.1 -p 15353 example.com A +tcp
```

停止服务：

```bash
docker compose down
```

## Python 黑盒测试

测试脚本只使用 Python 标准库，不依赖 `dig` 或 `nslookup`。本机测试：

```powershell
python tests/test_dns_server.py --skip-upstream
```

从宿主机或同一局域网的另一台机器测试时，指定运行 Docker 主机的局域网地址：

```powershell
python tests/test_dns_server.py --host 10.29.106.156 --skip-upstream
```

脚本会测试 UDP/TCP、本地 A/AAAA/CNAME、NXDOMAIN 和多 Question。测试上游转发时去掉 `--skip-upstream`；上游 DNS 不可达时，该项会失败，但不会影响本地权威记录测试。

## 项目结构

```text
src/dns_message.cpp       DNS 报文安全解析和序列化
src/zone.cpp              区文件和本地记录查询
src/dns_cache.cpp         TTL/LRU 缓存
src/dns_processor.cpp     本地权威和上游转发
src/dns_server.cpp        epoll、UDP、TCP 和优雅停止
src/thread_pool.cpp       工作线程池
tests/                    协议层单元测试
config/zone.db            默认本地区文件
```
