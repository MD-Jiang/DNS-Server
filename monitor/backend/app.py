"""DNS Server Monitor — asyncio proxy + FastAPI dashboard backend."""
import asyncio
import struct
import time
import os
import collections
import statistics
import random
import string
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import uvicorn
import psutil

# ── Config from env ──────────────────────────────────────────────────────────
DNS_SERVER_HOST = os.getenv("DNS_SERVER_HOST", "127.0.0.1")
DNS_SERVER_PORT = int(os.getenv("DNS_SERVER_PORT", "2053"))
PROXY_PORT      = int(os.getenv("PROXY_PORT",      "5353"))
HTTP_PORT       = int(os.getenv("HTTP_PORT",        "8080"))
DNS_PROC_NAME   = os.getenv("DNS_PROC_NAME",       "dns_server")

# ── Constants ────────────────────────────────────────────────────────────────
DNS_TYPES = {1:"A", 2:"NS", 5:"CNAME", 12:"PTR", 15:"MX",
             16:"TXT", 28:"AAAA", 33:"SRV", 255:"ANY"}
RCODES    = {0:"NOERROR", 1:"FORMERR", 2:"SERVFAIL",
             3:"NXDOMAIN", 4:"NOTIMP",  5:"REFUSED"}
MAX_LATENCY_SAMPLES = 10_000
QPS_WINDOW_SECONDS  = 60

# ── Stats store ──────────────────────────────────────────────────────────────
class StatsStore:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.total_queries    = 0
        self.query_types: Dict[str, int]  = collections.defaultdict(int)
        self.rcodes:      Dict[str, int]  = collections.defaultdict(int)
        self.domains:     Dict[str, int]  = collections.defaultdict(int)
        self.latencies:   List[float]     = []          # seconds
        # rolling QPS: list of (timestamp, count) per second bucket
        self._qps_buckets: collections.deque = collections.deque(
            maxlen=QPS_WINDOW_SECONDS
        )
        self._cur_second:  int  = int(time.time())
        self._cur_count:   int  = 0
        self.start_time = time.time()

    async def record(self, qtype: str, domain: str, rcode: str, latency: float):
        async with self.lock:
            self.total_queries += 1
            self.query_types[qtype] += 1
            self.rcodes[rcode]      += 1
            self.domains[domain]    += 1
            self.latencies.append(latency)
            if len(self.latencies) > MAX_LATENCY_SAMPLES:
                self.latencies = self.latencies[-MAX_LATENCY_SAMPLES:]
            now_sec = int(time.time())
            if now_sec != self._cur_second:
                self._qps_buckets.append((self._cur_second, self._cur_count))
                self._cur_second = now_sec
                self._cur_count  = 1
            else:
                self._cur_count += 1

    async def snapshot(self) -> dict:
        async with self.lock:
            lat = self.latencies or [0]
            lat_sorted = sorted(lat)
            p95_idx = int(len(lat_sorted) * 0.95)
            buckets = list(self._qps_buckets)
            # build last-60s timeline
            now_sec = int(time.time())
            qps_timeline = []
            bucket_map = {ts: cnt for ts, cnt in buckets}
            for i in range(QPS_WINDOW_SECONDS, 0, -1):
                ts = now_sec - i
                qps_timeline.append({"ts": ts, "count": bucket_map.get(ts, 0)})
            current_qps = self._cur_count  # this second so far
            return {
                "uptime_s":    round(time.time() - self.start_time, 1),
                "total":       self.total_queries,
                "current_qps": current_qps,
                "qps_timeline": qps_timeline,
                "query_types": dict(self.query_types),
                "rcodes":      dict(self.rcodes),
                "top_domains": sorted(
                    self.domains.items(), key=lambda x: x[1], reverse=True
                )[:10],
                "latency": {
                    "avg_ms":  round(statistics.mean(lat) * 1000, 2),
                    "p95_ms":  round(lat_sorted[p95_idx] * 1000, 2),
                    "max_ms":  round(max(lat) * 1000, 2),
                },
            }


stats = StatsStore()

# ── DNS wire helpers ─────────────────────────────────────────────────────────
def parse_dns_header(data: bytes) -> Tuple[int, int, int]:
    """Return (txid, qtype_int, rcode_int) or raise if too short."""
    if len(data) < 12:
        raise ValueError("too short")
    txid  = struct.unpack_from("!H", data, 0)[0]
    flags = struct.unpack_from("!H", data, 2)[0]
    rcode = flags & 0xF
    qdcount = struct.unpack_from("!H", data, 4)[0]
    qtype = 0
    if qdcount > 0:
        # skip QNAME (sequence of length-prefixed labels ending in 0)
        idx = 12
        while idx < len(data):
            ln = data[idx]
            if ln == 0:
                idx += 1
                break
            if ln & 0xC0 == 0xC0:   # compression pointer
                idx += 2
                break
            idx += ln + 1
        if idx + 4 <= len(data):
            qtype = struct.unpack_from("!H", data, idx)[0]
    return txid, qtype, rcode


def decode_qname(data: bytes, offset: int = 12) -> str:
    labels, idx = [], offset
    visited: set = set()
    while idx < len(data):
        if idx in visited:
            break
        visited.add(idx)
        ln = data[idx]
        if ln == 0:
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[idx + 1]
            labels += decode_qname(data, ptr).split(".")
            break
        idx += 1
        labels.append(data[idx:idx + ln].decode("ascii", errors="replace"))
        idx += ln
    return ".".join(labels) or "."


# ── Async DNS proxy ───────────────────────────────────────────────────────────
class DnsProxyProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._pending: Dict[int, Tuple[asyncio.DatagramTransport,
                                       tuple, float]] = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data: bytes, addr):
        try:
            txid, qtype, _ = parse_dns_header(data)
            domain = decode_qname(data)
        except Exception:
            return
        t0 = time.monotonic()
        try:
            resp = await asyncio.wait_for(
                self._forward(data), timeout=5.0
            )
        except asyncio.TimeoutError:
            await stats.record(
                DNS_TYPES.get(qtype, str(qtype)), domain, "TIMEOUT", 5.0
            )
            return
        latency = time.monotonic() - t0
        try:
            _, _, rcode_int = parse_dns_header(resp)
            rcode_str = RCODES.get(rcode_int, f"ERR{rcode_int}")
        except Exception:
            rcode_str = "UNKNOWN"
        await stats.record(
            DNS_TYPES.get(qtype, str(qtype)), domain, rcode_str, latency
        )
        if self.transport:
            self.transport.sendto(resp, addr)

    async def _forward(self, data: bytes) -> bytes:
        loop = asyncio.get_event_loop()
        future: asyncio.Future = loop.create_future()
        txid = struct.unpack_from("!H", data, 0)[0]
        # send to C++ server
        sock = _upstream_sock
        sock.sendto(data, (DNS_SERVER_HOST, DNS_SERVER_PORT))
        _pending_upstream[txid] = future
        try:
            return await asyncio.wait_for(future, timeout=4.9)
        finally:
            _pending_upstream.pop(txid, None)


_pending_upstream: Dict[int, asyncio.Future] = {}
_upstream_sock = None   # raw UDP socket set up at startup


class UpstreamProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, _addr):
        try:
            txid = struct.unpack_from("!H", data, 0)[0]
        except Exception:
            return
        fut = _pending_upstream.get(txid)
        if fut and not fut.done():
            fut.set_result(data)

# ── Performance tester ────────────────────────────────────────────────────────
@dataclass
class BenchResult:
    mode: str
    total_queries: int
    duration_s:    float
    qps:           float
    success:       int
    error:         int
    timeout:       int
    latencies:     List[float] = field(default_factory=list)
    domain_set:    str = "external"

    def to_dict(self) -> dict:
        lat = sorted(self.latencies) if self.latencies else [0]
        p50 = lat[int(len(lat) * 0.50)]
        p95 = lat[int(len(lat) * 0.95)]
        p99 = lat[int(len(lat) * 0.99)]
        return {
            "mode":         self.mode,
            "domain_set":   self.domain_set,
            "total":        self.total_queries,
            "duration_s":   round(self.duration_s, 2),
            "qps":          round(self.qps, 1),
            "success":      self.success,
            "error":        self.error,
            "timeout":      self.timeout,
            "latency_ms": {
                "avg": round(statistics.mean(self.latencies or [0]) * 1000, 2),
                "p50": round(p50 * 1000, 2),
                "p95": round(p95 * 1000, 2),
                "p99": round(p99 * 1000, 2),
                "max": round(max(self.latencies or [0]) * 1000, 2),
            },
        }


_BENCH_DOMAINS = [
    "google.com", "cloudflare.com", "github.com", "amazon.com", "microsoft.com",
    "youtube.com", "facebook.com", "twitter.com", "reddit.com", "openai.com",
    "wikipedia.org", "baidu.com", "taobao.com", "qq.com", "163.com",
]

_LOCAL_BENCH_DOMAINS = [
    "www.example.test", "api.example.test", "grafana.example.test",
    "ns1.example.test", "ns2.example.test", "git.example.test",
    "prom.example.test", "redis.example.test", "postgres.example.test",
    "mysql.example.test", "nas.example.test", "vpn.example.test",
    "dev.example.test", "mail.example.test", "router.example.test",
]


def _make_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS A-query for domain."""
    txid   = random.randint(0, 65535)
    flags  = 0x0100   # RD=1
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    qname  = b""
    for label in domain.rstrip(".").split("."):
        enc = label.encode()
        qname += bytes([len(enc)]) + enc
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)
    return header + question


async def _single_udp_query(host: str, port: int, data: bytes,
                             timeout: float = 2.0) -> Tuple[bool, float, str]:
    """Send one UDP DNS query. Returns (success, latency_s, rcode_str)."""
    loop = asyncio.get_event_loop()
    t0 = time.monotonic()
    transport = None
    try:
        fut: asyncio.Future = loop.create_future()

        class _OneShot(asyncio.DatagramProtocol):
            def datagram_received(self, recv_data, _addr):
                if not fut.done():
                    fut.set_result(recv_data)
            def error_received(self, exc):
                if not fut.done():
                    fut.set_exception(exc)
            def connection_lost(self, _):
                # only signal failure if we haven't resolved yet
                if not fut.done():
                    fut.set_exception(ConnectionError("connection lost"))

        transport, _ = await loop.create_datagram_endpoint(
            _OneShot, remote_addr=(host, port)
        )
        transport.sendto(data)
        resp = await asyncio.wait_for(fut, timeout=timeout)
        lat = time.monotonic() - t0
        _, _, rcode_int = parse_dns_header(resp)
        return True, lat, RCODES.get(rcode_int, f"ERR{rcode_int}")
    except asyncio.TimeoutError:
        return False, timeout, "TIMEOUT"
    except Exception:
        return False, time.monotonic() - t0, "ERROR"
    finally:
        if transport is not None:
            transport.close()


async def run_benchmark(mode: str, concurrency: int,
                        total: int, target_host: str,
                        target_port: int,
                        domain_set: str = "external") -> BenchResult:
    """Fire `total` queries with `concurrency` simultaneous coroutines, in batches."""
    if domain_set == "cached":
        # Phase 1: warm up cache by querying each domain once serially
        for domain in _BENCH_DOMAINS:
            await _single_udp_query(target_host, target_port,
                                    _make_dns_query(domain), timeout=3.0)
        domains = _BENCH_DOMAINS
    elif domain_set == "local":
        domains = _LOCAL_BENCH_DOMAINS
    else:
        domains = _BENCH_DOMAINS

    sem   = asyncio.Semaphore(concurrency)
    lats  = []
    ok = err = tout = 0
    batch_size = concurrency * 4  # run in chunks to cap memory

    async def _one():
        nonlocal ok, err, tout
        domain = random.choice(domains)
        data   = _make_dns_query(domain)
        async with sem:
            success, lat, rcode = await _single_udp_query(
                target_host, target_port, data, timeout=3.0
            )
        if not success:
            if rcode == "TIMEOUT":
                tout += 1
            else:
                err += 1
        else:
            ok += 1
        lats.append(lat)

    t0 = time.monotonic()
    remaining = total
    while remaining > 0:
        chunk = min(remaining, batch_size)
        await asyncio.gather(*[_one() for _ in range(chunk)])
        remaining -= chunk
    dur = time.monotonic() - t0
    return BenchResult(
        mode=mode, total_queries=total, duration_s=dur,
        qps=total / dur if dur else 0,
        success=ok, error=err, timeout=tout, latencies=lats,
        domain_set=domain_set,
    )

# ── FastAPI app & lifespan ────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _upstream_sock
    loop = asyncio.get_event_loop()
    # create upstream receiver socket
    _transport, _ = await loop.create_datagram_endpoint(
        UpstreamProtocol,
        local_addr=("0.0.0.0", 0),
    )
    _upstream_sock = _transport

    # start proxy listener
    proxy_transport, _ = await loop.create_datagram_endpoint(
        DnsProxyProtocol,
        local_addr=("0.0.0.0", PROXY_PORT),
    )
    print(f"DNS proxy listening on UDP :{PROXY_PORT} -> {DNS_SERVER_HOST}:{DNS_SERVER_PORT}")
    yield
    proxy_transport.close()
    _transport.close()


app = FastAPI(title="DNS Monitor", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── API routes ────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats():
    return await stats.snapshot()


@app.get("/api/process")
async def get_process():
    """Find and return metrics for the C++ dns_server process."""
    proc_info = None
    for proc in psutil.process_iter(["pid", "name", "cpu_percent",
                                      "memory_info", "create_time", "status"]):
        try:
            if DNS_PROC_NAME in proc.info["name"]:
                mem = proc.info["memory_info"]
                proc_info = {
                    "pid":        proc.info["pid"],
                    "name":       proc.info["name"],
                    "status":     proc.info["status"],
                    "cpu_pct":    proc.cpu_percent(interval=0.1),
                    "mem_rss_mb": round(mem.rss / 1024 / 1024, 2),
                    "mem_vms_mb": round(mem.vms / 1024 / 1024, 2),
                    "uptime_s":   round(time.time() - proc.info["create_time"], 1),
                }
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if proc_info is None:
        return JSONResponse({"online": False})
    proc_info["online"] = True
    return proc_info


@app.get("/api/server/health")
async def server_health():
    """Quick UDP ping to the C++ DNS server."""
    data = _make_dns_query("health.check.local")
    try:
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()

        class _Ping(asyncio.DatagramProtocol):
            def datagram_received(self, d, _):
                if not fut.done(): fut.set_result(True)
            def error_received(self, e):
                if not fut.done(): fut.set_exception(e)

        t, _ = await loop.create_datagram_endpoint(
            _Ping, remote_addr=(DNS_SERVER_HOST, DNS_SERVER_PORT)
        )
        t.sendto(data)
        await asyncio.wait_for(fut, timeout=1.5)
        t.close()
        return {"online": True}
    except Exception:
        return {"online": False}


@app.post("/api/bench")
async def run_bench(body: dict):
    """
    body: {
      "mode": "normal" | "stress",
      "concurrency": int,
      "total": int,
      "target_host": str,   # optional, defaults to DNS_SERVER_HOST
      "target_port": int    # optional, defaults to DNS_SERVER_PORT
    }
    """
    mode        = body.get("mode", "normal")
    concurrency = int(body.get("concurrency", 10))
    total       = int(body.get("total", 200))
    t_host      = body.get("target_host", DNS_SERVER_HOST)
    t_port      = int(body.get("target_port", DNS_SERVER_PORT))
    domain_set  = body.get("domain_set", "external")
    # safety caps
    concurrency = min(concurrency, 500)
    result = await run_benchmark(mode, concurrency, total, t_host, t_port, domain_set)
    return result.to_dict()


# serve frontend
_frontend = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(_frontend):
    app.mount("/", StaticFiles(directory=_frontend, html=True), name="static")


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=HTTP_PORT, reload=False)




