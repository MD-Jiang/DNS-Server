#!/usr/bin/env python3
"""DNS查询工具 + 黑盒测试套件。默认交互式查询，--test 运行测试。"""

from __future__ import annotations

import argparse
import ipaddress
import random
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Iterable

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
CLASS_IN = 1


@dataclass
class DnsResponse:
    transaction_id: int
    flags: int
    questions: int
    answers: list[tuple[str, int, bytes]]

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def authoritative(self) -> bool:
        return bool(self.flags & 0x0400)

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)


def encode_name(name: str) -> bytes:
    normalized = name.rstrip(".")
    if not normalized:
        return b"\x00"
    labels = normalized.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError(f"invalid DNS name: {name}")
    encoded = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels)
    if len(encoded) + 1 > 255:
        raise ValueError(f"DNS name is too long: {name}")
    return encoded + b"\x00"


def decode_name(packet: bytes, offset: int, max_jumps: int = 100) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset = offset
    jumped = False
    jumps = 0
    visited: set[int] = set()
    while True:
        if cursor >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[cursor]
        if length == 0:
            if not jumped:
                next_offset = cursor + 1
            return ("." if not labels else ".".join(labels) + "."), next_offset
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            target = ((length & 0x3F) << 8) | packet[cursor + 1]
            if target in visited or target >= len(packet) or jumps >= max_jumps:
                raise ValueError("invalid DNS compression pointer")
            visited.add(target)
            jumps += 1
            if not jumped:
                next_offset = cursor + 2
                jumped = True
            cursor = target
            continue
        if length & 0xC0 or length > 63 or cursor + length + 1 > len(packet):
            raise ValueError("invalid DNS label")
        start = cursor + 1
        labels.append(packet[start : start + length].decode("ascii"))
        cursor = start + length


def parse_response(packet: bytes, expected_id: int) -> DnsResponse:
    if len(packet) < 12:
        raise AssertionError("DNS response is shorter than the 12-byte header")
    transaction_id, flags, question_count, answer_count, _, _ = struct.unpack(
        "!HHHHHH", packet[:12]
    )
    if transaction_id != expected_id:
        raise AssertionError("transaction ID does not match")
    if not flags & 0x8000:
        raise AssertionError("response QR flag is not set")
    offset = 12
    for _ in range(question_count):
        _, offset = decode_name(packet, offset)
        if offset + 4 > len(packet):
            raise AssertionError("truncated question")
        offset += 4
    answers: list[tuple[str, int, bytes]] = []
    for _ in range(answer_count):
        name, offset = decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise AssertionError("truncated answer header")
        record_type, _, _, data_length = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        if offset + data_length > len(packet):
            raise AssertionError("truncated answer data")
        answers.append((name, record_type, packet[offset : offset + data_length]))
        offset += data_length
    return DnsResponse(transaction_id, flags, question_count, answers)


def make_query(name: str, record_type: int, question_count: int = 1) -> tuple[int, bytes]:
    transaction_id = random.randrange(1, 65536)
    question = encode_name(name) + struct.pack("!HH", record_type, CLASS_IN)
    packet = struct.pack("!HHHHHH", transaction_id, 0x0100, question_count, 0, 0, 0)
    return transaction_id, packet + question * question_count


def request_udp(host: str, port: int, query: bytes, transaction_id: int, timeout: float) -> DnsResponse:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(query, (host, port))
        response, _ = client.recvfrom(65535)
    return parse_response(response, transaction_id)


def request_tcp(host: str, port: int, query: bytes, transaction_id: int, timeout: float) -> DnsResponse:
    with socket.create_connection((host, port), timeout=timeout) as client:
        client.settimeout(timeout)
        client.sendall(struct.pack("!H", len(query)) + query)
        header = client.recv(2)
        if len(header) != 2:
            raise AssertionError("TCP response is missing its length prefix")
        length = struct.unpack("!H", header)[0]
        response = bytearray()
        while len(response) < length:
            chunk = client.recv(length - len(response))
            if not chunk:
                raise AssertionError("TCP response ended before the length prefix")
            response.extend(chunk)
    return parse_response(bytes(response), transaction_id)


def assert_has_type(response: DnsResponse, record_type: int) -> None:
    if not any(answer_type == record_type for _, answer_type, _ in response.answers):
        raise AssertionError(f"response has no record type {record_type}")


def run_test(label: str, callback) -> None:
    try:
        callback()
        print(f"PASS {label}")
    except Exception as error:
        print(f"FAIL {label}: {error}")
        raise


def run_tests(args) -> None:
    """执行原有的黑盒测试套件"""
    def local_a() -> None:
        transaction_id, query = make_query("example.test.", TYPE_A)
        response = request_udp(args.host, args.udp_port, query, transaction_id, args.timeout)
        assert response.rcode == 0 and response.authoritative
        assert_has_type(response, TYPE_A)

    def local_aaaa() -> None:
        transaction_id, query = make_query("ipv6.example.test.", TYPE_AAAA)
        response = request_udp(args.host, args.udp_port, query, transaction_id, args.timeout)
        assert response.rcode == 0
        assert_has_type(response, TYPE_AAAA)

    def cname() -> None:
        transaction_id, query = make_query("alias.example.test.", TYPE_CNAME)
        response = request_udp(args.host, args.udp_port, query, transaction_id, args.timeout)
        assert response.rcode == 0
        assert_has_type(response, TYPE_CNAME)

    def nxdomain() -> None:
        transaction_id, query = make_query("missing.example.test.", TYPE_A)
        response = request_udp(args.host, args.udp_port, query, transaction_id, args.timeout)
        assert response.rcode == 3

    def multiple_questions() -> None:
        transaction_id, query = make_query("example.test.", TYPE_A, question_count=2)
        response = request_udp(args.host, args.udp_port, query, transaction_id, args.timeout)
        assert response.questions == 2

    def tcp_a() -> None:
        transaction_id, query = make_query("example.test.", TYPE_A)
        response = request_tcp(args.host, args.tcp_port, query, transaction_id, args.timeout)
        assert response.rcode == 0
        assert_has_type(response, TYPE_A)

    run_test("UDP A record", local_a)
    run_test("UDP AAAA record", local_aaaa)
    run_test("UDP CNAME record", cname)
    run_test("NXDOMAIN", nxdomain)
    run_test("multiple questions", multiple_questions)
    run_test("TCP length-prefixed query", tcp_a)

    if not args.skip_upstream:
        def upstream() -> None:
            transaction_id, query = make_query(args.upstream_name, TYPE_A)
            response = request_udp(args.host, args.udp_port, query, transaction_id, args.timeout)
            assert response.rcode == 0
            assert_has_type(response, TYPE_A)

        run_test(f"upstream forwarding ({args.upstream_name})", upstream)


def interactive_lookup(args) -> None:
    """交互式查询域名 IPv4 地址（A 记录）"""
    print("DNS 查询工具 (输入空行退出)")
    while True:
        domain = input("请输入域名: ").strip()
        if not domain:
            break
        # 自动补全末尾点（可选）
        if not domain.endswith("."):
            domain += "."
        try:
            trans_id, query = make_query(domain, TYPE_A)
            response = request_udp(args.host, args.udp_port, query, trans_id, args.timeout)
        except Exception as e:
            print(f"查询失败: {e}")
            continue

        if response.rcode != 0:
            print(f"DNS 错误，rcode={response.rcode}")
            continue

        found = False
        for name, rtype, data in response.answers:
            if rtype == TYPE_A:
                ip = socket.inet_ntoa(data)
                print(ip)
                found = True
        if not found:
            print("未找到 A 记录")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="DNS server IPv4 address")
    parser.add_argument("--udp-port", type=int, default=2053, help="UDP port")
    parser.add_argument("--tcp-port", type=int, default=15353, help="TCP port")
    parser.add_argument("--timeout", type=float, default=3.0, help="timeout in seconds")
    parser.add_argument("--upstream-name", default="baidu.com.", help="upstream test domain")
    parser.add_argument("--skip-upstream", action="store_true", help="skip upstream test")
    parser.add_argument("--test", action="store_true", help="run the test suite instead of interactive lookup")

    args = parser.parse_args()

    if args.test:
        run_tests(args)
    else:
        interactive_lookup(args)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError) as error:
        print(f"程序终止: {error}", file=sys.stderr)
        raise SystemExit(1)