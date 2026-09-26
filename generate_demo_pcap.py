"""Generate a harmless PCAP for testing the ThreatLens PCAP pipeline.

It contains one normal HTTP connection, one normal SSH banner exchange, and
one DNS request/response. It contains no scanning, brute-force traffic, or
exploit payloads.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path
from time import time


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_tcp(source: str, destination: str, source_port: int, destination_port: int,
             sequence: int, acknowledgement: int, flags: int, payload: bytes = b"") -> bytes:
    tcp = struct.pack("!HHLLBBHHH", source_port, destination_port, sequence, acknowledgement,
                      5 << 4, flags, 64240, 0, 0) + payload
    pseudo = struct.pack("!4s4sBBH", ipaddress.ip_address(source).packed,
                         ipaddress.ip_address(destination).packed, 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + tcp


def ipv4_udp(source: str, destination: str, source_port: int, destination_port: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    pseudo = struct.pack("!4s4sBBH", ipaddress.ip_address(source).packed,
                         ipaddress.ip_address(destination).packed, 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp)) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 2, 0, 64, 17, 0,
                     ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + udp


def write_pcap(path: Path, packets: list[bytes]) -> None:
    now = int(time())
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for offset, packet in enumerate(packets):
            handle.write(struct.pack("<IIII", now, offset * 20_000, len(packet), len(packet)))
            handle.write(packet)


def main() -> None:
    client, server, dns = "10.10.10.25", "10.10.10.10", "8.8.8.8"
    packets = [
        # Harmless HTTP connection.
        ipv4_tcp(client, server, 50100, 80, 100, 0, 0x02),
        ipv4_tcp(server, client, 80, 50100, 200, 101, 0x12),
        ipv4_tcp(client, server, 50100, 80, 101, 201, 0x10),
        ipv4_tcp(client, server, 50100, 80, 101, 201, 0x18, b"GET /health HTTP/1.1\r\nHost: demo.local\r\n\r\n"),
        ipv4_tcp(server, client, 80, 50100, 201, 142, 0x18, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
        # Harmless SSH connection; one banner, not a login attempt.
        ipv4_tcp(client, server, 50101, 22, 300, 0, 0x02),
        ipv4_tcp(server, client, 22, 50101, 400, 301, 0x12),
        ipv4_tcp(client, server, 50101, 22, 301, 401, 0x10),
        ipv4_tcp(server, client, 22, 50101, 401, 301, 0x18, b"SSH-2.0-OpenSSH_9.0\r\n"),
        # Harmless DNS request/response.
        ipv4_udp(client, dns, 53000, 53, bytes.fromhex("1234010000010000000000000474657374056c6f63616c0000010001")),
        ipv4_udp(dns, client, 53, 53000, bytes.fromhex("1234818000010000000000000474657374056c6f63616c0000010001")),
    ]
    target = Path("demo_safe_traffic.pcap")
    write_pcap(target, packets)
    print(f"Created {target.resolve()} with {len(packets)} harmless packets.")


if __name__ == "__main__":
    main()
