from __future__ import annotations

import struct
from pathlib import Path

import pytest

from pcap_agent.agent import PcapFeatureAgent


LINKTYPE_ETHERNET = 1


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as fh:
        fh.write(struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,
            2,
            4,
            0,
            0,
            65535,
            LINKTYPE_ETHERNET,
        ))
        for timestamp, payload in packets:
            ts_sec = int(timestamp)
            ts_usec = int((timestamp - ts_sec) * 1_000_000)
            fh.write(struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload)))
            fh.write(payload)


def ethernet_frame(ethertype: int, payload: bytes) -> bytes:
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", ethertype) + payload


def ipv4_packet(protocol: int, payload: bytes) -> bytes:
    version_ihl = 0x45
    tos = 0
    total_length = 20 + len(payload)
    identification = 0
    flags_fragment = 0
    ttl = 64
    header_checksum = 0
    src = b"\x0a\x00\x00\x01"
    dst = b"\x0a\x00\x00\x02"
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        header_checksum,
        src,
        dst,
    )
    return header + payload


def test_feature_agent_extracts_basic_stats(tmp_path: Path) -> None:
    tcp_payload = b"T" * 20
    udp_payload = b"U" * 8
    packets = [
        (
            1.0,
            ethernet_frame(0x0800, ipv4_packet(6, tcp_payload)),
        ),
        (
            2.0,
            ethernet_frame(0x0800, ipv4_packet(17, udp_payload)),
        ),
    ]
    pcap_path = tmp_path / "sample.pcap"
    write_pcap(pcap_path, packets)

    agent = PcapFeatureAgent()
    report = agent.analyse(pcap_path)

    assert report.total_packets == 2
    assert report.total_bytes == sum(len(pkt) for _, pkt in packets)
    assert pytest.approx(report.duration_seconds, rel=1e-5) == 1.0
    assert pytest.approx(report.average_packet_size, rel=1e-5) == report.total_bytes / report.total_packets
    assert report.layer2_protocols["IPv4"] == 2
    assert report.ip_protocols["TCP"] == 1
    assert report.ip_protocols["UDP"] == 1


def test_empty_capture_returns_zeroed_report(tmp_path: Path) -> None:
    pcap_path = tmp_path / "empty.pcap"
    write_pcap(pcap_path, [])

    agent = PcapFeatureAgent()
    report = agent.analyse(pcap_path)

    assert report.total_packets == 0
    assert report.total_bytes == 0
    assert report.duration_seconds == 0.0
    assert report.packets_per_second == 0.0
    assert report.throughput_bps == 0.0
