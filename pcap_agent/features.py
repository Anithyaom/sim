"""Feature extraction primitives for PCAP packets."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Mapping, Optional, Tuple

from .parser import Packet


ETHERTYPE_MAP: Mapping[int, str] = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
}

IP_PROTOCOL_MAP: Mapping[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}


@dataclass
class PacketSizeStats:
    minimum: int
    maximum: int
    average: float


@dataclass
class FeatureReport:
    total_packets: int
    total_bytes: int
    duration_seconds: float
    packets_per_second: float
    throughput_bps: float
    average_packet_size: float
    layer2_protocols: Dict[str, int]
    ip_protocols: Dict[str, int]
    packet_size: PacketSizeStats

    def to_dict(self) -> Dict[str, object]:
        payload = asdict(self)
        return payload


class FeatureExtractor:
    """Compute descriptive statistics from an iterable of packets."""

    def extract_from_packets(self, packets: Iterable[Packet]) -> FeatureReport:
        total_packets = 0
        total_bytes = 0
        timestamps: List[float] = []
        layer2_counts: Counter[str] = Counter()
        ip_protocol_counts: Counter[str] = Counter()
        sizes: List[int] = []

        for packet in packets:
            total_packets += 1
            total_bytes += packet.original_length
            timestamps.append(packet.timestamp)
            sizes.append(packet.original_length)

            l2_name, l3_payload = _classify_layer2(packet.payload)
            layer2_counts[l2_name] += 1

            if l3_payload is not None:
                proto_name = _classify_ip_protocol(l3_payload)
                ip_protocol_counts[proto_name] += 1

        if total_packets == 0:
            empty_stats = PacketSizeStats(0, 0, 0.0)
            return FeatureReport(
                total_packets=0,
                total_bytes=0,
                duration_seconds=0.0,
                packets_per_second=0.0,
                throughput_bps=0.0,
                average_packet_size=0.0,
                layer2_protocols={},
                ip_protocols={},
                packet_size=empty_stats,
            )

        duration = max(timestamps) - min(timestamps) if total_packets > 1 else 0.0
        if duration > 0:
            packets_per_second = total_packets / duration
            throughput_bps = (total_bytes * 8) / duration
        else:
            packets_per_second = 0.0
            throughput_bps = 0.0
        avg_packet_size = total_bytes / total_packets
        size_stats = PacketSizeStats(min(sizes), max(sizes), avg_packet_size)

        return FeatureReport(
            total_packets=total_packets,
            total_bytes=total_bytes,
            duration_seconds=duration,
            packets_per_second=packets_per_second,
            throughput_bps=throughput_bps,
            average_packet_size=avg_packet_size,
            layer2_protocols=dict(layer2_counts),
            ip_protocols=dict(ip_protocol_counts),
            packet_size=size_stats,
        )


def _classify_layer2(payload: bytes) -> Tuple[str, Optional[bytes]]:
    if len(payload) < 14:
        return "Unknown", None

    ethertype = int.from_bytes(payload[12:14], "big")
    l2_name = ETHERTYPE_MAP.get(ethertype, f"0x{ethertype:04x}")
    l3_payload = payload[14:]

    if ethertype in (0x0800, 0x86DD):
        return l2_name, l3_payload
    return l2_name, None


def _classify_ip_protocol(payload: bytes) -> str:
    if not payload:
        return "Unknown"

    version = payload[0] >> 4
    if version == 4:
        if len(payload) < 20:
            return "Malformed IPv4"
        header_length = (payload[0] & 0x0F) * 4
        if len(payload) < header_length:
            return "Malformed IPv4"
        protocol_number = payload[9]
    elif version == 6:
        if len(payload) < 40:
            return "Malformed IPv6"
        protocol_number = payload[6]
    else:
        return f"IP version {version}"

    return IP_PROTOCOL_MAP.get(protocol_number, f"Protocol {protocol_number}")
