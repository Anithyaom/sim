"""Minimal PCAP reader with pure Python parsing utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional
import struct


@dataclass
class Packet:
    """Represents a single packet entry in a PCAP file."""

    timestamp: float
    captured_length: int
    original_length: int
    payload: bytes


class PcapFormatError(RuntimeError):
    """Raised when the file does not comply with the PCAP specification."""


class PcapParser:
    """Iterates over packets in a PCAP file.

    The parser intentionally avoids relying on third-party dependencies so it can
    run in restricted environments. It supports little and big endian PCAP files
    as described in the original libpcap specification.
    """

    GLOBAL_HEADER_SIZE = 24
    PACKET_HEADER_SIZE = 16

    def __init__(self, fileobj: BinaryIO):
        self._fh = fileobj
        self._endianness = "<"
        self._nanosecond_resolution = False
        self._network = None
        self._read_global_header()

    @classmethod
    def open(cls, path: str) -> "PcapParser":
        return cls(open(path, "rb"))

    def _read_global_header(self) -> None:
        header = self._fh.read(self.GLOBAL_HEADER_SIZE)
        if len(header) != self.GLOBAL_HEADER_SIZE:
            raise PcapFormatError("File too short to contain PCAP global header")

        magic_number = struct.unpack("<I", header[:4])[0]
        if magic_number == 0xA1B2C3D4:
            self._endianness = "<"
            self._nanosecond_resolution = False
        elif magic_number == 0xD4C3B2A1:
            self._endianness = ">"
            self._nanosecond_resolution = False
        elif magic_number == 0xA1B23C4D:
            self._endianness = "<"
            self._nanosecond_resolution = True
        elif magic_number == 0x4D3CB2A1:
            self._endianness = ">"
            self._nanosecond_resolution = True
        else:
            raise PcapFormatError("Unsupported PCAP magic number: 0x%08x" % magic_number)

        fmt = self._endianness + "HHIIII"
        (
            version_major,
            version_minor,
            _thiszone,
            _sigfigs,
            _snaplen,
            network,
        ) = struct.unpack(fmt, header[4:])

        if version_major != 2:
            raise PcapFormatError(f"Unsupported PCAP major version: {version_major}")
        self._network = network

    def packets(self) -> Iterator[Packet]:
        ts_scale = 1_000_000_000 if self._nanosecond_resolution else 1_000_000
        fmt = self._endianness + "IIII"
        while True:
            header = self._fh.read(self.PACKET_HEADER_SIZE)
            if not header:
                return
            if len(header) != self.PACKET_HEADER_SIZE:
                raise PcapFormatError("Truncated packet header")

            ts_sec, ts_frac, captured_length, original_length = struct.unpack(fmt, header)
            payload = self._fh.read(captured_length)
            if len(payload) != captured_length:
                raise PcapFormatError("Truncated packet payload")

            timestamp = ts_sec + ts_frac / ts_scale
            yield Packet(timestamp, captured_length, original_length, payload)

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "PcapParser":
        return self

    def __exit__(self, exc_type, exc, tb) -> Optional[bool]:
        self.close()
        return None


def iter_packets(path: str) -> Iterator[Packet]:
    """Convenience helper that iterates packets from a file path."""

    with PcapParser.open(path) as parser:
        for packet in parser.packets():
            yield packet
