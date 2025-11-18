"""High level interface for extracting features from PCAP captures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from .features import FeatureExtractor, FeatureReport
from .parser import iter_packets


class PcapFeatureAgent:
    """Facade that orchestrates parsing and feature extraction."""

    def __init__(self, extractor: FeatureExtractor | None = None):
        self._extractor = extractor or FeatureExtractor()

    def analyse(self, source: str | Path) -> FeatureReport:
        packets = iter_packets(str(source))
        return self._extractor.extract_from_packets(packets)

    def analyse_to_dict(self, source: str | Path) -> Dict[str, object]:
        report = self.analyse(source)
        return report.to_dict()

    def analyse_to_json(self, source: str | Path, *, pretty: bool = False) -> str:
        report_dict = self.analyse_to_dict(source)
        if pretty:
            return json.dumps(report_dict, indent=2, sort_keys=True)
        return json.dumps(report_dict)


__all__ = ["PcapFeatureAgent", "FeatureReport"]
