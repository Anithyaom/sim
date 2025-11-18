from __future__ import annotations

import argparse
import sys

from .agent import PcapFeatureAgent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract high level features from a PCAP file")
    parser.add_argument("pcap", help="Path to the PCAP capture to analyse")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print the resulting JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    agent = PcapFeatureAgent()
    try:
        output = agent.analyse_to_json(args.pcap, pretty=args.pretty)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive programming
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
