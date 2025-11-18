# PCAP Feature Agent

This project provides a lightweight, dependency-free agent capable of parsing
[PCAP](https://wiki.wireshark.org/Development/LibpcapFileFormat) captures and
computing descriptive statistics suitable for AI-driven network analytics. It
ships with a small framework that:

- parses PCAP files without third-party libraries,
- extracts protocol and traffic level features, and
- exposes a command line interface that returns JSON summaries.

## Installation

The project targets Python 3.11 or newer. To install the optional development
dependencies run:

```bash
pip install -e .[dev]
```

## Command line usage

```
python -m pcap_agent <capture.pcap> --pretty
```

The command prints a JSON document that contains aggregate statistics about the
packets inside the capture.

## Library usage

```python
from pcap_agent import PcapFeatureAgent

agent = PcapFeatureAgent()
report = agent.analyse("capture.pcap")
print(report.to_dict())
```

## Running the tests

```
pytest
```
