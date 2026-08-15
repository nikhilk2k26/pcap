# pcap

Advanced PCAP Analyzer — a Python toolkit and CLI for analyzing PCAP/PCAPNG network captures.

This repository contains the Advanced PCAP Analyzer package (located in the advanced-pcap-analyzer directory). The analyzer provides engineering-focused analysis of packet captures including TCP health, latency, flows/top-talkers, protocol-specific diagnostics (DNS, DHCP, ARP, HTTP, TLS), anomaly detection, and exportable reports (JSON/CSV/HTML).

Key features

- Full-analysis, diagnosis, and summary CLI commands
- Protocol-focused analyzers: TCP, DNS, DHCP, ARP, ICMP, HTTP, TLS, QoS
- Flow analysis (top talkers, conversation export)
- Large-file support (streaming/chunked parsing, sampling, limits, local indexing)
- Export reports to JSON, CSV, and HTML (interactive charts)
- Plugin interface to add custom analyzers
- Local processing by default; optional redaction for privacy

Requirements

- Python 3.11+
- tshark (Wireshark command-line) for packet decoding

Installing

From the repository root:

```bash
cd advanced-pcap-analyzer
pip install -e .
```

or install dependencies directly:

```bash
pip install -r advanced-pcap-analyzer/requirements.txt
```

Quick start

```bash
# Full analysis with all findings
advanced-pcap-analyzer analyze capture.pcapng

# Quick summary
advanced-pcap-analyzer summary capture.pcapng

# Export full report to HTML
advanced-pcap-analyzer export capture.pcapng --type full --format html --output report.html
```

Documentation

For full usage, commands, and plugin development see advanced-pcap-analyzer/README.md.

License

MIT License

Contributing

Contributions welcome — please open issues or pull requests. See advanced-pcap-analyzer/README.md for developer notes and plugin guidelines.
