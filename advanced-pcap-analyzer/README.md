# Advanced PCAP Analyzer

A professional-grade PCAP/PCAPNG analysis application designed for network engineers, NOC engineers, SREs, network security analysts, and troubleshooting specialists.

## Overview

Advanced PCAP Analyzer provides deep network diagnostics, performance analysis, fault detection, root-cause hints, and detailed engineering reports. It goes beyond basic packet counting to deliver actionable insights about:

- Connectivity failures
- TCP performance problems
- Packet loss indicators
- Retransmissions and duplicate ACKs
- Zero-window conditions
- Latency and RTT estimates
- MTU/MSS/PMTUD issues
- DNS, DHCP, ARP problems
- QoS/DSCP analysis
- Security anomalies

## Installation

### Prerequisites

- Python 3.11+
- tshark (Wireshark command-line tool)

### Install tshark

**Ubuntu/Debian:**
```bash
sudo apt-get install tshark
```

**CentOS/RHEL:**
```bash
sudo yum install wireshark-cli
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download from https://www.wireshark.org/download.html

### Install Python Package

```bash
cd advanced-pcap-analyzer
pip install -e .
```

Or install dependencies directly:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Analysis

```bash
# Full analysis with all findings
advanced-pcap-analyzer analyze capture.pcapng

# Quick summary
advanced-pcap-analyzer summary capture.pcapng

# Detailed diagnosis with root-cause hints
advanced-pcap-analyzer diagnose capture.pcapng
```

### Protocol-Specific Analysis

```bash
# TCP health analysis
advanced-pcap-analyzer tcp-health capture.pcapng

# Latency analysis
advanced-pcap-analyzer latency capture.pcapng

# DNS analysis
advanced-pcap-analyzer dns capture.pcapng

# DHCP analysis
advanced-pcap-analyzer dhcp capture.pcapng

# ARP analysis
advanced-pcap-analyzer arp capture.pcapng

# ICMP analysis
advanced-pcap-analyzer icmp capture.pcapng

# TLS analysis
advanced-pcap-analyzer tls capture.pcapng

# HTTP analysis
advanced-pcap-analyzer http capture.pcapng

# QoS/DSCP analysis
advanced-pcap-analyzer qos capture.pcapng

# Anomaly detection
advanced-pcap-analyzer anomalies capture.pcapng
```

### Flow Analysis

```bash
# Top talkers and conversations
advanced-pcap-analyzer flows capture.pcapng --top 50

# Export flows to CSV
advanced-pcap-analyzer flows capture.pcapng --export flows.csv
```

### Filtering

```bash
# Filter by IP address
advanced-pcap-analyzer analyze capture.pcapng --src-ip 192.168.1.10

# Filter by subnet
advanced-pcap-analyzer analyze capture.pcapng --subnet 10.0.0.0/8

# Filter by port
advanced-pcap-analyzer analyze capture.pcapng --port 443

# Filter by protocol
advanced-pcap-analyzer analyze capture.pcapng --protocol tcp

# Filter by time range
advanced-pcap-analyzer analyze capture.pcapng --start-time "2024-01-01T10:00:00" --end-time "2024-01-01T11:00:00"

# Show only retransmissions
advanced-pcap-analyzer analyze capture.pcapng --retransmissions-only

# Show only failed connections
advanced-pcap-analyzer analyze capture.pcapng --failed-connections

# Show packets with latency above threshold
advanced-pcap-analyzer analyze capture.pcapng --latency-above 200ms

# Combine filters
advanced-pcap-analyzer analyze capture.pcapng --protocol tcp --dst-ip 10.10.10.5 --retransmissions-only
```

### Export Reports

```bash
# Export findings to JSON
advanced-pcap-analyzer export capture.pcapng --type findings --format json --output findings.json

# Export flows to CSV
advanced-pcap-analyzer export capture.pcapng --type flows --format csv --output flows.csv

# Export full report to HTML
advanced-pcap-analyzer export capture.pcapng --type full --format html --output report.html

# Export executive summary to JSON
advanced-pcap-analyzer export capture.pcapng --type executive --format json --output summary.json
```

### Comparison Mode

```bash
# Compare before/after captures
advanced-pcap-analyzer compare before.pcapng after.pcapng

# Compare with specific focus
advanced-pcap-analyzer compare before.pcapng after.pcapng --focus tcp,latency
```

## Command Reference

| Command | Description |
|---------|-------------|
| `analyze` | Full analysis with all findings and recommendations |
| `diagnose` | Focused diagnosis with root-cause hints |
| `summary` | Quick capture summary |
| `flows` | Flow analysis and top talkers |
| `tcp-health` | TCP connection health analysis |
| `latency` | Latency and performance analysis |
| `dns` | DNS transaction analysis |
| `dhcp` | DHCP transaction analysis |
| `arp` | ARP and L2 analysis |
| `icmp` | ICMP event analysis |
| `tls` | TLS session analysis |
| `http` | HTTP transaction analysis |
| `qos` | QoS/DSCP analysis |
| `anomalies` | Security anomaly detection |
| `compare` | Compare two captures |
| `export` | Export data in various formats |

## Output Formats

### Console Report
Engineering-focused terminal output with color-coded severity levels using the `rich` library.

### JSON Report
Machine-readable output including:
- Findings with evidence
- Statistics
- Flows
- Transactions

### CSV Exports
- Packet index
- Flow records
- Findings
- TCP connection health
- DNS transactions
- HTTP transactions
- TLS sessions
- ICMP events
- ARP events
- DHCP events

### HTML Report
Interactive report with:
- Executive summary
- Engineering details
- Interactive charts (Plotly)
- Timeline graphs
- Top talkers
- Protocol hierarchy
- TCP health table
- DNS health table
- Findings with severity
- Downloadable tables

## Finding Schema

Each finding includes:

```json
{
  "finding_id": "TCP-RETRANS-HIGH",
  "title": "High TCP retransmission rate detected",
  "severity": "high",
  "confidence": "high",
  "category": "performance",
  "description": "TCP flow 192.168.1.10:54321 -> 10.10.10.5:443 has a retransmission rate of 12.4%.",
  "affected_object": "192.168.1.10:54321 -> 10.10.10.5:443",
  "evidence_frames": [1023, 1044, 1088, 1120],
  "first_seen": "2024-01-01T12:00:03.120Z",
  "last_seen": "2024-01-01T12:00:41.881Z",
  "count": 87,
  "metrics": {
    "packets": 1200,
    "retransmissions": 149,
    "retransmission_rate": 12.4,
    "avg_rtt_ms": 74.2
  },
  "possible_causes": [
    "network packet loss",
    "congestion",
    "interface errors",
    "QoS drops"
  ],
  "recommended_actions": [
    "check interface error counters",
    "verify QoS policy drops",
    "check path latency and congestion",
    "inspect middlebox or firewall session handling"
  ]
}
```

## Large File Handling

The analyzer supports large PCAP/PCAPNG files through:

- **Streaming/Chunked Parsing**: Does not load entire capture into memory
- **SQLite/DuckDB Indexing**: Local indexing for efficient queries
- **Progress Reporting**: Real-time progress updates
- **Sample Rate**: Approximate analysis with `--sample-rate`
- **Packet Limit**: Analyze first N packets with `--limit`

```bash
# Analyze first 10000 packets
advanced-pcap-analyzer analyze large_capture.pcapng --limit 10000

# Sample 10% of packets for approximate analysis
advanced-pcap-analyzer analyze large_capture.pcapng --sample-rate 0.1
```

## Plugin Development

Create custom analyzers by implementing the `AnalyzerPlugin` interface:

```python
from pcap_analyzer.plugins.analyzer_plugin import AnalyzerPlugin
from pcap_analyzer.models.finding import Finding

class MyCustomAnalyzer(AnalyzerPlugin):
    name = "my_custom_analyzer"
    description = "Custom protocol analysis"
    supported_protocols = ["myproto"]
    
    def analyze(self, packet_index, context):
        # Analyze packets and generate findings
        pass
    
    def generate_findings(self):
        # Return list of Finding objects
        return []
    
    def generate_metrics(self):
        # Return dict of metrics
        return {}
```

## Troubleshooting

### tshark not found
```bash
# Install tshark (see Installation section)
sudo apt-get install tshark  # Ubuntu/Debian
brew install wireshark       # macOS
```

### Permission denied on capture file
```bash
# Ensure read permissions
chmod +r capture.pcapng
```

### Memory issues with large files
```bash
# Use sampling or limit
advanced-pcap-analyzer analyze large.pcapng --sample-rate 0.1
advanced-pcap-analyzer analyze large.pcapng --limit 50000
```

### Corrupted capture file
The analyzer gracefully handles corrupted or truncated captures with warnings.

## Security and Privacy

- All processing is local by default
- No data is sent to external services
- Optional IP/MAC/domain redaction in reports
- Payload logging disabled by default

```bash
# Redact sensitive information in reports
advanced-pcap-analyzer analyze capture.pcapng --redact-ips --redact-macs --redact-domains
```

## License

MIT License

## Contributing

Contributions welcome! Please see the plugin development guide for extending functionality.
