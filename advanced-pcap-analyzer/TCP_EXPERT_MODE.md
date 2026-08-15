# TCP Expert Mode Documentation

## Overview

The TCP Expert Mode is an advanced analysis feature that performs deep inspection of TCP connections in PCAP/PCAPNG files. It classifies each connection's health, identifies problems, and provides actionable recommendations for network engineers.

## Features

### Connection Health Classification

Each TCP connection is classified into one of these categories:

| Status | Description | Priority |
|--------|-------------|----------|
| `healthy` | Normal operation with acceptable metrics | Low |
| `slow_handshake` | TCP handshake RTT > 200ms | Medium |
| `retransmission_heavy` | Retransmission rate > 15% | High |
| `lossy` | Packet loss indicators (dup ACKs, OOO) | High |
| `receiver_limited` | Zero window conditions stalling sender | Medium |
| `reset_by_endpoint` | Connection reset by server/client | High |
| `reset_by_middlebox` | Immediate reset (firewall/IPS) | Critical |
| `incomplete_handshake` | 3-way handshake did not complete | High |
| `timeout` | Connection attempt timed out | High |
| `unknown` | Insufficient data for classification | Low |

### Metrics Calculated

For each TCP connection, the analyzer calculates:

#### Timing Metrics
- **Initial RTT**: Time from SYN to SYN-ACK (milliseconds)
- **Average RTT**: Mean round-trip time from samples
- **Min/Max RTT**: Range of observed RTT values
- **Duration**: Total connection lifetime

#### Volume Metrics
- **Packets Sent/Received**: Per-direction packet counts
- **Bytes Sent/Received**: Per-direction byte counts
- **Throughput**: Bits per second (including retransmissions)
- **Goodput**: Effective bits per second (excluding retransmissions)

#### Health Metrics
- **Retransmissions**: Count of retransmitted packets
- **Retransmission Rate**: Percentage of retransmitted packets
- **Duplicate ACKs**: Count of duplicate acknowledgments
- **Out-of-Order Packets**: Packets arriving out of sequence
- **Zero Windows**: Times receiver advertised zero buffer space

#### TCP Options
- **MSS (Maximum Segment Size)**: Client and server values
- **Window Scale**: Scaling factors for both ends
- **SACK Permitted**: Selective Acknowledgment support
- **ECN Negotiated**: Explicit Congestion Notification status

#### Connection State
- **Connection Result**: successful, refused, reset, timeout, incomplete
- **TCP State**: ESTABLISHED, SYN_SENT, CLOSE_WAIT, etc.

## Usage

### Command Line Interface

#### Basic TCP Health Analysis

```bash
# Analyze all TCP connections and show summary
advanced-pcap-analyzer tcp health capture.pcapng

# Show only unhealthy connections
advanced-pcap-analyzer tcp health capture.pcapng --unhealthy

# Limit analysis to first 10000 packets
advanced-pcap-analyzer tcp health capture.pcapng --limit 10000

# Export results as JSON
advanced-pcap-analyzer tcp health capture.pcapng -f json -o tcp_health.json

# Export results as CSV
advanced-pcap-analyzer tcp health capture.pcapng -f csv -o tcp_health.csv
```

#### Detailed Flow Analysis

```bash
# Get detailed analysis of a specific flow
advanced-pcap-analyzer tcp detail capture.pcapng 192.168.1.10:54321-10.0.0.5:443

# Verbose output with packet-level findings
advanced-pcap-analyzer tcp detail capture.pcapng 192.168.1.10:54321-10.0.0.5:443 -v
```

### Python API

```python
from pcap_analyzer.analysis import TCPExpertAnalyzer
from pcap_analyzer.storage.sqlite_store import SQLiteStore
from pathlib import Path

# Create index from PCAP file
store = SQLiteStore()
db_path = store.create_index(Path("capture.pcapng"))

# Run TCP expert analysis
analyzer = TCPExpertAnalyzer()
connections = analyzer.analyze_from_db(db_path)

# Get summary statistics
stats = analyzer.get_summary_stats()
print(f"Total connections: {stats['total_connections']}")
print(f"Healthy rate: {stats['health_rate_pct']}%")

# Find unhealthy connections
unhealthy = analyzer.get_unhealthy_connections()
for conn in unhealthy:
    print(f"\nFlow: {conn.flow_id}")
    print(f"Status: {conn.health_status.value}")
    print(f"Problem: {conn.likely_problem}")
    print(f"Action: {conn.recommended_action}")

# Export connection details
for conn in connections:
    details = conn.to_dict()
    # Process or export details
```

## Output Examples

### Console Table Output

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            TCP Health Summary                                │
├──────────────────────────────────────────────────────────────────────────────┤
│ Total Connections: 247                                                       │
│ Healthy: 198 (80.2%)                                                         │
│ Unhealthy: 49                                                                │
│ Total Retransmissions: 1,523                                                 │
│ Total Zero Windows: 12                                                       │
│                                                                              │
│ Status Breakdown:                                                            │
│   - healthy: 198                                                             │
│   - slow_handshake: 15                                                       │
│   - retransmission_heavy: 8                                                  │
│   - reset_by_middlebox: 12                                                   │
│   - incomplete_handshake: 14                                                 │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                          TCP Connection Details                              │
├───────────────┬────────┬──────┬───────┬─────────┬──────────┬──────────┬──────┤
│ Flow          │ Status │ Pkts │ Bytes │ Retrans │ Dup ACKs │ Init RTT │ Prob │
├───────────────┼────────┼──────┼───────┼─────────┼──────────┼──────────┼──────┤
│ 192.168.1.10  │  red   │  150 │ 75000 │   45    │    12    │   85.2   │ High │
│   → 10.0.0.5  │        │      │       │         │          │          │ loss │
│   :54321      │        │      │       │         │          │          │      │
│   :443        │        │      │       │         │          │          │      │
└───────────────┴────────┴──────┴───────┴─────────┴──────────┴──────────┴──────┘
```

### JSON Finding Example

```json
{
  "flow_id": "192.168.1.10:54321-10.0.0.5:443",
  "src_ip": "192.168.1.10:54321",
  "dst_ip": "10.0.0.5:443",
  "duration_sec": 5.234,
  "packets": 150,
  "bytes": 75000,
  "retransmissions": 45,
  "retrans_rate_pct": 30.0,
  "dup_acks": 12,
  "out_of_order": 8,
  "zero_windows": 0,
  "initial_rtt_ms": 85.2,
  "avg_rtt_ms": 92.5,
  "mss": "1460/1460",
  "window_scale": "7/7",
  "sack": "Yes",
  "health_status": "retransmission_heavy",
  "likely_problem": "Retransmission rate is 30.0%, indicating severe packet loss.",
  "recommended_action": "Investigate interface errors, congestion, or faulty cabling on the path.",
  "result": "successful",
  "evidence_frames": [1023, 1045, 1089, 1102, 1156]
}
```

## Diagnosis Rules

### Reset by Middlebox Detection
**Condition**: RST received within 100ms of SYN, no SYN-ACK
**Indicates**: Firewall, IPS, or security device blocking connection
**Action**: Check firewall rules, ACLs, security group policies

### Retransmission Heavy Detection
**Condition**: Retransmission rate > 15%
**Indicates**: Severe packet loss on path
**Action**: Check interface errors, cable quality, switch port statistics

### Receiver Limited Detection
**Condition**: Multiple zero-window advertisements
**Indicates**: Receiving application cannot process data fast enough
**Action**: Check application performance, increase receive buffer

### Slow Handshake Detection
**Condition**: Initial RTT > 200ms
**Indicates**: High latency path or server overload
**Action**: Check network path, server CPU, SYN queue depth

## Integration

### With HTML Reports

The TCP expert analysis is automatically included in HTML reports:

```bash
advanced-pcap-analyzer analyze capture.pcapng --report html -o report.html
```

The report includes:
- TCP Health summary table
- Top unhealthy connections
- Retransmission timeline
- RTT distribution charts

### With Correlation Engine

TCP findings are correlated with other protocol analysis:

```python
from pcap_analyzer.detection import CorrelationEngine

correlator = CorrelationEngine()
results = correlator.correlate({
    'tcp_analysis': analyzer.get_summary_stats(),
    'icmp_analysis': icmp_results,
    'dns_analysis': dns_results
})
```

## Performance Considerations

- **Memory Efficient**: Uses SQLite indexing for large files
- **Streaming**: Processes packets incrementally
- **Limits**: Use `--limit` for very large captures during initial analysis
- **Sampling**: Consider `--sample-rate` for approximate analysis of huge files

## Troubleshooting

### No Connections Found
- Verify the capture contains TCP traffic
- Check if tshark is properly installed
- Ensure the capture file is not corrupted

### All Connections Show as Unknown
- Capture may be truncated
- Insufficient packets to determine state
- Check for missing handshake packets due to capture start timing

### High Memory Usage
- Reduce `--limit` parameter
- Use SQLite storage backend (default)
- Consider chunked processing for very large files

## Best Practices

1. **Capture Duration**: For TCP analysis, capture at least 2-3x the expected connection duration
2. **Capture Point**: Place capture as close to the problem endpoint as possible
3. **Filter Wisely**: Use capture filters to reduce file size while retaining relevant traffic
4. **Baseline First**: Capture normal behavior for comparison
5. **Check Both Directions**: Ensure bidirectional traffic is captured

## Related Commands

- `advanced-pcap-analyzer flows` - View all network flows
- `advanced-pcap-analyzer latency` - Analyze latency patterns
- `advanced-pcap-analyzer anomalies` - Detect anomalous behavior
- `advanced-pcap-analyzer diagnose` - Full diagnostic report
