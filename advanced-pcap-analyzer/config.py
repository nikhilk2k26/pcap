#!/usr/bin/env python3
"""
Configuration settings for Advanced PCAP Analyzer.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path


@dataclass
class AnalysisConfig:
    """Configuration for analysis operations."""
    
    # Chunk processing
    chunk_size: int = 10000  # packets per chunk
    max_in_memory_packets: int = 100000
    
    # Sampling
    default_sample_rate: float = 1.0  # 1.0 = no sampling
    min_sample_rate: float = 0.01  # minimum 1% sampling
    
    # Limits
    default_packet_limit: Optional[int] = None
    max_packet_limit: int = 10000000  # 10M packets max
    
    # Timeouts
    tshark_timeout_seconds: int = 300
    analysis_timeout_seconds: int = 600
    
    # RTT calculation
    rtt_sample_count: int = 1000  # max samples for RTT calculation
    rtt_outlier_threshold_ms: float = 5000.0  # ignore RTTs above this
    
    # Retransmission detection
    retransmission_window_ms: float = 1000.0  # window for detecting retransmissions
    
    # Flow tracking
    flow_timeout_seconds: int = 300  # TCP flow timeout
    udp_flow_timeout_seconds: int = 30  # UDP flow timeout
    
    # Finding thresholds
    high_retransmission_threshold: float = 5.0  # percent
    critical_retransmission_threshold: float = 15.0  # percent
    high_latency_threshold_ms: float = 200.0
    critical_latency_threshold_ms: float = 1000.0
    high_packet_loss_threshold: float = 5.0  # percent
    critical_packet_loss_threshold: float = 15.0  # percent
    
    # DNS thresholds
    dns_slow_response_threshold_ms: float = 100.0
    dns_high_nxdomain_threshold: float = 10.0  # percent
    
    # DHCP thresholds
    dhcp_slow_transaction_threshold_ms: float = 5000.0
    
    # ARP thresholds
    arp_storm_threshold_per_second: int = 100
    
    # Broadcast/multicast thresholds
    broadcast_storm_threshold_per_second: int = 1000
    
    # Security thresholds
    port_scan_threshold_unique_ports: int = 20
    port_scan_threshold_seconds: int = 60
    syn_flood_threshold_per_second: int = 100


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    
    # Console output
    console_width: int = 120
    console_color: bool = True
    show_progress: bool = True
    
    # Top N items
    top_talkers_count: int = 20
    top_conversations_count: int = 20
    top_protocols_count: int = 15
    top_findings_count: int = 50
    
    # HTML report
    html_template_path: Optional[Path] = None
    include_charts: bool = True
    include_raw_data: bool = False
    
    # CSV export
    csv_delimiter: str = ","
    csv_include_header: bool = True
    
    # JSON export
    json_indent: int = 2
    json_sort_keys: bool = False
    
    # Redaction
    redact_ips: bool = False
    redact_macs: bool = False
    redact_domains: bool = False
    redaction_pattern: str = "***REDACTED***"


@dataclass
class StorageConfig:
    """Configuration for storage backends."""
    
    # SQLite
    sqlite_db_path: Optional[Path] = None
    sqlite_use_memory: bool = False
    sqlite_journal_mode: str = "WAL"
    
    # DuckDB
    duckdb_db_path: Optional[Path] = None
    duckdb_use_memory: bool = True
    
    # Indexing
    create_packet_index: bool = True
    create_flow_index: bool = True
    index_batch_size: int = 5000


@dataclass
class TsharkConfig:
    """Configuration for tshark integration."""
    
    # Paths
    tshark_path: Optional[str] = None  # None = use PATH
    dumpcap_path: Optional[str] = None
    
    # Processing
    use_tshark_json: bool = True
    tshark_fields_separator: str = "|"
    
    # Fields to extract (tshark -e fields)
    default_fields: List[str] = field(default_factory=lambda: [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.cap_len",
        "frame.interface_id",
        "frame.encap_type",
        "eth.src",
        "eth.dst",
        "eth.type",
        "vlan.id",
        "vlan.priority",
        "mpls.label",
        "ip.version",
        "ip.src",
        "ip.dst",
        "ip.ttl",
        "ip.flags.df",
        "ip.flags.mf",
        "ip.frag_offset",
        "ip.dsfield.dscp",
        "ip.dsfield.ecn",
        "ip.proto",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags",
        "tcp.seq",
        "tcp.ack",
        "tcp.window_size",
        "tcp.window_size_scalefactor",
        "tcp.options.mss.val",
        "tcp.options.wscale.shift",
        "tcp.analysis.retransmission",
        "tcp.analysis.duplicate_ack",
        "tcp.analysis.out_of_order",
        "tcp.analysis.zero_window",
        "tcp.analysis.window_full",
        "icmp.type",
        "icmp.code",
        "dns.qry.name",
        "dns.resp.type",
        "dns.flags.rcode",
        "dhcp.type",
        "dhcp.server_ip",
        "dhcp.option.ip_address",
        "http.host",
        "http.request.method",
        "http.response.code",
        "tls.handshake.type",
        "tls.handshake.extensions_server_name",
        "rtp.sequence",
        "rtp.jitter",
    ])
    
    # Default display filter
    default_display_filter: str = ""
    
    # Promiscuous mode
    promiscuous_mode: bool = False


@dataclass
class Config:
    """Main configuration container."""
    
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    tshark: TsharkConfig = field(default_factory=TsharkConfig)
    
    # Global settings
    debug: bool = False
    verbose: bool = False
    log_file: Optional[Path] = None
    
    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "Config":
        """Load configuration from file or use defaults."""
        # For now, return default config
        # Can be extended to load from YAML/JSON
        return cls()


# Global default configuration
DEFAULT_CONFIG = Config()
