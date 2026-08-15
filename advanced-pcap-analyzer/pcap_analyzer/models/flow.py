#!/usr/bin/env python3
"""
Flow Record Model

Represents a network flow (similar to NetFlow/IPFIX).
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class FlowRecord:
    """
    Network flow record.
    
    Represents a unidirectional or bidirectional flow of packets
    sharing common 5-tuple (or more) characteristics.
    """
    
    # Flow key components
    flow_id: str = ""
    interface_id: Optional[int] = None
    
    # L2 information
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    vlan_id: Optional[int] = None
    
    # L3 information
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_version: Optional[int] = None
    protocol: Optional[int] = None  # IP protocol number
    dscp: Optional[int] = None
    
    # L4 information
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    
    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    start_timestamp_epoch: float = 0.0
    end_timestamp_epoch: float = 0.0
    
    # Packet/byte counts
    packets: int = 0
    bytes_total: int = 0
    bytes_payload: int = 0
    
    # TCP-specific
    tcp_flags_seen: int = 0  # Bitmask of all flags seen
    tcp_syn_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0
    tcp_retransmissions: int = 0
    tcp_duplicate_acks: int = 0
    tcp_out_of_order: int = 0
    tcp_zero_windows: int = 0
    
    # Derived metrics
    duration: float = 0.0  # seconds
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    bits_per_second: float = 0.0
    
    # Service identification
    service_name: Optional[str] = None  # e.g., "http", "ssh", "dns"
    application_protocol: Optional[str] = None
    
    # Direction inference
    is_client_to_server: Optional[bool] = None  # True if src is client
    initiator_ip: Optional[str] = None
    
    # DNS metadata (if applicable)
    dns_queries: int = 0
    dns_responses: int = 0
    dns_nxdomain_count: int = 0
    
    # HTTP metadata (if applicable)
    http_requests: int = 0
    http_responses: int = 0
    http_hosts: List[str] = field(default_factory=list)
    
    # TLS metadata (if applicable)
    tls_sessions: int = 0
    tls_sni_values: List[str] = field(default_factory=list)
    
    # Status
    is_complete: bool = False  # Flow completed normally (FIN/FIN or FIN/RST)
    is_failed: bool = False  # Flow failed (RST without data, timeout, etc.)
    failure_reason: Optional[str] = None
    
    def __post_init__(self):
        """Generate flow_id if not provided."""
        if not self.flow_id:
            self.flow_id = self._generate_flow_id()
        
        # Calculate duration and rates if timestamps are set
        if self.start_timestamp_epoch > 0 and self.end_timestamp_epoch > 0:
            self.duration = self.end_timestamp_epoch - self.start_timestamp_epoch
            if self.duration > 0:
                self.packets_per_second = self.packets / self.duration
                self.bytes_per_second = self.bytes_total / self.duration
                self.bits_per_second = (self.bytes_total * 8) / self.duration
    
    def _generate_flow_id(self) -> str:
        """Generate a unique flow identifier."""
        parts = []
        if self.src_ip:
            parts.append(self.src_ip)
        if self.dst_ip:
            parts.append(self.dst_ip)
        if self.src_port:
            parts.append(str(self.src_port))
        if self.dst_port:
            parts.append(str(self.dst_port))
        if self.protocol:
            parts.append(str(self.protocol))
        return "-".join(parts)
    
    @property
    def protocol_name(self) -> str:
        """Get protocol name from number."""
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            47: "GRE",
            50: "ESP",
            51: "AH",
            89: "OSPF",
            132: "SCTP",
        }
        return protocol_map.get(self.protocol, f"IP-{self.protocol}")
    
    @property
    def five_tuple(self) -> tuple:
        """Get the 5-tuple for this flow."""
        return (
            self.src_ip or "",
            self.dst_ip or "",
            self.src_port or 0,
            self.dst_port or 0,
            self.protocol or 0,
        )
    
    @property
    def reverse_five_tuple(self) -> tuple:
        """Get the reversed 5-tuple."""
        return (
            self.dst_ip or "",
            self.src_ip or "",
            self.dst_port or 0,
            self.src_port or 0,
            self.protocol or 0,
        )
    
    def add_packet(self, timestamp_epoch: float, packet_bytes: int, 
                   payload_bytes: int = 0, tcp_flags: Optional[int] = None):
        """Add a packet to this flow."""
        self.packets += 1
        self.bytes_total += packet_bytes
        self.bytes_payload += payload_bytes
        
        # Update timestamps
        if self.start_timestamp_epoch == 0 or timestamp_epoch < self.start_timestamp_epoch:
            self.start_timestamp_epoch = timestamp_epoch
        if timestamp_epoch > self.end_timestamp_epoch:
            self.end_timestamp_epoch = timestamp_epoch
        
        # Update TCP flags
        if tcp_flags is not None:
            self.tcp_flags_seen |= tcp_flags
            if tcp_flags & 0x02:  # SYN
                self.tcp_syn_count += 1
            if tcp_flags & 0x01:  # FIN
                self.tcp_fin_count += 1
            if tcp_flags & 0x04:  # RST
                self.tcp_rst_count += 1
        
        # Recalculate derived metrics
        self.__post_init__()
    
    def mark_retransmission(self):
        """Mark a retransmission in this flow."""
        self.tcp_retransmissions += 1
    
    def mark_duplicate_ack(self):
        """Mark a duplicate ACK in this flow."""
        self.tcp_duplicate_acks += 1
    
    def mark_out_of_order(self):
        """Mark an out-of-order packet in this flow."""
        self.tcp_out_of_order += 1
    
    def mark_zero_window(self):
        """Mark a zero-window condition in this flow."""
        self.tcp_zero_windows += 1
    
    def get_retransmission_rate(self) -> float:
        """Calculate retransmission rate as percentage."""
        if self.packets == 0:
            return 0.0
        return (self.tcp_retransmissions / self.packets) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'flow_id': self.flow_id,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'protocol_name': self.protocol_name,
            'vlan_id': self.vlan_id,
            'dscp': self.dscp,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'packets': self.packets,
            'bytes_total': self.bytes_total,
            'bytes_per_second': self.bytes_per_second,
            'bits_per_second': self.bits_per_second,
            'tcp_flags_seen': self.tcp_flags_seen,
            'tcp_retransmissions': self.tcp_retransmissions,
            'tcp_duplicate_acks': self.tcp_duplicate_acks,
            'retransmission_rate': self.get_retransmission_rate(),
            'service_name': self.service_name,
            'is_complete': self.is_complete,
            'is_failed': self.is_failed,
            'failure_reason': self.failure_reason,
        }
    
    def get_summary(self) -> str:
        """Get a human-readable summary of the flow."""
        src = f"{self.src_ip}:{self.src_port}" if self.src_ip else "unknown"
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_ip else "unknown"
        proto = self.protocol_name
        return f"{src} -> {dst} ({proto}) - {self.packets} pkts, {self.bytes_total} bytes"
