#!/usr/bin/env python3
"""
Summary Analyzer

Provides high-level capture summary statistics.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from config import Config


@dataclass
class CaptureSummary:
    """Summary statistics for a capture file."""
    
    # File info
    file_path: str = ""
    file_size_bytes: int = 0
    file_type: str = "unknown"
    
    # Packet counts
    total_packets: int = 0
    captured_packets: int = 0
    
    # Time range
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    start_timestamp: float = 0.0
    end_timestamp: float = 0.0
    
    # Protocol distribution
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    ethertype_counts: Dict[int, int] = field(default_factory=dict)
    
    # IP version distribution
    ipv4_packets: int = 0
    ipv6_packets: int = 0
    
    # Top IPs
    top_src_ips: List[tuple] = field(default_factory=list)  # (ip, count)
    top_dst_ips: List[tuple] = field(default_factory=list)
    
    # Top ports
    top_src_ports: List[tuple] = field(default_factory=list)
    top_dst_ports: List[tuple] = field(default_factory=list)
    
    # Traffic volume
    total_bytes: int = 0
    avg_packet_size: float = 0.0
    bytes_per_second: float = 0.0
    
    # TCP flags summary
    tcp_syn_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0
    tcp_ack_count: int = 0
    
    # Special traffic
    broadcast_packets: int = 0
    multicast_packets: int = 0
    fragmented_packets: int = 0
    retransmission_count: int = 0
    duplicate_ack_count: int = 0
    out_of_order_count: int = 0
    zero_window_count: int = 0
    
    # VLANs
    vlan_ids_seen: List[int] = field(default_factory=list)
    
    # Interfaces
    interface_ids: List[int] = field(default_factory=list)
    interface_names: Dict[int, str] = field(default_factory=dict)
    
    # DNS
    dns_query_count: int = 0
    dns_response_count: int = 0
    
    # HTTP
    http_request_count: int = 0
    http_response_count: int = 0
    
    # TLS
    tls_session_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'file_path': self.file_path,
            'file_size_bytes': self.file_size_bytes,
            'file_type': self.file_type,
            'total_packets': self.total_packets,
            'captured_packets': self.captured_packets,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration_seconds,
            'protocol_counts': self.protocol_counts,
            'ipv4_packets': self.ipv4_packets,
            'ipv6_packets': self.ipv6_packets,
            'top_src_ips': self.top_src_ips[:10],
            'top_dst_ips': self.top_dst_ips[:10],
            'total_bytes': self.total_bytes,
            'avg_packet_size': self.avg_packet_size,
            'bytes_per_second': self.bytes_per_second,
            'tcp_syn_count': self.tcp_syn_count,
            'tcp_fin_count': self.tcp_fin_count,
            'tcp_rst_count': self.tcp_rst_count,
            'broadcast_packets': self.broadcast_packets,
            'multicast_packets': self.multicast_packets,
            'fragmented_packets': self.fragmented_packets,
            'retransmission_count': self.retransmission_count,
            'vlan_ids_seen': self.vlan_ids_seen,
            'dns_query_count': self.dns_query_count,
            'http_request_count': self.http_request_count,
            'tls_session_count': self.tls_session_count,
        }


class SummaryAnalyzer:
    """
    Analyzes capture files to produce summary statistics.
    """
    
    def __init__(self, store, config: Optional[Config] = None):
        self.store = store
        self.config = config or Config()
    
    def analyze(self) -> CaptureSummary:
        """
        Perform summary analysis on the stored packets.
        
        Returns:
            CaptureSummary object with statistics
        """
        summary = CaptureSummary()
        
        with self.store.get_connection() as conn:
            cursor = conn.cursor()
            
            # Basic counts
            cursor.execute("SELECT COUNT(*) FROM packets")
            summary.total_packets = cursor.fetchone()[0]
            
            # Time range
            cursor.execute("""
                SELECT MIN(timestamp_epoch), MAX(timestamp_epoch), 
                       SUM(frame_length)
                FROM packets
            """)
            row = cursor.fetchone()
            if row[0] and row[1]:
                summary.start_timestamp = row[0]
                summary.end_timestamp = row[1]
                summary.start_time = datetime.fromtimestamp(row[0])
                summary.end_time = datetime.fromtimestamp(row[1])
                summary.duration_seconds = row[1] - row[0]
                summary.total_bytes = row[2] or 0
                
                if summary.duration_seconds > 0:
                    summary.bytes_per_second = summary.total_bytes / summary.duration_seconds
                if summary.total_packets > 0:
                    summary.avg_packet_size = summary.total_bytes / summary.total_packets
            
            # Protocol distribution
            cursor.execute("""
                SELECT protocol, COUNT(*) as cnt
                FROM packets
                WHERE protocol IS NOT NULL
                GROUP BY protocol
                ORDER BY cnt DESC
            """)
            protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
            for row in cursor.fetchall():
                proto_num = row[0]
                proto_name = protocol_map.get(proto_num, f"IP-{proto_num}")
                summary.protocol_counts[proto_name] = row[1]
            
            # IP version distribution
            cursor.execute("""
                SELECT ip_version, COUNT(*) as cnt
                FROM packets
                WHERE ip_version IS NOT NULL
                GROUP BY ip_version
            """)
            for row in cursor.fetchall():
                if row[0] == 4:
                    summary.ipv4_packets = row[1]
                elif row[0] == 6:
                    summary.ipv6_packets = row[1]
            
            # Top source IPs
            cursor.execute("""
                SELECT src_ip, COUNT(*) as cnt
                FROM packets
                WHERE src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY cnt DESC
                LIMIT 10
            """)
            summary.top_src_ips = [(row[0], row[1]) for row in cursor.fetchall()]
            
            # Top destination IPs
            cursor.execute("""
                SELECT dst_ip, COUNT(*) as cnt
                FROM packets
                WHERE dst_ip IS NOT NULL
                GROUP BY dst_ip
                ORDER BY cnt DESC
                LIMIT 10
            """)
            summary.top_dst_ips = [(row[0], row[1]) for row in cursor.fetchall()]
            
            # Top destination ports
            cursor.execute("""
                SELECT dst_port, COUNT(*) as cnt
                FROM packets
                WHERE dst_port IS NOT NULL
                GROUP BY dst_port
                ORDER BY cnt DESC
                LIMIT 10
            """)
            summary.top_dst_ports = [(row[0], row[1]) for row in cursor.fetchall()]
            
            # TCP flag counts
            cursor.execute("""
                SELECT 
                    SUM(CASE WHEN (tcp_flags & 0x02) != 0 THEN 1 ELSE 0 END) as syn_count,
                    SUM(CASE WHEN (tcp_flags & 0x01) != 0 THEN 1 ELSE 0 END) as fin_count,
                    SUM(CASE WHEN (tcp_flags & 0x04) != 0 THEN 1 ELSE 0 END) as rst_count,
                    SUM(CASE WHEN (tcp_flags & 0x10) != 0 THEN 1 ELSE 0 END) as ack_count
                FROM packets
                WHERE tcp_flags IS NOT NULL
            """)
            row = cursor.fetchone()
            if row:
                summary.tcp_syn_count = row[0] or 0
                summary.tcp_fin_count = row[1] or 0
                summary.tcp_rst_count = row[2] or 0
                summary.tcp_ack_count = row[3] or 0
            
            # Broadcast/multicast
            cursor.execute("""
                SELECT COUNT(*) FROM packets
                WHERE dst_mac LIKE 'ff:ff:%' OR dst_mac LIKE '%:%:%:ff:ff:ff'
            """)
            summary.broadcast_packets = cursor.fetchone()[0] or 0
            
            cursor.execute("""
                SELECT COUNT(*) FROM packets
                WHERE dst_mac LIKE '%:%:%:%' AND dst_mac NOT LIKE 'ff:ff:%'
                AND CAST(SUBSTR(dst_mac, 1, 2) AS INTEGER) % 2 = 1
            """)
            summary.multicast_packets = cursor.fetchone()[0] or 0
            
            # Fragmented packets
            cursor.execute("""
                SELECT COUNT(*) FROM packets
                WHERE fragment_offset > 0 OR ip_flags_mf = 1
            """)
            summary.fragmented_packets = cursor.fetchone()[0] or 0
            
            # Retransmissions and anomalies
            cursor.execute("""
                SELECT 
                    SUM(is_retransmission),
                    SUM(is_duplicate_ack),
                    SUM(is_out_of_order),
                    SUM(is_zero_window)
                FROM packets
            """)
            row = cursor.fetchone()
            if row:
                summary.retransmission_count = row[0] or 0
                summary.duplicate_ack_count = row[1] or 0
                summary.out_of_order_count = row[2] or 0
                summary.zero_window_count = row[3] or 0
            
            # VLAN IDs
            cursor.execute("""
                SELECT DISTINCT vlan_ids FROM packets
                WHERE vlan_ids IS NOT NULL AND vlan_ids != ''
            """)
            seen_vlans = set()
            for row in cursor.fetchall():
                if row[0]:
                    for v in str(row[0]).split(','):
                        try:
                            seen_vlans.add(int(v))
                        except ValueError:
                            pass
            summary.vlan_ids_seen = sorted(list(seen_vlans))
            
            # DNS queries
            cursor.execute("""
                SELECT COUNT(*) FROM packets
                WHERE dns_query_name IS NOT NULL
            """)
            summary.dns_query_count = cursor.fetchone()[0] or 0
            
            # HTTP requests
            cursor.execute("""
                SELECT COUNT(*) FROM packets
                WHERE http_host IS NOT NULL
            """)
            summary.http_request_count = cursor.fetchone()[0] or 0
            
            # TLS sessions
            cursor.execute("""
                SELECT COUNT(*) FROM packets
                WHERE tls_sni IS NOT NULL
            """)
            summary.tls_session_count = cursor.fetchone()[0] or 0
        
        return summary
