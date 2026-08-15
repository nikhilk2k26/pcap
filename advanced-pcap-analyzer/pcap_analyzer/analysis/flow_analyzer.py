#!/usr/bin/env python3
"""
Flow Analyzer

Creates NetFlow-like flow records from packet data.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from config import Config
from pcap_analyzer.models.flow import FlowRecord


@dataclass
class FlowAnalysisResult:
    """Result of flow analysis."""
    
    flows: List[FlowRecord] = field(default_factory=list)
    total_flows: int = 0
    
    # Top talkers
    top_src_ips: List[tuple] = field(default_factory=list)
    top_dst_ips: List[tuple] = field(default_factory=list)
    top_conversations: List[tuple] = field(default_factory=list)
    
    # Protocol distribution
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    
    # Service distribution
    service_distribution: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_flows': self.total_flows,
            'flows': [f.to_dict() for f in self.flows[:100]],
            'top_src_ips': self.top_src_ips[:10],
            'top_dst_ips': self.top_dst_ips[:10],
            'top_conversations': self.top_conversations[:10],
            'protocol_distribution': self.protocol_distribution,
            'service_distribution': self.service_distribution,
        }


class FlowAnalyzer:
    """
    Analyzes traffic flows and creates flow records.
    """
    
    def __init__(self, store, config: Optional[Config] = None):
        self.store = store
        self.config = config or Config()
    
    def analyze(self) -> FlowAnalysisResult:
        """
        Perform flow analysis.
        
        Returns:
            FlowAnalysisResult with flow records and statistics
        """
        result = FlowAnalysisResult()
        flows: Dict[str, FlowRecord] = {}
        
        src_ip_bytes: Dict[str, int] = defaultdict(int)
        dst_ip_bytes: Dict[str, int] = defaultdict(int)
        conversation_bytes: Dict[str, int] = defaultdict(int)
        protocol_counts: Dict[int, int] = defaultdict(int)
        service_counts: Dict[str, int] = defaultdict(int)
        
        with self.store.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get all packets with flow information
            cursor.execute("""
                SELECT
                    frame_number, timestamp_epoch, frame_length,
                    src_ip, dst_ip, src_port, dst_port,
                    protocol, dscp, vlan_ids, tcp_flags,
                    dns_query_name, http_host, tls_sni
                FROM packets
                WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
                ORDER BY frame_number
            """)
            
            for row in cursor.fetchall():
                (frame_num, timestamp, pkt_len, src_ip, dst_ip,
                 src_port, dst_port, proto, dscp, vlan_ids, flags,
                 dns_name, http_host, tls_sni) = row
                
                # Create flow key (bidirectional)
                if (src_ip, src_port) < (dst_ip, dst_port):
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                else:
                    flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
                
                if flow_key not in flows:
                    flows[flow_key] = FlowRecord(
                        flow_id=flow_key,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port or 0,
                        dst_port=dst_port or 0,
                        protocol=proto,
                        dscp=dscp,
                    )
                
                flow = flows[flow_key]
                flow.add_packet(timestamp, pkt_len, tcp_flags=flags)
                
                # Update metadata
                if dns_name:
                    flow.dns_queries += 1
                if http_host:
                    flow.http_requests += 1
                    if http_host not in flow.http_hosts:
                        flow.http_hosts.append(http_host)
                if tls_sni:
                    flow.tls_sessions += 1
                    if tls_sni not in flow.tls_sni_values:
                        flow.tls_sni_values.append(tls_sni)
                
                # Track bytes for top talkers
                src_ip_bytes[src_ip] += pkt_len
                dst_ip_bytes[dst_ip] += pkt_len
                conv_key = f"{min(src_ip, dst_ip)}-{max(src_ip, dst_ip)}"
                conversation_bytes[conv_key] += pkt_len
                
                protocol_counts[proto] += pkt_len
            
            # Post-process flows
            for flow in flows.values():
                # Determine service name
                if flow.dst_port == 53 or flow.src_port == 53:
                    flow.service_name = "dns"
                    service_counts["dns"] += flow.bytes_total
                elif flow.dst_port == 80 or flow.src_port == 80:
                    flow.service_name = "http"
                    service_counts["http"] += flow.bytes_total
                elif flow.dst_port == 443 or flow.src_port == 443:
                    flow.service_name = "https"
                    service_counts["https"] += flow.bytes_total
                elif flow.dst_port == 22 or flow.src_port == 22:
                    flow.service_name = "ssh"
                    service_counts["ssh"] += flow.bytes_total
                elif flow.dst_port == 21 or flow.src_port == 21:
                    flow.service_name = "ftp"
                    service_counts["ftp"] += flow.bytes_total
                elif flow.dst_port == 25 or flow.src_port == 25:
                    flow.service_name = "smtp"
                    service_counts["smtp"] += flow.bytes_total
                
                # Check for connection state
                if flow.tcp_rst_count > 0 and flow.tcp_syn_count > 0 and flow.packets < 5:
                    flow.is_failed = True
                    flow.failure_reason = "Connection reset early"
                
                if flow.tcp_fin_count >= 2 or (flow.tcp_fin_count >= 1 and flow.duration > 0):
                    flow.is_complete = True
                
                result.flows.append(flow)
            
            # Calculate top lists
            result.total_flows = len(flows)
            result.top_src_ips = sorted(src_ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
            result.top_dst_ips = sorted(dst_ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
            result.top_conversations = sorted(conversation_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Protocol distribution by name
            proto_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
            for proto, bytes_count in protocol_counts.items():
                name = proto_names.get(proto, f"IP-{proto}")
                result.protocol_distribution[name] = bytes_count
            
            result.service_distribution = dict(service_counts)
        
        return result
