#!/usr/bin/env python3
"""
Normalized Packet Model

Represents a normalized packet record with all extracted fields.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class NormalizedPacket:
    """
    Normalized packet record with standardized fields.
    
    All fields are optional to handle missing or unsupported protocol data.
    """
    
    # Frame information
    frame_number: int = 0
    timestamp_epoch: float = 0.0
    timestamp: Optional[datetime] = None
    interface_id: Optional[int] = None
    interface_name: Optional[str] = None
    encapsulation_type: Optional[int] = None
    
    # Frame size
    frame_length: int = 0  # Actual frame length on wire
    captured_length: int = 0  # Captured length (may be less due to snaplen)
    
    # Ethernet/L2
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    eth_type: Optional[int] = None  # EtherType
    
    # VLAN
    vlan_ids: List[int] = field(default_factory=list)
    vlan_priorities: List[int] = field(default_factory=list)
    qinq_tags: List[int] = field(default_factory=list)
    
    # MPLS
    mpls_labels: List[int] = field(default_factory=list)
    
    # IP
    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    ip_flags_df: bool = False
    ip_flags_mf: bool = False
    fragment_offset: int = 0
    dscp: Optional[int] = None
    ecn: Optional[int] = None
    protocol: Optional[int] = None  # IP protocol number
    ip_header_length: Optional[int] = None
    ip_total_length: Optional[int] = None
    ip_identification: Optional[int] = None
    
    # TCP
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[int] = None
    tcp_flags_str: Optional[str] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window_size: Optional[int] = None
    tcp_window_scale: Optional[int] = None
    tcp_mss: Optional[int] = None
    tcp_options: Optional[str] = None
    tcp_header_length: Optional[int] = None
    tcp_urgent_pointer: Optional[int] = None
    
    # TCP analysis flags (from tshark)
    is_retransmission: bool = False
    is_duplicate_ack: bool = False
    is_out_of_order: bool = False
    is_zero_window: bool = False
    is_window_full: bool = False
    is_keepalive: bool = False
    is_spurious_retransmission: bool = False
    retransmission_seq: Optional[int] = None
    
    # UDP
    udp_length: Optional[int] = None
    udp_checksum_status: Optional[str] = None
    
    # ICMP
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    icmp_id: Optional[int] = None
    icmp_seq: Optional[int] = None
    
    # DNS
    dns_query_name: Optional[str] = None
    dns_query_type: Optional[int] = None
    dns_response_type: Optional[int] = None
    dns_rcode: Optional[int] = None
    dns_flags_qr: Optional[bool] = None
    dns_truncated: bool = False
    dns_id: Optional[int] = None
    
    # DHCP
    dhcp_message_type: Optional[int] = None
    dhcp_server_ip: Optional[str] = None
    dhcp_requested_ip: Optional[str] = None
    dhcp_client_ip: Optional[str] = None
    dhcp_your_ip: Optional[str] = None
    dhcp_transaction_id: Optional[int] = None
    dhcp_lease_time: Optional[int] = None
    dhcp_client_mac: Optional[str] = None
    
    # HTTP
    http_host: Optional[str] = None
    http_request_method: Optional[str] = None
    http_request_uri: Optional[str] = None
    http_response_code: Optional[int] = None
    http_content_type: Optional[str] = None
    http_user_agent: Optional[str] = None
    
    # TLS
    tls_handshake_type: Optional[int] = None
    tls_handshake_version: Optional[str] = None
    tls_sni: Optional[str] = None
    tls_cipher: Optional[str] = None
    tls_session_id: Optional[str] = None
    tls_certificate_subject: Optional[str] = None
    tls_alert_message: Optional[str] = None
    
    # RTP (VoIP)
    rtp_sequence: Optional[int] = None
    rtp_timestamp: Optional[int] = None
    rtp_ssrc: Optional[int] = None
    rtp_payload_type: Optional[int] = None
    rtp_jitter: Optional[float] = None
    rtp_marker: bool = False
    
    # Raw tshark data for extensibility
    raw_fields: Dict[str, Any] = field(default_factory=dict)
    
    # Computed/derived fields
    flow_key: Optional[str] = None
    direction: Optional[str] = None  # "forward", "backward", "unknown"
    
    @property
    def is_ipv4(self) -> bool:
        """Check if this is an IPv4 packet."""
        return self.ip_version == 4
    
    @property
    def is_ipv6(self) -> bool:
        """Check if this is an IPv6 packet."""
        return self.ip_version == 6
    
    @property
    def is_tcp(self) -> bool:
        """Check if this is a TCP packet."""
        return self.protocol == 6
    
    @property
    def is_udp(self) -> bool:
        """Check if this is a UDP packet."""
        return self.protocol == 17
    
    @property
    def is_icmp(self) -> bool:
        """Check if this is an ICMP packet."""
        return self.protocol == 1
    
    @property
    def is_dns(self) -> bool:
        """Check if this is a DNS packet."""
        return self.dst_port == 53 or self.src_port == 53
    
    @property
    def is_http(self) -> bool:
        """Check if this is an HTTP packet."""
        return self.dst_port in (80, 8080) or self.src_port in (80, 8080)
    
    @property
    def is_https(self) -> bool:
        """Check if this is an HTTPS packet."""
        return self.dst_port == 443 or self.src_port == 443
    
    @property
    def is_dhcp(self) -> bool:
        """Check if this is a DHCP packet."""
        return self.src_port == 67 or self.dst_port == 67 or self.src_port == 68 or self.dst_port == 68
    
    @property
    def is_arp(self) -> bool:
        """Check if this is an ARP packet."""
        return self.eth_type == 0x0806
    
    @property
    def has_vlan(self) -> bool:
        """Check if this packet has VLAN tags."""
        return len(self.vlan_ids) > 0
    
    @property
    def is_fragmented(self) -> bool:
        """Check if this is a fragmented IP packet."""
        return self.fragment_offset > 0 or self.ip_flags_mf
    
    @property
    def tcp_flag_syn(self) -> bool:
        """Check if SYN flag is set."""
        if self.tcp_flags is None:
            return False
        return bool(self.tcp_flags & 0x02)
    
    @property
    def tcp_flag_ack(self) -> bool:
        """Check if ACK flag is set."""
        if self.tcp_flags is None:
            return False
        return bool(self.tcp_flags & 0x10)
    
    @property
    def tcp_flag_fin(self) -> bool:
        """Check if FIN flag is set."""
        if self.tcp_flags is None:
            return False
        return bool(self.tcp_flags & 0x01)
    
    @property
    def tcp_flag_rst(self) -> bool:
        """Check if RST flag is set."""
        if self.tcp_flags is None:
            return False
        return bool(self.tcp_flags & 0x04)
    
    @property
    def tcp_flag_psh(self) -> bool:
        """Check if PSH flag is set."""
        if self.tcp_flags is None:
            return False
        return bool(self.tcp_flags & 0x08)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'frame_number': self.frame_number,
            'timestamp_epoch': self.timestamp_epoch,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'interface_id': self.interface_id,
            'interface_name': self.interface_name,
            'frame_length': self.frame_length,
            'captured_length': self.captured_length,
            'src_mac': self.src_mac,
            'dst_mac': self.dst_mac,
            'eth_type': self.eth_type,
            'vlan_ids': self.vlan_ids,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'ip_version': self.ip_version,
            'ttl': self.ttl,
            'dscp': self.dscp,
            'protocol': self.protocol,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'tcp_flags': self.tcp_flags,
            'tcp_flags_str': self.tcp_flags_str,
            'tcp_seq': self.tcp_seq,
            'tcp_ack': self.tcp_ack,
            'tcp_window_size': self.tcp_window_size,
            'is_retransmission': self.is_retransmission,
            'is_duplicate_ack': self.is_duplicate_ack,
            'icmp_type': self.icmp_type,
            'dns_query_name': self.dns_query_name,
            'dhcp_message_type': self.dhcp_message_type,
            'http_host': self.http_host,
            'tls_sni': self.tls_sni,
            'flow_key': self.flow_key,
        }
    
    @classmethod
    def from_tshark_fields(cls, fields: Dict[str, Any]) -> "NormalizedPacket":
        """
        Create a NormalizedPacket from tshark field extraction.
        
        Args:
            fields: Dictionary of tshark -T fields output
            
        Returns:
            NormalizedPacket instance
        """
        packet = cls()
        
        # Map tshark fields to normalized packet fields
        field_map = {
            'frame.number': ('frame_number', int),
            'frame.time_epoch': ('timestamp_epoch', float),
            'frame.len': ('frame_length', int),
            'frame.cap_len': ('captured_length', int),
            'frame.interface_id': ('interface_id', int),
            'frame.encap_type': ('encapsulation_type', int),
            'eth.src': ('src_mac', str),
            'eth.dst': ('dst_mac', str),
            'eth.type': ('eth_type', lambda x: int(x, 16) if x else None),
            'vlan.id': ('vlan_ids', lambda x: [int(v) for v in x.split(',') if v]),
            'vlan.priority': ('vlan_priorities', lambda x: [int(v) for v in x.split(',') if v]),
            'ip.version': ('ip_version', int),
            'ip.src': ('src_ip', str),
            'ip.dst': ('dst_ip', str),
            'ip.ttl': ('ttl', int),
            'ip.flags.df': ('ip_flags_df', lambda x: x == '1'),
            'ip.flags.mf': ('ip_flags_mf', lambda x: x == '1'),
            'ip.frag_offset': ('fragment_offset', int),
            'ip.dsfield.dscp': ('dscp', int),
            'ip.dsfield.ecn': ('ecn', int),
            'ip.proto': ('protocol', int),
            'tcp.srcport': ('src_port', int),
            'tcp.dstport': ('dst_port', int),
            'tcp.flags': ('tcp_flags', lambda x: int(x, 16) if x else None),
            'tcp.seq': ('tcp_seq', int),
            'tcp.ack': ('tcp_ack', int),
            'tcp.window_size': ('tcp_window_size', int),
            'tcp.options.mss.val': ('tcp_mss', int),
            'tcp.analysis.retransmission': ('is_retransmission', lambda x: x == '1'),
            'tcp.analysis.duplicate_ack': ('is_duplicate_ack', lambda x: x == '1'),
            'tcp.analysis.out_of_order': ('is_out_of_order', lambda x: x == '1'),
            'tcp.analysis.zero_window': ('is_zero_window', lambda x: x == '1'),
            'tcp.analysis.window_full': ('is_window_full', lambda x: x == '1'),
            'icmp.type': ('icmp_type', int),
            'icmp.code': ('icmp_code', int),
            'dns.qry.name': ('dns_query_name', str),
            'dns.flags.rcode': ('dns_rcode', int),
            'dhcp.type': ('dhcp_message_type', int),
            'dhcp.server_ip': ('dhcp_server_ip', str),
            'http.host': ('http_host', str),
            'http.request.method': ('http_request_method', str),
            'http.response.code': ('http_response_code', int),
            'tls.handshake.extensions_server_name': ('tls_sni', str),
        }
        
        for tshark_field, (attr, converter) in field_map.items():
            if tshark_field in fields and fields[tshark_field]:
                value = fields[tshark_field]
                try:
                    if attr in ('vlan_ids', 'vlan_priorities'):
                        converted = converter(value)
                        setattr(packet, attr, converted)
                    else:
                        converted = converter(value) if value else None
                        setattr(packet, attr, converted)
                except (ValueError, TypeError):
                    pass
        
        # Store raw fields for extensibility
        packet.raw_fields = fields
        
        return packet
