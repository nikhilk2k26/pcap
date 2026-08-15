#!/usr/bin/env python3
"""
TCP Analyzer

Performs deep TCP connection analysis including:
- Connection tracking
- Retransmission detection
- RTT estimation
- Window analysis
- Connection state determination
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum

from config import Config


class TCPState(Enum):
    """TCP connection states."""
    SYN_SENT = "syn_sent"
    SYN_RECEIVED = "syn_received"
    ESTABLISHED = "established"
    FIN_WAIT_1 = "fin_wait_1"
    FIN_WAIT_2 = "fin_wait_2"
    CLOSE_WAIT = "close_wait"
    CLOSING = "closing"
    LAST_ACK = "last_ack"
    TIME_WAIT = "time_wait"
    CLOSED = "closed"
    RESET = "reset"
    UNKNOWN = "unknown"


class TCPConnectionResult(Enum):
    """TCP connection result."""
    SUCCESSFUL = "successful"
    REFUSED = "refused"
    RESET = "reset"
    TIMEOUT = "timeout"
    INCOMPLETE_HANDSHAKE = "incomplete_handshake"
    UNKNOWN = "unknown"


@dataclass
class TCPConnection:
    """Represents a TCP connection with all metrics."""
    
    # Flow identification
    flow_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    
    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    start_timestamp: float = 0.0
    end_timestamp: float = 0.0
    duration: float = 0.0
    
    # Packet counts
    packets_client_to_server: int = 0
    packets_server_to_client: int = 0
    bytes_client_to_server: int = 0
    bytes_server_to_client: int = 0
    
    # TCP flag counts
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    
    # Problem indicators
    retransmissions: int = 0
    fast_retransmissions: int = 0
    duplicate_acks: int = 0
    out_of_order_packets: int = 0
    zero_window_events: int = 0
    window_full_events: int = 0
    
    # RTT measurements (in milliseconds)
    initial_rtt_ms: Optional[float] = None
    rtt_samples: List[float] = field(default_factory=list)
    avg_rtt_ms: float = 0.0
    min_rtt_ms: float = 0.0
    max_rtt_ms: float = 0.0
    
    # TCP options
    client_mss: Optional[int] = None
    server_mss: Optional[int] = None
    client_window_scale: Optional[int] = None
    server_window_scale: Optional[int] = None
    sack_permitted: bool = False
    ecn_negotiated: bool = False
    
    # State tracking
    state: TCPState = TCPState.UNKNOWN
    result: TCPConnectionResult = TCPConnectionResult.UNKNOWN
    failure_reason: Optional[str] = None
    
    # Evidence frames
    syn_frame: Optional[int] = None
    syn_ack_frame: Optional[int] = None
    ack_frame: Optional[int] = None
    first_data_frame: Optional[int] = None
    fin_frames: List[int] = field(default_factory=list)
    rst_frames: List[int] = field(default_factory=list)
    retransmit_frames: List[int] = field(default_factory=list)
    
    @property
    def total_packets(self) -> int:
        return self.packets_client_to_server + self.packets_server_to_client
    
    @property
    def total_bytes(self) -> int:
        return self.bytes_client_to_server + self.bytes_server_to_client
    
    @property
    def retransmission_rate(self) -> float:
        if self.total_packets == 0:
            return 0.0
        return (self.retransmissions / self.total_packets) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'flow_id': self.flow_id,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'packets_client_to_server': self.packets_client_to_server,
            'packets_server_to_client': self.packets_server_to_client,
            'bytes_client_to_server': self.bytes_client_to_server,
            'bytes_server_to_client': self.bytes_server_to_client,
            'syn_count': self.syn_count,
            'syn_ack_count': self.syn_ack_count,
            'ack_count': self.ack_count,
            'fin_count': self.fin_count,
            'rst_count': self.rst_count,
            'retransmissions': self.retransmissions,
            'duplicate_acks': self.duplicate_acks,
            'out_of_order_packets': self.out_of_order_packets,
            'zero_window_events': self.zero_window_events,
            'initial_rtt_ms': self.initial_rtt_ms,
            'avg_rtt_ms': self.avg_rtt_ms,
            'min_rtt_ms': self.min_rtt_ms,
            'max_rtt_ms': self.max_rtt_ms,
            'client_mss': self.client_mss,
            'server_mss': self.server_mss,
            'state': self.state.value,
            'result': self.result.value,
            'failure_reason': self.failure_reason,
            'retransmission_rate': self.retransmission_rate,
            'retransmit_frames': self.retransmit_frames[:10],  # Limit evidence
        }


@dataclass
class TCPAnalysisResult:
    """Result of TCP analysis."""
    
    connections: List[TCPConnection] = field(default_factory=list)
    failed_connections: List[TCPConnection] = field(default_factory=list)
    high_retransmission_connections: List[TCPConnection] = field(default_factory=list)
    
    # Aggregate statistics
    total_connections: int = 0
    successful_connections: int = 0
    failed_connection_count: int = 0
    reset_connections: int = 0
    
    total_retransmissions: int = 0
    total_duplicate_acks: int = 0
    total_zero_windows: int = 0
    
    avg_rtt_ms: float = 0.0
    overall_retransmission_rate: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_connections': self.total_connections,
            'successful_connections': self.successful_connections,
            'failed_connections': self.failed_connection_count,
            'reset_connections': self.reset_connections,
            'total_retransmissions': self.total_retransmissions,
            'total_duplicate_acks': self.total_duplicate_acks,
            'total_zero_windows': self.total_zero_windows,
            'avg_rtt_ms': self.avg_rtt_ms,
            'overall_retransmission_rate': self.overall_retransmission_rate,
            'connections': [c.to_dict() for c in self.connections[:100]],  # Limit
        }


class TCPAnalyzer:
    """
    Analyzes TCP traffic for connection health and performance.
    """
    
    def __init__(self, store, config: Optional[Config] = None):
        self.store = store
        self.config = config or Config()
    
    def analyze(self) -> TCPAnalysisResult:
        """
        Perform TCP connection analysis.
        
        Returns:
            TCPAnalysisResult with connection details and statistics
        """
        result = TCPAnalysisResult()
        connections: Dict[str, TCPConnection] = {}
        
        with self.store.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get all TCP packets ordered by frame number
            cursor.execute("""
                SELECT 
                    frame_number, timestamp_epoch, frame_length,
                    src_ip, dst_ip, src_port, dst_port,
                    tcp_flags, tcp_seq, tcp_ack, tcp_window_size, tcp_mss,
                    is_retransmission, is_duplicate_ack, is_out_of_order,
                    is_zero_window, flow_key
                FROM packets
                WHERE protocol = 6 AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
                ORDER BY frame_number
            """)
            
            for row in cursor.fetchall():
                (frame_num, timestamp, pkt_len, src_ip, dst_ip, 
                 src_port, dst_port, flags, seq, ack, win_size, mss,
                 is_retrans, is_dupack, is_ooo, is_zerowin, flow_key) = row
                
                # Normalize flow key (smaller IP first for bidirectional)
                if not flow_key:
                    if (src_ip, src_port) < (dst_ip, dst_port):
                        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-6"
                    else:
                        flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-6"
                
                if flow_key not in connections:
                    connections[flow_key] = TCPConnection(
                        flow_id=flow_key,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                    )
                
                conn_obj = connections[flow_key]
                
                # Determine direction
                is_forward = (src_ip == conn_obj.src_ip and src_port == conn_obj.src_port)
                
                # Update packet counts
                if is_forward:
                    conn_obj.packets_client_to_server += 1
                    conn_obj.bytes_client_to_server += pkt_len
                else:
                    conn_obj.packets_server_to_client += 1
                    conn_obj.bytes_server_to_client += pkt_len
                
                # Track timestamps
                if conn_obj.start_timestamp == 0 or timestamp < conn_obj.start_timestamp:
                    conn_obj.start_timestamp = timestamp
                    conn_obj.start_time = datetime.fromtimestamp(timestamp)
                if timestamp > conn_obj.end_timestamp:
                    conn_obj.end_timestamp = timestamp
                    conn_obj.end_time = datetime.fromtimestamp(timestamp)
                
                # Process TCP flags
                if flags:
                    flags_int = int(flags) if isinstance(flags, str) else flags
                    
                    if flags_int & 0x02:  # SYN
                        conn_obj.syn_count += 1
                        if conn_obj.syn_frame is None:
                            conn_obj.syn_frame = frame_num
                            conn_obj.state = TCPState.SYN_SENT
                    
                    if flags_int & 0x10:  # ACK
                        conn_obj.ack_count += 1
                        
                        # Check for SYN-ACK
                        if flags_int & 0x02:
                            conn_obj.syn_ack_count += 1
                            conn_obj.syn_ack_frame = frame_num
                            conn_obj.state = TCPState.SYN_RECEIVED
                            
                            # Calculate initial RTT
                            if conn_obj.syn_frame and conn_obj.initial_rtt_ms is None:
                                # Would need SYN timestamp for accurate RTT
                                pass
                    
                    if flags_int & 0x01:  # FIN
                        conn_obj.fin_count += 1
                        conn_obj.fin_frames.append(frame_num)
                    
                    if flags_int & 0x04:  # RST
                        conn_obj.rst_count += 1
                        conn_obj.rst_frames.append(frame_num)
                        conn_obj.state = TCPState.RESET
                        conn_obj.result = TCPConnectionResult.RESET
                    
                    if flags_int & 0x08:  # PSH
                        conn_obj.psh_count += 1
                
                # Track problems
                if is_retrans:
                    conn_obj.retransmissions += 1
                    conn_obj.retransmit_frames.append(frame_num)
                
                if is_dupack:
                    conn_obj.duplicate_acks += 1
                
                if is_ooo:
                    conn_obj.out_of_order_packets += 1
                
                if is_zerowin:
                    conn_obj.zero_window_events += 1
                
                # Track MSS
                if mss:
                    if conn_obj.client_mss is None:
                        conn_obj.client_mss = int(mss) if isinstance(mss, str) else mss
            
            # Post-process connections
            for conn_obj in connections.values():
                # Calculate duration
                conn_obj.duration = conn_obj.end_timestamp - conn_obj.start_timestamp
                
                # Calculate RTT stats
                if conn_obj.rtt_samples:
                    conn_obj.avg_rtt_ms = sum(conn_obj.rtt_samples) / len(conn_obj.rtt_samples)
                    conn_obj.min_rtt_ms = min(conn_obj.rtt_samples)
                    conn_obj.max_rtt_ms = max(conn_obj.rtt_samples)
                
                # Determine connection result
                if conn_obj.result == TCPConnectionResult.UNKNOWN:
                    if conn_obj.syn_count > 0 and conn_obj.syn_ack_count == 0:
                        conn_obj.result = TCPConnectionResult.INCOMPLETE_HANDSHAKE
                        conn_obj.failure_reason = "SYN sent but no SYN-ACK received"
                    elif conn_obj.rst_count > 0 and conn_obj.syn_count > 0 and conn_obj.ack_count <= 1:
                        conn_obj.result = TCPConnectionResult.REFUSED
                        conn_obj.failure_reason = "Connection refused (RST after SYN)"
                    elif conn_obj.fin_count >= 2 or (conn_obj.fin_count >= 1 and conn_obj.ack_count > 1):
                        conn_obj.result = TCPConnectionResult.SUCCESSFUL
                        conn_obj.state = TCPState.CLOSED
                    elif conn_obj.syn_count > 0 and conn_obj.syn_ack_count > 0 and conn_obj.ack_count > 1:
                        conn_obj.result = TCPConnectionResult.SUCCESSFUL
                        conn_obj.state = TCPState.ESTABLISHED
                
                # Add to appropriate lists
                result.connections.append(conn_obj)
                
                if conn_obj.result != TCPConnectionResult.SUCCESSFUL:
                    result.failed_connections.append(conn_obj)
                
                if conn_obj.retransmission_rate > self.config.analysis.high_retransmission_threshold:
                    result.high_retransmission_connections.append(conn_obj)
            
            # Calculate aggregate statistics
            result.total_connections = len(connections)
            result.successful_connections = sum(
                1 for c in connections.values() 
                if c.result == TCPConnectionResult.SUCCESSFUL
            )
            result.failed_connection_count = len(result.failed_connections)
            result.reset_connections = sum(
                1 for c in connections.values() if c.rst_count > 0
            )
            
            all_retrans = sum(c.retransmissions for c in connections.values())
            all_dups = sum(c.duplicate_acks for c in connections.values())
            all_zeros = sum(c.zero_window_events for c in connections.values())
            
            result.total_retransmissions = all_retrans
            result.total_duplicate_acks = all_dups
            result.total_zero_windows = all_zeros
            
            all_rtts = [c.avg_rtt_ms for c in connections.values() if c.avg_rtt_ms > 0]
            if all_rtts:
                result.avg_rtt_ms = sum(all_rtts) / len(all_rtts)
            
            total_pkts = sum(c.total_packets for c in connections.values())
            if total_pkts > 0:
                result.overall_retransmission_rate = (all_retrans / total_pkts) * 100
        
        return result
