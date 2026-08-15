"""
TCP Expert Analyzer Module

Provides deep TCP connection analysis, health classification, and root-cause diagnostics.
"""
import sqlite3
from typing import List, Dict, Any, Optional, Iterator, Tuple
from collections import defaultdict
from pathlib import Path

from ..models.tcp_connection import TCPConnection, TCPHealthStatus, TCPConnectionState, TCPExpertFinding
from ..utils.logging_utils import get_logger


class TCPExpertAnalyzer:
    """
    Advanced TCP connection analyzer that tracks state, calculates metrics,
    and classifies connection health.
    """

    def __init__(self):
        self.logger = get_logger(__name__)
        # flow_id -> TCPConnection
        self.connections: Dict[str, TCPConnection] = {}
        # Track sequence numbers per flow for retransmission detection
        self.flow_state: Dict[str, Dict[str, Any]] = {}
        
    def analyze_stream(self, packets: Iterator[Dict[str, Any]]) -> List[TCPConnection]:
        """
        Analyze a stream of normalized packets.
        
        Args:
            packets: Iterator of normalized packet dictionaries
            
        Returns:
            List of analyzed TCPConnection objects
        """
        for pkt in packets:
            if pkt.get('protocol') != 'TCP':
                continue
                
            self._process_packet(pkt)
            
        # Finalize all connections
        for conn in self.connections.values():
            self._finalize_connection(conn)
            
        return list(self.connections.values())
    
    def analyze_from_db(self, db_path: Path, limit: Optional[int] = None) -> List[TCPConnection]:
        """
        Analyze TCP connections from a SQLite database index.
        
        Args:
            db_path: Path to the SQLite database
            limit: Optional limit on number of packets to process
            
        Returns:
            List of analyzed TCPConnection objects
        """
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        
        query = """
            SELECT * FROM packets 
            WHERE protocol = 'TCP'
            ORDER BY timestamp ASC
        """
        if limit:
            query += f" LIMIT {limit}"
            
        cursor = conn.execute(query)
        
        while True:
            row = cursor.fetchone()
            if row is None:
                break
            pkt = dict(row)
            self._process_packet(pkt)
            
        conn.close()
        
        # Finalize
        for conn_obj in self.connections.values():
            self._finalize_connection(conn_obj)
            
        return list(self.connections.values())

    def _get_flow_id(self, pkt: Dict[str, Any]) -> str:
        """Generate a consistent 5-tuple flow ID."""
        src_ip = pkt.get('src_ip', '')
        dst_ip = pkt.get('dst_ip', '')
        src_port = pkt.get('src_port', 0)
        dst_port = pkt.get('dst_port', 0)
        
        # Normalize so flow is bidirectional
        endpoints = sorted([
            (src_ip, src_port),
            (dst_ip, dst_port)
        ])
        
        return f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}"

    def _get_direction(self, pkt: Dict[str, Any], flow_id: str) -> str:
        """Determine if packet is forward or reverse direction."""
        src_ip = pkt.get('src_ip', '')
        src_port = pkt.get('src_port', 0)
        
        # Parse flow ID to find initiator
        parts = flow_id.split('-')
        init_endpoint = parts[0]  # Sorted first is considered initiator
        
        if f"{src_ip}:{src_port}" == init_endpoint:
            return 'forward'
        return 'reverse'

    def _process_packet(self, pkt: Dict[str, Any]) -> None:
        """Process a single TCP packet."""
        flow_id = self._get_flow_id(pkt)
        direction = self._get_direction(pkt, flow_id)
        frame_num = pkt.get('frame_number', 0)
        timestamp = float(pkt.get('timestamp', 0))
        tcp_flags = pkt.get('tcp_flags', {})
        seq = pkt.get('tcp_seq', 0)
        ack = pkt.get('tcp_ack', 0)
        window = pkt.get('tcp_window', 0)
        length = pkt.get('frame_len', 0)
        
        # Initialize connection if new
        if flow_id not in self.connections:
            self.connections[flow_id] = TCPConnection(
                flow_id=flow_id,
                src_ip=pkt.get('src_ip', ''),
                src_port=pkt.get('src_port', 0),
                dst_ip=pkt.get('dst_ip', ''),
                dst_port=pkt.get('dst_port', 0),
                start_time=timestamp
            )
            self.flow_state[flow_id] = {
                'last_seq_fwd': -1,
                'last_seq_rev': -1,
                'last_ack_fwd': -1,
                'last_ack_rev': -1,
                'syn_time': None,
                'syn_ack_time': None,
                'seen_seqs_fwd': set(),
                'seen_seqs_rev': set()
            }
            
        conn = self.connections[flow_id]
        state = self.flow_state[flow_id]
        
        # Update timing
        conn.end_time = timestamp
        conn.duration = conn.end_time - conn.start_time
        
        # Update volume
        conn.total_packets += 1
        conn.total_bytes += length
        if direction == 'forward':
            conn.packets_sent += 1
            conn.bytes_sent += length
        else:
            conn.packets_received += 1
            conn.bytes_received += length
            
        # Track evidence frames
        if len(conn.evidence_frames) < 100:  # Limit stored frames
            conn.evidence_frames.append(frame_num)
            
        # Process TCP Flags
        is_syn = tcp_flags.get('syn', False)
        is_ack = tcp_flags.get('ack', False)
        is_fin = tcp_flags.get('fin', False)
        is_rst = tcp_flags.get('rst', False)
        
        # Handshake Tracking
        if is_syn and not is_ack:
            conn.syn_count += 1
            if state['syn_time'] is None:
                state['syn_time'] = timestamp
                # Extract MSS/Window Scale from SYN
                conn.mss_client = pkt.get('tcp_mss', None)
                conn.window_scale_client = pkt.get('tcp_window_scale', None)
                conn.sack_permitted = pkt.get('tcp_sack_permitted', False)
                conn.ecn_negotiated = pkt.get('tcp_ecn', False)
                
        elif is_syn and is_ack:
            conn.syn_ack_count += 1
            if state['syn_ack_time'] is None:
                state['syn_ack_time'] = timestamp
                # Extract server options
                conn.mss_server = pkt.get('tcp_mss', None)
                conn.window_scale_server = pkt.get('tcp_window_scale', None)
                
            # Calculate Initial RTT
            if state['syn_time'] is not None:
                rtt = timestamp - state['syn_time']
                conn.initial_rtt = rtt
                conn.rtt_samples.append(rtt)
                
        elif is_ack and not is_syn and not is_fin and not is_rst:
            conn.ack_count += 1
            
            # Check for Zero Window
            if window == 0:
                conn.zero_windows += 1
                
        if is_fin:
            conn.fin_count += 1
            
        if is_rst:
            conn.rst_count += 1
            
        # Retransmission & OOO Detection
        self._detect_retransmissions(conn, state, pkt, direction, seq, ack, frame_num)
        
        # Update RTT estimates from ACKs (simple heuristic)
        if is_ack and direction == 'reverse' and state['last_seq_fwd'] > 0:
            # Simplified RTT estimation
            pass

    def _detect_retransmissions(
        self, 
        conn: TCPConnection, 
        state: Dict[str, Any], 
        pkt: Dict[str, Any], 
        direction: str,
        seq: int,
        ack: int,
        frame_num: int
    ) -> None:
        """Detect retransmissions, duplicate ACKs, and out-of-order packets."""
        
        if direction == 'forward':
            seen_seqs = state['seen_seqs_fwd']
            if seq in seen_seqs and seq != 0:
                # Likely retransmission
                conn.retransmissions += 1
                if len(conn.findings) < 10:
                    conn.findings.append(TCPExpertFinding(
                        category="retransmission",
                        severity="warning",
                        message=f"Retransmission detected at frame {frame_num}",
                        evidence_frames=[frame_num],
                        metrics={'seq': seq}
                    ))
            else:
                seen_seqs.add(seq)
                
            # Check for Duplicate ACKs (in reverse direction usually, but track here too)
            if state['last_ack_fwd'] == ack and ack != 0:
                conn.duplicate_acks += 1
                
            state['last_seq_fwd'] = seq
            state['last_ack_fwd'] = ack
            
        else:
            seen_seqs = state['seen_seqs_rev']
            if seq in seen_seqs and seq != 0:
                conn.retransmissions += 1
            else:
                seen_seqs.add(seq)
                
            if state['last_ack_rev'] == ack and ack != 0:
                conn.duplicate_acks += 1
                
            state['last_seq_rev'] = seq
            state['last_ack_rev'] = ack

    def _finalize_connection(self, conn: TCPConnection) -> None:
        """Finalize connection analysis and generate diagnosis."""
        
        # Calculate Duration
        conn.duration = conn.end_time - conn.start_time
        
        # Calculate Throughput
        if conn.duration > 0:
            conn.throughput_bps = (conn.total_bytes * 8) / conn.duration
            # Goodput excludes retransmissions (rough estimate)
            good_bytes = max(0, conn.total_bytes - (conn.retransmissions * 1460))
            conn.goodput_bps = (good_bytes * 8) / conn.duration
            
        # Calculate RTT Stats
        if conn.rtt_samples:
            conn.avg_rtt = sum(conn.rtt_samples) / len(conn.rtt_samples)
            conn.min_rtt = min(conn.rtt_samples)
            conn.max_rtt = max(conn.rtt_samples)
            
        # Determine Connection Result
        if conn.syn_count > 0 and conn.syn_ack_count > 0 and conn.ack_count > 0:
            if conn.fin_count >= 2 or (conn.fin_count > 0 and conn.rst_count == 0):
                conn.connection_result = "successful"
                conn.connection_state = TCPConnectionState.CLOSED
            elif conn.rst_count > 0:
                conn.connection_result = "reset"
                conn.connection_state = TCPConnectionState.CLOSED
            else:
                conn.connection_result = "successful"  # Still open or time-wait
                conn.connection_state = TCPConnectionState.ESTABLISHED
        elif conn.syn_count > 0 and conn.syn_ack_count == 0:
            conn.connection_result = "refused"
            conn.connection_state = TCPConnectionState.SYN_SENT
        elif conn.rst_count > 0:
            conn.connection_result = "reset"
            conn.connection_state = TCPConnectionState.CLOSED
        else:
            conn.connection_result = "incomplete"
            conn.connection_state = TCPConnectionState.UNKNOWN
            
        # Generate Expert Diagnosis
        conn.generate_diagnosis()

    def get_unhealthy_connections(self) -> List[TCPConnection]:
        """Return only connections with health issues."""
        return [
            c for c in self.connections.values()
            if c.health_status != TCPHealthStatus.HEALTHY
        ]
        
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for all analyzed connections."""
        total = len(self.connections)
        healthy = sum(1 for c in self.connections.values() if c.health_status == TCPHealthStatus.HEALTHY)
        
        status_counts = defaultdict(int)
        for c in self.connections.values():
            status_counts[c.health_status.value] += 1
            
        return {
            "total_connections": total,
            "healthy_connections": healthy,
            "unhealthy_connections": total - healthy,
            "health_rate_pct": round((healthy / total * 100) if total > 0 else 0, 2),
            "status_breakdown": dict(status_counts),
            "total_retransmissions": sum(c.retransmissions for c in self.connections.values()),
            "total_zero_windows": sum(c.zero_windows for c in self.connections.values())
        }
