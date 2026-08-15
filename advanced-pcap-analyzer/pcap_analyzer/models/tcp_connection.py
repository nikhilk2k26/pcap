"""
TCP Connection Model
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from datetime import datetime


class TCPConnectionState(Enum):
    """Final state of the TCP connection."""
    ESTABLISHED = "established"
    FIN_WAIT_1 = "fin-wait-1"
    FIN_WAIT_2 = "fin-wait-2"
    TIME_WAIT = "time-wait"
    CLOSE_WAIT = "close-wait"
    CLOSING = "closing"
    LAST_ACK = "last-ack"
    CLOSED = "closed"
    SYN_SENT = "syn-sent"
    SYN_RECEIVED = "syn-received"
    UNKNOWN = "unknown"


class TCPHealthStatus(Enum):
    """Expert classification of connection health."""
    HEALTHY = "healthy"
    SLOW_HANDSHAKE = "slow_handshake"
    RETRANSMISSION_HEAVY = "retransmission_heavy"
    LOSSY = "lossy"
    RECEIVER_LIMITED = "receiver_limited"
    RESET_BY_ENDPOINT = "reset_by_endpoint"
    RESET_BY_MIDDLEBOX = "reset_by_middlebox"
    INCOMPLETE_HANDSHAKE = "incomplete_handshake"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


@dataclass
class TCPExpertFinding:
    """Represents a specific finding about a TCP connection."""
    category: str
    severity: str  # info, warning, error, critical
    message: str
    evidence_frames: List[int] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TCPConnection:
    """
    Represents a fully analyzed TCP connection with expert diagnostics.
    """
    # Identity
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    
    # Timing
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0
    
    # Volume
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    
    # Handshake & State
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    connection_state: TCPConnectionState = TCPConnectionState.UNKNOWN
    connection_result: str = "unknown"  # successful, refused, reset, timeout, incomplete
    
    # Health Metrics
    retransmissions: int = 0
    fast_retransmissions: int = 0
    duplicate_acks: int = 0
    out_of_order: int = 0
    zero_windows: int = 0
    window_full: int = 0
    keepalives: int = 0
    
    # RTT Metrics (seconds)
    initial_rtt: Optional[float] = None
    avg_rtt: Optional[float] = None
    min_rtt: Optional[float] = None
    max_rtt: Optional[float] = None
    rtt_samples: List[float] = field(default_factory=list)
    
    # TCP Options
    mss_client: Optional[int] = None
    mss_server: Optional[int] = None
    window_scale_client: Optional[int] = None
    window_scale_server: Optional[int] = None
    sack_permitted: bool = False
    ecn_negotiated: bool = False
    
    # Expert Analysis
    health_status: TCPHealthStatus = TCPHealthStatus.UNKNOWN
    likely_problem: Optional[str] = None
    recommended_action: Optional[str] = None
    findings: List[TCPExpertFinding] = field(default_factory=list)
    evidence_frames: List[int] = field(default_factory=list)
    
    # Throughput
    throughput_bps: float = 0.0
    goodput_bps: float = 0.0
    retransmission_rate: float = 0.0

    def classify_health(self) -> TCPHealthStatus:
        """
        Classify the health of the connection based on metrics.
        Returns the primary health status.
        """
        reasons = []
        
        # 1. Check for Resets (Highest Priority)
        if self.rst_count > 0:
            if self.syn_count > 0 and self.syn_ack_count == 0:
                # RST after SYN, no SYN-ACK -> Likely Middlebox or Refused
                if self.duration < 0.1:
                    return TCPHealthStatus.RESET_BY_MIDDLEBOX
                else:
                    return TCPHealthStatus.RESET_BY_ENDPOINT
            elif self.total_packets > 10:
                # RST in established flow
                return TCPHealthStatus.RESET_BY_ENDPOINT

        # 2. Check for Incomplete Handshake
        if self.syn_count > 0 and self.syn_ack_count == 0:
            return TCPHealthStatus.INCOMPLETE_HANDSHAKE
        
        if self.syn_count > 0 and self.syn_ack_count > 0 and self.ack_count == 0:
            # SYN-SYN/ACK but no final ACK (Half-open)
            return TCPHealthStatus.INCOMPLETE_HANDSHAKE

        # 3. Check for Timeout / No Data
        if self.syn_count > 0 and self.total_packets < 4 and self.duration > 30.0:
            return TCPHealthStatus.TIMEOUT

        # 4. Check for Receiver Limitation (Zero Windows)
        if self.zero_windows > 5 or (self.zero_windows > 0 and self.total_packets > 100):
            return TCPHealthStatus.RECEIVER_LIMITED

        # 5. Check for Heavy Retransmissions
        if self.total_packets > 0:
            self.retransmission_rate = self.retransmissions / self.total_packets
            
            if self.retransmission_rate > 0.15:  # >15% retrans
                return TCPHealthStatus.RETRANSMISSION_HEAVY
            elif self.retransmission_rate > 0.05:  # >5% retrans
                reasons.append("lossy")

        # 6. Check for Loss Indicators (Dup ACKs, OOO)
        if self.duplicate_acks > 10 or self.out_of_order > 10:
            reasons.append("lossy")

        # 7. Check for Slow Handshake
        if self.initial_rtt and self.initial_rtt > 0.2:  # >200ms
            reasons.append("slow_handshake")

        # Determine Primary Status
        if "lossy" in reasons:
            return TCPHealthStatus.LOSSY
        if "slow_handshake" in reasons:
            return TCPHealthStatus.SLOW_HANDSHAKE
        
        # Default to healthy if handshake completed
        if self.syn_count > 0 and self.syn_ack_count > 0 and self.ack_count > 0:
            return TCPHealthStatus.HEALTHY
        
        return TCPHealthStatus.UNKNOWN

    def generate_diagnosis(self) -> None:
        """
        Generate likely problem and recommended action based on health status.
        """
        self.health_status = self.classify_health()
        
        # Calculate retransmission rate if not already done
        if self.total_packets > 0 and self.retransmission_rate == 0.0:
            self.retransmission_rate = self.retransmissions / self.total_packets
        
        diagnosis_map = {
            TCPHealthStatus.HEALTHY: (
                "Connection completed successfully with normal parameters.",
                "No action required."
            ),
            TCPHealthStatus.SLOW_HANDSHAKE: (
                f"TCP handshake took {self.initial_rtt*1000:.1f}ms, indicating high latency or server load.",
                "Check network path latency, server CPU load, or SYN queue depth."
            ) if self.initial_rtt else (
                "TCP handshake was slow.",
                "Check network path latency, server CPU load, or SYN queue depth."
            ),
            TCPHealthStatus.RETRANSMISSION_HEAVY: (
                f"Retransmission rate is {self.retransmission_rate*100:.1f}%, indicating severe packet loss.",
                "Investigate interface errors, congestion, or faulty cabling on the path."
            ),
            TCPHealthStatus.LOSSY: (
                "Packet loss detected via duplicate ACKs or out-of-order delivery.",
                "Check for micro-bursts, QoS drops, or wireless interference."
            ),
            TCPHealthStatus.RECEIVER_LIMITED: (
                "Receiver advertised zero window multiple times, stalling sender.",
                "Check receiving application performance and TCP receive buffer size."
            ),
            TCPHealthStatus.RESET_BY_ENDPOINT: (
                "Connection reset by one of the endpoints during data transfer.",
                "Check application logs for crashes or intentional resets."
            ),
            TCPHealthStatus.RESET_BY_MIDDLEBOX: (
                "Connection reset immediately after SYN, likely by firewall or IPS.",
                "Verify firewall ACLs, security group rules, or IPS signatures."
            ),
            TCPHealthStatus.INCOMPLETE_HANDSHAKE: (
                "TCP 3-way handshake did not complete.",
                "Check for asymmetric routing, dropped SYN-ACKs, or host firewall rules."
            ),
            TCPHealthStatus.TIMEOUT: (
                "Connection attempt timed out with no response.",
                "Verify host availability, routing, and ICMP filtering."
            ),
            TCPHealthStatus.UNKNOWN: (
                "Could not determine connection state definitively.",
                "Review raw packet trace for anomalies."
            )
        }
        
        self.likely_problem, self.recommended_action = diagnosis_map.get(
            self.health_status, 
            ("Unknown issue", "Manual review required.")
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            "flow_id": self.flow_id,
            "src_ip": f"{self.src_ip}:{self.src_port}",
            "dst_ip": f"{self.dst_ip}:{self.dst_port}",
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_sec": round(self.duration, 3),
            "packets": self.total_packets,
            "bytes": self.total_bytes,
            "retransmissions": self.retransmissions,
            "retrans_rate_pct": round(self.retransmission_rate * 100, 2),
            "dup_acks": self.duplicate_acks,
            "out_of_order": self.out_of_order,
            "zero_windows": self.zero_windows,
            "initial_rtt_ms": round(self.initial_rtt * 1000, 2) if self.initial_rtt else None,
            "avg_rtt_ms": round(self.avg_rtt * 1000, 2) if self.avg_rtt else None,
            "mss": f"{self.mss_client}/{self.mss_server}",
            "window_scale": f"{self.window_scale_client}/{self.window_scale_server}",
            "sack": "Yes" if self.sack_permitted else "No",
            "health_status": self.health_status.value,
            "likely_problem": self.likely_problem,
            "recommended_action": self.recommended_action,
            "result": self.connection_result,
            "evidence_frames": self.evidence_frames[:10]  # Limit for report
        }
