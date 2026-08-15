#!/usr/bin/env python3
"""
Latency Analyzer

Analyzes network latency including:
- TCP handshake RTT
- DNS query/response latency
- ICMP echo RTT
- Application response times
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from config import Config


@dataclass
class LatencySample:
    """A single latency measurement."""
    
    timestamp: float = 0.0
    frame_number: int = 0
    latency_ms: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    description: str = ""


@dataclass
class LatencyAnalysisResult:
    """Result of latency analysis."""
    
    # TCP handshake RTT
    tcp_handshake_rtts: List[float] = field(default_factory=list)
    avg_tcp_rtt_ms: float = 0.0
    min_tcp_rtt_ms: float = 0.0
    max_tcp_rtt_ms: float = 0.0
    
    # DNS latency
    dns_latencies: List[float] = field(default_factory=list)
    avg_dns_latency_ms: float = 0.0
    min_dns_latency_ms: float = 0.0
    max_dns_latency_ms: float = 0.0
    slow_dns_count: int = 0
    
    # ICMP RTT (ping-like)
    icmp_rtts: List[float] = field(default_factory=list)
    avg_icmp_rtt_ms: float = 0.0
    min_icmp_rtt_ms: float = 0.0
    max_icmp_rtt_ms: float = 0.0
    
    # HTTP response times (if visible)
    http_response_times: List[float] = field(default_factory=list)
    avg_http_response_ms: float = 0.0
    
    # Overall statistics
    all_samples: List[LatencySample] = field(default_factory=list)
    high_latency_count: int = 0
    latency_outliers: List[LatencySample] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'tcp': {
                'avg_ms': self.avg_tcp_rtt_ms,
                'min_ms': self.min_tcp_rtt_ms,
                'max_ms': self.max_tcp_rtt_ms,
                'samples': len(self.tcp_handshake_rtts),
            },
            'dns': {
                'avg_ms': self.avg_dns_latency_ms,
                'min_ms': self.min_dns_latency_ms,
                'max_ms': self.max_dns_latency_ms,
                'slow_count': self.slow_dns_count,
            },
            'icmp': {
                'avg_ms': self.avg_icmp_rtt_ms,
                'min_ms': self.min_icmp_rtt_ms,
                'max_ms': self.max_icmp_rtt_ms,
            },
            'http': {
                'avg_ms': self.avg_http_response_ms,
            },
            'high_latency_count': self.high_latency_count,
            'outlier_count': len(self.latency_outliers),
        }


class LatencyAnalyzer:
    """
    Analyzes network latency from various protocols.
    """
    
    def __init__(self, store, config: Optional[Config] = None):
        self.store = store
        self.config = config or Config()
    
    def analyze(self) -> LatencyAnalysisResult:
        """
        Perform latency analysis.
        
        Returns:
            LatencyAnalysisResult with latency measurements
        """
        result = LatencyAnalysisResult()
        
        with self.store.get_connection() as conn:
            cursor = conn.cursor()
            
            # Analyze TCP handshake RTT (SYN -> SYN-ACK)
            self._analyze_tcp_rtt(cursor, result)
            
            # Analyze DNS latency
            self._analyze_dns_latency(cursor, result)
            
            # Analyze ICMP RTT
            self._analyze_icmp_rtt(cursor, result)
            
            # Calculate overall statistics
            self._calculate_statistics(result)
        
        return result
    
    def _analyze_tcp_rtt(self, cursor, result: LatencyAnalysisResult):
        """Analyze TCP handshake RTT from SYN/SYN-ACK pairs."""
        # Get SYN packets
        cursor.execute("""
            SELECT frame_number, timestamp_epoch, src_ip, dst_ip, tcp_seq
            FROM packets
            WHERE protocol = 6 
            AND (tcp_flags & 0x02) != 0 
            AND (tcp_flags & 0x10) = 0
            AND src_ip IS NOT NULL
            ORDER BY frame_number
        """)
        
        syn_packets = {}
        for row in cursor.fetchall():
            frame, ts, src, dst, seq = row
            key = f"{dst}:{src}"  # Reverse for matching SYN-ACK
            syn_packets[key] = (frame, ts, src, dst)
        
        # Get SYN-ACK packets and calculate RTT
        cursor.execute("""
            SELECT frame_number, timestamp_epoch, src_ip, dst_ip
            FROM packets
            WHERE protocol = 6
            AND (tcp_flags & 0x02) != 0
            AND (tcp_flags & 0x10) != 0
            AND src_ip IS NOT NULL
            ORDER BY frame_number
        """)
        
        for row in cursor.fetchall():
            frame, ts, src, dst = row
            key = f"{src}:{dst}"
            
            if key in syn_packets:
                syn_frame, syn_ts, syn_src, syn_dst = syn_packets[key]
                rtt_ms = (ts - syn_ts) * 1000
                
                if rtt_ms > 0 and rtt_ms < self.config.analysis.rtt_outlier_threshold_ms:
                    result.tcp_handshake_rtts.append(rtt_ms)
                    
                    result.all_samples.append(LatencySample(
                        timestamp=ts,
                        frame_number=frame,
                        latency_ms=rtt_ms,
                        src_ip=syn_src,
                        dst_ip=syn_dst,
                        protocol="TCP",
                        description="TCP handshake RTT"
                    ))
    
    def _analyze_dns_latency(self, cursor, result: LatencyAnalysisResult):
        """Analyze DNS query/response latency."""
        cursor.execute("""
            SELECT frame_number, timestamp_epoch, src_ip, dst_ip, 
                   dns_query_name, dns_rcode
            FROM packets
            WHERE dns_query_name IS NOT NULL OR dns_rcode IS NOT NULL
            ORDER BY frame_number
        """)
        
        pending_queries = {}
        
        for row in cursor.fetchall():
            frame, ts, src, dst, query_name, rcode = row
            
            # Query (to port 53)
            if query_name and dst.split(':')[-1] == '53' if ':' in dst else True:
                key = f"{query_name}:{src}"
                pending_queries[key] = (frame, ts, src, dst, query_name)
            
            # Response (from port 53)
            elif rcode is not None:
                key = f"{query_name}:{dst}"
                if key in pending_queries:
                    q_frame, q_ts, q_src, q_dst, q_name = pending_queries[key]
                    latency_ms = (ts - q_ts) * 1000
                    
                    if latency_ms > 0 and latency_ms < 10000:  # Sanity check
                        result.dns_latencies.append(latency_ms)
                        
                        result.all_samples.append(LatencySample(
                            timestamp=ts,
                            frame_number=frame,
                            latency_ms=latency_ms,
                            src_ip=q_dst,
                            dst_ip=q_src,
                            protocol="DNS",
                            description=f"DNS response for {q_name}"
                        ))
                        
                        if latency_ms > self.config.analysis.dns_slow_response_threshold_ms:
                            result.slow_dns_count += 1
                        
                        del pending_queries[key]
    
    def _analyze_icmp_rtt(self, cursor, result: LatencyAnalysisResult):
        """Analyze ICMP echo request/reply RTT."""
        cursor.execute("""
            SELECT frame_number, timestamp_epoch, src_ip, dst_ip, 
                   icmp_type, icmp_id, icmp_seq
            FROM packets
            WHERE protocol = 1 AND icmp_type IN (0, 8)
            ORDER BY frame_number
        """)
        
        pending_requests = {}
        
        for row in cursor.fetchall():
            frame, ts, src, dst, icmp_type, icmp_id, icmp_seq = row
            
            if icmp_type == 8:  # Echo request
                key = f"{dst}:{icmp_id}:{icmp_seq}"
                pending_requests[key] = (frame, ts, src, dst)
            
            elif icmp_type == 0:  # Echo reply
                key = f"{src}:{icmp_id}:{icmp_seq}"
                if key in pending_requests:
                    req_frame, req_ts, req_src, req_dst = pending_requests[key]
                    rtt_ms = (ts - req_ts) * 1000
                    
                    if rtt_ms > 0 and rtt_ms < 10000:
                        result.icmp_rtts.append(rtt_ms)
                        
                        result.all_samples.append(LatencySample(
                            timestamp=ts,
                            frame_number=frame,
                            latency_ms=rtt_ms,
                            src_ip=req_src,
                            dst_ip=req_dst,
                            protocol="ICMP",
                            description="ICMP echo RTT"
                        ))
                        
                        del pending_requests[key]
    
    def _calculate_statistics(self, result: LatencyAnalysisResult):
        """Calculate aggregate statistics."""
        # TCP stats
        if result.tcp_handshake_rtts:
            result.avg_tcp_rtt_ms = sum(result.tcp_handshake_rtts) / len(result.tcp_handshake_rtts)
            result.min_tcp_rtt_ms = min(result.tcp_handshake_rtts)
            result.max_tcp_rtt_ms = max(result.tcp_handshake_rtts)
        
        # DNS stats
        if result.dns_latencies:
            result.avg_dns_latency_ms = sum(result.dns_latencies) / len(result.dns_latencies)
            result.min_dns_latency_ms = min(result.dns_latencies)
            result.max_dns_latency_ms = max(result.dns_latencies)
        
        # ICMP stats
        if result.icmp_rtts:
            result.avg_icmp_rtt_ms = sum(result.icmp_rtts) / len(result.icmp_rtts)
            result.min_icmp_rtt_ms = min(result.icmp_rtts)
            result.max_icmp_rtt_ms = max(result.icmp_rtts)
        
        # HTTP stats
        if result.http_response_times:
            result.avg_http_response_ms = sum(result.http_response_times) / len(result.http_response_times)
        
        # Count high latency samples
        threshold = self.config.analysis.high_latency_threshold_ms
        result.high_latency_count = sum(
            1 for s in result.all_samples if s.latency_ms > threshold
        )
        
        # Find outliers (> 3 standard deviations or above critical threshold)
        if result.all_samples:
            latencies = [s.latency_ms for s in result.all_samples]
            avg = sum(latencies) / len(latencies)
            variance = sum((l - avg) ** 2 for l in latencies) / len(latencies)
            std_dev = variance ** 0.5
            outlier_threshold = avg + (3 * std_dev)
            
            result.latency_outliers = [
                s for s in result.all_samples 
                if s.latency_ms > outlier_threshold or s.latency_ms > self.config.analysis.critical_latency_threshold_ms
            ]
