#!/usr/bin/env python3
"""
Correlation Engine

Advanced rule-based correlation logic for network troubleshooting.
Correlates events across multiple analyzers to suggest likely root causes.
"""

from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from pcap_analyzer.models.finding import Finding, Severity, Confidence, FindingCategory


class ProblemType(Enum):
    """Types of network problems the correlation engine can detect."""
    
    NO_CONNECTIVITY = "no_connectivity"
    INTERMITTENT_PERFORMANCE = "intermittent_performance"
    APPLICATION_SLOWNESS = "application_slowness"
    MTU_PROBLEMS = "mtu_problems"
    DNS_PROBLEMS = "dns_problems"
    ARP_IP_CONFLICTS = "arp_ip_conflicts"
    DHCP_FAILURES = "dhcp_failures"
    ICMP_ERRORS = "icmp_errors"
    TCP_PATH_ISSUES = "tcp_path_issues"
    CONGESTION = "congestion"
    MIDDLEBOX_INTERFERENCE = "middlebox_interference"


@dataclass
class CorrelatedEvent:
    """An event that can be correlated with other events."""
    
    event_type: str
    timestamp: float
    frame_number: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelationResult:
    """Result of correlating multiple events."""
    
    problem_type: ProblemType
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    affected_objects: List[str]
    evidence_frames: List[int]
    first_seen: float
    last_seen: float
    event_count: int
    correlated_events: List[CorrelatedEvent]
    possible_causes: List[str]
    recommended_actions: List[str]
    related_findings: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_finding(self) -> Finding:
        """Convert correlation result to a Finding object."""
        return Finding(
            finding_id=f"CORR-{self.problem_type.value.upper().replace('_', '-')}",
            title=self.title,
            severity=self.severity,
            confidence=self.confidence,
            category=FindingCategory.CORRELATION,
            description=self.description,
            affected_object=", ".join(self.affected_objects[:3]),
            evidence_frames=self.evidence_frames[:20],
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            count=self.event_count,
            metrics=self.metrics,
            possible_causes=self.possible_causes,
            recommended_actions=self.recommended_actions,
        )


class CorrelationEngine:
    """
    Advanced correlation engine for network troubleshooting.
    
    Correlates events across multiple analysis results to identify
    root causes and provide actionable recommendations.
    """
    
    def __init__(self):
        self.events: List[CorrelatedEvent] = []
        self.results: List[CorrelationResult] = []
        
        # Rules for each problem type
        self.rules = {
            ProblemType.NO_CONNECTIVITY: self._check_no_connectivity,
            ProblemType.INTERMITTENT_PERFORMANCE: self._check_intermittent_performance,
            ProblemType.APPLICATION_SLOWNESS: self._check_application_slowness,
            ProblemType.MTU_PROBLEMS: self._check_mtu_problems,
            ProblemType.DNS_PROBLEMS: self._check_dns_problems,
            ProblemType.ARP_IP_CONFLICTS: self._check_arp_ip_conflicts,
            ProblemType.DHCP_FAILURES: self._check_dhcp_failures,
            ProblemType.ICMP_ERRORS: self._check_icmp_errors,
            ProblemType.TCP_PATH_ISSUES: self._check_tcp_path_issues,
            ProblemType.CONGESTION: self._check_congestion,
            ProblemType.MIDDLEBOX_INTERFERENCE: self._check_middlebox_interference,
        }
    
    def add_event(self, event: CorrelatedEvent):
        """Add an event for correlation."""
        self.events.append(event)
    
    def add_events(self, events: List[CorrelatedEvent]):
        """Add multiple events for correlation."""
        self.events.extend(events)
    
    def clear_events(self):
        """Clear all events."""
        self.events = []
        self.results = []
    
    def correlate(self, analysis_results: Dict[str, Any]) -> List[CorrelationResult]:
        """
        Run correlation analysis on provided analysis results.
        
        Args:
            analysis_results: Dictionary containing analysis results from various analyzers
            
        Returns:
            List of CorrelationResult objects
        """
        self.results = []
        
        # Extract events from analysis results
        self._extract_events_from_analysis(analysis_results)
        
        # Run all correlation rules
        for problem_type, rule_func in self.rules.items():
            try:
                result = rule_func(analysis_results)
                if result:
                    self.results.append(result)
            except Exception as e:
                # Log error but continue with other rules
                pass
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        self.results.sort(key=lambda r: severity_order.get(r.severity, 5))
        
        return self.results
    
    def _extract_events_from_analysis(self, analysis_results: Dict[str, Any]):
        """Extract events from various analysis results."""
        # TCP connection events
        tcp_analysis = analysis_results.get("tcp_analysis")
        if tcp_analysis:
            for conn in getattr(tcp_analysis, 'connections', []):
                if hasattr(conn, 'syn_frame') and conn.syn_frame:
                    self.add_event(CorrelatedEvent(
                        event_type="tcp_syn",
                        timestamp=getattr(conn, 'start_time', 0),
                        frame_number=conn.syn_frame,
                        src_ip=conn.src_ip,
                        dst_ip=conn.dst_ip,
                        src_port=conn.src_port,
                        dst_port=conn.dst_port,
                        protocol="TCP",
                        details={"state": "syn_sent"},
                        metrics={
                            "syn_count": getattr(conn, 'syn_count', 1),
                            "syn_ack_count": getattr(conn, 'syn_ack_count', 0),
                        }
                    ))
                
                if hasattr(conn, 'rst_frames') and conn.rst_frames and isinstance(conn.rst_frames, list):
                    for rst_frame in conn.rst_frames:
                        self.add_event(CorrelatedEvent(
                            event_type="tcp_rst",
                            timestamp=0,  # Would need frame timestamp
                            frame_number=rst_frame,
                            src_ip=conn.src_ip,
                            dst_ip=conn.dst_ip,
                            src_port=conn.src_port,
                            dst_port=conn.dst_port,
                            protocol="TCP",
                            details={"state": "reset"},
                        ))
        
        # ICMP events
        icmp_analysis = analysis_results.get("icmp_analysis")
        if icmp_analysis:
            for icmp_event in getattr(icmp_analysis, 'events', []):
                self.add_event(CorrelatedEvent(
                    event_type=f"icmp_{icmp_event.get('type', 'unknown')}",
                    timestamp=icmp_event.get('timestamp', 0),
                    frame_number=icmp_event.get('frame_number', 0),
                    src_ip=icmp_event.get('src_ip'),
                    dst_ip=icmp_event.get('dst_ip'),
                    protocol="ICMP",
                    details=icmp_event,
                ))
        
        # DNS events
        dns_analysis = analysis_results.get("dns_analysis")
        if dns_analysis:
            for query in getattr(dns_analysis, 'queries', []) or []:
                self.add_event(CorrelatedEvent(
                    event_type="dns_query",
                    timestamp=query.get('timestamp', 0),
                    frame_number=query.get('frame_number', 0),
                    src_ip=query.get('client_ip'),
                    dst_ip=query.get('server_ip'),
                    dst_port=53,
                    protocol="DNS",
                    details=query,
                ))
    
    def _check_no_connectivity(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for no connectivity issues.
        
        Correlates:
        - SYN sent, no SYN-ACK
        - ICMP unreachable messages
        - RST after SYN
        - TTL exceeded
        """
        tcp_analysis = analysis_results.get("tcp_analysis")
        icmp_analysis = analysis_results.get("icmp_analysis")
        
        if not tcp_analysis:
            return None
        
        failed_connections = []
        syn_only_connections = []
        icmp_unreachables = []
        
        # Find SYN-only connections (no SYN-ACK)
        for conn in getattr(tcp_analysis, 'connections', []):
            syn_count = getattr(conn, 'syn_count', 0)
            syn_ack_count = getattr(conn, 'syn_ack_count', 0)
            
            if syn_count > 0 and syn_ack_count == 0:
                syn_only_connections.append(conn)
            
            # Also check for RST after SYN (connection refused)
            rst_count = getattr(conn, 'rst_count', 0)
            if syn_count > 0 and rst_count > 0 and syn_ack_count == 0:
                failed_connections.append(conn)
        
        # Find ICMP unreachable messages
        if icmp_analysis:
            for event in getattr(icmp_analysis, 'events', []):
                icmp_type = event.get('type', 0)
                if icmp_type in (3, 11):  # Destination Unreachable, Time Exceeded
                    icmp_unreachables.append(event)
        
        # Correlate: SYN without SYN-ACK + ICMP unreachable to same destination
        affected_destinations: Set[str] = set()
        evidence_frames = []
        correlated_events = []
        
        for conn in syn_only_connections:
            dst_key = f"{conn.dst_ip}:{conn.dst_port}"
            
            # Check if there's an ICMP unreachable for this destination
            has_icmp_unreachable = any(
                event.get('dst_ip') == conn.dst_ip
                for event in icmp_unreachables
            )
            
            if has_icmp_unreachable or getattr(conn, 'failure_reason', ''):
                affected_destinations.add(dst_key)
                if hasattr(conn, 'syn_frame'):
                    evidence_frames.append(conn.syn_frame)
                correlated_events.append(CorrelatedEvent(
                    event_type="connectivity_failure",
                    timestamp=getattr(conn, 'start_time', 0),
                    frame_number=getattr(conn, 'syn_frame', 0),
                    src_ip=conn.src_ip,
                    dst_ip=conn.dst_ip,
                    dst_port=conn.dst_port,
                    protocol="TCP",
                    details={"reason": "syn_no_ack"},
                ))
        
        if not affected_destinations:
            return None
        
        # Determine severity based on impact
        severity = Severity.HIGH if len(affected_destinations) > 5 else Severity.MEDIUM
        confidence = Confidence.HIGH if icmp_unreachables else Confidence.MEDIUM
        
        return CorrelationResult(
            problem_type=ProblemType.NO_CONNECTIVITY,
            severity=severity,
            confidence=confidence,
            title="Connectivity failure detected",
            description=(
                f"Multiple TCP connection attempts failed to reach {len(affected_destinations)} "
                f"destination(s). SYN packets were sent but no SYN-ACK was received. "
                f"{'ICMP unreachable messages confirm path failure.' if icmp_unreachables else ''}"
            ),
            affected_objects=list(affected_destinations),
            evidence_frames=evidence_frames,
            first_seen=min(e.start_time for e in correlated_events) if correlated_events else 0,
            last_seen=max(e.start_time for e in correlated_events) if correlated_events else 0,
            event_count=len(correlated_events),
            correlated_events=correlated_events,
            possible_causes=[
                "Firewall or ACL blocking traffic",
                "Routing issue preventing reachability",
                "Destination host or service is down",
                "Intermediate device dropping packets",
                "NAT or translation issue",
            ],
            recommended_actions=[
                "Verify firewall rules allow the traffic",
                "Check routing tables on source and intermediate devices",
                "Test connectivity with ping/traceroute",
                "Verify the destination service is running",
                "Check for ACL drops on intermediate devices",
                "Inspect NAT translations if applicable",
            ],
            metrics={
                "failed_destinations": len(affected_destinations),
                "icmp_unreachables": len(icmp_unreachables),
                "syn_only_connections": len(syn_only_connections),
            },
        )
    
    def _check_intermittent_performance(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for intermittent performance issues.
        
        Correlates:
        - Retransmissions
        - Duplicate ACKs
        - Out-of-order packets
        - Variable RTT
        """
        tcp_analysis = analysis_results.get("tcp_analysis")
        
        if not tcp_analysis:
            return None
        
        high_retrans_connections = []
        dup_ack_flows = []
        ooo_flows = []
        
        for conn in getattr(tcp_analysis, 'connections', []):
            retrans_rate = getattr(conn, 'retransmission_rate', 0)
            if retrans_rate > 5.0:  # >5% retransmission rate
                high_retrans_connections.append(conn)
            
            dup_ack_count = getattr(conn, 'duplicate_ack_count', 0)
            if dup_ack_count > 10:
                dup_ack_flows.append(conn)
            
            ooo_count = getattr(conn, 'out_of_order_count', 0)
            if ooo_count > 5:
                ooo_flows.append(conn)
        
        if not (high_retrans_connections or dup_ack_flows or ooo_flows):
            return None
        
        affected_flows = set()
        evidence_frames = []
        total_retrans = 0
        total_dup_acks = 0
        total_ooo = 0
        
        for conn in high_retrans_connections:
            flow_key = f"{conn.src_ip}:{conn.src_port} -> {conn.dst_ip}:{conn.dst_port}"
            affected_flows.add(flow_key)
            total_retrans += getattr(conn, 'retransmissions', 0)
            if hasattr(conn, 'retransmit_frames'):
                evidence_frames.extend(conn.retransmit_frames[:5])
        
        for conn in dup_ack_flows:
            flow_key = f"{conn.src_ip}:{conn.src_port} -> {conn.dst_ip}:{conn.dst_port}"
            affected_flows.add(flow_key)
            total_dup_acks += getattr(conn, 'duplicate_ack_count', 0)
        
        for conn in ooo_flows:
            flow_key = f"{conn.src_ip}:{conn.src_port} -> {conn.dst_ip}:{conn.dst_port}"
            affected_flows.add(flow_key)
            total_ooo += getattr(conn, 'out_of_order_count', 0)
        
        if not affected_flows:
            return None
        
        severity = Severity.HIGH if len(affected_flows) > 10 else Severity.MEDIUM
        
        return CorrelationResult(
            problem_type=ProblemType.INTERMITTENT_PERFORMANCE,
            severity=severity,
            confidence=Confidence.HIGH,
            title="Intermittent performance degradation detected",
            description=(
                f"Detected performance issues affecting {len(affected_flows)} TCP flow(s). "
                f"Indicators include retransmissions ({total_retrans}), duplicate ACKs ({total_dup_acks}), "
                f"and out-of-order packets ({total_ooo}). This suggests packet loss or congestion."
            ),
            affected_objects=list(affected_flows)[:10],
            evidence_frames=evidence_frames[:20],
            first_seen=0,
            last_seen=0,
            event_count=len(high_retrans_connections) + len(dup_ack_flows) + len(ooo_flows),
            correlated_events=[],
            possible_causes=[
                "Network packet loss on the path",
                "Network congestion causing buffer overflows",
                "Interface errors (CRC, collisions, runts)",
                "QoS policy dropping traffic",
                "Wireless interference or signal issues",
                "Faulty cable or transceiver",
            ],
            recommended_actions=[
                "Check interface error counters on all path devices",
                "Verify QoS policies and queue drops",
                "Monitor link utilization for congestion",
                "Check physical layer (cables, SFPs, ports)",
                "Review recent network changes",
                "Consider packet capture at multiple points to isolate segment",
            ],
            metrics={
                "affected_flows": len(affected_flows),
                "total_retransmissions": total_retrans,
                "total_duplicate_acks": total_dup_acks,
                "total_out_of_order": total_ooo,
                "avg_retrans_rate": sum(c.retransmission_rate for c in high_retrans_connections) / len(high_retrans_connections) if high_retrans_connections else 0,
            },
        )
    
    def _check_application_slowness(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for application slowness issues.
        
        Correlates:
        - High TCP handshake RTT but low retransmissions
        - Large gaps between request and response
        - Zero-window events
        """
        tcp_analysis = analysis_results.get("tcp_analysis")
        latency_analysis = analysis_results.get("latency_analysis")
        
        if not tcp_analysis and not latency_analysis:
            return None
        
        slow_handshakes = []
        zero_window_events = 0
        request_response_gaps = []
        
        # Check for high RTT with low retransmissions
        for conn in getattr(tcp_analysis, 'connections', []):
            avg_rtt = getattr(conn, 'avg_rtt_ms', 0)
            retrans_rate = getattr(conn, 'retransmission_rate', 0)
            
            # High RTT (>200ms) but low retransmissions (<2%)
            if avg_rtt > 200 and retrans_rate < 2.0:
                slow_handshakes.append(conn)
            
            zero_window = getattr(conn, 'zero_window_count', 0)
            zero_window_events += zero_window
        
        # Check latency analysis for application delays
        if latency_analysis:
            http_latencies = getattr(latency_analysis, 'http_latencies', [])
            for lat in http_latencies:
                if lat.get('response_time_ms', 0) > 1000:  # >1s response time
                    request_response_gaps.append(lat)
        
        if not (slow_handshakes or zero_window_events > 10 or request_response_gaps):
            return None
        
        affected_servers = set()
        for conn in slow_handshakes:
            affected_servers.add(f"{conn.dst_ip}:{conn.dst_port}")
        
        severity = Severity.MEDIUM
        if zero_window_events > 50 or len(request_response_gaps) > 20:
            severity = Severity.HIGH
        
        return CorrelationResult(
            problem_type=ProblemType.APPLICATION_SLOWNESS,
            severity=severity,
            confidence=Confidence.MEDIUM,
            title="Application-level slowness detected",
            description=(
                f"Detected signs of application-level slowness. "
                f"{len(slow_handshakes)} connection(s) show high RTT without packet loss, "
                f"{zero_window_events} zero-window events indicate receiver buffer exhaustion, "
                f"and {len(request_response_gaps)} request/response pairs show >1s delays."
            ),
            affected_objects=list(affected_servers)[:10],
            evidence_frames=[],
            first_seen=0,
            last_seen=0,
            event_count=len(slow_handshakes) + len(request_response_gaps),
            correlated_events=[],
            possible_causes=[
                "Server application processing delay",
                "Receiver application too slow to consume data",
                "TCP receive buffer exhaustion",
                "Backend dependency slowness (database, API)",
                "Resource exhaustion on server (CPU, memory, disk)",
                "Lock contention or thread pool exhaustion",
            ],
            recommended_actions=[
                "Check application logs on the server",
                "Monitor server resource utilization (CPU, memory, disk I/O)",
                "Review database query performance",
                "Check application thread pools and connection pools",
                "Verify TCP receive buffer settings (net.ipv4.tcp_rmem)",
                "Profile application to identify bottlenecks",
            ],
            metrics={
                "slow_handshake_connections": len(slow_handshakes),
                "zero_window_events": zero_window_events,
                "slow_request_responses": len(request_response_gaps),
                "avg_slow_rtt_ms": sum(c.avg_rtt_ms for c in slow_handshakes) / len(slow_handshakes) if slow_handshakes else 0,
            },
        )
    
    def _check_mtu_problems(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for MTU/MSS/PMTUD issues.
        
        Correlates:
        - ICMP fragmentation-needed messages
        - DF bit set on large packets
        - MSS mismatch
        - Fragmented packets
        """
        icmp_analysis = analysis_results.get("icmp_analysis")
        mtu_analysis = analysis_results.get("mtu_analysis")
        
        frag_needed_events = []
        df_large_packets = []
        mss_mismatches = []
        fragmented_packets = []
        
        # Check for ICMP fragmentation needed (Type 3, Code 4)
        if icmp_analysis:
            for event in getattr(icmp_analysis, 'events', []):
                icmp_type = event.get('type', 0)
                icmp_code = event.get('code', 0)
                if icmp_type == 3 and icmp_code == 4:  # Fragmentation needed
                    frag_needed_events.append(event)
        
        # Check MTU analysis results
        if mtu_analysis:
            df_large_packets = getattr(mtu_analysis, 'df_large_packets', [])
            mss_mismatches = getattr(mtu_analysis, 'mss_mismatches', [])
            fragmented_packets = getattr(mtu_analysis, 'fragmented_packets', [])
        
        total_mtu_events = (
            len(frag_needed_events) + 
            len(df_large_packets) + 
            len(mss_mismatches) +
            len(fragmented_packets)
        )
        
        if total_mtu_events == 0:
            return None
        
        affected_pairs = set()
        evidence_frames = []
        
        for event in frag_needed_events:
            next_hop_mtu = event.get('next_hop_mtu', 'unknown')
            affected_pairs.add(f"{event.get('src_ip')} -> {event.get('dst_ip')} (MTU={next_hop_mtu})")
            evidence_frames.append(event.get('frame_number', 0))
        
        for pkt in df_large_packets:
            affected_pairs.add(f"{pkt.get('src_ip')} -> {pkt.get('dst_ip')} (size={pkt.get('size', 0)})")
        
        severity = Severity.HIGH if len(frag_needed_events) > 10 else Severity.MEDIUM
        
        return CorrelationResult(
            problem_type=ProblemType.MTU_PROBLEMS,
            severity=severity,
            confidence=Confidence.HIGH if frag_needed_events else Confidence.MEDIUM,
            title="MTU/MSS/PMTUD issues detected",
            description=(
                f"Detected {total_mtu_events} MTU-related event(s). "
                f"{len(frag_needed_events)} ICMP fragmentation-needed messages received, "
                f"{len(df_large_packets)} large packets with DF bit set, "
                f"{len(mss_mismatches)} MSS mismatches observed. "
                f"This indicates path MTU discovery issues or MTU mismatches."
            ),
            affected_objects=list(affected_pairs)[:10],
            evidence_frames=evidence_frames[:20],
            first_seen=0,
            last_seen=0,
            event_count=total_mtu_events,
            correlated_events=[],
            possible_causes=[
                "Path MTU mismatch between segments",
                "Tunnel interface MTU too small (GRE, IPsec, VXLAN)",
                "PMTUD black hole (ICMP filtered)",
                "MSS clamping not configured on edge devices",
                "Jumbo frames on one side, standard MTU on the other",
            ],
            recommended_actions=[
                "Verify end-to-end path MTU",
                "Check tunnel interface MTU settings",
                "Configure MSS clamping on edge firewalls/routers",
                "Ensure ICMP fragmentation-needed is not filtered",
                "Consider reducing interface MTU if jumbo frames not needed",
                "Use 'ping -M do -s <size>' to test path MTU",
            ],
            metrics={
                "fragmentation_needed_count": len(frag_needed_events),
                "df_large_packets_count": len(df_large_packets),
                "mss_mismatch_count": len(mss_mismatches),
                "fragmented_packets_count": len(fragmented_packets),
            },
        )
    
    def _check_dns_problems(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for DNS problems.
        
        Correlates:
        - DNS retransmissions
        - High DNS response time
        - SERVFAIL/NXDOMAIN spikes
        """
        dns_analysis = analysis_results.get("dns_analysis")
        
        if not dns_analysis:
            return None
        
        slow_queries = getattr(dns_analysis, 'slow_queries', [])
        unanswered_queries = getattr(dns_analysis, 'unanswered_queries', 0)
        nxdomain_count = getattr(dns_analysis, 'nxdomain_count', 0)
        servfail_count = getattr(dns_analysis, 'servfail_count', 0)
        total_queries = getattr(dns_analysis, 'total_queries', 1)
        retransmitted_queries = getattr(dns_analysis, 'retransmitted_queries', 0)
        
        # Calculate rates
        nxdomain_rate = (nxdomain_count / total_queries) * 100 if total_queries > 0 else 0
        servfail_rate = (servfail_count / total_queries) * 100 if total_queries > 0 else 0
        retrans_rate = (retransmitted_queries / total_queries) * 100 if total_queries > 0 else 0
        
        dns_issues = []
        if len(slow_queries) > 5:
            dns_issues.append("slow_responses")
        if unanswered_queries > 10:
            dns_issues.append("unanswered_queries")
        if nxdomain_rate > 10:
            dns_issues.append("high_nxdomain")
        if servfail_rate > 5:
            dns_issues.append("high_servfail")
        if retrans_rate > 5:
            dns_issues.append("high_retransmissions")
        
        if not dns_issues:
            return None
        
        # Identify problematic DNS servers
        dns_servers = getattr(dns_analysis, 'dns_servers', {})
        problematic_servers = []
        for server, stats in dns_servers.items():
            if stats.get('avg_latency_ms', 0) > 200 or stats.get('failure_rate', 0) > 10:
                problematic_servers.append(server)
        
        severity = Severity.HIGH if servfail_rate > 20 or len(problematic_servers) > 2 else Severity.MEDIUM
        
        return CorrelationResult(
            problem_type=ProblemType.DNS_PROBLEMS,
            severity=severity,
            confidence=Confidence.HIGH,
            title="DNS service degradation detected",
            description=(
                f"DNS infrastructure showing signs of degradation. "
                f"Issues detected: {', '.join(dns_issues)}. "
                f"NXDOMAIN rate: {nxdomain_rate:.1f}%, SERVFAIL rate: {servfail_rate:.1f}%, "
                f"Retransmission rate: {retrans_rate:.1f}%. "
                f"{'Problematic servers: ' + ', '.join(problematic_servers) if problematic_servers else ''}"
            ),
            affected_objects=problematic_servers if problematic_servers else ["DNS infrastructure"],
            evidence_frames=[],
            first_seen=0,
            last_seen=0,
            event_count=len(slow_queries) + unanswered_queries + nxdomain_count + servfail_count,
            correlated_events=[],
            possible_causes=[
                "DNS server overload or resource exhaustion",
                "Network packet loss to DNS servers",
                "Upstream DNS resolver issues",
                "DNS cache poisoning or attacks",
                "Misconfigured DNS views or ACLs",
                "Excessive DNS tunneling activity",
            ],
            recommended_actions=[
                "Check DNS server health (CPU, memory, query rate)",
                "Verify network path to DNS servers",
                "Review DNS server logs for errors",
                "Consider adding local DNS caching (dnsmasq, unbound)",
                "Evaluate alternative upstream DNS providers",
                "Check for DNS amplification attacks",
                "Verify DNSSEC validation if enabled",
            ],
            metrics={
                "total_queries": total_queries,
                "slow_queries": len(slow_queries),
                "unanswered_queries": unanswered_queries,
                "nxdomain_count": nxdomain_count,
                "nxdomain_rate": round(nxdomain_rate, 2),
                "servfail_count": servfail_count,
                "servfail_rate": round(servfail_rate, 2),
                "retransmitted_queries": retransmitted_queries,
                "problematic_servers": problematic_servers,
            },
        )
    
    def _check_arp_ip_conflicts(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for ARP/IP conflicts.
        
        Correlates:
        - Duplicate ARP replies
        - Gratuitous ARP conflicts
        - Multiple MACs for same IP
        """
        arp_analysis = analysis_results.get("arp_analysis")
        
        if not arp_analysis:
            return None
        
        duplicate_ips = getattr(arp_analysis, 'duplicate_ips', [])
        arp_storm_detected = getattr(arp_analysis, 'storm_detected', False)
        gratuitous_arp_count = getattr(arp_analysis, 'gratuitous_arp_count', 0)
        mac_flapping = getattr(arp_analysis, 'mac_flapping', [])
        
        if not (duplicate_ips or arp_storm_detected or mac_flapping):
            return None
        
        affected_ips = set()
        for dup in duplicate_ips:
            affected_ips.add(dup.get('ip'))
        
        for flap in mac_flapping:
            affected_ips.add(flap.get('ip'))
        
        severity = Severity.CRITICAL if duplicate_ips else Severity.HIGH if mac_flapping else Severity.MEDIUM
        
        return CorrelationResult(
            problem_type=ProblemType.ARP_IP_CONFLICTS,
            severity=severity,
            confidence=Confidence.HIGH if duplicate_ips else Confidence.MEDIUM,
            title="ARP/IP conflict detected",
            description=(
                f"Detected ARP-layer anomalies. "
                f"{'Duplicate IP addresses: ' + str([d['ip'] for d in duplicate_ips]) + '. ' if duplicate_ips else ''}"
                f"{'MAC flapping detected for ' + str(len(mac_flapping)) + ' IP(s). ' if mac_flapping else ''}"
                f"{'ARP storm condition detected. ' if arp_storm_detected else ''}"
                f"High gratuitous ARP count: {gratuitous_arp_count}."
            ),
            affected_objects=list(affected_ips)[:10],
            evidence_frames=[],
            first_seen=0,
            last_seen=0,
            event_count=len(duplicate_ips) + len(mac_flapping) + gratuitous_arp_count,
            correlated_events=[],
            possible_causes=[
                "Duplicate IP address configuration",
                "ARP spoofing/poisoning attack",
                "Misconfigured failover cluster (VIP not properly failing over)",
                "VM migration without proper ARP update",
                "Rogue DHCP server assigning duplicate IPs",
                "Network loop causing ARP storms",
            ],
            recommended_actions=[
                "Identify all devices claiming the duplicate IP",
                "Check for unauthorized devices on the network",
                "Verify HA cluster configuration",
                "Enable DHCP snooping and dynamic ARP inspection",
                "Check switch port security settings",
                "Investigate VM migration events",
                "Look for network loops in L2 topology",
            ],
            metrics={
                "duplicate_ip_count": len(duplicate_ips),
                "mac_flapping_count": len(mac_flapping),
                "gratuitous_arp_count": gratuitous_arp_count,
                "arp_storm_detected": arp_storm_detected,
            },
        )
    
    def _check_dhcp_failures(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for DHCP failures.
        
        Correlates:
        - Missing DHCP offer
        - Missing DHCP ACK
        - DHCP NAK responses
        - Slow lease assignment
        """
        dhcp_analysis = analysis_results.get("dhcp_analysis")
        
        if not dhcp_analysis:
            return None
        
        failed_transactions = getattr(dhcp_analysis, 'failed_transactions', [])
        nak_count = getattr(dhcp_analysis, 'nak_count', 0)
        slow_assignments = getattr(dhcp_analysis, 'slow_assignments', [])
        missing_offers = getattr(dhcp_analysis, 'missing_offers', [])
        missing_acks = getattr(dhcp_analysis, 'missing_acks', [])
        
        total_failures = (
            len(failed_transactions) + 
            nak_count + 
            len(missing_offers) + 
            len(missing_acks)
        )
        
        if total_failures == 0:
            return None
        
        affected_clients = set()
        for txn in failed_transactions:
            affected_clients.add(txn.get('client_mac', 'unknown'))
        for offer in missing_offers:
            affected_clients.add(offer.get('client_mac', 'unknown'))
        
        severity = Severity.HIGH if nak_count > 5 or len(missing_offers) > 10 else Severity.MEDIUM
        
        return CorrelationResult(
            problem_type=ProblemType.DHCP_FAILURES,
            severity=severity,
            confidence=Confidence.HIGH,
            title="DHCP service issues detected",
            description=(
                f"DHCP service experiencing issues. "
                f"{len(failed_transactions)} failed transaction(s), "
                f"{nak_count} DHCP NAK response(s), "
                f"{len(missing_offers)} discover(s) without offer, "
                f"{len(missing_acks)} request(s) without ACK, "
                f"{len(slow_assignments)} slow assignment(s)."
            ),
            affected_objects=list(affected_clients)[:10],
            evidence_frames=[],
            first_seen=0,
            last_seen=0,
            event_count=total_failures,
            correlated_events=[],
            possible_causes=[
                "DHCP server overload or failure",
                "DHCP scope exhausted (no available addresses)",
                "Network connectivity issue to DHCP server",
                "DHCP relay agent misconfiguration",
                "Rogue DHCP server responding with NAK",
                "Client requesting invalid/leased address",
            ],
            recommended_actions=[
                "Check DHCP server status and logs",
                "Verify DHCP scope utilization",
                "Check DHCP relay agent configuration",
                "Look for rogue DHCP servers",
                "Verify network connectivity to DHCP server",
                "Consider increasing DHCP lease time to reduce load",
            ],
            metrics={
                "failed_transactions": len(failed_transactions),
                "nak_count": nak_count,
                "missing_offers": len(missing_offers),
                "missing_acks": len(missing_acks),
                "slow_assignments": len(slow_assignments),
            },
        )
    
    def _check_icmp_errors(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for ICMP error patterns.
        
        Correlates:
        - Destination unreachable patterns
        - Time exceeded (traceroute-like)
        - Administratively prohibited
        - ICMP filtering indicators
        """
        icmp_analysis = analysis_results.get("icmp_analysis")
        
        if not icmp_analysis:
            return None
        
        events = getattr(icmp_analysis, 'events', [])
        
        unreachable_count = 0
        time_exceeded_count = 0
        admin_prohibited_count = 0
        frag_needed_count = 0
        
        unreachable_targets = defaultdict(int)
        
        for event in events:
            icmp_type = event.get('type', 0)
            icmp_code = event.get('code', 0)
            
            if icmp_type == 3:  # Destination Unreachable
                unreachable_count += 1
                code_descriptions = {
                    0: "network_unreachable",
                    1: "host_unreachable",
                    2: "protocol_unreachable",
                    3: "port_unreachable",
                    9: "admin_prohibited",
                    10: "admin_prohibited",
                    13: "comm_admin_prohibited",
                }
                reason = code_descriptions.get(icmp_code, f"code_{icmp_code}")
                unreachable_targets[(event.get('dst_ip'), reason)] += 1
            
            elif icmp_type == 11:  # Time Exceeded
                time_exceeded_count += 1
            
            elif icmp_type == 3 and icmp_code in (9, 10, 13):  # Admin prohibited
                admin_prohibited_count += 1
            
            elif icmp_type == 3 and icmp_code == 4:  # Fragmentation needed
                frag_needed_count += 1
        
        total_icmp_errors = unreachable_count + time_exceeded_count + admin_prohibited_count
        
        if total_icmp_errors < 5:  # Threshold for significance
            return None
        
        # Check for patterns
        patterns = []
        if admin_prohibited_count > 5:
            patterns.append("administrative_filtering")
        if time_exceeded_count > 20:
            patterns.append("traceroute_activity_or_ttl_issues")
        if unreachable_count > 10:
            patterns.append("widespread_unreachability")
        
        severity = Severity.HIGH if admin_prohibited_count > 20 else Severity.MEDIUM
        
        return CorrelationResult(
            problem_type=ProblemType.ICMP_ERRORS,
            severity=severity,
            confidence=Confidence.MEDIUM,
            title="ICMP error pattern detected",
            description=(
                f"Significant ICMP error traffic detected. "
                f"{unreachable_count} destination unreachable, "
                f"{time_exceeded_count} time exceeded, "
                f"{admin_prohibited_count} administratively prohibited. "
                f"Patterns: {', '.join(patterns) if patterns else 'none identified'}."
            ),
            affected_objects=[str(k[0]) for k in unreachable_targets.keys()][:10],
            evidence_frames=[],
            first_seen=0,
            last_seen=0,
            event_count=total_icmp_errors,
            correlated_events=[],
            possible_causes=[
                "Firewall ACL blocking traffic",
                "Routing issues causing unreachability",
                "Traceroute or network probing activity",
                "Service not listening on target ports",
                "ICMP rate limiting on devices",
                "Network segmentation issues",
            ],
            recommended_actions=[
                "Review firewall logs for blocked traffic",
                "Verify routing tables and path availability",
                "Check if traceroute activity is expected",
                "Verify services are running on target hosts",
                "Review ICMP rate limiting policies",
                "Investigate network segmentation design",
            ],
            metrics={
                "destination_unreachable": unreachable_count,
                "time_exceeded": time_exceeded_count,
                "administratively_prohibited": admin_prohibited_count,
                "fragmentation_needed": frag_needed_count,
                "patterns_detected": patterns,
            },
        )
    
    def _check_tcp_path_issues(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for TCP path-specific issues.
        
        Correlates:
        - Asymmetric routing indicators
        - Middlebox TCP option stripping
        - Window scaling issues
        """
        tcp_analysis = analysis_results.get("tcp_analysis")
        
        if not tcp_analysis:
            return None
        
        window_scale_issues = []
        option_stripping_suspected = []
        
        for conn in getattr(tcp_analysis, 'connections', []):
            # Check for window scale mismatch
            client_ws = getattr(conn, 'client_window_scale', -1)
            server_ws = getattr(conn, 'server_window_scale', -1)
            
            if client_ws != server_ws and client_ws >= 0 and server_ws >= 0:
                window_scale_issues.append(conn)
            
            # Check for missing TCP options that should be present
            syn_options = getattr(conn, 'syn_tcp_options', [])
            synack_options = getattr(conn, 'synack_tcp_options', [])
            
            # If SYN has SACK permitted but SYN-ACK doesn't, middlebox may be stripping
            if 'sack' in [opt.lower() for opt in syn_options] and \
               'sack' not in [opt.lower() for opt in synack_options]:
                option_stripping_suspected.append(conn)
        
        total_issues = len(window_scale_issues) + len(option_stripping_suspected)
        
        if total_issues == 0:
            return None
        
        severity = Severity.MEDIUM
        
        return CorrelationResult(
            problem_type=ProblemType.TCP_PATH_ISSUES,
            severity=severity,
            confidence=Confidence.MEDIUM,
            title="TCP path issues detected",
            description=(
                f"Detected {len(window_scale_issues)} connection(s) with window scale mismatches "
                f"and {len(option_stripping_suspected)} connection(s) with suspected TCP option stripping. "
                f"This may indicate middlebox interference or asymmetric routing."
            ),
            affected_objects=[],
            evidence_frames=[],
            first_seen=0,
            last_seen=0,
            event_count=total_issues,
            correlated_events=[],
            possible_causes=[
                "Middlebox (firewall/NAT) stripping TCP options",
                "Asymmetric routing causing inconsistent TCP state",
                "TCP normalization on security devices",
                "Load balancer modifying TCP parameters",
                "Transparent proxy interfering with TCP",
            ],
            recommended_actions=[
                "Check firewall TCP normalization settings",
                "Verify routing symmetry on the path",
                "Review load balancer TCP profiles",
                "Check for transparent proxies on the path",
                "Compare TCP options at different capture points",
            ],
            metrics={
                "window_scale_mismatches": len(window_scale_issues),
                "option_stripping_suspected": len(option_stripping_suspected),
            },
        )
    
    def _check_congestion(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for network congestion indicators.
        
        Correlates:
        - Widespread retransmissions across many flows
        - ECN CE marks
        - Queue drop indicators
        - Latency spikes
        """
        tcp_analysis = analysis_results.get("tcp_analysis")
        qos_analysis = analysis_results.get("qos_analysis")
        
        if not tcp_analysis:
            return None
        
        # Count flows with retransmissions
        retrans_flows = []
        ecn_marked_flows = []
        total_retrans = 0
        
        for conn in getattr(tcp_analysis, 'connections', []):
            retrans = getattr(conn, 'retransmissions', 0)
            if retrans > 0:
                retrans_flows.append(conn)
                total_retrans += retrans
            
            ecn_ce = getattr(conn, 'ecn_ce_count', 0)
            if ecn_ce > 0:
                ecn_marked_flows.append(conn)
        
        total_flows = len(getattr(tcp_analysis, 'connections', []))
        retrans_flow_ratio = len(retrans_flows) / total_flows if total_flows > 0 else 0
        
        # Congestion is indicated when many flows have retransmissions
        if retrans_flow_ratio < 0.3 or total_retrans < 50:  # Need significant impact
            return None
        
        severity = Severity.HIGH if retrans_flow_ratio > 0.7 else Severity.MEDIUM
        
        return CorrelationResult(
            problem_type=ProblemType.CONGESTION,
            severity=severity,
            confidence=Confidence.HIGH if len(ecn_marked_flows) > 0 else Confidence.MEDIUM,
            title="Network congestion detected",
            description=(
                f"Widespread retransmissions detected across {len(retrans_flows)} of {total_flows} flows "
                f"({retrans_flow_ratio*100:.1f}%). Total retransmissions: {total_retrans}. "
                f"{'ECN congestion experienced marks detected.' if ecn_marked_flows else ''}"
            ),
            affected_objects=[],
            evidence_frames=[],
            first_seen=0,
            last_seen=0,
            event_count=total_retrans,
            correlated_events=[],
            possible_causes=[
                "Link utilization exceeding capacity",
                "Buffer exhaustion on network devices",
                "Microbursts causing tail drops",
                "Insufficient bandwidth for workload",
                "QoS policy not prioritizing critical traffic",
            ],
            recommended_actions=[
                "Monitor link utilization on path devices",
                "Check interface queue drops",
                "Review QoS policies and class maps",
                "Consider bandwidth upgrade or traffic engineering",
                "Implement traffic shaping to prevent microbursts",
                "Enable ECN on endpoints if supported",
            ],
            metrics={
                "total_flows": total_flows,
                "flows_with_retransmissions": len(retrans_flows),
                "retransmission_flow_ratio": round(retrans_flow_ratio, 3),
                "total_retransmissions": total_retrans,
                "ecn_marked_flows": len(ecn_marked_flows),
            },
        )
    
    def _check_middlebox_interference(self, analysis_results: Dict[str, Any]) -> Optional[CorrelationResult]:
        """
        Check for middlebox interference indicators.
        
        Correlates:
        - TCP timestamp modification
        - Sequence number adjustment
        - Unexpected TTL changes
        - DSCP remarking
        """
        tcp_analysis = analysis_results.get("tcp_analysis")
        qos_analysis = analysis_results.get("qos_analysis")
        ttl_analysis = analysis_results.get("ttl_analysis")
        
        suspicious_indicators = []
        
        # Check for DSCP remarking
        if qos_analysis:
            remarked_flows = getattr(qos_analysis, 'remarked_flows', [])
            if len(remarked_flows) > 5:
                suspicious_indicators.append(("dscp_remarking", len(remarked_flows)))
        
        # Check for unexpected TTL changes
        if ttl_analysis:
            ttl_anomalies = getattr(ttl_analysis, 'anomalies', [])
            if len(ttl_anomalies) > 5:
                suspicious_indicators.append(("ttl_anomalies", len(ttl_anomalies)))
        
        if not suspicious_indicators:
            return None
        
        severity = Severity.MEDIUM
        
        return CorrelationResult(
            problem_type=ProblemType.MIDDLEBOX_INTERFERENCE,
            severity=severity,
            confidence=Confidence.MEDIUM,
            title="Middlebox interference detected",
            description=(
                f"Detected indicators of middlebox interference. "
                f"{'DSCP remarking: ' + str(suspicious_indicators[0][1]) + ' flow(s). ' if any(i[0]=='dscp_remarking' for i in suspicious_indicators) else ''}"
                f"{'TTL anomalies: ' + str(suspicious_indicators[1][1]) if any(i[0]=='ttl_anomalies' for i in suspicious_indicators) else ''}"
            ),
            affected_objects=[],
            evidence_frames=[],
            first_seen=0,
            last_seen=0,
            event_count=sum(count for _, count in suspicious_indicators),
            correlated_events=[],
            possible_causes=[
                "Firewall performing traffic normalization",
                "WAN optimizer modifying traffic",
                "Load balancer rewriting headers",
                "Transparent proxy intercepting connections",
                "QoS policy remarking DSCP values",
                "NAT device modifying TTL",
            ],
            recommended_actions=[
                "Inventory middleboxes on the traffic path",
                "Review firewall normalization policies",
                "Check QoS marking policies",
                "Verify load balancer persistence and rewriting settings",
                "Compare captures at different points to identify modification point",
            ],
            metrics={
                "indicators": dict(suspicious_indicators),
            },
        )
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of correlation results."""
        return {
            "total_results": len(self.results),
            "by_severity": {
                "critical": len([r for r in self.results if r.severity == Severity.CRITICAL]),
                "high": len([r for r in self.results if r.severity == Severity.HIGH]),
                "medium": len([r for r in self.results if r.severity == Severity.MEDIUM]),
                "low": len([r for r in self.results if r.severity == Severity.LOW]),
                "info": len([r for r in self.results if r.severity == Severity.INFO]),
            },
            "by_problem_type": {
                pt.value: len([r for r in self.results if r.problem_type == pt])
                for pt in ProblemType
            },
            "results": [
                {
                    "problem_type": r.problem_type.value,
                    "title": r.title,
                    "severity": r.severity.value,
                    "confidence": r.confidence.value,
                    "affected_objects_count": len(r.affected_objects),
                    "event_count": r.event_count,
                }
                for r in self.results
            ],
        }
