#!/usr/bin/env python3
"""
Finding Engine

Generates findings from analysis results using rule-based detection.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime

from config import Config
from pcap_analyzer.models.finding import (
    Finding, Severity, Confidence, FindingCategory, FINDING_TEMPLATES
)


class FindingEngine:
    """
    Generates findings from analysis results.
    
    Uses configurable rules and thresholds to detect issues and
    generate actionable findings with recommendations.
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
    
    def generate_findings(
        self,
        tcp_analysis=None,
        dns_analysis=None,
        latency_analysis=None,
        summary=None,
    ) -> List[Finding]:
        """
        Generate findings from analysis results.
        
        Args:
            tcp_analysis: TCPAnalyzer result
            dns_analysis: DNSAnalyzer result
            latency_analysis: LatencyAnalyzer result
            summary: SummaryAnalyzer result
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        if tcp_analysis:
            findings.extend(self._check_tcp_issues(tcp_analysis))
        
        if dns_analysis:
            findings.extend(self._check_dns_issues(dns_analysis))
        
        if latency_analysis:
            findings.extend(self._check_latency_issues(latency_analysis))
        
        if summary:
            findings.extend(self._check_summary_issues(summary))
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        return findings
    
    def _check_tcp_issues(self, tcp_analysis) -> List[Finding]:
        """Check for TCP-related issues."""
        findings = []
        
        # Check for high retransmission connections
        for conn in tcp_analysis.high_retransmission_connections:
            template = FINDING_TEMPLATES["TCP_RETRANS_HIGH"]
            finding = Finding(
                finding_id=template["finding_id"],
                title=template["title"],
                severity=template["severity"],
                confidence=template["confidence"],
                category=template["category"],
                description=(
                    f"TCP flow {conn.src_ip}:{conn.src_port} -> "
                    f"{conn.dst_ip}:{conn.dst_port} has a retransmission rate of "
                    f"{conn.retransmission_rate:.1f}%."
                ),
                affected_object=f"{conn.src_ip}:{conn.src_port} -> {conn.dst_ip}:{conn.dst_port}",
                evidence_frames=conn.retransmit_frames[:10],
                count=conn.retransmissions,
                metrics={
                    'packets': conn.total_packets,
                    'retransmissions': conn.retransmissions,
                    'retransmission_rate': round(conn.retransmission_rate, 2),
                    'avg_rtt_ms': round(conn.avg_rtt_ms, 2) if conn.avg_rtt_ms > 0 else None,
                },
                possible_causes=template["possible_causes"],
                recommended_actions=template["recommended_actions"],
            )
            findings.append(finding)
        
        # Check for failed connections
        for conn in tcp_analysis.failed_connections:
            if conn.result.value == "incomplete_handshake":
                template = FINDING_TEMPLATES["TCP_CONN_FAILED"]
                finding = Finding(
                    finding_id=template["finding_id"],
                    title=template["title"],
                    severity=template["severity"],
                    confidence=Confidence.HIGH,
                    category=FindingCategory.CONNECTIVITY,
                    description=(
                        f"TCP connection attempt from {conn.src_ip}:{conn.src_port} to "
                        f"{conn.dst_ip}:{conn.dst_port} failed: {conn.failure_reason}"
                    ),
                    affected_object=f"{conn.src_ip}:{conn.src_port} -> {conn.dst_ip}:{conn.dst_port}",
                    evidence_frames=[conn.syn_frame] if conn.syn_frame else [],
                    count=conn.syn_count,
                    metrics={
                        'syn_count': conn.syn_count,
                        'syn_ack_count': conn.syn_ack_count,
                    },
                    possible_causes=template["possible_causes"],
                    recommended_actions=template["recommended_actions"],
                )
                findings.append(finding)
            
            elif conn.result.value == "refused":
                finding = Finding(
                    finding_id="TCP-CONN-REFUSED",
                    title="TCP connection refused",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.CONNECTIVITY,
                    description=(
                        f"TCP connection from {conn.src_ip}:{conn.src_port} to "
                        f"{conn.dst_ip}:{conn.dst_port} was refused (RST after SYN). "
                        f"Service may not be running or firewall is blocking."
                    ),
                    affected_object=f"{conn.src_ip}:{conn.src_port} -> {conn.dst_ip}:{conn.dst_port}",
                    evidence_frames=conn.rst_frames[:5],
                    count=conn.rst_count,
                    possible_causes=[
                        "service not listening on destination port",
                        "firewall rejecting connection",
                        "host unreachable",
                    ],
                    recommended_actions=[
                        "verify service is running on destination",
                        "check firewall rules",
                        "test with telnet/nc to verify connectivity",
                    ],
                )
                findings.append(finding)
        
        # Check for zero-window conditions
        total_zero_windows = tcp_analysis.total_zero_windows
        if total_zero_windows > 10:
            finding = Finding(
                finding_id="TCP-ZERO-WINDOW",
                title="TCP zero-window condition detected",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=FindingCategory.TCP_HEALTH,
                description=(
                    f"Detected {total_zero_windows} TCP zero-window events. "
                    f"This indicates receiver buffer exhaustion."
                ),
                affected_object="Multiple TCP flows",
                count=total_zero_windows,
                metrics={'zero_window_events': total_zero_windows},
                possible_causes=FINDING_TEMPLATES["TCP_ZERO_WINDOW"]["possible_causes"],
                recommended_actions=FINDING_TEMPLATES["TCP_ZERO_WINDOW"]["recommended_actions"],
            )
            findings.append(finding)
        
        return findings
    
    def _check_dns_issues(self, dns_analysis) -> List[Finding]:
        """Check for DNS-related issues."""
        findings = []
        
        # Check for slow DNS responses
        if dns_analysis.slow_queries_count > 5:
            template = FINDING_TEMPLATES["DNS_SLOW_RESPONSE"]
            finding = Finding(
                finding_id=template["finding_id"],
                title=template["title"],
                severity=template["severity"],
                confidence=template["confidence"],
                category=template["category"],
                description=(
                    f"Detected {dns_analysis.slow_queries_count} DNS queries with response time "
                    f"above {self.config.analysis.dns_slow_response_threshold_ms}ms. "
                    f"Average latency: {dns_analysis.avg_latency_ms:.1f}ms"
                ),
                affected_object="DNS infrastructure",
                count=dns_analysis.slow_queries_count,
                metrics={
                    'slow_queries': dns_analysis.slow_queries_count,
                    'avg_latency_ms': round(dns_analysis.avg_latency_ms, 2),
                    'max_latency_ms': round(dns_analysis.max_latency_ms, 2),
                },
                possible_causes=template["possible_causes"],
                recommended_actions=template["recommended_actions"],
            )
            findings.append(finding)
        
        # Check for high NXDOMAIN rate
        if dns_analysis.total_queries > 0:
            nxdomain_rate = (dns_analysis.nxdomain_count / dns_analysis.total_queries) * 100
            if nxdomain_rate > self.config.analysis.dns_high_nxdomain_threshold:
                template = FINDING_TEMPLATES["DNS_NXDOMAIN_HIGH"]
                finding = Finding(
                    finding_id=template["finding_id"],
                    title=template["title"],
                    severity=template["severity"],
                    confidence=template["confidence"],
                    category=template["category"],
                    description=(
                        f"High rate of NXDOMAIN responses: {nxdomain_rate:.1f}% "
                        f"({dns_analysis.nxdomain_count} of {dns_analysis.total_queries} queries)"
                    ),
                    affected_object="DNS infrastructure",
                    count=dns_analysis.nxdomain_count,
                    metrics={
                        'nxdomain_count': dns_analysis.nxdomain_count,
                        'total_queries': dns_analysis.total_queries,
                        'nxdomain_rate': round(nxdomain_rate, 2),
                    },
                    possible_causes=template["possible_causes"],
                    recommended_actions=template["recommended_actions"],
                )
                findings.append(finding)
        
        # Check for unanswered queries
        if dns_analysis.unanswered_queries > 10:
            finding = Finding(
                finding_id="DNS-UNANSWERED",
                title="Unanswered DNS queries detected",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.DNS,
                description=(
                    f"{dns_analysis.unanswered_queries} DNS queries received no response. "
                    f"This may indicate DNS server issues or packet loss."
                ),
                affected_object="DNS infrastructure",
                count=dns_analysis.unanswered_queries,
                metrics={
                    'unanswered_queries': dns_analysis.unanswered_queries,
                    'total_queries': dns_analysis.total_queries,
                },
                possible_causes=[
                    "DNS server overload or failure",
                    "network packet loss",
                    "firewall blocking DNS responses",
                ],
                recommended_actions=[
                    "check DNS server health",
                    "verify network path to DNS servers",
                    "check for DNS traffic filtering",
                ],
            )
            findings.append(finding)
        
        return findings
    
    def _check_latency_issues(self, latency_analysis) -> List[Finding]:
        """Check for latency-related issues."""
        findings = []
        
        # Check for high TCP RTT
        if latency_analysis.avg_tcp_rtt_ms > self.config.analysis.high_latency_threshold_ms:
            finding = Finding(
                finding_id="LATENCY-HIGH-TCP",
                title="High TCP latency detected",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=FindingCategory.LATENCY,
                description=(
                    f"Average TCP handshake RTT is {latency_analysis.avg_tcp_rtt_ms:.1f}ms. "
                    f"Max RTT: {latency_analysis.max_tcp_rtt_ms:.1f}ms"
                ),
                affected_object="Network path",
                count=len(latency_analysis.tcp_handshake_rtts),
                metrics={
                    'avg_rtt_ms': round(latency_analysis.avg_tcp_rtt_ms, 2),
                    'min_rtt_ms': round(latency_analysis.min_tcp_rtt_ms, 2),
                    'max_rtt_ms': round(latency_analysis.max_tcp_rtt_ms, 2),
                },
                possible_causes=[
                    "long network path",
                    "congestion on path",
                    "queuing delays",
                    "satellite or long-distance links",
                ],
                recommended_actions=[
                    "analyze path with traceroute",
                    "check for congestion indicators",
                    "verify routing is optimal",
                ],
            )
            findings.append(finding)
        
        return findings
    
    def _check_summary_issues(self, summary) -> List[Finding]:
        """Check for issues visible in summary statistics."""
        findings = []
        
        # Check overall retransmission rate
        if summary.total_packets > 0:
            retrans_rate = (summary.retransmission_count / summary.total_packets) * 100
            if retrans_rate > self.config.analysis.critical_retransmission_threshold:
                finding = Finding(
                    finding_id="RETRANS-CRITICAL",
                    title="Critical retransmission rate detected",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.PACKET_LOSS,
                    description=(
                        f"Overall retransmission rate is {retrans_rate:.1f}% "
                        f"({summary.retransmission_count} of {summary.total_packets} packets)"
                    ),
                    affected_object="All traffic",
                    count=summary.retransmission_count,
                    metrics={
                        'retransmission_count': summary.retransmission_count,
                        'total_packets': summary.total_packets,
                        'retransmission_rate': round(retrans_rate, 2),
                    },
                    possible_causes=[
                        "severe network congestion",
                        "interface errors",
                        "faulty network equipment",
                        "wireless interference",
                    ],
                    recommended_actions=[
                        "immediately check interface error counters",
                        "identify congested links",
                        "check for hardware issues",
                        "engage network operations team",
                    ],
                )
                findings.append(finding)
        
        return findings
