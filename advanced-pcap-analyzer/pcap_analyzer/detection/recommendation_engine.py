#!/usr/bin/env python3
"""
Recommendation Engine

Provides root-cause suggestions and remediation recommendations.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from pcap_analyzer.models.finding import Finding


@dataclass
class Recommendation:
    """A specific recommendation for addressing a finding."""
    
    priority: int  # 1 = highest
    action: str
    rationale: str
    commands: List[str] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.commands is None:
            self.commands = []
        if self.references is None:
            self.references = []


class RecommendationEngine:
    """
    Generates recommendations based on findings.
    """
    
    def __init__(self):
        pass
    
    def generate_recommendations(self, finding: Finding) -> List[Recommendation]:
        """
        Generate recommendations for a specific finding.
        
        Args:
            finding: The finding to generate recommendations for
            
        Returns:
            List of Recommendation objects
        """
        recommendations = []
        
        # TCP retransmissions
        if finding.finding_id == "TCP-RETRANS-HIGH":
            recommendations.extend(self._recommend_for_retrans(finding))
        
        # TCP connection failures
        elif finding.finding_id == "TCP-CONN-FAILED":
            recommendations.extend(self._recommend_for_conn_failure(finding))
        
        # DNS issues
        elif finding.finding_id in ("DNS-SLOW-RESPONSE", "DNS-UNANSWERED"):
            recommendations.extend(self._recommend_for_dns(finding))
        
        # Zero window
        elif finding.finding_id == "TCP-ZERO-WINDOW":
            recommendations.extend(self._recommend_for_zero_window(finding))
        
        # High latency
        elif finding.finding_id == "LATENCY-HIGH-TCP":
            recommendations.extend(self._recommend_for_latency(finding))
        
        return recommendations
    
    def _recommend_for_retrans(self, finding: Finding) -> List[Recommendation]:
        """Generate recommendations for high retransmission."""
        return [
            Recommendation(
                priority=1,
                action="Check interface error counters on path devices",
                rationale="Physical layer issues or duplex mismatches cause packet loss",
                commands=[
                    "show interfaces counters errors",
                    "show interfaces status",
                    "ethtool -S <interface>",
                ],
            ),
            Recommendation(
                priority=2,
                action="Verify QoS policy drops",
                rationale="QoS policies may be dropping traffic during congestion",
                commands=[
                    "show policy-map interface <interface>",
                    "show queueing interface <interface>",
                ],
            ),
            Recommendation(
                priority=3,
                action="Check for network congestion",
                rationale="Congestion causes buffer overflows and packet loss",
                commands=[
                    "show interfaces utilization",
                    "monitor interface <interface>",
                ],
            ),
        ]
    
    def _recommend_for_conn_failure(self, finding: Finding) -> List[Recommendation]:
        """Generate recommendations for connection failures."""
        return [
            Recommendation(
                priority=1,
                action="Verify service is running on destination",
                rationale="Service may not be listening on the target port",
                commands=[
                    f"telnet {finding.affected_object.split('->')[-1].strip()}",
                    "systemctl status <service>",
                    "netstat -tlnp | grep <port>",
                ],
            ),
            Recommendation(
                priority=2,
                action="Check firewall rules",
                rationale="Firewall may be blocking the connection",
                commands=[
                    "show access-lists",
                    "show firewall session-table",
                    "iptables -L -n",
                ],
            ),
            Recommendation(
                priority=3,
                action="Verify routing to destination",
                rationale="Routing issues may prevent reachability",
                commands=[
                    "traceroute <destination>",
                    "show ip route <destination>",
                ],
            ),
        ]
    
    def _recommend_for_dns(self, finding: Finding) -> List[Recommendation]:
        """Generate recommendations for DNS issues."""
        return [
            Recommendation(
                priority=1,
                action="Check DNS server health",
                rationale="DNS server may be overloaded or experiencing issues",
                commands=[
                    "systemctl status named",
                    "top -p $(pgrep named)",
                    "dig @localhost version.bind chaos txt",
                ],
            ),
            Recommendation(
                priority=2,
                action="Verify network path to DNS servers",
                rationale="Network issues may affect DNS traffic",
                commands=[
                    "ping <dns-server>",
                    "traceroute <dns-server>",
                ],
            ),
            Recommendation(
                priority=3,
                action="Consider adding local DNS caching",
                rationale="Local caching reduces DNS server load and improves response times",
                commands=[
                    "apt install dnsmasq",
                    "systemctl enable systemd-resolved",
                ],
            ),
        ]
    
    def _recommend_for_zero_window(self, finding: Finding) -> List[Recommendation]:
        """Generate recommendations for zero-window conditions."""
        return [
            Recommendation(
                priority=1,
                action="Check receiving application performance",
                rationale="Application may be too slow to consume received data",
                commands=[
                    "top -p <pid>",
                    "iotop",
                    "strace -p <pid>",
                ],
            ),
            Recommendation(
                priority=2,
                action="Verify TCP receive buffer settings",
                rationale="Buffer size may be too small for the workload",
                commands=[
                    "sysctl net.ipv4.tcp_rmem",
                    "ss -tm",
                ],
            ),
        ]
    
    def _recommend_for_latency(self, finding: Finding) -> List[Recommendation]:
        """Generate recommendations for high latency."""
        return [
            Recommendation(
                priority=1,
                action="Analyze network path with traceroute",
                rationale="Identify hops contributing to latency",
                commands=[
                    "traceroute -n <destination>",
                    "mtr <destination>",
                ],
            ),
            Recommendation(
                priority=2,
                action="Check for congestion on path",
                rationale="Congestion causes queuing delays",
                commands=[
                    "show interfaces utilization",
                    "show policy-map interface",
                ],
            ),
            Recommendation(
                priority=3,
                action="Verify routing is optimal",
                rationale="Suboptimal routing may add unnecessary hops",
                commands=[
                    "show ip route <destination>",
                    "show bgp summary",
                ],
            ),
        ]
