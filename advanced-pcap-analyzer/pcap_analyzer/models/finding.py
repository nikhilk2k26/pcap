#!/usr/bin/env python3
"""
Finding Model

Represents analysis findings with severity, confidence, and recommendations.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """Finding severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(Enum):
    """Finding confidence levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingCategory(Enum):
    """Finding categories."""
    CONNECTIVITY = "connectivity"
    PERFORMANCE = "performance"
    TCP_HEALTH = "tcp_health"
    PACKET_LOSS = "packet_loss"
    LATENCY = "latency"
    MTU_MSS = "mtu_mss"
    FRAGMENTATION = "fragmentation"
    ICMP = "icmp"
    DNS = "dns"
    DHCP = "dhcp"
    ARP = "arp"
    VLAN = "vlan"
    QOS = "qos"
    SECURITY = "security"
    ANOMALY = "anomaly"
    APPLICATION = "application"
    CORRELATION = "correlation"


@dataclass
class Finding:
    """
    Analysis finding with evidence and recommendations.
    
    Each finding represents a detected issue or observation with:
    - Clear identification
    - Severity and confidence assessment
    - Evidence (frame numbers, metrics)
    - Possible causes
    - Recommended actions
    """
    
    # Identification
    finding_id: str  # Unique identifier like "TCP-RETRANS-HIGH"
    title: str  # Human-readable title
    
    # Assessment
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    
    # Description
    description: str  # Detailed description of the finding
    
    # Affected object (IP, flow, interface, etc.)
    affected_object: Optional[str] = None
    
    # Evidence
    evidence_frames: List[int] = field(default_factory=list)  # Frame numbers
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    count: int = 1  # Number of occurrences
    
    # Metrics
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Root cause analysis
    possible_causes: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    
    # Additional context
    tags: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'finding_id': self.finding_id,
            'title': self.title,
            'severity': self.severity.value,
            'confidence': self.confidence.value,
            'category': self.category.value,
            'description': self.description,
            'affected_object': self.affected_object,
            'evidence_frames': self.evidence_frames,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'count': self.count,
            'metrics': self.metrics,
            'possible_causes': self.possible_causes,
            'recommended_actions': self.recommended_actions,
            'tags': self.tags,
            'related_findings': self.related_findings,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create Finding from dictionary."""
        return cls(
            finding_id=data['finding_id'],
            title=data['title'],
            severity=Severity(data['severity']),
            confidence=Confidence(data['confidence']),
            category=FindingCategory(data['category']),
            description=data['description'],
            affected_object=data.get('affected_object'),
            evidence_frames=data.get('evidence_frames', []),
            first_seen=datetime.fromisoformat(data['first_seen']) if data.get('first_seen') else None,
            last_seen=datetime.fromisoformat(data['last_seen']) if data.get('last_seen') else None,
            count=data.get('count', 1),
            metrics=data.get('metrics', {}),
            possible_causes=data.get('possible_causes', []),
            recommended_actions=data.get('recommended_actions', []),
            tags=data.get('tags', []),
            related_findings=data.get('related_findings', []),
        )
    
    def add_evidence_frame(self, frame_number: int):
        """Add an evidence frame number."""
        if frame_number not in self.evidence_frames:
            self.evidence_frames.append(frame_number)
            self.evidence_frames.sort()
    
    def update_time_range(self, timestamp: datetime):
        """Update first_seen and last_seen timestamps."""
        if self.first_seen is None or timestamp < self.first_seen:
            self.first_seen = timestamp
        if self.last_seen is None or timestamp > self.last_seen:
            self.last_seen = timestamp
    
    def get_summary(self) -> str:
        """Get a one-line summary of the finding."""
        return f"[{self.severity.value.upper()}] {self.title}: {self.affected_object or 'N/A'}"


# Pre-defined finding templates for common issues

FINDING_TEMPLATES = {
    "TCP_RETRANS_HIGH": {
        "finding_id": "TCP-RETRANS-HIGH",
        "title": "High TCP retransmission rate detected",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "category": FindingCategory.TCP_HEALTH,
        "possible_causes": [
            "network packet loss",
            "congestion on the path",
            "interface errors or duplex mismatch",
            "QoS policy drops",
            "buffer exhaustion on network devices",
        ],
        "recommended_actions": [
            "check interface error counters on path devices",
            "verify QoS policy drops and queue depths",
            "check path latency and congestion indicators",
            "inspect middlebox or firewall session handling",
            "review cable quality and physical layer issues",
        ],
    },
    "TCP_ZERO_WINDOW": {
        "finding_id": "TCP-ZERO-WINDOW",
        "title": "TCP zero-window condition detected",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "category": FindingCategory.TCP_HEALTH,
        "possible_causes": [
            "receiver application processing slowly",
            "receiver TCP buffer exhaustion",
            "memory pressure on receiving host",
            "TCP window scaling misconfiguration",
        ],
        "recommended_actions": [
            "check receiving application performance",
            "verify TCP receive buffer settings",
            "check system memory and CPU utilization",
            "verify middlebox window size handling",
        ],
    },
    "TCP_CONN_FAILED": {
        "finding_id": "TCP-CONN-FAILED",
        "title": "TCP connection attempt failed",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "category": FindingCategory.CONNECTIVITY,
        "possible_causes": [
            "destination host down or unreachable",
            "firewall blocking the connection",
            "routing issue preventing reachability",
            "ACL blocking at intermediate device",
            "service not listening on destination port",
        ],
        "recommended_actions": [
            "verify route to destination exists",
            "check firewall/ACL rules for blocking",
            "test connectivity with traceroute",
            "verify service is running on destination",
            "check for NAT translation issues",
        ],
    },
    "DNS_SLOW_RESPONSE": {
        "finding_id": "DNS-SLOW-RESPONSE",
        "title": "DNS server slow response detected",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "category": FindingCategory.DNS,
        "possible_causes": [
            "DNS server overload or resource exhaustion",
            "network latency to DNS server",
            "DNS server performing recursive lookups",
            "firewall inspection delaying DNS traffic",
        ],
        "recommended_actions": [
            "check DNS server health and query rates",
            "verify network path to DNS server",
            "consider adding local DNS caching",
            "review DNS ACLs and firewall rules",
        ],
    },
    "DNS_NXDOMAIN_HIGH": {
        "finding_id": "DNS-NXDOMAIN-HIGH",
        "title": "High rate of NXDOMAIN responses",
        "severity": Severity.LOW,
        "confidence": Confidence.MEDIUM,
        "category": FindingCategory.DNS,
        "possible_causes": [
            "misconfigured applications requesting invalid domains",
            "typo-squatting or malware activity",
            "stale DNS cache entries",
            "DNS tunneling attempts",
        ],
        "recommended_actions": [
            "identify sources of invalid queries",
            "check for malware or unauthorized software",
            "review application DNS configurations",
            "monitor for DNS tunneling patterns",
        ],
    },
    "MTU_ISSUE": {
        "finding_id": "MTU-ISSUE",
        "title": "MTU/MSS mismatch or PMTUD issue detected",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "category": FindingCategory.MTU_MSS,
        "possible_causes": [
            "MTU mismatch along the path",
            "tunnel interface MTU too small",
            "ICMP fragmentation-needed messages blocked",
            "PMTUD black hole",
        ],
        "recommended_actions": [
            "verify path MTU with ping tests",
            "adjust MSS clamping on edge devices",
            "ensure ICMP is not filtered",
            "check tunnel interface MTU settings",
        ],
    },
    "ARP_STORM": {
        "finding_id": "ARP-STORM",
        "title": "Excessive ARP traffic detected",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "category": FindingCategory.ARP,
        "possible_causes": [
            "network loop or broadcast storm",
            "faulty network device",
            "ARP cache poisoning attempt",
            "misconfigured host generating excessive ARP",
        ],
        "recommended_actions": [
            "check for network loops",
            "identify source of excessive ARP",
            "verify STP configuration",
            "check for ARP spoofing indicators",
        ],
    },
    "DUPLICATE_IP": {
        "finding_id": "DUPLICATE-IP",
        "title": "Duplicate IP address detected",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "category": FindingCategory.ARP,
        "possible_causes": [
            "static IP conflict",
            "DHCP server assigning duplicate addresses",
            "rogue DHCP server",
            "misconfigured device",
        ],
        "recommended_actions": [
            "identify all devices using the IP",
            "check DHCP server lease tables",
            "verify static IP assignments",
            "isolate conflicting devices",
        ],
    },
}
