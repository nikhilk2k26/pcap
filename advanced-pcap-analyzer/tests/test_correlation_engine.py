#!/usr/bin/env python3
"""
Tests for the Correlation Engine.
"""

import pytest
from unittest.mock import Mock

from pcap_analyzer.detection.correlation_engine import (
    CorrelationEngine,
    CorrelatedEvent,
    CorrelationResult,
    ProblemType,
)
from pcap_analyzer.models.finding import Severity, Confidence


class TestCorrelatedEvent:
    """Test CorrelatedEvent dataclass."""

    def test_create_event(self):
        event = CorrelatedEvent(
            event_type="tcp_syn",
            timestamp=1234567890.0,
            frame_number=100,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
        )
        assert event.event_type == "tcp_syn"
        assert event.frame_number == 100
        assert event.src_ip == "192.168.1.10"
        assert event.dst_ip == "10.0.0.5"
        assert event.details == {}
        assert event.metrics == {}

    def test_create_event_with_details(self):
        event = CorrelatedEvent(
            event_type="icmp_unreachable",
            timestamp=1234567890.0,
            frame_number=200,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.10",
            protocol="ICMP",
            details={"type": 3, "code": 1, "reason": "host_unreachable"},
        )
        assert event.details["type"] == 3
        assert event.details["code"] == 1


class TestCorrelationResult:
    """Test CorrelationResult dataclass."""

    def test_create_result(self):
        result = CorrelationResult(
            problem_type=ProblemType.NO_CONNECTIVITY,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Connectivity failure detected",
            description="Multiple connection attempts failed",
            affected_objects=["10.0.0.5:443", "10.0.0.6:80"],
            evidence_frames=[100, 101, 102],
            first_seen=1234567890.0,
            last_seen=1234567900.0,
            event_count=5,
            correlated_events=[],
            possible_causes=["firewall blocking", "host down"],
            recommended_actions=["check firewall", "verify host status"],
        )
        assert result.problem_type == ProblemType.NO_CONNECTIVITY
        assert result.severity == Severity.HIGH
        assert len(result.affected_objects) == 2
        assert len(result.evidence_frames) == 3

    def test_to_finding(self):
        result = CorrelationResult(
            problem_type=ProblemType.MTU_PROBLEMS,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            title="MTU issues detected",
            description="ICMP fragmentation needed messages received",
            affected_objects=["192.168.1.1 -> 10.0.0.1"],
            evidence_frames=[50, 51],
            first_seen=1234567890.0,
            last_seen=1234567900.0,
            event_count=3,
            correlated_events=[],
            possible_causes=["MTU mismatch"],
            recommended_actions=["check path MTU"],
        )
        finding = result.to_finding()
        assert finding.finding_id == "CORR-MTU-PROBLEMS"
        assert finding.severity == Severity.MEDIUM
        assert finding.category.value == "correlation"


class TestCorrelationEngine:
    """Test CorrelationEngine functionality."""

    def test_create_engine(self):
        engine = CorrelationEngine()
        assert engine.events == []
        assert engine.results == []

    def test_add_event(self):
        engine = CorrelationEngine()
        event = CorrelatedEvent(
            event_type="tcp_syn",
            timestamp=1234567890.0,
            frame_number=100,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
        )
        engine.add_event(event)
        assert len(engine.events) == 1

    def test_add_events(self):
        engine = CorrelationEngine()
        events = [
            CorrelatedEvent("tcp_syn", 1234567890.0, 100),
            CorrelatedEvent("tcp_rst", 1234567891.0, 101),
        ]
        engine.add_events(events)
        assert len(engine.events) == 2

    def test_clear_events(self):
        engine = CorrelationEngine()
        engine.add_event(CorrelatedEvent("tcp_syn", 1234567890.0, 100))
        engine.clear_events()
        assert engine.events == []
        assert engine.results == []


class TestNoConnectivityCorrelation:
    """Test no connectivity correlation rules."""

    def test_detect_syn_no_ack(self):
        engine = CorrelationEngine()
        
        # Mock TCP analysis with SYN-only connections
        tcp_analysis = Mock()
        conn = Mock()
        conn.syn_count = 3
        conn.syn_ack_count = 0
        conn.rst_count = 0
        conn.src_ip = "192.168.1.10"
        conn.dst_ip = "10.0.0.5"
        conn.src_port = 54321
        conn.dst_port = 443
        conn.syn_frame = 100
        conn.start_time = 1234567890.0
        conn.failure_reason = "no_syn_ack"
        tcp_analysis.connections = [conn]
        
        analysis_results = {"tcp_analysis": tcp_analysis}
        results = engine.correlate(analysis_results)
        
        # Should detect connectivity issue
        connectivity_results = [
            r for r in results if r.problem_type == ProblemType.NO_CONNECTIVITY
        ]
        assert len(connectivity_results) > 0

    def test_detect_with_icmp_unreachable(self):
        engine = CorrelationEngine()
        
        # Mock TCP analysis
        tcp_analysis = Mock()
        conn = Mock()
        conn.syn_count = 1
        conn.syn_ack_count = 0
        conn.rst_count = 0
        conn.src_ip = "192.168.1.10"
        conn.dst_ip = "10.0.0.5"
        conn.src_port = 54321
        conn.dst_port = 443
        conn.syn_frame = 100
        conn.start_time = 1234567890.0
        conn.failure_reason = "no_syn_ack"
        tcp_analysis.connections = [conn]
        
        # Mock ICMP analysis with unreachable
        icmp_analysis = Mock()
        icmp_event = {
            "type": 3,
            "code": 1,
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.10",
            "frame_number": 101,
            "timestamp": 1234567890.5,
        }
        icmp_analysis.events = [icmp_event]
        
        analysis_results = {
            "tcp_analysis": tcp_analysis,
            "icmp_analysis": icmp_analysis,
        }
        results = engine.correlate(analysis_results)
        
        connectivity_results = [
            r for r in results if r.problem_type == ProblemType.NO_CONNECTIVITY
        ]
        assert len(connectivity_results) > 0
        # Confidence should be HIGH when ICMP confirms
        assert connectivity_results[0].confidence == Confidence.HIGH


class TestIntermittentPerformanceCorrelation:
    """Test intermittent performance correlation rules."""

    def test_detect_high_retransmissions(self):
        engine = CorrelationEngine()
        
        tcp_analysis = Mock()
        conn = Mock()
        conn.retransmission_rate = 8.5  # >5%
        conn.duplicate_ack_count = 15
        conn.out_of_order_count = 3
        conn.src_ip = "192.168.1.10"
        conn.dst_ip = "10.0.0.5"
        conn.src_port = 54321
        conn.dst_port = 443
        conn.retransmissions = 50
        conn.retransmit_frames = [100, 105, 110]
        tcp_analysis.connections = [conn]
        
        analysis_results = {"tcp_analysis": tcp_analysis}
        results = engine.correlate(analysis_results)
        
        perf_results = [
            r for r in results if r.problem_type == ProblemType.INTERMITTENT_PERFORMANCE
        ]
        assert len(perf_results) > 0

    def test_multiple_affected_flows(self):
        engine = CorrelationEngine()
        
        tcp_analysis = Mock()
        connections = []
        for i in range(15):
            conn = Mock()
            conn.retransmission_rate = 6.0 + i
            conn.duplicate_ack_count = 5
            conn.out_of_order_count = 2
            conn.src_ip = f"192.168.1.{10 + i}"
            conn.dst_ip = "10.0.0.5"
            conn.src_port = 54321 + i
            conn.dst_port = 443
            conn.retransmissions = 10
            conn.retransmit_frames = [100 + i]
            connections.append(conn)
        tcp_analysis.connections = connections
        
        analysis_results = {"tcp_analysis": tcp_analysis}
        results = engine.correlate(analysis_results)
        
        perf_results = [
            r for r in results if r.problem_type == ProblemType.INTERMITTENT_PERFORMANCE
        ]
        assert len(perf_results) > 0
        # Should be HIGH severity with many affected flows
        assert perf_results[0].severity == Severity.HIGH


class TestApplicationSlownessCorrelation:
    """Test application slowness correlation rules."""

    def test_detect_high_rtt_low_retrans(self):
        engine = CorrelationEngine()
        
        tcp_analysis = Mock()
        conn = Mock()
        conn.avg_rtt_ms = 250  # >200ms
        conn.retransmission_rate = 1.0  # <2%
        conn.zero_window_count = 0
        conn.src_ip = "192.168.1.10"
        conn.dst_ip = "10.0.0.5"
        conn.src_port = 54321
        conn.dst_port = 443
        tcp_analysis.connections = [conn]
        
        analysis_results = {"tcp_analysis": tcp_analysis}
        results = engine.correlate(analysis_results)
        
        slow_results = [
            r for r in results if r.problem_type == ProblemType.APPLICATION_SLOWNESS
        ]
        assert len(slow_results) > 0

    def test_detect_zero_window(self):
        engine = CorrelationEngine()
        
        tcp_analysis = Mock()
        conn = Mock()
        conn.avg_rtt_ms = 50
        conn.retransmission_rate = 0.5
        conn.zero_window_count = 60  # >50 triggers HIGH severity
        tcp_analysis.connections = [conn]
        
        analysis_results = {"tcp_analysis": tcp_analysis}
        results = engine.correlate(analysis_results)
        
        slow_results = [
            r for r in results if r.problem_type == ProblemType.APPLICATION_SLOWNESS
        ]
        assert len(slow_results) > 0
        assert slow_results[0].severity == Severity.HIGH


class TestMTUProblemsCorrelation:
    """Test MTU problems correlation rules."""

    def test_detect_fragmentation_needed(self):
        engine = CorrelationEngine()
        
        icmp_analysis = Mock()
        # ICMP Type 3, Code 4 = Fragmentation Needed
        icmp_event = {
            "type": 3,
            "code": 4,
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.10",
            "frame_number": 500,
            "next_hop_mtu": 1500,
        }
        icmp_analysis.events = [icmp_event] * 15  # Multiple events
        
        analysis_results = {"icmp_analysis": icmp_analysis}
        results = engine.correlate(analysis_results)
        
        mtu_results = [
            r for r in results if r.problem_type == ProblemType.MTU_PROBLEMS
        ]
        assert len(mtu_results) > 0
        # Should be HIGH with many events
        assert mtu_results[0].severity == Severity.HIGH


class TestDNSProblemsCorrelation:
    """Test DNS problems correlation rules."""

    def test_detect_slow_queries(self):
        engine = CorrelationEngine()
        
        dns_analysis = Mock()
        dns_analysis.slow_queries = list(range(10))  # 10 slow queries
        dns_analysis.unanswered_queries = 5
        dns_analysis.nxdomain_count = 50
        dns_analysis.servfail_count = 10
        dns_analysis.total_queries = 200
        dns_analysis.retransmitted_queries = 15
        dns_analysis.dns_servers = {
            "8.8.8.8": {"avg_latency_ms": 250, "failure_rate": 5},
        }
        
        analysis_results = {"dns_analysis": dns_analysis}
        results = engine.correlate(analysis_results)
        
        dns_results = [
            r for r in results if r.problem_type == ProblemType.DNS_PROBLEMS
        ]
        assert len(dns_results) > 0

    def test_detect_high_servfail_rate(self):
        engine = CorrelationEngine()
        
        dns_analysis = Mock()
        dns_analysis.slow_queries = []
        dns_analysis.unanswered_queries = 0
        dns_analysis.nxdomain_count = 10
        dns_analysis.servfail_count = 50  # High SERVFAIL
        dns_analysis.total_queries = 100
        dns_analysis.retransmitted_queries = 5
        dns_analysis.dns_servers = {}
        
        analysis_results = {"dns_analysis": dns_analysis}
        results = engine.correlate(analysis_results)
        
        dns_results = [
            r for r in results if r.problem_type == ProblemType.DNS_PROBLEMS
        ]
        assert len(dns_results) > 0
        # Should be HIGH with high SERVFAIL rate
        assert dns_results[0].severity == Severity.HIGH


class TestARPIPConflictsCorrelation:
    """Test ARP/IP conflict correlation rules."""

    def test_detect_duplicate_ip(self):
        engine = CorrelationEngine()
        
        arp_analysis = Mock()
        arp_analysis.duplicate_ips = [
            {"ip": "192.168.1.100", "macs": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]}
        ]
        arp_analysis.storm_detected = False
        arp_analysis.gratuitous_arp_count = 5
        arp_analysis.mac_flapping = []
        
        analysis_results = {"arp_analysis": arp_analysis}
        results = engine.correlate(analysis_results)
        
        arp_results = [
            r for r in results if r.problem_type == ProblemType.ARP_IP_CONFLICTS
        ]
        assert len(arp_results) > 0
        # Duplicate IP is CRITICAL
        assert arp_results[0].severity == Severity.CRITICAL


class TestCongestionCorrelation:
    """Test congestion correlation rules."""

    def test_detect_widespread_retransmissions(self):
        engine = CorrelationEngine()
        
        tcp_analysis = Mock()
        connections = []
        for i in range(20):
            conn = Mock()
            conn.retransmissions = 10 if i < 15 else 0  # 75% have retrans
            conn.ecn_ce_count = 5 if i < 5 else 0
            connections.append(conn)
        tcp_analysis.connections = connections
        
        analysis_results = {"tcp_analysis": tcp_analysis}
        results = engine.correlate(analysis_results)
        
        congestion_results = [
            r for r in results if r.problem_type == ProblemType.CONGESTION
        ]
        assert len(congestion_results) > 0
        # With ECN marks, confidence should be HIGH
        assert congestion_results[0].confidence == Confidence.HIGH


class TestCorrelationSummary:
    """Test correlation summary generation."""

    def test_get_summary(self):
        engine = CorrelationEngine()
        
        # Create some mock results
        engine.results = [
            CorrelationResult(
                problem_type=ProblemType.NO_CONNECTIVITY,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Test",
                description="Test",
                affected_objects=[],
                evidence_frames=[],
                first_seen=0,
                last_seen=0,
                event_count=1,
                correlated_events=[],
                possible_causes=[],
                recommended_actions=[],
            ),
            CorrelationResult(
                problem_type=ProblemType.MTU_PROBLEMS,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="Test",
                description="Test",
                affected_objects=[],
                evidence_frames=[],
                first_seen=0,
                last_seen=0,
                event_count=1,
                correlated_events=[],
                possible_causes=[],
                recommended_actions=[],
            ),
        ]
        
        summary = engine.get_summary()
        assert summary["total_results"] == 2
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert "no_connectivity" in summary["by_problem_type"]
        assert "mtu_problems" in summary["by_problem_type"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
