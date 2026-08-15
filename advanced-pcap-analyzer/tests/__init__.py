#!/usr/bin/env python3
"""
Test suite for Advanced PCAP Analyzer.
"""

import pytest
from pathlib import Path


def test_file_detector():
    """Test file detection module."""
    from pcap_analyzer.ingestion.file_detector import FileDetector, CaptureFileType
    
    detector = FileDetector()
    
    # Test with non-existent file
    result = detector.detect(Path("/nonexistent/file.pcap"))
    assert not result.is_valid
    assert result.file_type == CaptureFileType.UNKNOWN


def test_packet_model():
    """Test packet model creation."""
    from pcap_analyzer.models.packet import NormalizedPacket
    
    packet = NormalizedPacket(
        frame_number=1,
        timestamp_epoch=1234567890.123,
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        protocol=6,
        src_port=12345,
        dst_port=80,
    )
    
    assert packet.is_tcp
    assert packet.is_ipv4
    assert not packet.is_udp


def test_flow_model():
    """Test flow record model."""
    from pcap_analyzer.models.flow import FlowRecord
    
    flow = FlowRecord(
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        src_port=12345,
        dst_port=443,
        protocol=6,
    )
    
    assert "192.168.1.1" in flow.flow_id
    assert "192.168.1.2" in flow.flow_id
    assert flow.protocol_name == "TCP"


def test_finding_model():
    """Test finding model."""
    from pcap_analyzer.models.finding import Finding, Severity, Confidence, FindingCategory
    
    finding = Finding(
        finding_id="TEST-001",
        title="Test Finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=FindingCategory.TCP_HEALTH,
        description="This is a test finding",
        affected_object="192.168.1.1:80",
    )
    
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH
    assert "TEST-001" in finding.finding_id
    
    # Test serialization
    data = finding.to_dict()
    assert data['severity'] == 'high'


def test_tcp_analyzer_basic():
    """Test TCP analyzer basic functionality."""
    # This test would require a real store with packets
    # For now, just verify the class can be imported and instantiated
    from pcap_analyzer.analysis.tcp_analyzer import TCPAnalyzer, TCPConnection
    
    conn = TCPConnection(
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        src_port=12345,
        dst_port=80,
    )
    
    assert conn.src_ip == "192.168.1.1"
    assert conn.dst_port == 80


def test_dns_analyzer_basic():
    """Test DNS analyzer basic functionality."""
    from pcap_analyzer.analysis.dns_analyzer import DNSAnalyzer, DNSTransaction
    
    txn = DNSTransaction(
        query_frame=1,
        query_name="example.com",
        client_ip="192.168.1.1",
        server_ip="8.8.8.8",
    )
    
    assert txn.query_name == "example.com"
    assert txn.query_type_name == "TYPE0"


def test_config_loading():
    """Test configuration loading."""
    from config import Config, DEFAULT_CONFIG
    
    config = Config.load()
    
    assert config.analysis.chunk_size > 0
    assert config.report.top_talkers_count > 0


def test_storage_basic():
    """Test storage backend basic operations."""
    from pcap_analyzer.storage.sqlite_store import SQLiteStore
    from config import Config
    
    config = Config()
    config.storage.sqlite_use_memory = True
    
    store = SQLiteStore(config)
    store.initialize_schema()
    
    count = store.get_packet_count()
    assert count == 0
    
    store.cleanup()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
