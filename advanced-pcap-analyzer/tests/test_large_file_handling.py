#!/usr/bin/env python3
"""
Tests for Large File Handling

Tests streaming, chunking, sampling, and database storage.
"""

import pytest
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch


class TestChunkProcessor:
    """Test chunked processing of large files."""
    
    def test_chunk_info_creation(self):
        """Test ChunkInfo dataclass."""
        from pcap_analyzer.ingestion.chunk_processor import ChunkInfo
        
        chunk = ChunkInfo(
            chunk_id=0,
            start_frame=1,
            end_frame=1000
        )
        
        assert chunk.chunk_id == 0
        assert chunk.start_frame == 1
        assert chunk.end_frame == 1000
        assert chunk.packet_count == 0
        assert chunk.status == "pending"
    
    def test_processing_progress(self):
        """Test ProcessingProgress tracking."""
        from pcap_analyzer.ingestion.chunk_processor import ProcessingProgress
        
        progress = ProcessingProgress(
            total_packets=10000,
            processed_packets=5000
        )
        
        assert progress.percent_complete == 50.0
        assert progress.total_packets == 10000
        assert progress.processed_packets == 5000
    
    def test_progress_bar_formatter(self):
        """Test progress bar formatting."""
        from pcap_analyzer.ingestion.chunk_processor import create_progress_bar
        
        formatter = create_progress_bar(100, width=20)
        
        result = formatter(50)
        assert "50.0%" in result
        assert "(50/100)" in result
        
        result_zero = formatter(0)
        assert "0.0%" in result_zero
    
    def test_file_hash_computation(self):
        """Test SHA-256 file hash computation."""
        from pcap_analyzer.ingestion.chunk_processor import ChunkProcessor
        
        processor = ChunkProcessor()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data for hashing")
            temp_path = Path(f.name)
        
        try:
            hash1 = processor.compute_file_hash(temp_path)
            hash2 = processor.compute_file_hash(temp_path)
            
            assert hash1 == hash2
            assert len(hash1) == 64  # SHA-256 hex length
        finally:
            temp_path.unlink()
    
    def test_packet_count_estimation(self):
        """Test packet count estimation from file size."""
        from pcap_analyzer.ingestion.chunk_processor import ChunkProcessor
        
        processor = ChunkProcessor()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # Write 500KB (should estimate ~1000 packets at 500 bytes each)
            f.write(b"x" * 500000)
            temp_path = Path(f.name)
        
        try:
            estimated = processor.estimate_packet_count(temp_path)
            assert estimated == 1000
        finally:
            temp_path.unlink()


class TestSQLiteStore:
    """Test SQLite storage backend."""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        from pcap_analyzer.storage.sqlite_store import SQLiteStore
        
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SQLiteStore(db_path)
            yield store
            store.close()
    
    def test_database_initialization(self, temp_db):
        """Test database schema creation."""
        conn = temp_db._get_connection()
        
        # Check tables exist
        tables = conn.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
        """).fetchall()
        
        table_names = [t[0] for t in tables]
        assert 'packets' in table_names
        assert 'flows' in table_names
        assert 'findings' in table_names
    
    def test_packet_ingestion(self, temp_db):
        """Test packet ingestion."""
        packets = iter([
            {
                'frame_number': 1,
                'timestamp': 1000.0,
                'src_ip': '192.168.1.1',
                'dst_ip': '192.168.1.2',
                'protocol': 6,
                'src_port': 12345,
                'dst_port': 80,
                'frame_length': 1500,
                'tcp_flags': 2,
            },
            {
                'frame_number': 2,
                'timestamp': 1000.001,
                'src_ip': '192.168.1.2',
                'dst_ip': '192.168.1.1',
                'protocol': 6,
                'src_port': 80,
                'dst_port': 12345,
                'frame_length': 1500,
                'tcp_flags': 18,
            }
        ])
        
        count = temp_db.ingest_packets(packets)
        assert count == 2
        
        # Verify packets stored
        packet_count = temp_db.get_packet_count()
        assert packet_count == 2
    
    def test_time_range_query(self, temp_db):
        """Test time range retrieval."""
        packets = iter([
            {'frame_number': i, 'timestamp': 1000.0 + i * 0.001}
            for i in range(1, 101)
        ])
        
        temp_db.ingest_packets(packets)
        
        start, end = temp_db.get_time_range()
        assert start == 1000.001
        assert end == 1000.1
    
    def test_stream_packets(self, temp_db):
        """Test streaming packets from database."""
        packets = iter([
            {
                'frame_number': i,
                'timestamp': 1000.0 + i * 0.001,
                'src_ip': f'192.168.1.{i % 256}',
                'protocol': 6,
            }
            for i in range(1, 101)
        ])
        
        temp_db.ingest_packets(packets)
        
        # Stream all packets
        streamed = list(temp_db.stream_packets())
        assert len(streamed) == 100
        
        # Stream with limit
        limited = list(temp_db.stream_packets(limit=10))
        assert len(limited) == 10
        
        # Stream with filter
        filtered = list(temp_db.stream_packets(
            filter_expr="src_ip = ?",
            params=('192.168.1.1',)
        ))
        assert len(filtered) > 0
    
    def test_aggregation_queries(self, temp_db):
        """Test aggregation queries."""
        packets = iter([
            {
                'frame_number': i,
                'timestamp': 1000.0,
                'src_ip': '192.168.1.1' if i % 2 == 0 else '192.168.1.2',
                'frame_length': 1000,
            }
            for i in range(1, 101)
        ])
        
        temp_db.ingest_packets(packets)
        
        results = temp_db.aggregate(
            group_by=['src_ip'],
            aggregations={
                'packet_count': 'COUNT(*)',
                'total_bytes': 'SUM(frame_length)'
            }
        )
        
        assert len(results) == 2
        assert results[0]['packet_count'] == 50
        assert results[0]['total_bytes'] == 50000
    
    def test_top_talkers(self, temp_db):
        """Test top talkers query."""
        packets = iter([
            {
                'frame_number': i,
                'timestamp': 1000.0,
                'src_ip': f'192.168.1.{i % 10}',
                'frame_length': 1000 * (i % 10 + 1),
            }
            for i in range(1, 101)
        ])
        
        temp_db.ingest_packets(packets)
        
        top = temp_db.get_top_talkers(limit=5)
        assert len(top) <= 5
    
    def test_finding_storage(self, temp_db):
        """Test finding storage and retrieval."""
        finding = {
            'finding_id': 'TEST-001',
            'title': 'Test Finding',
            'severity': 'high',
            'confidence': 'high',
            'category': 'performance',
            'description': 'Test description',
            'evidence_frames': [1, 2, 3],
            'metrics': {'retransmissions': 10},
            'possible_causes': ['network loss'],
            'recommended_actions': ['check interface']
        }
        
        temp_db.save_finding(finding)
        
        findings = temp_db.get_all_findings()
        assert len(findings) == 1
        assert findings[0]['finding_id'] == 'TEST-001'
        assert findings[0]['evidence_frames'] == [1, 2, 3]
    
    def test_flow_upsert(self, temp_db):
        """Test flow record insertion."""
        flow = {
            'flow_key': '192.168.1.1:12345-192.168.1.2:80-6',
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 6,
            'start_time': 1000.0,
            'end_time': 1001.0,
            'duration': 1000.0,
            'bytes_sent': 5000,
            'bytes_received': 15000,
        }
        
        temp_db.upsert_flow(flow)
        
        flows = temp_db.get_flows()
        assert len(flows) == 1
        assert flows[0]['bytes_sent'] == 5000
    
    def test_analysis_state_tracking(self, temp_db):
        """Test analysis state for resumable processing."""
        # Update state
        temp_db._update_analysis_state(
            temp_db._get_connection(),
            'analysis-123',
            5000,
            'running'
        )
        
        # Retrieve state
        state = temp_db.get_analysis_state('analysis-123')
        assert state is not None
        assert state['last_processed_frame'] == 5000
        assert state['status'] == 'running'


class TestDuckDBStore:
    """Test DuckDB storage backend."""
    
    @pytest.fixture
    def temp_duckdb(self):
        """Create temporary DuckDB database."""
        from pcap_analyzer.storage.duckdb_store import DuckDBStore
        
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.ddb"
            store = DuckDBStore(db_path)
            yield store
            store.close()
    
    def test_duckdb_initialization(self, temp_duckdb):
        """Test DuckDB schema creation."""
        conn = temp_duckdb._get_connection()
        
        # Check tables exist
        result = conn.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'main'
        """).fetchall()
        
        table_names = [t[0] for t in result]
        assert 'packets' in table_names
    
    def test_duckdb_aggregation(self, temp_duckdb):
        """Test DuckDB aggregation performance."""
        packets = iter([
            {
                'frame_number': i,
                'timestamp': 1000.0 + i * 0.001,
                'src_ip': f'192.168.1.{i % 50}',
                'dst_ip': f'192.168.2.{i % 30}',
                'protocol': 6,
                'frame_length': 1000 + (i % 500),
            }
            for i in range(1, 1001)
        ])
        
        temp_duckdb.ingest_packets(packets)
        
        # Test complex aggregation
        results = temp_duckdb.aggregate(
            group_by=['src_ip', 'protocol'],
            aggregations={
                'packets': 'COUNT(*)',
                'bytes': 'SUM(frame_length)',
                'avg_size': 'AVG(frame_length)',
                'min_ts': 'MIN(timestamp_epoch)',
                'max_ts': 'MAX(timestamp_epoch)'
            }
        )
        
        assert len(results) > 0
    
    def test_bandwidth_over_time(self, temp_duckdb):
        """Test bandwidth time-series query."""
        packets = iter([
            {
                'frame_number': i,
                'timestamp': float(i),
                'frame_length': 1000,
            }
            for i in range(1, 101)
        ])
        
        temp_duckdb.ingest_packets(packets)
        
        bandwidth = temp_duckdb.get_bandwidth_over_time(interval_seconds=10.0)
        assert len(bandwidth) > 0


class TestMemoryEfficiency:
    """Test memory-efficient processing."""
    
    def test_batch_inserts(self):
        """Test batch insert behavior."""
        from pcap_analyzer.storage.sqlite_store import SQLiteStore
        
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SQLiteStore(db_path, batch_size=100)
            
            # Generate many packets
            def packet_generator(count):
                for i in range(count):
                    yield {
                        'frame_number': i,
                        'timestamp': 1000.0 + i * 0.001,
                        'src_ip': '192.168.1.1',
                    }
            
            # Ingest should not load all into memory
            count = store.ingest_packets(packet_generator(1000))
            assert count == 1000
            
            store.close()
    
    def test_streaming_queries(self):
        """Test streaming query results."""
        from pcap_analyzer.storage.sqlite_store import SQLiteStore
        
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SQLiteStore(db_path)
            
            # Insert test data
            packets = iter([
                {'frame_number': i, 'timestamp': float(i)}
                for i in range(1000)
            ])
            store.ingest_packets(packets)
            
            # Stream results instead of loading all
            count = 0
            for packet in store.stream_packets(batch_size=100):
                count += 1
                # Process one at a time, not all in memory
            
            assert count == 1000
            store.close()


class TestResumableProcessing:
    """Test resumable analysis capabilities."""
    
    def test_resume_from_checkpoint(self):
        """Test resuming from saved state."""
        from pcap_analyzer.storage.sqlite_store import SQLiteStore
        from pcap_analyzer.ingestion.chunk_processor import ChunkProcessor
        
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SQLiteStore(db_path)
            
            # Simulate interrupted analysis
            conn = store._get_connection()
            store._update_analysis_state(conn, 'test-analysis', 5000, 'running')
            
            # Retrieve state
            state = store.get_analysis_state('test-analysis')
            assert state['last_processed_frame'] == 5000
            assert state['status'] == 'running'
            
            store.close()
    
    def test_file_deduplication(self):
        """Test file hash-based deduplication."""
        from pcap_analyzer.ingestion.chunk_processor import ChunkProcessor
        
        processor = ChunkProcessor()
        
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"identical content")
            path1 = Path(f1.name)
        
        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"identical content")
            path2 = Path(f2.name)
        
        try:
            hash1 = processor.compute_file_hash(path1)
            hash2 = processor.compute_file_hash(path2)
            
            assert hash1 == hash2
        finally:
            path1.unlink()
            path2.unlink()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
