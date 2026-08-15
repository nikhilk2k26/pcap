#!/usr/bin/env python3
"""
DuckDB Storage Backend

Provides DuckDB-based storage for packet indexing and analytical queries.
Optimized for large-scale aggregations and time-series analysis.
"""

import duckdb
from pathlib import Path
from typing import Optional, List, Dict, Any, Iterator, Tuple
from contextlib import contextmanager
import json
import tempfile

from ..utils.logging_utils import get_logger


class DuckDBStore:
    """
    DuckDB-based storage for packet data and analysis results.
    
    Features:
    - Columnar storage for fast aggregations
    - Streaming ingestion
    - Time-series optimizations
    - SQL analytics support
    - Memory-mapped files for large datasets
    """

    def __init__(self, db_path: Optional[Path] = None, 
                 use_memory: bool = False,
                 batch_size: int = 5000):
        """
        Initialize DuckDB store.
        
        Args:
            db_path: Path to DuckDB database file (None for in-memory)
            use_memory: Use in-memory database
            batch_size: Batch size for inserts
        """
        self.db_path = db_path
        self.use_memory = use_memory
        self.batch_size = batch_size
        self.logger = get_logger(__name__)
        self._connection: Optional[duckdb.DuckDBPyConnection] = None
        self._initialized = False
        
        if not use_memory and db_path is None:
            # Create temporary file
            temp_dir = Path(tempfile.mkdtemp(prefix="pcap_duckdb_"))
            self.db_path = temp_dir / "packets.ddb"

    def _get_connection(self) -> duckdb.DuckDBPyConnection:
        """Get or create database connection."""
        if self._connection is None:
            if self.use_memory:
                self._connection = duckdb.connect(':memory:')
            else:
                self._connection = duckdb.connect(str(self.db_path))
            
            # Configure for performance
            self._connection.execute("SET threads TO 4")
            self._connection.execute("SET memory_limit='2GB'")
            self._connection.execute("SET preserve_insertion_order=false")
            
        return self._connection

    def initialize_schema(self):
        """Create database tables and indexes."""
        if self._initialized:
            return
        
        conn = self._get_connection()
        
        # Packets table - optimized for time-series
        conn.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                frame_number BIGINT PRIMARY KEY,
                timestamp_epoch DOUBLE PRECISION NOT NULL,
                interface_id INTEGER,
                frame_length INTEGER,
                captured_length INTEGER,
                src_mac VARCHAR,
                dst_mac VARCHAR,
                eth_type INTEGER,
                vlan_ids VARCHAR,  -- JSON array
                vlan_priorities VARCHAR,  -- JSON array
                src_ip VARCHAR,
                dst_ip VARCHAR,
                ip_version INTEGER,
                ttl INTEGER,
                ip_flags INTEGER,
                fragment_offset INTEGER,
                df_flag BOOLEAN,
                mf_flag BOOLEAN,
                dscp INTEGER,
                ecn INTEGER,
                protocol INTEGER,
                src_port INTEGER,
                dst_port INTEGER,
                tcp_flags INTEGER,
                tcp_seq BIGINT,
                tcp_ack BIGINT,
                tcp_window_size INTEGER,
                tcp_window_scale INTEGER,
                tcp_mss INTEGER,
                tcp_options VARCHAR,  -- JSON
                is_retransmission BOOLEAN DEFAULT FALSE,
                is_duplicate_ack BOOLEAN DEFAULT FALSE,
                is_out_of_order BOOLEAN DEFAULT FALSE,
                is_zero_window BOOLEAN DEFAULT FALSE,
                icmp_type INTEGER,
                icmp_code INTEGER,
                dns_query_name VARCHAR,
                dns_response_code INTEGER,
                dns_query_type INTEGER,
                dhcp_message_type INTEGER,
                dhcp_server_ip VARCHAR,
                dhcp_client_ip VARCHAR,
                http_host VARCHAR,
                http_method VARCHAR,
                http_status INTEGER,
                tls_sni VARCHAR,
                tls_version VARCHAR,
                rtp_ssrc INTEGER,
                rtp_seq INTEGER,
                flow_key VARCHAR,
                packet_info VARCHAR  -- JSON
            )
        """)
        
        # Create indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp_epoch)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_port ON packets(src_port)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_port ON packets(dst_port)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_flow_key ON packets(flow_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_dns_query ON packets(dns_query_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_tls_sni ON packets(tls_sni)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_retrans ON packets(is_retransmission)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_dscp ON packets(dscp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_ttl ON packets(ttl)")
        
        # Flows table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                flow_key VARCHAR PRIMARY KEY,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                src_port INTEGER,
                dst_port INTEGER,
                protocol INTEGER,
                ip_version INTEGER,
                vlan_id INTEGER,
                dscp INTEGER,
                start_timestamp DOUBLE PRECISION,
                end_timestamp DOUBLE PRECISION,
                duration_ms DOUBLE PRECISION,
                packets_sent BIGINT,
                packets_received BIGINT,
                bytes_sent BIGINT,
                bytes_received BIGINT,
                tcp_syn_count INTEGER,
                tcp_fin_count INTEGER,
                tcp_rst_count INTEGER,
                tcp_retransmissions BIGINT,
                tcp_duplicate_acks BIGINT,
                tcp_out_of_order BIGINT,
                tcp_zero_windows BIGINT,
                avg_rtt_ms DOUBLE PRECISION,
                min_rtt_ms DOUBLE PRECISION,
                max_rtt_ms DOUBLE PRECISION,
                service_name VARCHAR,
                state VARCHAR,
                is_failed BOOLEAN,
                failure_reason VARCHAR
            )
        """)
        
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_start_time ON flows(start_timestamp)")
        
        # Findings table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id VARCHAR PRIMARY KEY,
                title VARCHAR NOT NULL,
                severity VARCHAR NOT NULL,
                confidence VARCHAR NOT NULL,
                category VARCHAR NOT NULL,
                description VARCHAR,
                affected_object VARCHAR,
                evidence_frames VARCHAR,  -- JSON array
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                count INTEGER DEFAULT 1,
                metrics VARCHAR,  -- JSON
                possible_causes VARCHAR,  -- JSON array
                recommended_actions VARCHAR,  -- JSON array
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Analysis state for resumable processing
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_state (
                analysis_id VARCHAR PRIMARY KEY,
                file_hash VARCHAR,
                file_path VARCHAR,
                last_processed_frame BIGINT DEFAULT 0,
                status VARCHAR DEFAULT 'pending',
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                error_message VARCHAR,
                metadata VARCHAR  -- JSON
            )
        """)
        
        self._initialized = True
        self.logger.info(f"DuckDB store initialized at {self.db_path or ':memory:'}")

    def ingest_packets(self, packets: Iterator[Dict[str, Any]],
                       analysis_id: Optional[str] = None) -> int:
        """
        Ingest packets from an iterator.
        
        Args:
            packets: Iterator of packet dictionaries
            analysis_id: Optional analysis ID for tracking
            
        Returns:
            Number of packets ingested
        """
        self.initialize_schema()
        conn = self._get_connection()
        
        count = 0
        batch = []
        
        for packet in packets:
            batch.append(packet)
            count += 1
            
            if len(batch) >= self.batch_size:
                self._insert_batch(conn, batch)
                batch = []
                
                # Update analysis state periodically
                if analysis_id and count % (self.batch_size * 10) == 0:
                    self._update_analysis_state(conn, analysis_id, count, 'running')
        
        # Insert remaining packets
        if batch:
            self._insert_batch(conn, batch)
        
        # Mark complete
        if analysis_id:
            self._update_analysis_state(conn, analysis_id, count, 'completed')
        
        self.logger.info(f"Ingested {count} packets into DuckDB")
        return count

    def _insert_batch(self, conn: duckdb.DuckDBPyConnection, 
                      batch: List[Dict[str, Any]]):
        """Insert a batch of packets using efficient bulk insert."""
        if not batch:
            return
        
        # Convert to DataFrame-like structure for DuckDB
        # Prepare column arrays
        columns = {
            'frame_number': [],
            'timestamp_epoch': [],
            'interface_id': [],
            'frame_length': [],
            'captured_length': [],
            'src_mac': [],
            'dst_mac': [],
            'eth_type': [],
            'vlan_ids': [],
            'vlan_priorities': [],
            'src_ip': [],
            'dst_ip': [],
            'ip_version': [],
            'ttl': [],
            'ip_flags': [],
            'fragment_offset': [],
            'df_flag': [],
            'mf_flag': [],
            'dscp': [],
            'ecn': [],
            'protocol': [],
            'src_port': [],
            'dst_port': [],
            'tcp_flags': [],
            'tcp_seq': [],
            'tcp_ack': [],
            'tcp_window_size': [],
            'tcp_window_scale': [],
            'tcp_mss': [],
            'tcp_options': [],
            'is_retransmission': [],
            'is_duplicate_ack': [],
            'is_out_of_order': [],
            'is_zero_window': [],
            'icmp_type': [],
            'icmp_code': [],
            'dns_query_name': [],
            'dns_response_code': [],
            'dns_query_type': [],
            'dhcp_message_type': [],
            'dhcp_server_ip': [],
            'dhcp_client_ip': [],
            'http_host': [],
            'http_method': [],
            'http_status': [],
            'tls_sni': [],
            'tls_version': [],
            'rtp_ssrc': [],
            'rtp_seq': [],
            'flow_key': [],
            'packet_info': []
        }
        
        for pkt in batch:
            columns['frame_number'].append(pkt.get('frame_number'))
            columns['timestamp_epoch'].append(pkt.get('timestamp', 0.0))
            columns['interface_id'].append(pkt.get('interface_id'))
            columns['frame_length'].append(pkt.get('frame_length'))
            columns['captured_length'].append(pkt.get('captured_length'))
            columns['src_mac'].append(pkt.get('src_mac'))
            columns['dst_mac'].append(pkt.get('dst_mac'))
            columns['eth_type'].append(pkt.get('eth_type'))
            columns['vlan_ids'].append(json.dumps(pkt.get('vlan_ids', [])))
            columns['vlan_priorities'].append(json.dumps(pkt.get('vlan_priorities', [])))
            columns['src_ip'].append(pkt.get('src_ip'))
            columns['dst_ip'].append(pkt.get('dst_ip'))
            columns['ip_version'].append(pkt.get('ip_version'))
            columns['ttl'].append(pkt.get('ttl'))
            columns['ip_flags'].append(pkt.get('ip_flags'))
            columns['fragment_offset'].append(pkt.get('fragment_offset'))
            columns['df_flag'].append(pkt.get('df_flag'))
            columns['mf_flag'].append(pkt.get('mf_flag'))
            columns['dscp'].append(pkt.get('dscp'))
            columns['ecn'].append(pkt.get('ecn'))
            columns['protocol'].append(pkt.get('protocol'))
            columns['src_port'].append(pkt.get('src_port'))
            columns['dst_port'].append(pkt.get('dst_port'))
            columns['tcp_flags'].append(pkt.get('tcp_flags'))
            columns['tcp_seq'].append(pkt.get('tcp_seq'))
            columns['tcp_ack'].append(pkt.get('tcp_ack'))
            columns['tcp_window_size'].append(pkt.get('tcp_window'))
            columns['tcp_window_scale'].append(pkt.get('tcp_window_scale'))
            columns['tcp_mss'].append(pkt.get('tcp_mss'))
            columns['tcp_options'].append(json.dumps(pkt.get('tcp_options', {})))
            columns['is_retransmission'].append(bool(pkt.get('tcp_retransmission', 0)))
            columns['is_duplicate_ack'].append(bool(pkt.get('tcp_dup_ack', 0)))
            columns['is_out_of_order'].append(bool(pkt.get('tcp_out_of_order', 0)))
            columns['is_zero_window'].append(bool(pkt.get('tcp_zero_window', 0)))
            columns['icmp_type'].append(pkt.get('icmp_type'))
            columns['icmp_code'].append(pkt.get('icmp_code'))
            columns['dns_query_name'].append(pkt.get('dns_query_name'))
            columns['dns_response_code'].append(pkt.get('dns_response_code'))
            columns['dns_query_type'].append(pkt.get('dns_query_type'))
            columns['dhcp_message_type'].append(pkt.get('dhcp_message_type'))
            columns['dhcp_server_ip'].append(pkt.get('dhcp_server_ip'))
            columns['dhcp_client_ip'].append(pkt.get('dhcp_client_ip'))
            columns['http_host'].append(pkt.get('http_host'))
            columns['http_method'].append(pkt.get('http_method'))
            columns['http_status'].append(pkt.get('http_status'))
            columns['tls_sni'].append(pkt.get('tls_sni'))
            columns['tls_version'].append(pkt.get('tls_version'))
            columns['rtp_ssrc'].append(pkt.get('rtp_ssrc'))
            columns['rtp_seq'].append(pkt.get('rtp_seq'))
            columns['flow_key'].append(pkt.get('flow_key'))
            columns['packet_info'].append(json.dumps(pkt.get('packet_info', {})))
        
        # Build INSERT statement - 51 columns
        insert_sql = """
            INSERT OR REPLACE INTO packets (
                frame_number, timestamp_epoch, interface_id, frame_length,
                captured_length, src_mac, dst_mac, eth_type, vlan_ids,
                vlan_priorities, src_ip, dst_ip, ip_version, ttl, ip_flags,
                fragment_offset, df_flag, mf_flag, dscp, ecn, protocol,
                src_port, dst_port, tcp_flags, tcp_seq, tcp_ack,
                tcp_window_size, tcp_window_scale, tcp_mss, tcp_options,
                is_retransmission, is_duplicate_ack, is_out_of_order,
                is_zero_window, icmp_type, icmp_code, dns_query_name,
                dns_response_code, dns_query_type, dhcp_message_type,
                dhcp_server_ip, dhcp_client_ip, http_host, http_method,
                http_status, tls_sni, tls_version, rtp_ssrc, rtp_seq,
                flow_key, packet_info
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        # Execute batch insert
        conn.executemany(insert_sql, list(zip(*columns.values())))

    def _update_analysis_state(self, conn: duckdb.DuckDBPyConnection,
                               analysis_id: str,
                               last_frame: int,
                               status: str):
        """Update analysis progress state."""
        conn.execute("""
            INSERT OR REPLACE INTO analysis_state 
            (analysis_id, last_processed_frame, status, started_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (analysis_id, last_frame, status))

    def get_packet_count(self, filter_expr: Optional[str] = None,
                         params: Optional[Tuple] = None) -> int:
        """Get packet count with optional filter."""
        conn = self._get_connection()
        query = "SELECT COUNT(*) FROM packets"
        if filter_expr:
            query += f" WHERE {filter_expr}"
        result = conn.execute(query, params).fetchone()
        return result[0] if result else 0

    def get_time_range(self) -> Tuple[float, float]:
        """Get capture time range."""
        conn = self._get_connection()
        result = conn.execute("""
            SELECT MIN(timestamp_epoch), MAX(timestamp_epoch) FROM packets
        """).fetchone()
        return (result[0] or 0.0, result[1] or 0.0)

    def stream_packets(self,
                       columns: Optional[List[str]] = None,
                       filter_expr: Optional[str] = None,
                       params: Optional[Tuple] = None,
                       order_by: str = "timestamp_epoch",
                       limit: Optional[int] = None,
                       offset: int = 0) -> Iterator[Dict[str, Any]]:
        """
        Stream packets from database with filtering.
        
        Yields:
            Packet dictionaries
        """
        conn = self._get_connection()
        
        col_str = ", ".join(columns) if columns else "*"
        
        query = f"SELECT {col_str} FROM packets"
        if filter_expr:
            query += f" WHERE {filter_expr}"
        query += f" ORDER BY {order_by}"
        if limit:
            query += f" LIMIT {limit}"
        query += f" OFFSET {offset}"
        
        result = conn.execute(query, params)
        
        while True:
            rows = result.fetchmany(1000)
            if not rows:
                break
            
            for row in rows:
                if columns:
                    yield dict(zip(columns, row))
                else:
                    # Get column names
                    col_names = [desc[0] for desc in result.description]
                    yield dict(zip(col_names, row))

    def aggregate(self, group_by: List[str],
                  aggregations: Dict[str, str],
                  filter_expr: Optional[str] = None,
                  params: Optional[Tuple] = None,
                  having: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Perform aggregation query.
        
        Args:
            group_by: Columns to group by
            aggregations: Dict of {alias: "AGG_FUNC(column)"}
            filter_expr: Optional WHERE clause
            params: Query parameters
            having: Optional HAVING clause
            
        Returns:
            List of aggregation results
        """
        conn = self._get_connection()
        
        group_cols = ", ".join(group_by)
        agg_cols = ", ".join(f"{expr} AS {alias}"
                            for alias, expr in aggregations.items())
        
        query = f"SELECT {group_cols}, {agg_cols} FROM packets"
        
        if filter_expr:
            query += f" WHERE {filter_expr}"
        
        query += f" GROUP BY {group_cols}"
        
        if having:
            query += f" HAVING {having}"
        
        # Order by first aggregation descending
        first_agg = list(aggregations.keys())[0] if aggregations else None
        if first_agg:
            query += f" ORDER BY {first_agg} DESC"
        
        result = conn.execute(query, params or ())
        col_names = [desc[0] for desc in result.description]
        
        return [dict(zip(col_names, row)) for row in result.fetchall()]

    def get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top talkers by bytes."""
        return self.aggregate(
            group_by=["src_ip"],
            aggregations={
                "packets": "COUNT(*)",
                "bytes": "SUM(frame_length)",
                "avg_packet_size": "AVG(frame_length)",
                "first_seen": "MIN(timestamp_epoch)",
                "last_seen": "MAX(timestamp_epoch)"
            },
            filter_expr="src_ip IS NOT NULL"
        )[:limit]

    def get_conversations(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get top conversations."""
        return self.aggregate(
            group_by=["src_ip", "dst_ip", "protocol"],
            aggregations={
                "packets": "COUNT(*)",
                "bytes": "SUM(frame_length)",
                "avg_packet_size": "AVG(frame_length)"
            },
            filter_expr="src_ip IS NOT NULL AND dst_ip IS NOT NULL"
        )[:limit]

    def get_bandwidth_over_time(self, interval_seconds: float = 1.0) -> List[Dict[str, Any]]:
        """Get bandwidth usage over time buckets."""
        conn = self._get_connection()
        
        query = """
            SELECT 
                FLOOR(timestamp_epoch / ?) AS time_bucket,
                COUNT(*) AS packets,
                SUM(frame_length) AS bytes,
                AVG(frame_length) AS avg_packet_size
            FROM packets
            GROUP BY time_bucket
            ORDER BY time_bucket
        """
        
        result = conn.execute(query, (interval_seconds,))
        col_names = [desc[0] for desc in result.description]
        
        return [dict(zip(col_names, row)) for row in result.fetchall()]

    def save_finding(self, finding: Dict[str, Any]):
        """Save a finding to the database."""
        conn = self._get_connection()
        conn.execute("""
            INSERT OR REPLACE INTO findings (
                finding_id, title, severity, confidence, category,
                description, affected_object, evidence_frames,
                first_seen, last_seen, count, metrics,
                possible_causes, recommended_actions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.get('finding_id'),
            finding.get('title'),
            finding.get('severity'),
            finding.get('confidence'),
            finding.get('category'),
            finding.get('description'),
            finding.get('affected_object'),
            json.dumps(finding.get('evidence_frames', [])),
            finding.get('first_seen'),
            finding.get('last_seen'),
            finding.get('count', 1),
            json.dumps(finding.get('metrics', {})),
            json.dumps(finding.get('possible_causes', [])),
            json.dumps(finding.get('recommended_actions', []))
        ))

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Retrieve all findings."""
        conn = self._get_connection()
        result = conn.execute("SELECT * FROM findings ORDER BY severity, created_at")
        col_names = [desc[0] for desc in result.description]
        
        findings = []
        for row in result.fetchall():
            finding = dict(zip(col_names, row))
            finding['evidence_frames'] = json.loads(finding.get('evidence_frames') or '[]')
            finding['metrics'] = json.loads(finding.get('metrics') or '{}')
            finding['possible_causes'] = json.loads(finding.get('possible_causes') or '[]')
            finding['recommended_actions'] = json.loads(finding.get('recommended_actions') or '[]')
            findings.append(finding)
        
        return findings

    def upsert_flow(self, flow: Dict[str, Any]):
        """Insert or update a flow record."""
        conn = self._get_connection()
        conn.execute("""
            INSERT OR REPLACE INTO flows (
                flow_key, src_ip, dst_ip, src_port, dst_port, protocol,
                ip_version, vlan_id, dscp, start_timestamp, end_timestamp,
                duration_ms, packets_sent, packets_received, bytes_sent,
                bytes_received, tcp_syn_count, tcp_fin_count, tcp_rst_count,
                tcp_retransmissions, tcp_duplicate_acks, tcp_out_of_order,
                tcp_zero_windows, avg_rtt_ms, min_rtt_ms, max_rtt_ms,
                service_name, state, is_failed, failure_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flow.get('flow_key'),
            flow.get('src_ip'),
            flow.get('dst_ip'),
            flow.get('src_port'),
            flow.get('dst_port'),
            flow.get('protocol'),
            flow.get('ip_version'),
            flow.get('vlan_id'),
            flow.get('dscp'),
            flow.get('start_time'),
            flow.get('end_time'),
            flow.get('duration'),
            flow.get('packets_sent', 0),
            flow.get('packets_received', 0),
            flow.get('bytes_sent', 0),
            flow.get('bytes_received', 0),
            flow.get('tcp_syn_count', 0),
            flow.get('tcp_fin_count', 0),
            flow.get('tcp_rst_count', 0),
            flow.get('retransmissions', 0),
            flow.get('dup_acks', 0),
            flow.get('out_of_order', 0),
            flow.get('zero_windows', 0),
            flow.get('avg_rtt_ms'),
            flow.get('min_rtt_ms'),
            flow.get('max_rtt_ms'),
            flow.get('service_name'),
            flow.get('state'),
            flow.get('is_failed'),
            flow.get('failure_reason')
        ))

    def get_flows(self, filter_expr: Optional[str] = None,
                  params: Optional[Tuple] = None,
                  limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get flow records."""
        conn = self._get_connection()
        query = "SELECT * FROM flows"
        if filter_expr:
            query += f" WHERE {filter_expr}"
        query += " ORDER BY bytes_sent + bytes_received DESC"
        if limit:
            query += f" LIMIT {limit}"
        
        result = conn.execute(query, params or ())
        col_names = [desc[0] for desc in result.description]
        return [dict(zip(col_names, row)) for row in result.fetchall()]

    def get_analysis_state(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Get analysis state for resumable processing."""
        conn = self._get_connection()
        result = conn.execute(
            "SELECT * FROM analysis_state WHERE analysis_id = ?",
            (analysis_id,)
        )
        row = result.fetchone()
        if row:
            col_names = [desc[0] for desc in result.description]
            return dict(zip(col_names, row))
        return None

    def execute_query(self, sql: str, params: Optional[Tuple] = None) -> List[Dict[str, Any]]:
        """Execute arbitrary SQL query."""
        conn = self._get_connection()
        result = conn.execute(sql, params or ())
        col_names = [desc[0] for desc in result.description]
        return [dict(zip(col_names, row)) for row in result.fetchall()]

    def close(self):
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
