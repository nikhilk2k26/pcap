#!/usr/bin/env python3
"""
SQLite Storage Backend

Provides SQLite-based storage for packet indexing and querying.
Supports large file handling through chunked inserts.
"""

import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any, Iterator, Tuple
from contextlib import contextmanager
import json

from config import Config


class SQLiteStore:
    """
    SQLite-based storage for packet data and analysis results.
    
    Features:
    - Chunked inserts for large files
    - Indexed queries for fast filtering
    - Temporary database support (in-memory or file-based)
    - Packet and flow tables
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.db_path: Optional[Path] = None
        self.conn: Optional[sqlite3.Connection] = None
        self._initialized = False
    
    @contextmanager
    def get_connection(self):
        """Get a database connection."""
        if self.conn is None:
            self._connect()
        yield self.conn
    
    def _connect(self):
        """Establish database connection."""
        if self.config.storage.sqlite_use_memory:
            self.db_path = None
            self.conn = sqlite3.connect(":memory:")
        else:
            # Create temporary database file
            import tempfile
            temp_dir = tempfile.mkdtemp(prefix="pcap_analyzer_")
            self.db_path = Path(temp_dir) / "packets.db"
            self.conn = sqlite3.connect(str(self.db_path))
        
        # Configure connection
        self.conn.execute(f"PRAGMA journal_mode = {self.config.storage.sqlite_journal_mode}")
        self.conn.execute("PRAGMA synchronous = NORMAL")
        self.conn.execute("PRAGMA cache_size = 100000")  # 100MB cache
        self.conn.execute("PRAGMA temp_store = MEMORY")
    
    def initialize_schema(self):
        """Create database tables and indexes."""
        if self._initialized:
            return
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Packets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    frame_number INTEGER PRIMARY KEY,
                    timestamp_epoch REAL NOT NULL,
                    interface_id INTEGER,
                    frame_length INTEGER,
                    captured_length INTEGER,
                    src_mac TEXT,
                    dst_mac TEXT,
                    eth_type INTEGER,
                    vlan_ids TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    ip_version INTEGER,
                    ttl INTEGER,
                    dscp INTEGER,
                    protocol INTEGER,
                    src_port INTEGER,
                    dst_port INTEGER,
                    tcp_flags INTEGER,
                    tcp_seq INTEGER,
                    tcp_ack INTEGER,
                    tcp_window_size INTEGER,
                    tcp_mss INTEGER,
                    is_retransmission INTEGER DEFAULT 0,
                    is_duplicate_ack INTEGER DEFAULT 0,
                    is_out_of_order INTEGER DEFAULT 0,
                    is_zero_window INTEGER DEFAULT 0,
                    icmp_type INTEGER,
                    icmp_code INTEGER,
                    dns_query_name TEXT,
                    dns_rcode INTEGER,
                    dhcp_message_type INTEGER,
                    http_host TEXT,
                    tls_sni TEXT,
                    flow_key TEXT,
                    raw_json TEXT
                )
            """)
            
            # Create indexes for common queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_port ON packets(src_port)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_port ON packets(dst_port)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp_epoch)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_flow_key ON packets(flow_key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dns_query ON packets(dns_query_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_retrans ON packets(is_retransmission)")
            
            # Flows table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    flow_id TEXT PRIMARY KEY,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol INTEGER,
                    vlan_id INTEGER,
                    dscp INTEGER,
                    start_timestamp REAL,
                    end_timestamp REAL,
                    packets INTEGER,
                    bytes_total INTEGER,
                    tcp_syn_count INTEGER,
                    tcp_fin_count INTEGER,
                    tcp_rst_count INTEGER,
                    tcp_retransmissions INTEGER,
                    tcp_duplicate_acks INTEGER,
                    service_name TEXT,
                    is_complete INTEGER,
                    is_failed INTEGER,
                    failure_reason TEXT
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol)")
            
            # Findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT,
                    title TEXT,
                    severity TEXT,
                    confidence TEXT,
                    category TEXT,
                    description TEXT,
                    affected_object TEXT,
                    evidence_frames TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    count INTEGER,
                    metrics TEXT,
                    possible_causes TEXT,
                    recommended_actions TEXT,
                    raw_json TEXT
                )
            """)
            
            conn.commit()
            self._initialized = True
    
    def ingest_file(self, file_path: Path, limit: Optional[int] = None, 
                   sample_rate: float = 1.0) -> int:
        """
        Ingest packets from a capture file.
        
        Args:
            file_path: Path to PCAP/PCAPNG file
            limit: Maximum packets to ingest
            sample_rate: Sample rate (1.0 = all packets)
            
        Returns:
            Number of packets ingested
        """
        from pcap_analyzer.ingestion.tshark_runner import TsharkRunner
        
        self.initialize_schema()
        
        runner = TsharkRunner(self.config)
        result = runner.run_extraction(
            file_path,
            limit=limit,
        )
        
        if not result.success:
            raise RuntimeError(f"tshark extraction failed: {result.error_message}")
        
        # Parse tshark output and insert into database
        packet_count = 0
        batch = []
        batch_size = self.config.storage.index_batch_size
        
        lines = result.stdout.strip().split('\n')
        header_line = lines[0] if lines else ""
        
        # Parse header to get field names
        headers = header_line.split('\t') if header_line else []
        
        for line in lines[1:]:
            if not line:
                continue
            
            # Apply sampling
            import random
            if sample_rate < 1.0 and random.random() > sample_rate:
                continue
            
            values = line.split('\t')
            if len(values) != len(headers):
                continue
            
            fields = dict(zip(headers, values))
            packet_data = self._parse_tshark_fields(fields)
            batch.append(packet_data)
            
            if len(batch) >= batch_size:
                self._insert_batch(batch)
                packet_count += len(batch)
                batch = []
        
        # Insert remaining packets
        if batch:
            self._insert_batch(batch)
            packet_count += len(batch)
        
        return packet_count
    
    def _parse_tshark_fields(self, fields: Dict[str, str]) -> Dict[str, Any]:
        """Parse tshark field output into database-ready format."""
        def safe_int(val: str, default: int = 0) -> int:
            try:
                return int(val) if val else default
            except ValueError:
                return default
        
        def safe_float(val: str, default: float = 0.0) -> float:
            try:
                return float(val) if val else default
            except ValueError:
                return default
        
        return {
            'frame_number': safe_int(fields.get('frame.number', '0')),
            'timestamp_epoch': safe_float(fields.get('frame.time_epoch', '0')),
            'interface_id': safe_int(fields.get('frame.interface_id', '0')) or None,
            'frame_length': safe_int(fields.get('frame.len', '0')),
            'captured_length': safe_int(fields.get('frame.cap_len', '0')),
            'src_mac': fields.get('eth.src') or None,
            'dst_mac': fields.get('eth.dst') or None,
            'eth_type': safe_int(fields.get('eth.type', '0'), None),
            'vlan_ids': fields.get('vlan.id') or None,
            'src_ip': fields.get('ip.src') or None,
            'dst_ip': fields.get('ip.dst') or None,
            'ip_version': safe_int(fields.get('ip.version', '0'), None),
            'ttl': safe_int(fields.get('ip.ttl', '0'), None),
            'dscp': safe_int(fields.get('ip.dsfield.dscp', '0'), None),
            'protocol': safe_int(fields.get('ip.proto', '0'), None),
            'src_port': safe_int(fields.get('tcp.srcport') or fields.get('udp.srcport'), None),
            'dst_port': safe_int(fields.get('tcp.dstport') or fields.get('udp.dstport'), None),
            'tcp_flags': safe_int(fields.get('tcp.flags', '0'), None),
            'tcp_seq': safe_int(fields.get('tcp.seq', '0'), None),
            'tcp_ack': safe_int(fields.get('tcp.ack', '0'), None),
            'tcp_window_size': safe_int(fields.get('tcp.window_size', '0'), None),
            'tcp_mss': safe_int(fields.get('tcp.options.mss.val', '0'), None),
            'is_retransmission': 1 if fields.get('tcp.analysis.retransmission') == '1' else 0,
            'is_duplicate_ack': 1 if fields.get('tcp.analysis.duplicate_ack') == '1' else 0,
            'is_out_of_order': 1 if fields.get('tcp.analysis.out_of_order') == '1' else 0,
            'is_zero_window': 1 if fields.get('tcp.analysis.zero_window') == '1' else 0,
            'icmp_type': safe_int(fields.get('icmp.type', '0'), None),
            'icmp_code': safe_int(fields.get('icmp.code', '0'), None),
            'dns_query_name': fields.get('dns.qry.name') or None,
            'dns_rcode': safe_int(fields.get('dns.flags.rcode', '0'), None),
            'dhcp_message_type': safe_int(fields.get('dhcp.type', '0'), None),
            'http_host': fields.get('http.host') or None,
            'tls_sni': fields.get('tls.handshake.extensions_server_name') or None,
            'flow_key': None,  # Will be computed
            'raw_json': json.dumps(fields),
        }
    
    def _insert_batch(self, batch: List[Dict[str, Any]]):
        """Insert a batch of packets."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            for packet in batch:
                # Compute flow key
                if packet['src_ip'] and packet['dst_ip']:
                    proto = packet['protocol'] or 0
                    sport = packet['src_port'] or 0
                    dport = packet['dst_port'] or 0
                    packet['flow_key'] = f"{packet['src_ip']}:{sport}-{packet['dst_ip']}:{dport}-{proto}"
                
                cursor.execute("""
                    INSERT OR REPLACE INTO packets (
                        frame_number, timestamp_epoch, interface_id, frame_length,
                        captured_length, src_mac, dst_mac, eth_type, vlan_ids,
                        src_ip, dst_ip, ip_version, ttl, dscp, protocol,
                        src_port, dst_port, tcp_flags, tcp_seq, tcp_ack,
                        tcp_window_size, tcp_mss, is_retransmission, is_duplicate_ack,
                        is_out_of_order, is_zero_window, icmp_type, icmp_code,
                        dns_query_name, dns_rcode, dhcp_message_type, http_host,
                        tls_sni, flow_key, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    packet['frame_number'], packet['timestamp_epoch'], packet['interface_id'],
                    packet['frame_length'], packet['captured_length'], packet['src_mac'],
                    packet['dst_mac'], packet['eth_type'], packet['vlan_ids'],
                    packet['src_ip'], packet['dst_ip'], packet['ip_version'], packet['ttl'],
                    packet['dscp'], packet['protocol'], packet['src_port'], packet['dst_port'],
                    packet['tcp_flags'], packet['tcp_seq'], packet['tcp_ack'],
                    packet['tcp_window_size'], packet['tcp_mss'], packet['is_retransmission'],
                    packet['is_duplicate_ack'], packet['is_out_of_order'], packet['is_zero_window'],
                    packet['icmp_type'], packet['icmp_code'], packet['dns_query_name'],
                    packet['dns_rcode'], packet['dhcp_message_type'], packet['http_host'],
                    packet['tls_sni'], packet['flow_key'], packet['raw_json'],
                ))
            
            conn.commit()
    
    def query_packets(self, where_clause: Optional[str] = None, 
                     params: Optional[tuple] = None,
                     limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Query packets with optional WHERE clause."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM packets"
            if where_clause:
                query += f" WHERE {where_clause}"
            query += " ORDER BY frame_number"
            if limit:
                query += f" LIMIT {limit}"
            
            cursor.execute(query, params or ())
            
            columns = [desc[0] for desc in cursor.description]
            results = []
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            return results
    
    def query_flows(self, where_clause: Optional[str] = None,
                   params: Optional[tuple] = None,
                   order_by: str = "bytes_total DESC") -> List[Dict[str, Any]]:
        """Query flows with optional filtering."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM flows"
            if where_clause:
                query += f" WHERE {where_clause}"
            query += f" ORDER BY {order_by}"
            
            cursor.execute(query, params or ())
            
            columns = [desc[0] for desc in cursor.description]
            results = []
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            return results
    
    def get_packet_count(self, filter_expr: Optional[str] = None,
                         params: Optional[tuple] = None) -> int:
        """Get packet count with optional filter."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT COUNT(*) FROM packets"
            if filter_expr:
                query += f" WHERE {filter_expr}"
            cursor.execute(query, params or ())
            return cursor.fetchone()[0]
    
    def get_time_range(self) -> Tuple[float, float]:
        """Get capture time range."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MIN(timestamp_epoch), MAX(timestamp_epoch) FROM packets")
            row = cursor.fetchone()
            return (row[0] or 0.0, row[1] or 0.0)
    
    def ingest_packets(self, packets: Iterator[Dict[str, Any]], 
                       batch_size: Optional[int] = None) -> int:
        """
        Ingest packets from an iterator.
        
        Args:
            packets: Iterator of packet dictionaries
            batch_size: Override default batch size
            
        Returns:
            Number of packets ingested
        """
        self.initialize_schema()
        
        count = 0
        batch = []
        use_batch_size = batch_size or self.config.storage.index_batch_size
        
        for packet in packets:
            batch.append(self._parse_tshark_fields(packet) if 'layers' in packet else packet)
            count += 1
            
            if len(batch) >= use_batch_size:
                self._insert_batch(batch)
                batch = []
        
        # Insert remaining
        if batch:
            self._insert_batch(batch)
        
        return count
    
    def cleanup(self):
        """Clean up database resources."""
        if self.conn:
            self.conn.close()
            self.conn = None
        
        if self.db_path and self.db_path.exists():
            try:
                self.db_path.unlink()
                self.db_path.parent.rmdir()
            except Exception:
                pass
