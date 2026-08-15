#!/usr/bin/env python3
"""
DNS Analyzer

Analyzes DNS traffic for performance and issues.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from config import Config


@dataclass
class DNSTransaction:
    """Represents a DNS transaction (query + response)."""
    
    query_frame: int = 0
    response_frame: Optional[int] = None
    
    query_timestamp: float = 0.0
    response_timestamp: float = 0.0
    latency_ms: float = 0.0
    
    query_name: str = ""
    query_type: int = 0
    response_code: int = 0  # 0 = NOERROR, 3 = NXDOMAIN, 2 = SERVFAIL
    
    client_ip: str = ""
    server_ip: str = ""
    
    is_tcp: bool = False
    is_truncated: bool = False
    is_retransmission: bool = False
    
    @property
    def query_type_name(self) -> str:
        type_map = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 
                   15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
        return type_map.get(self.query_type, f"TYPE{self.query_type}")
    
    @property
    def rcode_name(self) -> str:
        code_map = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 
                   3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
        return code_map.get(self.response_code, f"RCODE{self.response_code}")
    
    @property
    def has_error(self) -> bool:
        return self.response_code != 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'query_frame': self.query_frame,
            'response_frame': self.response_frame,
            'latency_ms': self.latency_ms,
            'query_name': self.query_name,
            'query_type': self.query_type_name,
            'response_code': self.rcode_name,
            'client_ip': self.client_ip,
            'server_ip': self.server_ip,
            'is_tcp': self.is_tcp,
            'has_error': self.has_error,
        }


@dataclass
class DNSAnalysisResult:
    """Result of DNS analysis."""
    
    transactions: List[DNSTransaction] = field(default_factory=list)
    
    # Statistics
    total_queries: int = 0
    total_responses: int = 0
    unanswered_queries: int = 0
    
    # Response codes
    nxdomain_count: int = 0
    servfail_count: int = 0
    refused_count: int = 0
    
    # Latency
    avg_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    slow_queries_count: int = 0  # Above threshold
    
    # Top queried domains
    top_domains: List[tuple] = field(default_factory=list)  # (domain, count)
    
    # Top clients
    top_clients: List[tuple] = field(default_factory=list)  # (ip, count)
    
    # Top servers
    top_servers: List[tuple] = field(default_factory=list)  # (ip, count)
    
    # Query types
    query_type_counts: Dict[str, int] = field(default_factory=dict)
    
    # TCP vs UDP
    tcp_queries: int = 0
    udp_queries: int = 0
    truncated_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_queries': self.total_queries,
            'total_responses': self.total_responses,
            'unanswered_queries': self.unanswered_queries,
            'nxdomain_count': self.nxdomain_count,
            'servfail_count': self.servfail_count,
            'refused_count': self.refused_count,
            'avg_latency_ms': self.avg_latency_ms,
            'min_latency_ms': self.min_latency_ms,
            'max_latency_ms': self.max_latency_ms,
            'slow_queries_count': self.slow_queries_count,
            'top_domains': self.top_domains[:10],
            'top_clients': self.top_clients[:10],
            'top_servers': self.top_servers[:10],
            'query_type_counts': self.query_type_counts,
            'tcp_queries': self.tcp_queries,
            'udp_queries': self.udp_queries,
            'truncated_count': self.truncated_count,
        }


class DNSAnalyzer:
    """
    Analyzes DNS traffic for performance and issues.
    """
    
    def __init__(self, store, config: Optional[Config] = None):
        self.store = store
        self.config = config or Config()
    
    def analyze(self) -> DNSAnalysisResult:
        """
        Perform DNS analysis.
        
        Returns:
            DNSAnalysisResult with transaction details and statistics
        """
        result = DNSAnalysisResult()
        pending_queries: Dict[str, DNSTransaction] = {}  # key by query_name + client
        domain_counts: Dict[str, int] = defaultdict(int)
        client_counts: Dict[str, int] = defaultdict(int)
        server_counts: Dict[str, int] = defaultdict(int)
        type_counts: Dict[int, int] = defaultdict(int)
        latencies: List[float] = []
        
        with self.store.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get all DNS packets
            cursor.execute("""
                SELECT
                    frame_number, timestamp_epoch, protocol,
                    src_ip, dst_ip, src_port, dst_port,
                    dns_query_name, dns_rcode
                FROM packets
                WHERE dns_query_name IS NOT NULL OR dns_rcode IS NOT NULL
                ORDER BY frame_number
            """)
            
            for row in cursor.fetchall():
                (frame_num, timestamp, proto, src_ip, dst_ip, 
                 src_port, dst_port, query_name, rcode) = row
                
                is_dns_server = (src_port == 53 or dst_port == 53)
                if not is_dns_server:
                    continue
                
                is_tcp = (proto == 6)
                
                # Determine if this is a query or response
                is_query = (dst_port == 53 and query_name)
                is_response = (src_port == 53 and rcode is not None)
                
                if is_query:
                    result.total_queries += 1
                    result.udp_queries += 0 if is_tcp else 1
                    result.tcp_queries += 1 if is_tcp else 0
                    
                    domain_counts[query_name] += 1
                    client_counts[src_ip] += 1
                    server_counts[dst_ip] += 1
                    
                    # Store pending query
                    key = f"{query_name}:{src_ip}"
                    pending_queries[key] = DNSTransaction(
                        query_frame=frame_num,
                        query_timestamp=timestamp,
                        query_name=query_name,
                        client_ip=src_ip,
                        server_ip=dst_ip,
                        is_tcp=is_tcp,
                    )
                    
                elif is_response:
                    result.total_responses += 1
                    
                    # Find matching query
                    key = f"{query_name}:{dst_ip}"
                    if key in pending_queries:
                        txn = pending_queries[key]
                        txn.response_frame = frame_num
                        txn.response_timestamp = timestamp
                        txn.response_code = rcode
                        txn.latency_ms = (timestamp - txn.query_timestamp) * 1000
                        
                        latencies.append(txn.latency_ms)
                        
                        if rcode == 3:  # NXDOMAIN
                            result.nxdomain_count += 1
                        elif rcode == 2:  # SERVFAIL
                            result.servfail_count += 1
                        elif rcode == 5:  # REFUSED
                            result.refused_count += 1
                        
                        del pending_queries[key]
            
            # Process results
            result.transactions = list(pending_queries.values())
            result.unanswered_queries = len(pending_queries)
            
            # Calculate latency stats
            if latencies:
                result.avg_latency_ms = sum(latencies) / len(latencies)
                result.min_latency_ms = min(latencies)
                result.max_latency_ms = max(latencies)
                result.slow_queries_count = sum(
                    1 for l in latencies 
                    if l > self.config.analysis.dns_slow_response_threshold_ms
                )
            
            # Top lists
            result.top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            result.top_clients = sorted(client_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            result.top_servers = sorted(server_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return result
