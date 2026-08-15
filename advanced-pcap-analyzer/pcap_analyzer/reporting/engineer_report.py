#!/usr/bin/env python3
"""
Engineer Report Generator

Generates detailed technical reports for network engineers.
"""

from typing import Optional, List
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from config import Config


class EngineerReportGenerator:
    """
    Generates detailed technical reports for engineers.
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.console = Console(width=self.config.report.console_width)
    
    def print_report(self, summary, tcp_analysis, dns_analysis, findings):
        """Print complete engineer report."""
        
        # Header
        self.console.print(Panel(
            "[bold blue]Advanced PCAP Analyzer - Engineering Report[/bold blue]\n"
            f"Generated: {datetime.now().isoformat()}",
            title="🔧 Technical Analysis"
        ))
        
        # Capture details
        self._print_capture_details(summary)
        
        # TCP deep dive
        self._print_tcp_deep_dive(tcp_analysis)
        
        # DNS analysis
        self._print_dns_detail(dns_analysis)
        
        # Findings with evidence
        self._print_findings_detail(findings)
    
    def _print_capture_details(self, summary):
        """Print detailed capture information."""
        table = Table(title="Capture Details")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("File", summary.file_path)
        table.add_row("Duration", f"{summary.duration_seconds:.3f} seconds")
        table.add_row("Total Packets", f"{summary.total_packets:,}")
        table.add_row("Total Bytes", f"{summary.total_bytes:,}")
        table.add_row("Avg Packet Size", f"{summary.avg_packet_size:.1f} bytes")
        table.add_row("Packets/sec", f"{summary.total_packets/max(0.001, summary.duration_seconds):,.0f}")
        table.add_row("Bytes/sec", f"{summary.bytes_per_second:,.0f}")
        
        self.console.print(table)
    
    def _print_tcp_deep_dive(self, tcp_analysis):
        """Print detailed TCP analysis."""
        self.console.print(Panel("[bold]TCP Connection Analysis[/bold]"))
        
        # Connection state breakdown
        table = Table(title="Connection States")
        table.add_column("State", style="cyan")
        table.add_column("Count", justify="right", style="green")
        table.add_column("%", justify="right")
        
        total = max(1, tcp_analysis.total_connections)
        table.add_row("Successful", str(tcp_analysis.successful_connections), 
                     f"{(tcp_analysis.successful_connections/total)*100:.1f}%")
        table.add_row("Failed", str(tcp_analysis.failed_connection_count),
                     f"{(tcp_analysis.failed_connection_count/total)*100:.1f}%")
        table.add_row("Reset", str(tcp_analysis.reset_connections),
                     f"{(tcp_analysis.reset_connections/total)*100:.1f}%")
        
        self.console.print(table)
        
        # Problem connections
        if tcp_analysis.high_retransmission_connections:
            table = Table(title="High Retransmission Flows (>5%)")
            table.add_column("Flow", style="blue", max_width=40)
            table.add_column("Retrans", justify="right")
            table.add_column("Rate %", justify="right", style="red")
            table.add_column("RTT ms", justify="right")
            
            for conn in sorted(tcp_analysis.high_retransmission_connections, 
                             key=lambda c: c.retransmission_rate, reverse=True)[:15]:
                table.add_row(
                    f"{conn.src_ip}:{conn.src_port}→{conn.dst_ip}:{conn.dst_port}",
                    str(conn.retransmissions),
                    f"{conn.retransmission_rate:.1f}",
                    f"{conn.avg_rtt_ms:.1f}" if conn.avg_rtt_ms > 0 else "N/A",
                )
            
            self.console.print(table)
    
    def _print_dns_detail(self, dns_analysis):
        """Print detailed DNS analysis."""
        self.console.print(Panel("[bold]DNS Transaction Analysis[/bold]"))
        
        table = Table(title="DNS Performance")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Queries", str(dns_analysis.total_queries))
        table.add_row("Responses", str(dns_analysis.total_responses))
        table.add_row("Success Rate", f"{(dns_analysis.total_responses/max(1,dns_analysis.total_queries))*100:.1f}%")
        table.add_row("NXDOMAIN", str(dns_analysis.nxdomain_count))
        table.add_row("SERVFAIL", str(dns_analysis.servfail_count))
        table.add_row("Unanswered", str(dns_analysis.unanswered_queries))
        table.add_row("Avg Latency", f"{dns_analysis.avg_latency_ms:.2f}ms")
        table.add_row("Min Latency", f"{dns_analysis.min_latency_ms:.2f}ms")
        table.add_row("Max Latency", f"{dns_analysis.max_latency_ms:.2f}ms")
        
        self.console.print(table)
    
    def _print_findings_detail(self, findings):
        """Print detailed findings with evidence."""
        if not findings:
            self.console.print(Panel("[green]No significant findings[/green]"))
            return
        
        self.console.print(Panel(f"[bold red]{len(findings)} Findings Detected[/bold red]"))
        
        for i, finding in enumerate(findings, 1):
            panel = Panel(
                f"[bold]Finding #{i}: {finding.finding_id}[/bold]\n\n"
                f"[bold]{finding.title}[/bold]\n\n"
                f"{finding.description}\n\n"
                f"[bold]Evidence:[/bold]\n"
                f"• Affected: {finding.affected_object or 'N/A'}\n"
                f"• Frames: {finding.evidence_frames[:10]}{'...' if len(finding.evidence_frames) > 10 else ''}\n"
                f"• Count: {finding.count}\n"
                f"• First seen: {finding.first_seen}\n"
                f"• Last seen: {finding.last_seen}\n\n"
                f"[bold]Metrics:[/bold]\n" +
                "\n".join(f"• {k}: {v}" for k, v in finding.metrics.items()) +
                f"\n\n[bold]Possible Causes:[/bold]\n" +
                "\n".join(f"• {c}" for c in finding.possible_causes) +
                f"\n\n[bold]Recommended Actions:[/bold]\n" +
                "\n".join(f"• {a}" for a in finding.recommended_actions),
                title=f"[{finding.severity.value.upper()}] {finding.category.value}",
                border_style={
                    'critical': 'red',
                    'high': 'red', 
                    'medium': 'yellow',
                    'low': 'blue',
                    'info': 'green',
                }.get(finding.severity.value, 'white'),
            )
            self.console.print(panel)
