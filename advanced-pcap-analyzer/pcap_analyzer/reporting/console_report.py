#!/usr/bin/env python3
"""
Console Report Generator

Generates engineering-focused terminal output using rich library.
"""

from typing import Optional, List
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.text import Text

from config import Config


class ConsoleReportGenerator:
    """
    Generates console reports using rich formatting.
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.console = Console(width=self.config.report.console_width)
    
    def print_summary(self, summary):
        """Print capture summary."""
        self.console.print(Panel.fit(
            f"[bold blue]Capture Summary[/bold blue]\n\n"
            f"File: {summary.file_path}\n"
            f"Packets: {summary.total_packets:,}\n"
            f"Duration: {summary.duration_seconds:.2f}s\n"
            f"Bytes: {summary.total_bytes:,}",
            title="📊 Analysis Overview"
        ))
        
        # Protocol distribution
        table = Table(title="Protocol Distribution")
        table.add_column("Protocol", style="cyan")
        table.add_column("Packets", justify="right", style="green")
        table.add_column("%", justify="right")
        
        total = sum(summary.protocol_counts.values()) or 1
        for proto, count in summary.protocol_counts.items():
            pct = (count / total) * 100
            table.add_row(proto, f"{count:,}", f"{pct:.1f}%")
        
        self.console.print(table)
        
        # Top IPs
        if summary.top_src_ips:
            table = Table(title="Top Source IPs")
            table.add_column("IP Address", style="blue")
            table.add_column("Packets", justify="right", style="green")
            for ip, count in summary.top_src_ips[:5]:
                table.add_row(ip, f"{count:,}")
            self.console.print(table)
    
    def print_findings(self, findings):
        """Print analysis findings."""
        if not findings:
            self.console.print("[green]✓ No significant issues detected[/green]")
            return
        
        self.console.print(Panel(f"[bold red]Found {len(findings)} issues[/bold red]"))
        
        for finding in findings:
            severity_colors = {
                'critical': 'bold white on red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'blue',
                'info': 'green',
            }
            
            color = severity_colors.get(finding.severity.value, 'white')
            
            panel = Panel(
                f"[bold]{finding.title}[/bold]\n\n"
                f"{finding.description}\n\n"
                f"[italic]Affected:[/italic] {finding.affected_object or 'N/A'}\n"
                f"[italic]Evidence frames:[/italic] {finding.evidence_frames[:5]}...\n\n"
                f"[bold]Recommendations:[/bold]\n" + 
                "\n".join(f"  • {a}" for a in finding.recommended_actions[:3]),
                title=f"[{color}] {finding.finding_id} [{color}]",
                border_style=color.split()[-1] if ' ' in color else color,
            )
            self.console.print(panel)
    
    def print_tcp_health(self, tcp_analysis):
        """Print TCP health analysis."""
        self.console.print(Panel("[bold magenta]TCP Health Analysis[/bold magenta]"))
        
        # Summary stats
        table = Table(title="TCP Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Connections", str(tcp_analysis.total_connections))
        table.add_row("Successful", str(tcp_analysis.successful_connections))
        table.add_row("Failed", str(tcp_analysis.failed_connection_count))
        table.add_row("Reset", str(tcp_analysis.reset_connections))
        table.add_row("Retransmissions", str(tcp_analysis.total_retransmissions))
        table.add_row("Zero Windows", str(tcp_analysis.total_zero_windows))
        table.add_row("Avg RTT", f"{tcp_analysis.avg_rtt_ms:.2f}ms")
        table.add_row("Retrans Rate", f"{tcp_analysis.overall_retransmission_rate:.2f}%")
        
        self.console.print(table)
        
        # Failed connections
        if tcp_analysis.failed_connections:
            table = Table(title="Failed/Problematic Connections")
            table.add_column("Flow", style="blue")
            table.add_column("Issue", style="red")
            table.add_column("Retrans %", justify="right")
            
            for conn in tcp_analysis.failed_connections[:10]:
                issue = conn.failure_reason or conn.result.value
                table.add_row(
                    f"{conn.src_ip}:{conn.src_port} → {conn.dst_ip}:{conn.dst_port}",
                    issue,
                    f"{conn.retransmission_rate:.1f}%",
                )
            
            self.console.print(table)
    
    def print_dns(self, dns_analysis):
        """Print DNS analysis."""
        self.console.print(Panel("[bold cyan]DNS Analysis[/bold cyan]"))
        
        table = Table(title="DNS Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Queries", str(dns_analysis.total_queries))
        table.add_row("Responses", str(dns_analysis.total_responses))
        table.add_row("Unanswered", str(dns_analysis.unanswered_queries))
        table.add_row("NXDOMAIN", str(dns_analysis.nxdomain_count))
        table.add_row("SERVFAIL", str(dns_analysis.servfail_count))
        table.add_row("Avg Latency", f"{dns_analysis.avg_latency_ms:.2f}ms")
        table.add_row("Slow Queries", str(dns_analysis.slow_queries_count))
        
        self.console.print(table)
        
        if dns_analysis.top_domains:
            table = Table(title="Top Queried Domains")
            table.add_column("Domain", style="blue")
            table.add_column("Count", justify="right", style="green")
            for domain, count in dns_analysis.top_domains[:10]:
                table.add_row(domain, str(count))
            self.console.print(table)
    
    def print_latency(self, latency_analysis):
        """Print latency analysis."""
        self.console.print(Panel("[bold yellow]Latency Analysis[/bold yellow]"))
        
        table = Table(title="RTT/Latency Statistics")
        table.add_column("Type", style="cyan")
        table.add_column("Avg (ms)", justify="right", style="green")
        table.add_column("Min (ms)", justify="right")
        table.add_column("Max (ms)", justify="right")
        
        if latency_analysis.tcp_handshake_rtts:
            table.add_row(
                "TCP Handshake",
                f"{latency_analysis.avg_tcp_rtt_ms:.2f}",
                f"{latency_analysis.min_tcp_rtt_ms:.2f}",
                f"{latency_analysis.max_tcp_rtt_ms:.2f}",
            )
        
        if latency_analysis.dns_latencies:
            table.add_row(
                "DNS",
                f"{latency_analysis.avg_dns_latency_ms:.2f}",
                f"{latency_analysis.min_dns_latency_ms:.2f}",
                f"{latency_analysis.max_dns_latency_ms:.2f}",
            )
        
        if latency_analysis.icmp_rtts:
            table.add_row(
                "ICMP",
                f"{latency_analysis.avg_icmp_rtt_ms:.2f}",
                f"{latency_analysis.min_icmp_rtt_ms:.2f}",
                f"{latency_analysis.max_icmp_rtt_ms:.2f}",
            )
        
        self.console.print(table)
    
    def print_flows(self, flows):
        """Print flow analysis."""
        self.console.print(Panel("[bold green]Top Flows[/bold green]"))
        
        table = Table(title="Top Conversations by Bytes")
        table.add_column("Source", style="blue")
        table.add_column("Destination", style="blue")
        table.add_column("Proto", style="cyan")
        table.add_column("Packets", justify="right")
        table.add_column("Bytes", justify="right", style="green")
        
        for flow in flows[:20]:
            table.add_row(
                f"{flow.src_ip}:{flow.src_port}",
                f"{flow.dst_ip}:{flow.dst_port}",
                flow.protocol_name,
                f"{flow.packets:,}",
                f"{flow.bytes_total:,}",
            )
        
        self.console.print(table)
    
    def print_diagnosis(self, findings):
        """Print focused diagnosis with root-cause hints."""
        self.console.print(Panel("[bold red]Diagnosis Report[/bold red]"))
        
        if not findings:
            self.console.print("[green]No critical issues detected[/green]")
            return
        
        tree = Tree("🔍 Findings and Root Causes")
        
        for finding in findings:
            branch = tree.add(f"[bold]{finding.title}[/bold]")
            branch.add(f"Severity: [{finding.severity.value}]{finding.severity.value.upper()}[/{finding.severity.value}]")
            branch.add(f"Description: {finding.description}")
            
            causes = branch.add("Possible Causes:")
            for cause in finding.possible_causes[:3]:
                causes.add(f"• {cause}")
            
            actions = branch.add("Recommended Actions:")
            for action in finding.recommended_actions[:3]:
                actions.add(f"• {action}")
        
        self.console.print(tree)
    
    def print_arp(self, arp_analysis):
        """Print ARP analysis."""
        self.console.print(Panel("[bold magenta]ARP Analysis[/bold magenta]"))
        self.console.print("ARP analysis results would be displayed here.")
    
    def print_dhcp(self, dhcp_analysis):
        """Print DHCP analysis."""
        self.console.print(Panel("[bold cyan]DHCP Analysis[/bold cyan]"))
        self.console.print("DHCP analysis results would be displayed here.")
    
    def print_icmp(self, icmp_analysis):
        """Print ICMP analysis."""
        self.console.print(Panel("[bold green]ICMP Analysis[/bold green]"))
        self.console.print("ICMP analysis results would be displayed here.")
    
    def print_tls(self, tls_analysis):
        """Print TLS analysis."""
        self.console.print(Panel("[bold yellow]TLS Analysis[/bold yellow]"))
        self.console.print("TLS analysis results would be displayed here.")
    
    def print_http(self, http_analysis):
        """Print HTTP analysis."""
        self.console.print(Panel("[bold blue]HTTP Analysis[/bold blue]"))
        self.console.print("HTTP analysis results would be displayed here.")
    
    def print_qos(self, qos_analysis):
        """Print QoS analysis."""
        self.console.print(Panel("[bold magenta]QoS/DSCP Analysis[/bold magenta]"))
        self.console.print("QoS analysis results would be displayed here.")
    
    def print_anomalies(self, anomalies):
        """Print anomaly detection results."""
        self.console.print(Panel("[bold red]Security Anomalies[/bold red]"))
        self.console.print("Anomaly detection results would be displayed here.")
    
    def print_comparison(self, before_summary, after_summary, focus=None):
        """Print comparison between two captures."""
        self.console.print(Panel("[bold cyan]Capture Comparison[/bold cyan]"))
        
        table = Table(title="Before vs After")
        table.add_column("Metric", style="cyan")
        table.add_column("Before", justify="right")
        table.add_column("After", justify="right")
        table.add_column("Change", justify="right")
        
        metrics = [
            ("Packets", before_summary.total_packets, after_summary.total_packets),
            ("Bytes", before_summary.total_bytes, after_summary.total_bytes),
            ("Duration (s)", f"{before_summary.duration_seconds:.1f}", f"{after_summary.duration_seconds:.1f}"),
            ("Retransmissions", before_summary.retransmission_count, after_summary.retransmission_count),
        ]
        
        for name, before_val, after_val in metrics:
            if isinstance(before_val, (int, float)) and isinstance(after_val, (int, float)):
                change = after_val - before_val
                change_str = f"+{change:,}" if change > 0 else f"{change:,}"
                if change > 0:
                    change_str = f"[red]{change_str}[/red]"
                elif change < 0:
                    change_str = f"[green]{change_str}[/green]"
            else:
                change_str = "N/A"
            
            table.add_row(name, str(before_val), str(after_val), change_str)
        
        self.console.print(table)
