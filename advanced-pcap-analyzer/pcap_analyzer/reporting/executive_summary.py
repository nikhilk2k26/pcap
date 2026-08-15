#!/usr/bin/env python3
"""
Executive Summary Generator

Generates high-level executive summaries for management.
"""

from typing import Optional
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from config import Config


class ExecutiveSummaryGenerator:
    """
    Generates executive summaries for non-technical stakeholders.
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.console = Console()
    
    def print_summary(self, summary):
        """Print executive summary to console."""
        
        # Determine overall health
        critical_issues = 0
        warnings = 0
        
        if summary.retransmission_count > 0:
            retrans_rate = (summary.retransmission_count / max(1, summary.total_packets)) * 100
            if retrans_rate > 15:
                critical_issues += 1
            elif retrans_rate > 5:
                warnings += 1
        
        health_status = "✅ HEALTHY"
        health_color = "green"
        if critical_issues > 0:
            health_status = "❌ CRITICAL ISSUES DETECTED"
            health_color = "red"
        elif warnings > 0:
            health_status = "⚠️ WARNINGS DETECTED"
            health_color = "yellow"
        
        self.console.print(Panel(
            f"[bold {health_color}]{health_status}[/bold {health_color}]\n\n"
            f"Capture analyzed: {summary.file_path}\n"
            f"Time period: {summary.duration_seconds:.1f} seconds\n"
            f"Total traffic: {summary.total_packets:,} packets ({summary.total_bytes:,} bytes)\n\n"
            f"[bold]Key Metrics:[/bold]\n"
            f"• Retransmissions: {summary.retransmission_count:,}\n"
            f"• TCP Connections: {summary.tcp_syn_count:,} initiated\n"
            f"• DNS Queries: {summary.dns_query_count:,}\n",
            title="📊 Executive Summary",
            border_style=health_color,
        ))
        
        if critical_issues > 0:
            self.console.print("\n[bold red]Immediate action required. See detailed report for findings.[/bold red]")
        elif warnings > 0:
            self.console.print("\n[yellow]Review recommended for identified warnings.[/yellow]")
        else:
            self.console.print("\n[green]No critical issues detected. Network appears healthy.[/green]")
    
    def generate_text(self, summary, findings=None) -> str:
        """Generate text executive summary."""
        
        lines = [
            "=" * 60,
            "EXECUTIVE SUMMARY - PCAP Analysis Report",
            "=" * 60,
            "",
            f"File: {summary.file_path}",
            f"Duration: {summary.duration_seconds:.1f} seconds",
            f"Total Packets: {summary.total_packets:,}",
            f"Total Bytes: {summary.total_bytes:,}",
            "",
            "-" * 60,
            "OVERALL STATUS",
            "-" * 60,
        ]
        
        # Calculate health
        if summary.total_packets > 0:
            retrans_rate = (summary.retransmission_count / summary.total_packets) * 100
        else:
            retrans_rate = 0
        
        if retrans_rate > 15:
            status = "CRITICAL - Immediate attention required"
        elif retrans_rate > 5:
            status = "WARNING - Issues detected, review recommended"
        else:
            status = "HEALTHY - No critical issues detected"
        
        lines.append(f"Status: {status}")
        lines.append(f"Retransmission Rate: {retrans_rate:.2f}%")
        lines.append("")
        
        if findings:
            lines.extend([
                "-" * 60,
                "KEY FINDINGS",
                "-" * 60,
            ])
            
            critical = [f for f in findings if f.severity.value in ('critical', 'high')]
            for f in critical[:5]:
                lines.append(f"• [{f.severity.value.upper()}] {f.title}")
        
        lines.extend([
            "",
            "-" * 60,
            "RECOMMENDATIONS",
            "-" * 60,
        ])
        
        if retrans_rate > 5:
            lines.append("• Investigate network path for packet loss")
            lines.append("• Check interface error counters on network devices")
            lines.append("• Review QoS policies and queue depths")
        else:
            lines.append("• Continue regular monitoring")
            lines.append("• No immediate action required")
        
        lines.extend([
            "",
            "=" * 60,
            f"Report generated: {datetime.now().isoformat()}",
            "=" * 60,
        ])
        
        return "\n".join(lines)
