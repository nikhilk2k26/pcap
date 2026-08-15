#!/usr/bin/env python3
"""
Command-Line Interface for Advanced PCAP Analyzer.

Provides commands for analyzing PCAP/PCAPNG files with various analysis modes.
"""

import sys
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from config import Config, DEFAULT_CONFIG
from pcap_analyzer.ingestion.file_detector import FileDetector
from pcap_analyzer.ingestion.tshark_runner import TsharkRunner
from pcap_analyzer.storage.sqlite_store import SQLiteStore
from pcap_analyzer.analysis.summary_analyzer import SummaryAnalyzer
from pcap_analyzer.analysis.tcp_analyzer import TCPAnalyzer
from pcap_analyzer.analysis.dns_analyzer import DNSAnalyzer
from pcap_analyzer.analysis.latency_analyzer import LatencyAnalyzer
from pcap_analyzer.detection.finding_engine import FindingEngine
from pcap_analyzer.reporting.console_report import ConsoleReportGenerator
from pcap_analyzer.reporting.json_report import JSONReportGenerator
from pcap_analyzer.reporting.html_report import HTMLReportGenerator
from pcap_analyzer.reporting.executive_summary import ExecutiveSummaryGenerator
from pcap_analyzer.reporting.engineer_report import EngineerReportGenerator

app = typer.Typer(
    name="advanced-pcap-analyzer",
    help="Advanced PCAP/PCAPNG analysis for network engineers, NOC, SREs, and security analysts.",
    add_completion=True,
)

console = Console()


def _validate_file(file_path: str) -> Path:
    """Validate that the input file exists and is readable."""
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {path}")
        raise typer.Exit(code=1)
    if not path.is_file():
        console.print(f"[red]Error:[/red] Not a file: {path}")
        raise typer.Exit(code=1)
    return path


def _check_tshark():
    """Check if tshark is available."""
    runner = TsharkRunner()
    if not runner.check_tshark():
        console.print("[red]Error:[/red] tshark not found. Please install Wireshark/tshark.")
        console.print("  Ubuntu/Debian: sudo apt-get install tshark")
        console.print("  macOS: brew install wireshark")
        console.print("  Windows: https://www.wireshark.org/download.html")
        raise typer.Exit(code=1)


def _create_store(config: Config) -> SQLiteStore:
    """Create a storage backend."""
    return SQLiteStore(config)


@app.command("analyze")
def cmd_analyze(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file path"),
    format: str = typer.Option("console", "-f", "--format", help="Output format: console, json, html"),
    limit: Optional[int] = typer.Option(None, "-l", "--limit", help="Limit to first N packets"),
    sample_rate: float = typer.Option(1.0, "--sample-rate", help="Sample rate (0.01-1.0)"),
    start_time: Optional[str] = typer.Option(None, "--start-time", help="Start time filter"),
    end_time: Optional[str] = typer.Option(None, "--end-time", help="End time filter"),
    src_ip: Optional[str] = typer.Option(None, "--src-ip", help="Source IP filter"),
    dst_ip: Optional[str] = typer.Option(None, "--dst-ip", help="Destination IP filter"),
    protocol: Optional[str] = typer.Option(None, "--protocol", help="Protocol filter"),
    port: Optional[int] = typer.Option(None, "--port", help="Port filter"),
    retransmissions_only: bool = typer.Option(False, "--retransmissions-only", help="Show only retransmissions"),
    failed_connections: bool = typer.Option(False, "--failed-connections", help="Show only failed connections"),
    latency_above: Optional[str] = typer.Option(None, "--latency-above", help="Filter by latency threshold"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
    debug: bool = typer.Option(False, "--debug", help="Debug mode"),
):
    """Full analysis of a PCAP/PCAPNG file with all findings and recommendations."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    config.debug = debug
    config.verbose = verbose
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Analyzing {file_path.name}...", total=None)
        
        try:
            # Create store and ingest packets
            store = _create_store(config)
            store.ingest_file(file_path, limit=limit, sample_rate=sample_rate)
            
            # Run analyzers
            summary = SummaryAnalyzer(store, config).analyze()
            tcp_analysis = TCPAnalyzer(store, config).analyze()
            dns_analysis = DNSAnalyzer(store, config).analyze()
            latency_analysis = LatencyAnalyzer(store, config).analyze()
            
            # Generate findings
            finding_engine = FindingEngine(config)
            findings = finding_engine.generate_findings(tcp_analysis, dns_analysis, latency_analysis, summary)
            
            # Generate report
            if format == "json":
                generator = JSONReportGenerator(config)
                report = generator.generate(summary, tcp_analysis, dns_analysis, latency_analysis, findings)
                if output:
                    Path(output).write_text(report)
                    console.print(f"[green]Report saved to:[/green] {output}")
                else:
                    console.print(report)
            elif format == "html":
                generator = HTMLReportGenerator(config)
                report = generator.generate(summary, tcp_analysis, dns_analysis, latency_analysis, findings)
                if output:
                    Path(output).write_text(report)
                    console.print(f"[green]Report saved to:[/green] {output}")
                else:
                    console.print("[red]Error:[/red] HTML output requires --output file")
            else:
                generator = ConsoleReportGenerator(config)
                generator.print_summary(summary)
                generator.print_findings(findings)
                generator.print_tcp_health(tcp_analysis)
                
        except Exception as e:
            if debug:
                import traceback
                traceback.print_exc()
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(code=1)


@app.command("diagnose")
def cmd_diagnose(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
):
    """Focused diagnosis with root-cause hints and recommendations."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    config.verbose = verbose
    
    console.print(f"[bold blue]Diagnosing:[/bold blue] {file_path}\n")
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        summary = SummaryAnalyzer(store, config).analyze()
        tcp_analysis = TCPAnalyzer(store, config).analyze()
        
        finding_engine = FindingEngine(config)
        findings = finding_engine.generate_findings(tcp_analysis=tcp_analysis, summary=summary)
        
        generator = ConsoleReportGenerator(config)
        generator.print_diagnosis(findings)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("summary")
def cmd_summary(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
):
    """Quick capture summary."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        summary = SummaryAnalyzer(store, config).analyze()
        
        generator = ExecutiveSummaryGenerator(config)
        generator.print_summary(summary)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("flows")
def cmd_flows(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
    top: int = typer.Option(20, "-t", "--top", help="Show top N flows"),
    export: Optional[str] = typer.Option(None, "-e", "--export", help="Export to CSV file"),
    protocol: Optional[str] = typer.Option(None, "--protocol", help="Filter by protocol"),
):
    """Flow analysis and top talkers."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        from pcap_analyzer.analysis.flow_analyzer import FlowAnalyzer
        flow_analyzer = FlowAnalyzer(store, config)
        flows = flow_analyzer.analyze()
        
        # Sort by bytes and get top N
        sorted_flows = sorted(flows, key=lambda f: f.bytes_total, reverse=True)[:top]
        
        generator = ConsoleReportGenerator(config)
        generator.print_flows(sorted_flows)
        
        if export:
            import csv
            with open(export, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                               'protocol', 'packets', 'bytes', 'duration'])
                for flow in sorted_flows:
                    writer.writerow([
                        flow.flow_id, flow.src_ip, flow.dst_ip, flow.src_port,
                        flow.dst_port, flow.protocol, flow.packets, flow.bytes_total,
                        flow.duration
                    ])
            console.print(f"[green]Flows exported to:[/green] {export}")
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("tcp-health")
def cmd_tcp_health(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
):
    """TCP connection health analysis."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    config.verbose = verbose
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        tcp_analysis = TCPAnalyzer(store, config).analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_tcp_health(tcp_analysis)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("latency")
def cmd_latency(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
):
    """Latency and performance analysis."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        latency_analysis = LatencyAnalyzer(store, config).analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_latency(latency_analysis)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("dns")
def cmd_dns(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
):
    """DNS transaction analysis."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        dns_analysis = DNSAnalyzer(store, config).analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_dns(dns_analysis)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("dhcp")
def cmd_dhcp(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
):
    """DHCP transaction analysis."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        from pcap_analyzer.analysis.dhcp_analyzer import DHCPAnalyzer
        dhcp_analyzer = DHCPAnalyzer(store, config)
        dhcp_analysis = dhcp_analyzer.analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_dhcp(dhcp_analysis)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("arp")
def cmd_arp(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
):
    """ARP and L2 analysis."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        from pcap_analyzer.analysis.arp_analyzer import ARPAnalyzer
        arp_analyzer = ARPAnalyzer(store, config)
        arp_analysis = arp_analyzer.analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_arp(arp_analysis)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("icmp")
def cmd_icmp(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
):
    """ICMP event analysis."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        from pcap_analyzer.analysis.icmp_analyzer import ICMPAnalyzer
        icmp_analyzer = ICMPAnalyzer(store, config)
        icmp_analysis = icmp_analyzer.analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_icmp(icmp_analysis)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("tls")
def cmd_tls(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
):
    """TLS session analysis."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        from pcap_analyzer.analysis.tls_analyzer import TLSAnalyzer
        tls_analyzer = TLSAnalyzer(store, config)
        tls_analysis = tls_analyzer.analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_tls(tls_analysis)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("http")
def cmd_http(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
):
    """HTTP transaction analysis."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        from pcap_analyzer.analysis.http_analyzer import HTTPAnalyzer
        http_analyzer = HTTPAnalyzer(store, config)
        http_analysis = http_analyzer.analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_http(http_analysis)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("qos")
def cmd_qos(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
):
    """QoS/DSCP analysis."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        from pcap_analyzer.analysis.qos_dscp_analyzer import QoSDSCPAnalyzer
        qos_analyzer = QoSDSCPAnalyzer(store, config)
        qos_analysis = qos_analyzer.analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_qos(qos_analysis)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("anomalies")
def cmd_anomalies(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
):
    """Security anomaly detection."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        from pcap_analyzer.analysis.anomaly_analyzer import AnomalyAnalyzer
        anomaly_analyzer = AnomalyAnalyzer(store, config)
        anomalies = anomaly_analyzer.analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_anomalies(anomalies)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("compare")
def cmd_compare(
    before_file: str = typer.Argument(..., help="Before capture file"),
    after_file: str = typer.Argument(..., help="After capture file"),
    focus: Optional[str] = typer.Option(None, "--focus", help="Focus areas: tcp,latency,dns,etc."),
):
    """Compare two captures (before/after change analysis)."""
    _check_tshark()
    before_path = _validate_file(before_file)
    after_path = _validate_file(after_file)
    
    config = DEFAULT_CONFIG
    
    console.print(f"[bold blue]Comparing:[/bold blue]")
    console.print(f"  Before: {before_path}")
    console.print(f"  After:  {after_path}\n")
    
    try:
        # Analyze both files
        before_store = _create_store(config)
        before_store.ingest_file(before_path)
        before_summary = SummaryAnalyzer(before_store, config).analyze()
        
        after_store = _create_store(config)
        after_store.ingest_file(after_path)
        after_summary = SummaryAnalyzer(after_store, config).analyze()
        
        generator = ConsoleReportGenerator(config)
        generator.print_comparison(before_summary, after_summary, focus)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("export")
def cmd_export(
    file: str = typer.Argument(..., help="PCAP or PCAPNG file to analyze"),
    type: str = typer.Option("findings", "-t", "--type", help="Export type: findings, flows, packets, full"),
    format: str = typer.Option("json", "-f", "--format", help="Export format: json, csv"),
    output: str = typer.Option(..., "-o", "--output", help="Output file path"),
):
    """Export data in various formats."""
    _check_tshark()
    file_path = _validate_file(file)
    
    config = DEFAULT_CONFIG
    
    try:
        store = _create_store(config)
        store.ingest_file(file_path)
        
        summary = SummaryAnalyzer(store, config).analyze()
        tcp_analysis = TCPAnalyzer(store, config).analyze()
        dns_analysis = DNSAnalyzer(store, config).analyze()
        latency_analysis = LatencyAnalyzer(store, config).analyze()
        
        finding_engine = FindingEngine(config)
        findings = finding_engine.generate_findings(tcp_analysis, dns_analysis, latency_analysis, summary)
        
        if type == "findings":
            if format == "json":
                generator = JSONReportGenerator(config)
                content = generator.generate_findings_json(findings)
                Path(output).write_text(content)
            elif format == "csv":
                import csv
                with open(output, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['finding_id', 'title', 'severity', 'confidence', 
                                   'category', 'description', 'count'])
                    for f in findings:
                        writer.writerow([f.finding_id, f.title, f.severity, f.confidence,
                                       f.category, f.description, f.count])
        elif type == "flows":
            from pcap_analyzer.analysis.flow_analyzer import FlowAnalyzer
            flow_analyzer = FlowAnalyzer(store, config)
            flows = flow_analyzer.analyze()
            
            if format == "csv":
                import csv
                with open(output, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                                   'protocol', 'packets', 'bytes', 'duration'])
                    for flow in flows:
                        writer.writerow([flow.flow_id, flow.src_ip, flow.dst_ip,
                                       flow.src_port, flow.dst_port, flow.protocol,
                                       flow.packets, flow.bytes_total, flow.duration])
        elif type == "full":
            if format == "json":
                generator = JSONReportGenerator(config)
                report = generator.generate(summary, tcp_analysis, dns_analysis, latency_analysis, findings)
                Path(output).write_text(report)
            elif format == "html":
                generator = HTMLReportGenerator(config)
                report = generator.generate(summary, tcp_analysis, dns_analysis, latency_analysis, findings)
                Path(output).write_text(report)
        
        console.print(f"[green]Exported to:[/green] {output}")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
