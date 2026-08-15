"""
TCP Expert CLI Commands

Provides commands for deep TCP connection analysis.
"""
import typer
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ..analysis.tcp_expert_analyzer import TCPExpertAnalyzer
from ..storage.sqlite_store import SQLiteStore
from ..reporting.json_report import JSONReportGenerator
from ..reporting.csv_report import CSVReportGenerator


app = typer.Typer(help="TCP Expert Analysis Commands")
console = Console()


@app.command("health")
def tcp_health(
    file: Path = typer.Argument(..., help="PCAP/PCAPNG file to analyze"),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path"),
    format: str = typer.Option("table", "-f", "--format", help="Output format (table, json, csv)"),
    limit: Optional[int] = typer.Option(None, "--limit", help="Limit number of packets"),
    unhealthy_only: bool = typer.Option(False, "--unhealthy", help="Show only unhealthy connections"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output")
):
    """
    Analyze TCP connections and classify their health.
    
    Classifies each connection as:
    - healthy
    - slow_handshake
    - retransmission_heavy
    - lossy
    - receiver_limited
    - reset_by_endpoint
    - reset_by_middlebox
    - incomplete_handshake
    - timeout
    """
    console.print(f"[bold blue]Analyzing TCP connections in {file}...[/bold blue]")
    
    if not file.exists():
        console.print(f"[red]Error: File not found: {file}[/red]")
        raise typer.Exit(1)
    
    # Use SQLite store for memory-efficient processing
    store = SQLiteStore()
    db_path = store.create_index(file)
    
    # Run TCP Expert Analyzer
    analyzer = TCPExpertAnalyzer()
    connections = analyzer.analyze_from_db(db_path, limit=limit)
    
    if unhealthy_only:
        connections = [c for c in connections if c.health_status.name != "HEALTHY"]
    
    stats = analyzer.get_summary_stats()
    
    # Output results
    if format == "json":
        report = JSONReportGenerator()
        data = {
            "summary": stats,
            "connections": [c.to_dict() for c in connections]
        }
        if output:
            report.generate(data, str(output))
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            import json
            print(json.dumps(data, indent=2))
            
    elif format == "csv":
        if output:
            csv_gen = CSVReportGenerator()
            csv_gen.generate_tcp_health(connections, str(output))
            console.print(f"[green]CSV saved to {output}[/green]")
        else:
            console.print("[yellow]Specify --output for CSV format[/yellow]")
            
    else:  # table format
        _print_tcp_health_table(connections, stats, verbose)


def _print_tcp_health_table(connections: List, stats: dict, verbose: bool = False):
    """Print TCP health results as a rich table."""
    
    # Summary Panel
    summary_panel = Panel(
        f"""[bold]Total Connections:[/bold] {stats['total_connections']}
[bold]Healthy:[/bold] {stats['healthy_connections']} ({stats['health_rate_pct']}%)
[bold]Unhealthy:[/bold] {stats['unhealthy_connections']}
[bold]Total Retransmissions:[/bold] {stats['total_retransmissions']}
[bold]Total Zero Windows:[/bold] {stats['total_zero_windows']}

[bold]Status Breakdown:[/bold]
{chr(10).join(f'  - {k}: {v}' for k, v in stats['status_breakdown'].items())}
""",
        title="TCP Health Summary",
        border_style="blue",
        box=box.ROUNDED
    )
    console.print(summary_panel)
    console.print()
    
    if not connections:
        console.print("[green]No connections to display.[/green]")
        return
    
    # Detailed Table
    table = Table(title="TCP Connection Details", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    
    table.add_column("Flow", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Pkts", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Retrans", justify="right")
    table.add_column("Dup ACKs", justify="right")
    table.add_column("Zero Win", justify="right")
    table.add_column("Init RTT (ms)", justify="right")
    table.add_column("Problem", style="yellow")
    
    # Sort by health status (unhealthy first)
    status_priority = {
        "reset_by_middlebox": 0,
        "reset_by_endpoint": 1,
        "incomplete_handshake": 2,
        "timeout": 3,
        "retransmission_heavy": 4,
        "lossy": 5,
        "receiver_limited": 6,
        "slow_handshake": 7,
        "healthy": 8,
        "unknown": 9
    }
    
    sorted_conns = sorted(
        connections, 
        key=lambda c: status_priority.get(c.health_status.value, 9)
    )
    
    for conn in sorted_conns[:50]:  # Limit display to 50
        status_style = {
            "healthy": "green",
            "slow_handshake": "yellow",
            "retransmission_heavy": "red",
            "lossy": "orange",
            "receiver_limited": "magenta",
            "reset_by_endpoint": "red",
            "reset_by_middlebox": "red bold",
            "incomplete_handshake": "red",
            "timeout": "red",
            "unknown": "gray"
        }.get(conn.health_status.value, "white")
        
        flow_str = f"{conn.src_ip}:{conn.src_port}\n  → {conn.dst_ip}:{conn.dst_port}"
        
        table.add_row(
            flow_str,
            f"[{status_style}]{conn.health_status.value}[/{status_style}]",
            str(conn.total_packets),
            str(conn.total_bytes),
            f"[red]{conn.retransmissions}[/red]" if conn.retransmissions > 0 else "0",
            f"[yellow]{conn.duplicate_acks}[/yellow]" if conn.duplicate_acks > 0 else "0",
            f"[magenta]{conn.zero_windows}[/magenta]" if conn.zero_windows > 0 else "0",
            f"{conn.initial_rtt*1000:.1f}" if conn.initial_rtt else "N/A",
            conn.likely_problem[:40] + "..." if conn.likely_problem and len(conn.likely_problem) > 40 else (conn.likely_problem or "")
        )
    
    console.print(table)
    
    if len(connections) > 50:
        console.print(f"[italic]Showing top 50 of {len(connections)} connections. Use --output for full export.[/italic]")
    
    # Recommendations Panel
    unhealthy = [c for c in connections if c.health_status.value != "healthy"]
    if unhealthy:
        console.print()
        rec_panel = Panel(
            "\n".join([
                f"[bold]{i+1}. {c.src_ip}:{c.src_port} → {c.dst_ip}:{c.dst_port}[/bold]\n"
                f"   Status: [{status_priority.get(c.health_status.value, 'white')}]{c.health_status.value}[/{status_priority.get(c.health_status.value, 'white')}]\n"
                f"   Problem: {c.likely_problem}\n"
                f"   [green]Action:[/green] {c.recommended_action}\n"
                for i, c in enumerate(unhealthy[:5])
            ]),
            title="Top Recommended Actions",
            border_style="green",
            box=box.ROUNDED
        )
        console.print(rec_panel)


@app.command("detail")
def tcp_detail(
    file: Path = typer.Argument(..., help="PCAP/PCAPNG file"),
    flow_id: str = typer.Argument(..., help="Flow ID to analyze"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show detailed packet info")
):
    """
    Show detailed analysis of a specific TCP flow.
    
    Flow ID format: src_ip:src_port-dst_ip:dst_port
    """
    console.print(f"[bold blue]Analyzing flow: {flow_id}[/bold blue]")
    
    store = SQLiteStore()
    db_path = store.create_index(file)
    
    analyzer = TCPExpertAnalyzer()
    connections = analyzer.analyze_from_db(db_path)
    
    # Find matching connection
    target_conn = None
    for conn in connections:
        if conn.flow_id == flow_id:
            target_conn = conn
            break
    
    if not target_conn:
        console.print(f"[red]Flow not found: {flow_id}[/red]")
        raise typer.Exit(1)
    
    # Print detailed report
    _print_connection_detail(target_conn, verbose)


def _print_connection_detail(conn, verbose: bool = False):
    """Print detailed connection analysis."""
    
    console.print()
    console.print(Panel(
        f"[bold]Flow:[/bold] {conn.flow_id}\n"
        f"[bold]Duration:[/bold] {conn.duration:.3f}s\n"
        f"[bold]Result:[/bold] {conn.connection_result}\n"
        f"[bold]State:[/bold] {conn.connection_state.value}",
        title="Connection Overview",
        border_style="cyan"
    ))
    
    # Metrics Table
    metrics_table = Table(title="Performance Metrics", box=box.ROUNDED)
    metrics_table.add_column("Metric", style="cyan")
    metrics_table.add_column("Value", style="yellow")
    
    metrics_table.add_row("Packets (Sent/Recv)", f"{conn.packets_sent} / {conn.packets_received}")
    metrics_table.add_row("Bytes (Sent/Recv)", f"{conn.bytes_sent:,} / {conn.bytes_received:,}")
    metrics_table.add_row("Throughput", f"{conn.throughput_bps/1e6:.2f} Mbps")
    metrics_table.add_row("Goodput", f"{conn.goodput_bps/1e6:.2f} Mbps")
    metrics_table.add_row("Retransmissions", str(conn.retransmissions))
    metrics_table.add_row("Retrans Rate", f"{conn.retransmission_rate*100:.2f}%")
    metrics_table.add_row("Duplicate ACKs", str(conn.duplicate_acks))
    metrics_table.add_row("Out-of-Order", str(conn.out_of_order))
    metrics_table.add_row("Zero Windows", str(conn.zero_windows))
    
    if conn.initial_rtt:
        metrics_table.add_row("Initial RTT", f"{conn.initial_rtt*1000:.2f} ms")
    if conn.avg_rtt:
        metrics_table.add_row("Avg RTT", f"{conn.avg_rtt*1000:.2f} ms")
        metrics_table.add_row("Min/Max RTT", f"{conn.min_rtt*1000:.2f} / {conn.max_rtt*1000:.2f} ms")
    
    console.print(metrics_table)
    
    # TCP Options
    options_table = Table(title="TCP Options", box=box.ROUNDED)
    options_table.add_column("Option", style="cyan")
    options_table.add_column("Client", style="yellow")
    options_table.add_column("Server", style="yellow")
    
    options_table.add_row("MSS", str(conn.mss_client or "N/A"), str(conn.mss_server or "N/A"))
    options_table.add_row("Window Scale", str(conn.window_scale_client or "0"), str(conn.window_scale_server or "0"))
    options_table.add_row("SACK Permitted", "Yes" if conn.sack_permitted else "No", "Yes" if conn.sack_permitted else "No")
    options_table.add_row("ECN", "Yes" if conn.ecn_negotiated else "No", "Yes" if conn.ecn_negotiated else "No")
    
    console.print(options_table)
    
    # Diagnosis Panel
    diagnosis_panel = Panel(
        f"[bold]Health Status:[/bold] [{_get_status_color(conn.health_status.value)}]{conn.health_status.value}[/{_get_status_color(conn.health_status.value)}]\n\n"
        f"[bold]Likely Problem:[/bold] {conn.likely_problem}\n\n"
        f"[bold green]Recommended Action:[/bold green]\n{conn.recommended_action}",
        title="Expert Diagnosis",
        border_style="green"
    )
    console.print(diagnosis_panel)
    
    if verbose and conn.findings:
        console.print()
        console.print("[bold]Detailed Findings:[/bold]")
        for finding in conn.findings:
            console.print(f"  - [{finding.severity}] {finding.message}")
            if finding.evidence_frames:
                console.print(f"    Frames: {finding.evidence_frames[:5]}")


def _get_status_color(status: str) -> str:
    """Get color for status string."""
    colors = {
        "healthy": "green",
        "slow_handshake": "yellow",
        "retransmission_heavy": "red",
        "lossy": "orange",
        "receiver_limited": "magenta",
        "reset_by_endpoint": "red",
        "reset_by_middlebox": "red bold",
        "incomplete_handshake": "red",
        "timeout": "red",
        "unknown": "gray"
    }
    return colors.get(status, "white")


# Export for main CLI
def register_tcp_commands(main_app: typer.Typer):
    """Register TCP commands with main app."""
    main_app.add_typer(app, name="tcp")
