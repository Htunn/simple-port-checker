"""
Command Line Interface for Simple Port Checker.

This module provides a comprehensive CLI for port scanning and L7 protection detection.
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.panel import Panel
from rich.text import Text

from .core.port_scanner import PortChecker, ScanConfig
from .core.l7_detector import L7Detector
from .models.scan_result import ScanResult, BatchScanResult
from .models.l7_result import L7Result, BatchL7Result
from .utils.common_ports import TOP_PORTS, get_service_name, get_port_description


console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Simple Port Checker - A comprehensive tool for checking firewall ports and L7 protection."""
    pass


@main.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--ports", "-p", help="Comma-separated list of ports to scan")
@click.option("--timeout", "-t", default=3, help="Connection timeout in seconds")
@click.option("--concurrent", "-c", default=100, help="Maximum concurrent connections")
@click.option("--output", "-o", help="Output file (JSON format)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--top-ports", is_flag=True, help="Scan top 25 most common ports")
def scan(targets, ports, timeout, concurrent, output, verbose, top_ports):
    """Scan target hosts for open ports."""

    # Parse ports
    if top_ports:
        port_list = TOP_PORTS[:25]
    elif ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            console.print(
                "[red]Error: Invalid port format. Use comma-separated numbers.[/red]"
            )
            sys.exit(1)
    else:
        port_list = TOP_PORTS

    console.print(f"[blue]Starting port scan for {len(targets)} target(s)[/blue]")
    console.print(f"[yellow]Ports to scan: {len(port_list)} ports[/yellow]")
    console.print(f"[yellow]Timeout: {timeout}s, Concurrent: {concurrent}[/yellow]")

    # Run scan
    asyncio.run(
        _run_port_scan(list(targets), port_list, timeout, concurrent, output, verbose)
    )


@main.command("l7-check")
@click.argument("targets", nargs=-1, required=True)
@click.option("--timeout", "-t", default=10, help="Request timeout in seconds")
@click.option("--user-agent", "-u", help="Custom User-Agent string")
@click.option("--output", "-o", help="Output file (JSON format)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--port", "-p", type=int, help="Specific port to check")
@click.option("--path", default="/", help="URL path to test")
def l7_check(targets, timeout, user_agent, output, verbose, port, path):
    """Check for L7 protection services (WAF, CDN, etc.)."""

    console.print(
        f"[blue]Starting L7 protection check for {len(targets)} target(s)[/blue]"
    )
    console.print(f"[yellow]Timeout: {timeout}s[/yellow]")

    # Run L7 detection
    asyncio.run(
        _run_l7_detection(
            list(targets), timeout, user_agent, output, verbose, port, path
        )
    )


@main.command("full-scan")
@click.argument("targets", nargs=-1, required=True)
@click.option("--ports", "-p", help="Comma-separated list of ports to scan")
@click.option("--timeout", "-t", default=5, help="Connection timeout in seconds")
@click.option("--concurrent", "-c", default=50, help="Maximum concurrent connections")
@click.option("--output", "-o", help="Output file (JSON format)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def full_scan(targets, ports, timeout, concurrent, output, verbose):
    """Perform both port scanning and L7 protection detection."""

    console.print(f"[blue]Starting full scan for {len(targets)} target(s)[/blue]")

    # Parse ports
    if ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            console.print(
                "[red]Error: Invalid port format. Use comma-separated numbers.[/red]"
            )
            sys.exit(1)
    else:
        port_list = TOP_PORTS

    # Run full scan
    asyncio.run(
        _run_full_scan(list(targets), port_list, timeout, concurrent, output, verbose)
    )


async def _run_port_scan(
    targets: List[str],
    ports: List[int],
    timeout: int,
    concurrent: int,
    output: Optional[str],
    verbose: bool,
):
    """Run port scanning with progress display."""

    config = ScanConfig(timeout=timeout, concurrent_limit=concurrent)
    scanner = PortChecker(config)

    start_time = time.time()
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        scan_task = progress.add_task("Scanning hosts...", total=len(targets))

        for target in targets:
            progress.update(scan_task, description=f"Scanning {target}...")

            try:
                result = await scanner.scan_host(target, ports, timeout)
                results.append(result)

                if verbose:
                    _display_scan_result(result)

            except Exception as e:
                console.print(f"[red]Error scanning {target}: {e}[/red]")

            progress.advance(scan_task)

    total_time = time.time() - start_time
    batch_result = BatchScanResult(results=results, total_scan_time=total_time)

    # Display summary
    _display_scan_summary(batch_result)

    # Save output if requested
    if output:
        _save_results(batch_result, output)


async def _run_l7_detection(
    targets: List[str],
    timeout: int,
    user_agent: Optional[str],
    output: Optional[str],
    verbose: bool,
    port: Optional[int],
    path: str,
):
    """Run L7 protection detection with progress display."""

    detector = L7Detector(timeout=timeout, user_agent=user_agent)

    start_time = time.time()
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        detect_task = progress.add_task("Checking L7 protection...", total=len(targets))

        for target in targets:
            progress.update(detect_task, description=f"Checking {target}...")

            try:
                result = await detector.detect(target, port, path)
                results.append(result)

                if verbose:
                    _display_l7_result(result)

            except Exception as e:
                console.print(f"[red]Error checking {target}: {e}[/red]")

            progress.advance(detect_task)

    total_time = time.time() - start_time
    batch_result = BatchL7Result(results=results, total_scan_time=total_time)

    # Display summary
    _display_l7_summary(batch_result)

    # Save output if requested
    if output:
        _save_results(batch_result, output)


async def _run_full_scan(
    targets: List[str],
    ports: List[int],
    timeout: int,
    concurrent: int,
    output: Optional[str],
    verbose: bool,
):
    """Run full scan combining port scanning and L7 detection."""

    console.print("[yellow]Phase 1: Port Scanning[/yellow]")
    await _run_port_scan(targets, ports, timeout, concurrent, None, verbose)

    console.print("\n[yellow]Phase 2: L7 Protection Detection[/yellow]")
    await _run_l7_detection(targets, timeout, None, None, verbose, None, "/")

    console.print("\n[green]Full scan completed![/green]")


def _display_scan_result(result: ScanResult):
    """Display individual scan result."""

    table = Table(title=f"Port Scan Results - {result.host}")
    table.add_column("Port", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Banner", style="dim")

    for port_result in result.ports:
        status = "Open" if port_result.is_open else "Closed"
        status_style = "green" if port_result.is_open else "red"

        table.add_row(
            str(port_result.port),
            f"[{status_style}]{status}[/{status_style}]",
            port_result.service,
            (
                port_result.banner[:50] + "..."
                if len(port_result.banner) > 50
                else port_result.banner
            ),
        )

    console.print(table)
    console.print()


def _display_l7_result(result: L7Result):
    """Display individual L7 detection result."""

    if result.error:
        console.print(f"[red]L7 Check failed for {result.host}: {result.error}[/red]")
        return

    panel_content = []

    if result.is_protected:
        primary = result.primary_protection
        panel_content.append(f"[green]✓ L7 Protection Detected[/green]")
        panel_content.append(f"[yellow]Primary: {primary.service.value}[/yellow]")
        panel_content.append(f"[yellow]Confidence: {primary.confidence:.1%}[/yellow]")

        if len(result.detections) > 1:
            panel_content.append(
                f"[dim]Additional detections: {len(result.detections) - 1}[/dim]"
            )
    else:
        panel_content.append("[red]✗ No L7 Protection Detected[/red]")
        panel_content.append("[bold red]The endpoint is NOT protected by any L7 service (WAF/CDN)[/bold red]")

    panel_content.append(f"[dim]Response time: {result.response_time:.2f}s[/dim]")

    console.print(
        Panel(
            "\n".join(panel_content),
            title=f"L7 Check - {result.host}",
            border_style="blue",
        )
    )


def _display_scan_summary(batch_result: BatchScanResult):
    """Display port scan summary."""

    console.print("\n")
    console.print(
        Panel(
            f"[green]Scan completed in {batch_result.total_scan_time:.2f} seconds[/green]\n"
            f"[yellow]Hosts scanned: {len(batch_result.results)}[/yellow]\n"
            f"[yellow]Successful scans: {len(batch_result.successful_scans)}[/yellow]\n"
            f"[yellow]Failed scans: {len(batch_result.failed_scans)}[/yellow]\n"
            f"[yellow]Total open ports found: {sum(len(r.open_ports) for r in batch_result.successful_scans)}[/yellow]",
            title="Port Scan Summary",
            border_style="green",
        )
    )

    # Display top open ports
    port_counts = {}
    for result in batch_result.successful_scans:
        for port in result.open_ports:
            port_counts[port.port] = port_counts.get(port.port, 0) + 1

    if port_counts:
        console.print("\n[bold]Most Common Open Ports:[/bold]")
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[
            :10
        ]

        table = Table()
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="yellow")
        table.add_column("Count", style="green")

        for port, count in sorted_ports:
            service = get_service_name(port)
            table.add_row(str(port), service, str(count))

        console.print(table)


def _display_l7_summary(batch_result: BatchL7Result):
    """Display L7 detection summary."""

    console.print("\n")
    console.print(
        Panel(
            f"[green]L7 check completed in {batch_result.total_scan_time:.2f} seconds[/green]\n"
            f"[yellow]Hosts checked: {len(batch_result.results)}[/yellow]\n"
            f"[yellow]Protected hosts: {len(batch_result.protected_hosts)}[/yellow]\n"
            f"[bold red]Unprotected hosts: {len(batch_result.unprotected_hosts)}[/bold red]\n"
            f"[yellow]Failed checks: {len(batch_result.failed_checks)}[/yellow]",
            title="L7 Protection Summary",
            border_style="blue",
        )
    )

    # Display protection services summary
    protection_summary = batch_result.get_protection_summary()
    if protection_summary:
        console.print("\n[bold]Detected Protection Services:[/bold]")

        table = Table()
        table.add_column("Service", style="cyan")
        table.add_column("Count", style="green")

        for service, count in sorted(protection_summary.items()):
            table.add_row(service.replace("_", " ").title(), str(count))

        console.print(table)
    
    # Display unprotected hosts
    if batch_result.unprotected_hosts:
        console.print("\n[bold red]Unprotected Hosts (No L7 Protection):[/bold red]")
        
        unprotected_table = Table()
        unprotected_table.add_column("Host", style="red")
        unprotected_table.add_column("Status", style="red")
        
        for result in batch_result.unprotected_hosts:
            unprotected_table.add_row(result.host, "NOT PROTECTED")
            
        console.print(unprotected_table)


def _save_results(results, filename: str):
    """Save results to file."""
    try:
        Path(filename).parent.mkdir(parents=True, exist_ok=True)

        if hasattr(results, "to_json"):
            with open(filename, "w") as f:
                f.write(results.to_json())
        else:
            with open(filename, "w") as f:
                json.dump(results, f, indent=2, default=str)

        console.print(f"[green]Results saved to {filename}[/green]")

    except Exception as e:
        console.print(f"[red]Error saving results: {e}[/red]")


@main.command()
@click.argument("target")
@click.option("--port", "-p", type=int, help="Specific port for service detection")
def service_detect(target, port):
    """Detect service version and information for a specific host/port."""

    console.print(f"[blue]Detecting service information for {target}[/blue]")

    if port:
        console.print(f"[yellow]Target port: {port}[/yellow]")

    asyncio.run(_run_service_detection(target, port))


async def _run_service_detection(target: str, port: Optional[int]):
    """Run service detection."""

    scanner = PortChecker()

    if port:
        # Check specific port
        service_info = await scanner.check_service_version(target, port)
        _display_service_info(target, port, service_info)
    else:
        # Scan common ports first, then detect services
        result = await scanner.scan_host(target, TOP_PORTS[:10])

        if result.error:
            console.print(f"[red]Error: {result.error}[/red]")
            return

        console.print(f"[green]Found {len(result.open_ports)} open ports[/green]")

        for port_result in result.open_ports:
            service_info = await scanner.check_service_version(
                target, port_result.port, port_result.service
            )
            _display_service_info(target, port_result.port, service_info)


def _display_service_info(target: str, port: int, service_info: dict):
    """Display service information."""

    table = Table(title=f"Service Information - {target}:{port}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")

    table.add_row("Port", str(port))
    table.add_row("Service", service_info.get("service", "unknown"))
    table.add_row("Version", service_info.get("version", "unknown"))
    table.add_row("Banner", service_info.get("banner", "none")[:100])

    if service_info.get("headers"):
        table.add_row("Headers", str(len(service_info["headers"])) + " found")

    if service_info.get("error"):
        table.add_row("Error", service_info["error"])

    console.print(table)
    console.print()


if __name__ == "__main__":
    main()
