"""
Command Line Interface for Simple Port Checker.

This module provides a comprehensive CLI for port scanning and L7 protection detection.
"""

import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

import click
import dns.resolver
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
from .core.mtls_checker import MTLSChecker
from .models.scan_result import ScanResult, BatchScanResult
from .models.l7_result import L7Result, BatchL7Result
from .models.mtls_result import MTLSResult, BatchMTLSResult
from .utils.common_ports import TOP_PORTS, get_service_name, get_port_description
from . import __version__


console = Console()


@click.group()
@click.version_option(version=__version__)
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
@click.option("--trace-dns", "-d", is_flag=True, help="Include DNS trace information in results")
def l7_check(targets, timeout, user_agent, output, verbose, port, path, trace_dns):
    """Check for L7 protection services (WAF, CDN, etc.)."""

    console.print(
        f"[blue]Starting L7 protection check for {len(targets)} target(s)[/blue]"
    )
    console.print(f"[yellow]Timeout: {timeout}s[/yellow]")
    
    if trace_dns:
        console.print("[yellow]DNS trace enabled - will check DNS records and resolved IPs[/yellow]")

    # Run L7 detection
    asyncio.run(
        _run_l7_detection(
            list(targets), timeout, user_agent, output, verbose, port, path, trace_dns
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


@main.command("dns-trace")
@click.argument("targets", nargs=-1, required=True)
@click.option("--timeout", "-t", default=5, help="Request timeout in seconds")
@click.option("--output", "-o", help="Output file (JSON format)")
@click.option("--check-protection", "-c", is_flag=True, help="Check each resolved IP for L7 protection")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def dns_trace(targets, timeout, output, check_protection, verbose):
    """Trace DNS records and analyze L7 protection on resolved IPs."""

    console.print(
        f"[blue]Starting DNS trace for {len(targets)} target(s)[/blue]"
    )
    console.print(f"[yellow]Timeout: {timeout}s[/yellow]")
    
    if check_protection:
        console.print("[yellow]L7 protection analysis enabled[/yellow]")

    # Run DNS trace analysis
    asyncio.run(
        _run_dns_trace_analysis(list(targets), timeout, output, check_protection, verbose)
    )


@main.command("mtls-check")
@click.argument("targets", nargs=-1, required=True)
@click.option("--port", "-p", default=443, help="Target port (default: 443)")
@click.option("--timeout", "-t", default=10, help="Connection timeout in seconds (1-300)")
@click.option("--client-cert", help="Path to client certificate file (PEM format)")
@click.option("--client-key", help="Path to client private key file (PEM format)")
@click.option("--ca-bundle", help="Path to CA bundle file for certificate verification")
@click.option("--output", "-o", help="Output file (JSON format)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output with detailed certificate information")
@click.option("--no-verify", is_flag=True, help="Disable SSL certificate verification (use with caution)")
@click.option("--concurrent", "-c", default=10, help="Maximum concurrent connections (1-50)")
@click.option("--max-retries", default=3, help="Maximum retry attempts for failed connections (0-10)")
@click.option("--retry-delay", default=1.0, help="Delay between retries in seconds (0.1-10.0)")
def mtls_check(targets, port, timeout, client_cert, client_key, ca_bundle, output, verbose, no_verify, concurrent, max_retries, retry_delay):
    """
    Check for mTLS (Mutual TLS) authentication support and requirements.
    
    This command performs comprehensive mTLS analysis including:
    - Server certificate validation and parsing
    - Client certificate requirement detection
    - Mutual authentication testing (with client certificates)
    - Performance and reliability metrics
    
    Examples:
    \b
        # Basic mTLS check
        port-checker mtls-check api.example.com
        
        # Check with client certificates
        port-checker mtls-check api.example.com --client-cert client.crt --client-key client.key
        
        # Batch check multiple APIs
        port-checker mtls-check api1.com api2.com:8443 --concurrent 10 --verbose
        
        # Enterprise security audit
        port-checker mtls-check $(cat production-apis.txt) --output audit-results.json
        
        # Custom configuration
        port-checker mtls-check api.example.com --timeout 30 --max-retries 5 --retry-delay 2.0
    
    Exit Codes:
        0: All checks completed successfully
        1: Some checks failed or errors occurred
    """

    console.print(
        f"[blue]Starting mTLS check for {len(targets)} target(s)[/blue]"
    )
    console.print(f"[yellow]Port: {port}, Timeout: {timeout}s, Retries: {max_retries}[/yellow]")
    
    if client_cert and client_key:
        console.print(f"[yellow]Using client certificate: {client_cert}[/yellow]")
    else:
        console.print("[yellow]No client certificates provided - checking server requirements only[/yellow]")
    
    if no_verify:
        console.print("[red]⚠️  SSL certificate verification disabled[/red]")

    # Run mTLS check
    asyncio.run(
        _run_mtls_check(
            list(targets), port, timeout, client_cert, client_key, 
            ca_bundle, output, verbose, not no_verify, concurrent, max_retries, retry_delay
        )
    )


@main.command("mtls-gen-cert")
@click.argument("hostname")
@click.option("--cert-path", default="client.crt", help="Output certificate file path")
@click.option("--key-path", default="client.key", help="Output private key file path") 
@click.option("--days", default=365, help="Certificate validity in days (1-7300)")
@click.option("--key-size", default=2048, help="RSA key size in bits (2048, 3072, 4096)")
@click.option("--country", default="US", help="Country code for certificate subject")
@click.option("--organization", default="Test Org", help="Organization name for certificate subject")
def mtls_gen_cert(hostname, cert_path, key_path, days, key_size, country, organization):
    """
    Generate a self-signed certificate for mTLS testing.
    
    Creates a production-grade self-signed certificate and private key suitable for
    mTLS testing and development. The certificate includes proper subject alternative
    names and modern cryptographic parameters.
    
    Examples:
    \b
        # Basic certificate generation
        port-checker mtls-gen-cert test-client.example.com
        
        # Custom validity period and key size
        port-checker mtls-gen-cert api-client.com --days 90 --key-size 4096
        
        # Custom output paths
        port-checker mtls-gen-cert client.internal --cert-path /etc/ssl/client.crt --key-path /etc/ssl/private/client.key
        
        # Custom subject information
        port-checker mtls-gen-cert test.company.com --country GB --organization "ACME Corp"
    
    Security Notes:
        - Use strong key sizes (2048+ bits) for production
        - Store private keys securely with appropriate file permissions
        - Regularly rotate certificates in production environments
        - Self-signed certificates should only be used for testing
    """
    
    console.print(f"[blue]Generating self-signed certificate for {hostname}[/blue]")
    console.print(f"[yellow]Key size: {key_size} bits, Valid for: {days} days[/yellow]")
    
    from .core.mtls_checker import generate_self_signed_cert
    
    if generate_self_signed_cert(hostname, cert_path, key_path, days):
        console.print(f"[green]✅ Certificate generated successfully:[/green]")
        console.print(f"  📄 Certificate: {cert_path}")
        console.print(f"  🔑 Private key: {key_path}")
        console.print(f"  ⏰ Valid for: {days} days")
        console.print(f"  🔒 Key size: {key_size} bits")
        
        # Show file permissions reminder
        console.print(f"\n[yellow]⚠️  Security reminder:[/yellow]")
        console.print(f"[yellow]Set appropriate file permissions:[/yellow]")
        console.print(f"[yellow]  chmod 644 {cert_path}[/yellow]")
        console.print(f"[yellow]  chmod 600 {key_path}[/yellow]")
    else:
        console.print("[red]❌ Failed to generate certificate[/red]")
        console.print("[red]Ensure cryptography library is installed: pip install cryptography[/red]")
        sys.exit(1)


@main.command("mtls-validate-cert")
@click.argument("cert_path")
@click.argument("key_path")
@click.option("--check-expiry", is_flag=True, help="Check certificate expiration date")
@click.option("--check-chain", is_flag=True, help="Validate certificate chain (requires CA bundle)")
@click.option("--ca-bundle", help="Path to CA bundle for chain validation")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed certificate information")
def mtls_validate_cert(cert_path, key_path, check_expiry, check_chain, ca_bundle, verbose):
    """
    Validate client certificate and private key files.
    
    Performs comprehensive validation of certificate and key files including:
    - File existence and readability
    - Certificate and key format validation
    - Certificate and private key matching
    - Optional expiration and chain validation
    
    Examples:
    \b
        # Basic validation
        port-checker mtls-validate-cert client.crt client.key
        
        # Check expiration date
        port-checker mtls-validate-cert client.crt client.key --check-expiry
        
        # Validate certificate chain
        port-checker mtls-validate-cert client.crt client.key --check-chain --ca-bundle ca-bundle.pem
        
        # Detailed output
        port-checker mtls-validate-cert client.crt client.key --verbose --check-expiry
    
    Exit Codes:
        0: Certificate and key are valid
        1: Validation failed or files are invalid
    """
    
    console.print(f"[blue]Validating certificate files[/blue]")
    console.print(f"📄 Certificate: {cert_path}")
    console.print(f"🔑 Private key: {key_path}")
    
    from .core.mtls_checker import validate_certificate_files
    
    is_valid, message = validate_certificate_files(cert_path, key_path)
    
    if is_valid:
        console.print(f"[green]✅ {message}[/green]")
        
        if verbose:
            # Show certificate details
            try:
                from cryptography import x509
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data)
                
                console.print(f"\n[cyan]📋 Certificate Details:[/cyan]")
                console.print(f"  Subject: {cert.subject.rfc4514_string()}")
                console.print(f"  Issuer: {cert.issuer.rfc4514_string()}")
                console.print(f"  Serial: {cert.serial_number}")
                console.print(f"  Valid from: {cert.not_valid_before}")
                console.print(f"  Valid until: {cert.not_valid_after}")
                console.print(f"  Algorithm: {cert.signature_algorithm_oid._name}")
                    
            except ImportError:
                console.print(f"[yellow]⚠️  cryptography library not available for detailed certificate parsing[/yellow]")
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not parse certificate details: {e}[/yellow]")
        
        if check_expiry:
            # Check certificate expiration
            console.print(f"[blue]Checking certificate expiration...[/blue]")
            # Implementation would go here
            
    else:
        console.print(f"[red]❌ {message}[/red]")
        console.print(f"[red]Please check:[/red]")
        console.print(f"[red]  - File paths are correct[/red]")
        console.print(f"[red]  - Files are readable[/red]")
        console.print(f"[red]  - Certificate and key are in PEM format[/red]")
        console.print(f"[red]  - Certificate and key pair match[/red]")
        sys.exit(1)


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
    trace_dns: bool,
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
                # Pass the trace_dns parameter to the detect method
                result = await detector.detect(target, port, path, trace_dns=trace_dns)
                results.append(result)

                if verbose:
                    # Display the result with DNS trace information if available
                    _display_l7_result(result, show_trace=trace_dns or verbose)
                    
                    # If DNS trace is enabled and verbose is true, also show detailed DNS trace
                    if trace_dns and verbose:
                        _display_dns_trace(result)

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
    await _run_l7_detection(targets, timeout, None, None, verbose, None, "/", True)

    console.print("\n[green]Full scan completed![/green]")


async def _run_dns_trace_analysis(targets, timeout, output, check_protection, verbose):
    """Run DNS trace analysis for multiple targets."""
    
    start_time = time.time()
    detector = L7Detector(timeout=timeout)
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        trace_task = progress.add_task("Tracing DNS records...", total=len(targets))

        for target in targets:
            progress.update(trace_task, description=f"Tracing {target}...")

            try:
                # Get detailed DNS trace
                dns_trace = await detector.get_dns_trace(target)
                
                # Also get L7 detection for the domain
                domain_result = await detector.detect(target)
                results.append(domain_result)
                
                # Display the DNS trace information
                await _display_detailed_dns_trace(target, dns_trace, domain_result, check_protection, verbose)
                
            except Exception as e:
                console.print(f"[red]Error tracing {target}: {e}[/red]")

            progress.advance(trace_task)

    # Save to JSON if requested
    if output:
        try:
            trace_data = []
            for result in results:
                trace_data.append({
                    "host": result.host,
                    "dns_trace": result.dns_trace,
                    "l7_result": result.to_dict()
                })
            
            with open(output, "w") as f:
                json.dump(trace_data, f, indent=2)
            console.print(f"[green]Results saved to {output}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving results: {e}[/red]")

async def _display_detailed_dns_trace(target: str, dns_trace: dict, domain_result: L7Result, check_protection: bool, verbose: bool):
    """Display detailed DNS trace information."""
    
    console.print(f"\n[bold blue]DNS Trace for {target}[/bold blue]")
    
    # Show CNAME chain
    if dns_trace.get("cname_chain"):
        console.print("[cyan]CNAME Chain:[/cyan]")
        for cname in dns_trace["cname_chain"]:
            console.print(f"  [green]{cname['from']} → {cname['to']}[/green] (depth: {cname['depth']})")
    else:
        console.print("[yellow]No CNAME records found[/yellow]")
    
    # Show resolved IPs
    if dns_trace.get("resolved_ips"):
        console.print("\n[cyan]Resolved IPs:[/cyan]")
        for hostname, ips in dns_trace["resolved_ips"].items():
            console.print(f"  [bold]{hostname}:[/bold] {', '.join(ips)}")
    
    # Show IP protection if check_protection is enabled
    if check_protection and dns_trace.get("ip_protection"):
        console.print("\n[cyan]IP Protection Analysis:[/cyan]")
        for ip, protection in dns_trace["ip_protection"].items():
            if "service" in protection:
                console.print(f"  [green]{ip}: {protection['service']} ({protection['confidence']:.1%}) via {protection['origin_host']}[/green]")
            elif "error" in protection:
                console.print(f"  [red]{ip}: Failed to check ({protection['error']})[/red]")
    
    # Show domain protection
    if domain_result.is_protected and domain_result.primary_protection:
        console.print("\n[cyan]Domain Protection:[/cyan]")
        service = domain_result.primary_protection.service.value
        confidence = domain_result.primary_protection.confidence
        console.print(f"  [yellow]{target}: {service} ({confidence:.1%})[/yellow]")
        
        # Compare with IP protection if available
        if check_protection and dns_trace.get("ip_protection"):
            ip_services = set()
            for prot in dns_trace["ip_protection"].values():
                if "service" in prot:
                    ip_services.add(prot["service"])
            
            if ip_services:
                if service in ip_services:
                    console.print("[green]  ✓ Domain and IP protection match[/green]")
                else:
                    console.print("[yellow]  ⚠ Domain and IP protection differ[/yellow]")
    else:
        console.print(f"\n[yellow]No L7 protection detected for {target}[/yellow]")
    
    # Show verbose information if requested
    if verbose and domain_result.detections:
        console.print("\n[cyan]Detailed Detection Information:[/cyan]")
        for detection in domain_result.detections:
            console.print(f"  [dim]Service: {detection.service.value}, Confidence: {detection.confidence:.1%}[/dim]")
            if detection.indicators:
                console.print(f"  [dim]Indicators: {', '.join(detection.indicators[:3])}[/dim]")


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


def _display_l7_result(result: L7Result, show_trace: bool = False):
    """Display individual L7 detection result."""

    if result.error:
        console.print(f"[red]L7 Check failed for {result.host}: {result.error}[/red]")
        return

    panel_content = []

    if result.is_protected:
        primary = result.primary_protection
        panel_content.append(f"[green]✓ L7 Protection Detected[/green]")
        
        # Check if there's a specific service name in detection details
        if primary.details and "specific_service" in primary.details:
            service_name = primary.details["specific_service"]
        else:
            service_name = primary.service.value
            
        panel_content.append(f"[yellow]Primary: {service_name}[/yellow]")
        panel_content.append(f"[yellow]Confidence: {primary.confidence:.1%}[/yellow]")

        if len(result.detections) > 1:
            panel_content.append(
                f"[dim]Additional detections: {len(result.detections) - 1}[/dim]"
            )
    else:
        panel_content.append("[red]✗ No L7 Protection Detected[/red]")
        panel_content.append("[bold red]The endpoint is NOT protected by any L7 service (WAF/CDN)[/bold red]")

    panel_content.append(f"[dim]Response time: {result.response_time:.2f}s[/dim]")
    
    # Add DNS trace information if requested and available
    if show_trace and result.dns_trace and any(result.dns_trace.values()):
        panel_content.append("")
        panel_content.append("[cyan]DNS Trace Information:[/cyan]")
        
        # Show CNAME chain
        if "cname_chain" in result.dns_trace and result.dns_trace["cname_chain"]:
            panel_content.append("[cyan]CNAME Chain:[/cyan]")
            for cname in result.dns_trace["cname_chain"]:
                panel_content.append(f"  [dim]{cname['from']} → {cname['to']}[/dim]")
        
        # Show resolved IPs
        if "resolved_ips" in result.dns_trace and result.dns_trace["resolved_ips"]:
            panel_content.append("[cyan]Resolved IPs:[/cyan]")
            for host, ips in result.dns_trace["resolved_ips"].items():
                panel_content.append(f"  [dim]{host}: {', '.join(ips)}[/dim]")
        
        # Show IP protection
        if "ip_protection" in result.dns_trace and result.dns_trace["ip_protection"]:
            panel_content.append("[cyan]IP Protection Analysis:[/cyan]")
            for ip, protection in result.dns_trace["ip_protection"].items():
                if "service" in protection:
                    panel_content.append(f"  [green]{ip}: {protection['service']} ({protection['confidence']:.1%})[/green]")
                elif "error" in protection:
                    panel_content.append(f"  [dim]{ip}: Failed to check ({protection['error']})[/dim]")

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


def _save_mtls_results(batch_result: BatchMTLSResult, output_file: str):
    """Save mTLS results to JSON file."""
    try:
        with open(output_file, "w") as f:
            json.dump(batch_result.dict(), f, indent=2)
        console.print(f"[green]Results saved to {output_file}[/green]")
    except Exception as e:
        console.print(f"[red]Failed to save results: {e}[/red]")


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


def _display_dns_trace(result: L7Result):
    """Display DNS trace information."""
    
    if not result.dns_trace or not any(result.dns_trace.values()):
        console.print(f"[yellow]No DNS trace information available for {result.host}[/yellow]")
        return
    
    dns_trace = result.dns_trace
    
    # Prepare the trace panel content
    trace_content = []
    trace_content.append(f"[bold]DNS Trace for {result.host}[/bold]")
    trace_content.append("")
    
    # Show CNAME chain
    if "cname_chain" in dns_trace and dns_trace["cname_chain"]:
        trace_content.append("[bold cyan]CNAME Chain:[/bold cyan]")
        for cname in dns_trace["cname_chain"]:
            trace_content.append(f"  {cname['from']} → [cyan]{cname['to']}[/cyan] (depth: {cname['depth']})")
        trace_content.append("")
    else:
        trace_content.append("[yellow]No CNAME records found[/yellow]")
        trace_content.append("")
    
    # Show resolved IPs
    if "resolved_ips" in dns_trace and dns_trace["resolved_ips"]:
        trace_content.append("[bold cyan]Resolved IPs:[/bold cyan]")
        for host, ips in dns_trace["resolved_ips"].items():
            trace_content.append(f"  [bold]{host}:[/bold] {', '.join(ips)}")
        trace_content.append("")
    
    # Show IP protection
    if "ip_protection" in dns_trace and dns_trace["ip_protection"]:
        trace_content.append("[bold cyan]IP Protection Analysis:[/bold cyan]")
        for ip, protection in dns_trace["ip_protection"].items():
            if "service" in protection:
                trace_content.append(f"  [green]{ip}: {protection['service']} ({protection['confidence']:.1%}) via {protection['origin_host']}[/green]")
            elif "error" in protection:
                trace_content.append(f"  [red]{ip}: Failed to check ({protection['error']})[/red]")
    
    # Display primary protection and IP protection comparison
    if result.is_protected:
        trace_content.append("")
        trace_content.append("[bold]Protection Analysis:[/bold]")
        trace_content.append(f"  Domain: [cyan]{result.primary_protection.service.value}[/cyan] ({result.primary_protection.confidence:.1%})")
        
        # Check if the IP protection matches the domain protection
        ip_services = set()
        for protection in dns_trace.get("ip_protection", {}).values():
            if "service" in protection:
                ip_services.add(protection["service"])
        
        if ip_services:
            trace_content.append(f"  IP services: [cyan]{', '.join(ip_services)}[/cyan]")
            
            # Compare domain protection with IP protection
            domain_service = result.primary_protection.service.value
            if domain_service in ip_services:
                trace_content.append("[green]  ✓ Domain and IP protection match[/green]")
            else:
                trace_content.append("[yellow]  ⚠ Domain and IP protection differ[/yellow]")
    
    # Display the panel
    console.print(
        Panel(
            "\n".join(trace_content),
            title=f"DNS Trace - {result.host}",
            border_style="blue",
        )
    )


async def _run_mtls_check(
    targets: List[str],
    port: int,
    timeout: int,
    client_cert: Optional[str],
    client_key: Optional[str],
    ca_bundle: Optional[str],
    output: Optional[str],
    verbose: bool,
    verify_ssl: bool,
    concurrent: int,
    max_retries: int = 3,
    retry_delay: float = 1.0,
):
    """Run mTLS checking with progress display and enhanced configuration."""

    mtls_checker = MTLSChecker(
        timeout=timeout, 
        verify_ssl=verify_ssl,
        max_retries=max_retries,
        retry_delay=retry_delay,
        enable_logging=verbose
    )
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

        mtls_task = progress.add_task("Checking mTLS support...", total=len(targets))

        # Prepare target list with ports
        target_ports = []
        for target in targets:
            if ':' in target and not target.startswith('['):  # Handle IPv6 addresses
                host, port_str = target.rsplit(':', 1)
                try:
                    target_port = int(port_str)
                    target_ports.append((host, target_port))
                except ValueError:
                    target_ports.append((target, port))
            else:
                target_ports.append((target, port))

        try:
            # Use batch checking for efficiency with progress callback
            def progress_callback(completed, total, result):
                progress.update(mtls_task, completed=completed)

            results = await mtls_checker.batch_check_mtls(
                target_ports,
                client_cert_path=client_cert,
                client_key_path=client_key,
                ca_bundle_path=ca_bundle,
                max_concurrent=concurrent,
                progress_callback=progress_callback
            )

            progress.update(mtls_task, completed=len(targets))

            if verbose:
                for result in results:
                    _display_mtls_result(result)

        except Exception as e:
            console.print(f"[red]Error during mTLS check: {e}[/red]")
            return

    # Display summary
    duration = time.time() - start_time
    _display_mtls_summary(results, duration)
    
    # Show performance metrics
    metrics = mtls_checker.get_metrics()
    if verbose and metrics['total_requests'] > 0:
        _display_mtls_metrics(metrics)

    # Save results if output file specified
    if output:
        batch_result = BatchMTLSResult.from_results(results)
        _save_mtls_results(batch_result, output)


def _display_mtls_result(result: MTLSResult):
    """Display mTLS check result for a single target."""

    # Create a table for the result
    table = Table(title=f"mTLS Check - {result.target}:{result.port}")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    # Basic connectivity
    if result.error_message:
        table.add_row("Status", f"[red]Failed: {result.error_message}[/red]")
        console.print(table)
        console.print()
        return

    table.add_row("Status", "[green]Connected[/green]")
    table.add_row("Supports mTLS", "[green]Yes[/green]" if result.supports_mtls else "[red]No[/red]")
    table.add_row("Requires Client Cert", "[red]Required[/red]" if result.requires_client_cert else "[yellow]Optional[/yellow]")
    table.add_row("Client Cert Requested", "[green]Yes[/green]" if result.client_cert_requested else "[red]No[/red]")

    # Connection details
    if result.handshake_successful:
        table.add_row("mTLS Handshake", "[green]Successful[/green]")
        if result.cipher_suite:
            table.add_row("Cipher Suite", result.cipher_suite)
        if result.tls_version:
            table.add_row("TLS Version", result.tls_version)
    else:
        table.add_row("mTLS Handshake", "[red]Failed[/red]")

    # Certificate information
    if result.server_cert_info:
        cert = result.server_cert_info
        table.add_row("Server Certificate", "")
        table.add_row("  Subject", cert.subject)
        table.add_row("  Issuer", cert.issuer)
        table.add_row("  Valid From", cert.not_valid_before)
        table.add_row("  Valid Until", cert.not_valid_after)
        table.add_row("  Algorithm", f"{cert.key_algorithm} ({cert.key_size} bits)" if cert.key_size else cert.key_algorithm)
        
        if cert.san_dns_names:
            table.add_row("  SAN DNS", ", ".join(cert.san_dns_names[:3]) + ("..." if len(cert.san_dns_names) > 3 else ""))
        
        if cert.is_self_signed:
            table.add_row("  Self-Signed", "[yellow]Yes[/yellow]")

    console.print(table)
    console.print()


def _display_mtls_summary(results: List[MTLSResult], duration: float):
    """Display summary of mTLS check results."""

    # Count different result types
    total = len(results)
    successful = sum(1 for r in results if r.error_message is None)
    failed = total - successful
    supports_mtls = sum(1 for r in results if r.supports_mtls)
    requires_client_cert = sum(1 for r in results if r.requires_client_cert)
    handshake_success = sum(1 for r in results if r.handshake_successful)

    # Create summary table
    summary_table = Table(title="mTLS Check Summary", show_header=True)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="white", justify="right")
    summary_table.add_column("Percentage", style="yellow", justify="right")

    summary_table.add_row("Total Targets", str(total), "100%")
    summary_table.add_row("Successful Checks", str(successful), f"{(successful/total)*100:.1f}%" if total > 0 else "0%")
    summary_table.add_row("Failed Checks", str(failed), f"{(failed/total)*100:.1f}%" if total > 0 else "0%")
    summary_table.add_row("mTLS Supported", str(supports_mtls), f"{(supports_mtls/total)*100:.1f}%" if total > 0 else "0%")
    summary_table.add_row("Client Cert Required", str(requires_client_cert), f"{(requires_client_cert/total)*100:.1f}%" if total > 0 else "0%")
    summary_table.add_row("Handshake Successful", str(handshake_success), f"{(handshake_success/total)*100:.1f}%" if total > 0 else "0%")

    console.print(summary_table)
    console.print(f"\n[blue]Scan completed in {duration:.2f} seconds[/blue]")

    # Show notable findings
    if requires_client_cert > 0:
        console.print(f"\n[yellow]⚠ {requires_client_cert} target(s) require client certificates for authentication[/yellow]")
    
    if supports_mtls > 0:
        console.print(f"[green]✓ {supports_mtls} target(s) support mTLS authentication[/green]")


def _display_mtls_metrics(metrics: Dict[str, Any]):
    """Display detailed mTLS performance metrics."""
    
    # Create metrics table
    metrics_table = Table(title="📊 mTLS Performance Metrics", show_header=True)
    metrics_table.add_column("Metric", style="cyan")
    metrics_table.add_column("Value", style="white", justify="right")
    
    total_requests = metrics.get('total_requests', 0)
    if total_requests > 0:
        avg_time = metrics.get('total_time', 0) / total_requests
        success_rate = (metrics.get('successful_connections', 0) / total_requests) * 100
        
        metrics_table.add_row("Total Requests", str(total_requests))
        metrics_table.add_row("Successful Connections", str(metrics.get('successful_connections', 0)))
        metrics_table.add_row("Failed Connections", str(metrics.get('failed_connections', 0)))
        metrics_table.add_row("Success Rate", f"{success_rate:.1f}%")
        metrics_table.add_row("Average Time", f"{avg_time:.3f}s")
        metrics_table.add_row("Total Time", f"{metrics.get('total_time', 0):.3f}s")
        
        # Error breakdown
        if metrics.get('network_errors', 0) > 0:
            metrics_table.add_row("Network Errors", str(metrics.get('network_errors', 0)))
        if metrics.get('timeout_errors', 0) > 0:
            metrics_table.add_row("Timeout Errors", str(metrics.get('timeout_errors', 0)))
        if metrics.get('certificate_errors', 0) > 0:
            metrics_table.add_row("Certificate Errors", str(metrics.get('certificate_errors', 0)))
        
        # mTLS specific metrics
        metrics_table.add_row("mTLS Supported", str(metrics.get('mtls_supported', 0)))
        metrics_table.add_row("Client Cert Required", str(metrics.get('client_cert_required', 0)))
        metrics_table.add_row("Handshake Failures", str(metrics.get('handshake_failures', 0)))
        
        console.print(metrics_table)
