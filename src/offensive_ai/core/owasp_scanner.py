"""
OWASP Top 10 2021 vulnerability scanner orchestrator.

This module coordinates all OWASP security checks including passive analysis
and optional active probing.
"""

import asyncio
import time
from typing import Any, List, Optional, Set
from urllib.parse import urlparse

import httpx

from ..models.owasp_result import (
    OwaspFinding,
    OwaspCategoryResult,
    OwaspScanResult,
    BatchOwaspResult,
    ScanMode,
    SeverityLevel,
)
from ..utils.owasp_remediation import OWASP_CATEGORIES, get_category_info
from .security_headers import SecurityHeaderChecker, HeaderAnalysisResult
from .cert_analyzer import CertificateAnalyzer


# Default categories for safe mode (passive checks only)
SAFE_MODE_CATEGORIES = ["A02", "A05", "A06", "A07"]

# All categories
ALL_CATEGORIES = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]


class OwaspScanner:
    """
    Orchestrates OWASP Top 10 2021 vulnerability scanning.
    
    Coordinates passive checks (security headers, TLS, cookies, version detection)
    and optional active probing (path fuzzing, method enumeration, error detection).
    """
    
    def __init__(
        self,
        mode: str = "safe",
        categories: Optional[List[str]] = None,
        timeout: float = 10.0,
        judge: Any | None = None,
    ):
        """
        Initialize OWASP scanner.
        
        Args:
            mode: Scanning mode ('safe' or 'deep')
            categories: Specific categories to scan (default: based on mode)
            timeout: Request timeout in seconds
            judge: Optional LLMJudge instance to triage MEDIUM/LOW findings
        """
        self.mode = ScanMode(mode)
        self.timeout = timeout
        self.judge = judge
        
        # Determine which categories to scan
        if categories:
            self.enabled_categories = [c.upper() for c in categories]
        else:
            # Default based on mode
            if self.mode == ScanMode.SAFE:
                self.enabled_categories = SAFE_MODE_CATEGORIES
            else:
                self.enabled_categories = ALL_CATEGORIES
        
        # Initialize component checkers
        self.header_checker = SecurityHeaderChecker(timeout=timeout)
        self.cert_analyzer = CertificateAnalyzer()
    
    async def scan(self, target: str) -> OwaspScanResult:
        """
        Perform OWASP Top 10 security scan on target.
        
        Args:
            target: Target URL or hostname
        
        Returns:
            OwaspScanResult with all findings
        """
        start_time = time.time()
        
        # Ensure target has scheme
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        
        # Parse target
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.path
        
        # Initialize result
        result = OwaspScanResult(
            target=target,
            scan_mode=self.mode,
            enabled_categories=self.enabled_categories,
            categories=[],
        )
        
        # Run checks for each enabled category
        for category_id in self.enabled_categories:
            category_result = await self._scan_category(category_id, target, hostname)
            result.categories.append(category_result)
        
        # Calculate scores and grades
        for category in result.categories:
            category.calculate_grade()
        
        result.calculate_overall_grade()

        # Optional LLM triage of MEDIUM/LOW findings
        if self.judge:
            await self._triage_with_llm(result.all_findings)

        # Record scan duration
        result.scan_duration = time.time() - start_time
        
        return result

    async def _triage_with_llm(self, findings: List[OwaspFinding]) -> None:
        """Enrich MEDIUM/LOW findings with LLM judge reasoning."""
        triage_severities = {SeverityLevel.MEDIUM, SeverityLevel.LOW}
        for finding in findings:
            if finding.severity not in triage_severities:
                continue
            try:
                context = f"{finding.title}: {finding.description}"
                evidence = finding.evidence or ""
                eval_result = await self.judge.evaluate(context, evidence)
                finding.llm_reasoning = eval_result.reasoning
                finding.llm_confidence = eval_result.confidence
                # Upgrade LOW → MEDIUM if judge is confident
                if finding.severity == SeverityLevel.LOW and eval_result.confidence > 0.7:
                    finding.severity = SeverityLevel.MEDIUM
                    finding.score = 5  # MEDIUM score
            except Exception:
                pass
    
    async def _scan_category(
        self,
        category_id: str,
        target: str,
        hostname: str,
    ) -> OwaspCategoryResult:
        """Scan a specific OWASP category."""
        category_info = get_category_info(category_id)
        
        if not category_info:
            # Unknown category
            return OwaspCategoryResult(
                category_id=category_id,
                category_name=f"Unknown Category {category_id}",
                testable=False,
                not_testable_reason="Unknown category",
            )
        
        category_result = OwaspCategoryResult(
            category_id=category_id,
            category_name=category_info["name"],
            testable=category_info.get("testable", True),
            not_testable_reason=category_info.get("not_testable_reason"),
        )
        
        # If not testable, return early
        if not category_result.testable:
            return category_result
        
        # Run category-specific checks
        if category_id == "A01":
            findings = await self._check_a01_access_control(target)
        elif category_id == "A02":
            findings = await self._check_a02_cryptographic_failures(target, hostname)
        elif category_id == "A03":
            findings = await self._check_a03_injection(target)
        elif category_id == "A04":
            findings = await self._check_a04_insecure_design(target)
        elif category_id == "A05":
            findings = await self._check_a05_security_misconfiguration(target)
        elif category_id == "A06":
            findings = await self._check_a06_vulnerable_components(target)
        elif category_id == "A07":
            findings = await self._check_a07_auth_failures(target)
        elif category_id == "A08":
            findings = await self._check_a08_integrity_failures(target)
        elif category_id == "A10":
            findings = await self._check_a10_ssrf(target)
        elif category_id == "A03_2025":
            findings = await self._check_a03_2025_supply_chain(target)
        elif category_id == "A10_2025":
            findings = await self._check_a10_2025_exception_handling(target)
        else:
            findings = []
        
        category_result.findings = findings
        return category_result
    
    async def _check_a01_access_control(self, target: str) -> List[OwaspFinding]:
        """Check for broken access control issues (A01)."""
        findings = []
        
        # Get headers for CORS analysis
        try:
            header_result = await self.header_checker.check_headers(target)
            
            # Check for CORS misconfigurations
            for issue in header_result.cors_issues:
                severity = SeverityLevel.HIGH if "credentials" in issue else SeverityLevel.MEDIUM
                
                findings.append(OwaspFinding(
                    category="A01",
                    severity=severity,
                    title="CORS Misconfiguration",
                    description=issue,
                    remediation_key="cors_misconfiguration",
                    cwe_id=942,
                    evidence=f"Access-Control-Allow-Origin header analysis",
                ))
        except Exception as e:
            pass  # Continue with other checks
        
        return findings
    
    async def _check_a02_cryptographic_failures(
        self,
        target: str,
        hostname: str,
    ) -> List[OwaspFinding]:
        """Check for cryptographic failures (A02)."""
        findings = []
        
        # Check security headers related to crypto
        try:
            header_result = await self.header_checker.check_headers(target)
            
            # Check HSTS
            hsts_analysis = header_result.headers.get("HSTS")
            if hsts_analysis:
                if not hsts_analysis.present:
                    findings.append(OwaspFinding(
                        category="A02",
                        severity=SeverityLevel.HIGH,
                        title="Missing HSTS Header",
                        description="HTTP Strict Transport Security (HSTS) header is not set",
                        remediation_key="missing_hsts",
                        cwe_id=319,
                        evidence="Strict-Transport-Security header not found",
                    ))
                elif hsts_analysis.grade in ["D", "F"]:
                    findings.append(OwaspFinding(
                        category="A02",
                        severity=SeverityLevel.MEDIUM,
                        title="Weak HSTS Configuration",
                        description=f"HSTS header present but weak: {', '.join(hsts_analysis.issues)}",
                        remediation_key="missing_hsts",
                        cwe_id=319,
                        evidence=f"HSTS: {hsts_analysis.value}",
                    ))
            
            # Check for insecure cookies
            for cookie in header_result.cookies:
                if not cookie.has_secure:
                    findings.append(OwaspFinding(
                        category="A02",
                        severity=SeverityLevel.MEDIUM,
                        title="Insecure Cookie",
                        description=f"Cookie '{cookie.cookie_name}' missing Secure flag",
                        remediation_key="insecure_cookie",
                        cwe_id=614,
                        evidence=f"Cookie: {cookie.cookie_name}",
                    ))
        except Exception:
            pass
        
        # Check TLS/SSL configuration if HTTPS
        if target.startswith('https://'):
            try:
                # Extract port from target
                parsed = urlparse(target)
                port = parsed.port or 443
                
                # Analyze certificate
                chain = await asyncio.to_thread(
                    self.cert_analyzer.get_certificate_chain,
                    hostname,
                    port,
                )
                
                if chain and chain.certificates:
                    cert = chain.certificates[0]  # Server certificate
                    
                    # Check for weak key size
                    if cert.key_size < 2048:
                        findings.append(OwaspFinding(
                            category="A02",
                            severity=SeverityLevel.CRITICAL,
                            title="Weak Certificate Key Size",
                            description=f"Certificate uses {cert.key_size}-bit key (minimum: 2048-bit)",
                            remediation_key="weak_tls_version",
                            cwe_id=326,
                            evidence=f"Key size: {cert.key_size} bits",
                        ))
                    
                    # Check for weak signature algorithm
                    if "sha1" in cert.signature_algorithm.lower() or "md5" in cert.signature_algorithm.lower():
                        findings.append(OwaspFinding(
                            category="A02",
                            severity=SeverityLevel.HIGH,
                            title="Weak Certificate Signature Algorithm",
                            description=f"Certificate uses weak signature algorithm: {cert.signature_algorithm}",
                            remediation_key="weak_cipher_suite",
                            cwe_id=327,
                            evidence=f"Signature algorithm: {cert.signature_algorithm}",
                        ))
                    
                    # Check expiration
                    if cert.is_expired:
                        findings.append(OwaspFinding(
                            category="A02",
                            severity=SeverityLevel.CRITICAL,
                            title="Expired SSL Certificate",
                            description=f"Certificate expired on {cert.not_after}",
                            remediation_key="weak_tls_version",
                            cwe_id=298,
                            evidence=f"Expired: {cert.not_after}",
                        ))
            except Exception:
                pass  # SSL errors handled gracefully
        
        return findings
    
    async def _check_a03_injection(self, target: str) -> List[OwaspFinding]:
        """Check for injection vulnerabilities (A03)."""
        findings = []
        
        # Passive check: Look for error messages in responses
        # Active checks would require --deep mode
        if self.mode == ScanMode.DEEP:
            # TODO: Implement active injection testing
            pass
        
        return findings
    
    async def _check_a04_insecure_design(self, target: str) -> List[OwaspFinding]:
        """Check for insecure design issues (A04)."""
        findings = []
        
        # Check for rate limiting headers (passive)
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                response = await client.get(target)
                
                # Check for rate limiting headers
                rate_limit_headers = [
                    "X-RateLimit-Limit",
                    "X-RateLimit-Remaining",
                    "RateLimit-Limit",
                    "Retry-After",
                ]
                
                has_rate_limiting = any(h in response.headers for h in rate_limit_headers)
                
                if not has_rate_limiting:
                    findings.append(OwaspFinding(
                        category="A04",
                        severity=SeverityLevel.LOW,
                        title="No Rate Limiting Detected",
                        description="No rate limiting headers found - API may be vulnerable to abuse",
                        remediation_key="missing_csp",  # Placeholder
                        cwe_id=770,
                        evidence="No X-RateLimit-* or RateLimit-* headers found",
                    ))
        except Exception:
            pass
        
        return findings
    
    async def _check_a05_security_misconfiguration(self, target: str) -> List[OwaspFinding]:
        """Check for security misconfiguration (A05)."""
        findings = []
        
        try:
            header_result = await self.header_checker.check_headers(target)
            
            # Check all security headers
            for header_name, analysis in header_result.headers.items():
                if not analysis.present:
                    # Map to appropriate severity
                    if header_name in ["HSTS", "CSP"]:
                        severity = SeverityLevel.HIGH
                    else:
                        severity = SeverityLevel.MEDIUM
                    
                    # Map header to remediation key
                    remediation_map = {
                        "CSP": "missing_csp",
                        "X-Content-Type-Options": "missing_x_content_type_options",
                        "X-Frame-Options": "missing_x_frame_options",
                        "Referrer-Policy": "missing_referrer_policy",
                        "Permissions-Policy": "missing_permissions_policy",
                    }
                    
                    remediation_key = remediation_map.get(header_name, "missing_csp")
                    
                    if header_name != "HSTS":  # HSTS is covered in A02
                        findings.append(OwaspFinding(
                            category="A05",
                            severity=severity,
                            title=f"Missing {analysis.header_name} Header",
                            description=f"Security header {analysis.header_name} is not set",
                            remediation_key=remediation_key,
                            cwe_id=16,
                            evidence=f"{analysis.header_name} header not found",
                        ))
            
            # Check for information disclosure
            for header_name, value in header_result.information_disclosure.items():
                remediation_key = "information_disclosure_server_header" if header_name == "Server" else "information_disclosure_x_powered_by"
                
                findings.append(OwaspFinding(
                    category="A05",
                    severity=SeverityLevel.LOW,
                    title=f"Information Disclosure via {header_name} Header",
                    description=f"{header_name} header reveals: {value}",
                    remediation_key=remediation_key,
                    cwe_id=200,
                    evidence=f"{header_name}: {value}",
                ))
        except Exception:
            pass
        
        return findings
    
    async def _check_a06_vulnerable_components(self, target: str) -> List[OwaspFinding]:
        """Check for vulnerable and outdated components (A06)."""
        findings = []
        
        try:
            header_result = await self.header_checker.check_headers(target)
            
            # Check disclosed versions
            for header_name, value in header_result.information_disclosure.items():
                # Parse version information
                findings.append(OwaspFinding(
                    category="A06",
                    severity=SeverityLevel.MEDIUM,
                    title=f"Outdated Component Version Disclosed",
                    description=f"Server reveals version information that may be outdated: {value}",
                    remediation_key="outdated_server_version",
                    cwe_id=1104,
                    evidence=f"{header_name}: {value}",
                ))
        except Exception:
            pass
        
        return findings
    
    async def _check_a07_auth_failures(self, target: str) -> List[OwaspFinding]:
        """Check for authentication failures (A07)."""
        findings = []
        
        try:
            header_result = await self.header_checker.check_headers(target)
            
            # Check cookie security
            for cookie in header_result.cookies:
                issues = []
                
                if not cookie.has_secure:
                    issues.append("missing Secure flag")
                if not cookie.has_httponly:
                    issues.append("missing HttpOnly flag")
                if not cookie.has_samesite:
                    issues.append("missing SameSite attribute")
                
                if issues:
                    findings.append(OwaspFinding(
                        category="A07",
                        severity=SeverityLevel.MEDIUM,
                        title=f"Insecure Session Cookie: {cookie.cookie_name}",
                        description=f"Cookie has security issues: {', '.join(issues)}",
                        remediation_key="insecure_cookie",
                        cwe_id=614,
                        evidence=f"Cookie: {cookie.cookie_name}",
                    ))
        except Exception:
            pass
        
        return findings
    
    async def _check_a08_integrity_failures(self, target: str) -> List[OwaspFinding]:
        """Check for software and data integrity failures (A08)."""
        findings = []
        
        # Check for CSP with SRI (Subresource Integrity)
        # This would require HTML parsing - placeholder for now
        
        return findings
    
    async def _check_a10_ssrf(self, target: str) -> List[OwaspFinding]:
        """Check for SSRF vulnerabilities (A10)."""
        findings = []
        
        # SSRF detection requires active testing with payloads
        # Only in deep mode
        if self.mode == ScanMode.DEEP:
            # TODO: Implement SSRF testing
            pass
        
        return findings
    
    async def _check_a03_2025_supply_chain(self, target: str) -> List[OwaspFinding]:
        """Check for software supply chain vulnerabilities (OWASP 2025 A03)."""
        findings = []
        
        # Check for security.txt file (supply chain contact info)
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(f"https://{target}/.well-known/security.txt", follow_redirects=True)
                if resp.status_code != 200:
                    findings.append(OwaspFinding(
                        category="A03_2025",
                        severity=SeverityLevel.LOW,
                        title="Missing security.txt File",
                        description="No security.txt file for vulnerability disclosure",
                        remediation_key="software_supply_chain",
                        cwe_id=1395,
                        evidence="/.well-known/security.txt not found",
                    ))
        except Exception:
            findings.append(OwaspFinding(
                category="A03_2025",
                severity=SeverityLevel.LOW,
                title="Missing security.txt File",
                description="No security.txt file for vulnerability disclosure",
                remediation_key="software_supply_chain",
                cwe_id=1395,
                evidence="/.well-known/security.txt not accessible",
            ))
        
        # Check for Software Bill of Materials (SBOM)
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                sbom_paths = ["/.well-known/sbom", "/sbom.json", "/sbom.xml"]
                sbom_found = False
                for path in sbom_paths:
                    try:
                        resp = await client.get(f"https://{target}{path}", follow_redirects=True)
                        if resp.status_code == 200:
                            sbom_found = True
                            break
                    except:
                        continue
                
                if not sbom_found:
                    findings.append(OwaspFinding(
                        category="A03_2025",
                        severity=SeverityLevel.MEDIUM,
                        title="Missing Software Bill of Materials (SBOM)",
                        description="No publicly accessible SBOM found for supply chain transparency",
                        remediation_key="software_supply_chain",
                        cwe_id=829,
                        evidence="SBOM not found at common locations",
                    ))
        except Exception:
            pass
        
        return findings
    
    async def _check_a10_2025_exception_handling(self, target: str) -> List[OwaspFinding]:
        """Check for exception handling issues (OWASP 2025 A10)."""
        findings = []
        
        # Check for verbose error pages via security headers
        try:
            header_result = await self.header_checker.check_headers(target)
            
            # Server version disclosure
            if header_result.server_header:
                findings.append(OwaspFinding(
                    category="A10_2025",
                    severity=SeverityLevel.LOW,
                    title="Server Version Disclosure in Error Handling",
                    description="Server header exposes version information that may aid attackers in exception exploitation",
                    remediation_key="exception_handling",
                    cwe_id=209,
                    evidence=f"Server: {header_result.server_header}",
                ))
            
            # X-Powered-By disclosure
            if header_result.powered_by:
                findings.append(OwaspFinding(
                    category="A10_2025",
                    severity=SeverityLevel.LOW,
                    title="Technology Stack Disclosure",
                    description="X-Powered-By header exposes technology information useful for targeted attacks",
                    remediation_key="exception_handling",
                    cwe_id=209,
                    evidence=f"X-Powered-By: {header_result.powered_by}",
                ))
        except Exception:
            pass
        
        # Test for verbose error messages by requesting invalid paths
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                # Request non-existent page to trigger 404
                resp = await client.get(f"https://{target}/nonexistent-test-path-{int(time.time())}", follow_redirects=False)
                
                # Check if response contains stack trace indicators
                if resp.status_code == 404:
                    body = resp.text.lower()
                    stack_trace_indicators = [
                        "traceback", "stack trace", "at line", 
                        "exception", "error at", "file \"", 
                        "in module", "line number", ".php on line",
                        "at object.", "at function", "stacktrace"
                    ]
                    
                    for indicator in stack_trace_indicators:
                        if indicator in body:
                            findings.append(OwaspFinding(
                                category="A10_2025",
                                severity=SeverityLevel.MEDIUM,
                                title="Verbose Error Messages Detected",
                                description="Error pages may expose stack traces or internal application details",
                                remediation_key="exception_handling",
                                cwe_id=209,
                                evidence=f"404 error page contains '{indicator}'",
                            ))
                            break
        except Exception:
            pass
        
        return findings
    
    async def batch_scan(
        self,
        targets: List[str],
        max_concurrent: int = 5,
    ) -> BatchOwaspResult:
        """
        Scan multiple targets concurrently.
        
        Args:
            targets: List of target URLs/hostnames
            max_concurrent: Maximum concurrent scans
        
        Returns:
            BatchOwaspResult with all scan results
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(target: str) -> Optional[OwaspScanResult]:
            async with semaphore:
                try:
                    return await self.scan(target)
                except Exception:
                    return None
        
        tasks = [scan_with_semaphore(target) for target in targets]
        results = await asyncio.gather(*tasks)
        
        # Filter out failed scans
        successful_results = [r for r in results if r is not None]
        
        batch_result = BatchOwaspResult(
            results=successful_results,
            total_targets=len(targets),
            successful_scans=len(successful_results),
            failed_scans=len(targets) - len(successful_results),
            scan_mode=self.mode,
        )
        
        return batch_result
