"""
Security header analyzer for OWASP Top 10 scanning.

This module analyzes HTTP security headers, cookies, CORS configuration,
and information disclosure from web responses.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx


@dataclass
class HeaderAnalysis:
    """Analysis result for a single security header."""
    
    header_name: str
    present: bool
    value: Optional[str] = None
    grade: str = "F"  # A, B, C, D, F
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class CookieAnalysis:
    """Analysis of cookie security attributes."""
    
    cookie_name: str
    has_secure: bool = False
    has_httponly: bool = False
    has_samesite: bool = False
    samesite_value: Optional[str] = None
    issues: List[str] = field(default_factory=list)


@dataclass
class HeaderAnalysisResult:
    """Complete result of security header analysis."""
    
    url: str
    status_code: int
    headers: Dict[str, HeaderAnalysis] = field(default_factory=dict)
    cookies: List[CookieAnalysis] = field(default_factory=list)
    cors_issues: List[str] = field(default_factory=list)
    information_disclosure: Dict[str, str] = field(default_factory=dict)
    overall_grade: str = "F"
    findings_count: int = 0


class SecurityHeaderChecker:
    """
    Analyzes HTTP security headers and related security configurations.
    
    Checks for:
    - Security headers (HSTS, CSP, X-Frame-Options, etc.)
    - Cookie security attributes
    - CORS misconfiguration
    - Information disclosure via headers
    """
    
    # Security headers to check
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "X-Frame-Options",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-XSS-Protection": "X-XSS-Protection",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
    }
    
    # Headers that may disclose information
    DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
    
    def __init__(self, timeout: float = 10.0, follow_redirects: bool = True):
        """
        Initialize the security header checker.
        
        Args:
            timeout: Request timeout in seconds
            follow_redirects: Whether to follow HTTP redirects
        """
        self.timeout = timeout
        self.follow_redirects = follow_redirects
    
    async def check_headers(self, url: str) -> HeaderAnalysisResult:
        """
        Analyze security headers for a given URL.
        
        Args:
            url: Target URL to analyze
        
        Returns:
            HeaderAnalysisResult with complete analysis
        """
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                verify=False,  # Don't fail on SSL errors - we're checking security
            ) as client:
                response = await client.get(url)
                
                result = HeaderAnalysisResult(
                    url=url,
                    status_code=response.status_code,
                )
                
                # Analyze security headers
                result.headers = self._analyze_security_headers(response.headers)
                
                # Analyze cookies
                result.cookies = self._analyze_cookies(response.cookies)
                
                # Check CORS configuration
                result.cors_issues = self._analyze_cors(response.headers)
                
                # Check for information disclosure
                result.information_disclosure = self._detect_information_disclosure(response.headers)
                
                # Calculate overall grade
                result.overall_grade = self._calculate_overall_grade(result)
                
                # Count findings (issues across all categories)
                result.findings_count = self._count_findings(result)
                
                return result
        
        except httpx.RequestError as e:
            # Return error result
            return HeaderAnalysisResult(
                url=url,
                status_code=0,
                overall_grade="F",
                findings_count=1,
            )
        except Exception as e:
            return HeaderAnalysisResult(
                url=url,
                status_code=0,
                overall_grade="F",
                findings_count=1,
            )
    
    def _analyze_security_headers(self, headers: httpx.Headers) -> Dict[str, HeaderAnalysis]:
        """Analyze all security headers."""
        results = {}
        
        for header_name, short_name in self.SECURITY_HEADERS.items():
            header_value = headers.get(header_name)
            analysis = HeaderAnalysis(
                header_name=header_name,
                present=header_value is not None,
                value=header_value,
            )
            
            if header_value:
                # Grade based on header-specific criteria
                if header_name == "Strict-Transport-Security":
                    analysis.grade, analysis.issues, analysis.recommendations = self._grade_hsts(header_value)
                elif header_name == "Content-Security-Policy":
                    analysis.grade, analysis.issues, analysis.recommendations = self._grade_csp(header_value)
                elif header_name == "X-Frame-Options":
                    analysis.grade, analysis.issues, analysis.recommendations = self._grade_x_frame_options(header_value)
                elif header_name == "X-Content-Type-Options":
                    analysis.grade, analysis.issues, analysis.recommendations = self._grade_x_content_type_options(header_value)
                elif header_name == "Referrer-Policy":
                    analysis.grade, analysis.issues, analysis.recommendations = self._grade_referrer_policy(header_value)
                elif header_name == "Permissions-Policy":
                    analysis.grade, analysis.issues, analysis.recommendations = self._grade_permissions_policy(header_value)
                else:
                    analysis.grade = "B"  # Present but not specifically graded
            else:
                analysis.grade = "F"
                analysis.issues.append(f"{header_name} header is missing")
                analysis.recommendations.append(f"Add {header_name} header to improve security")
            
            results[short_name] = analysis
        
        return results
    
    def _grade_hsts(self, value: str) -> tuple[str, List[str], List[str]]:
        """Grade HSTS header configuration."""
        issues = []
        recommendations = []
        
        # Parse max-age
        max_age_match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
        if not max_age_match:
            return "F", ["Missing max-age directive"], ["Add max-age directive"]
        
        max_age = int(max_age_match.group(1))
        
        # Check max-age value (recommended: at least 1 year = 31536000)
        if max_age < 31536000:
            issues.append(f"max-age is {max_age} (less than 1 year)")
            recommendations.append("Increase max-age to at least 31536000 (1 year)")
        
        # Check for includeSubDomains
        if 'includesubdomains' not in value.lower():
            issues.append("Missing includeSubDomains directive")
            recommendations.append("Add includeSubDomains for better protection")
        
        # Check for preload
        has_preload = 'preload' in value.lower()
        
        # Grade based on configuration
        if max_age >= 31536000 and 'includesubdomains' in value.lower() and has_preload:
            return "A", issues, recommendations
        elif max_age >= 31536000 and 'includesubdomains' in value.lower():
            return "B", issues, recommendations
        elif max_age >= 31536000:
            return "C", issues, recommendations
        else:
            return "D", issues, recommendations
    
    def _grade_csp(self, value: str) -> tuple[str, List[str], List[str]]:
        """Grade Content-Security-Policy header."""
        issues = []
        recommendations = []
        
        # Check for unsafe directives
        if "'unsafe-inline'" in value:
            issues.append("Contains 'unsafe-inline' directive")
            recommendations.append("Remove 'unsafe-inline' and use nonces or hashes")
        
        if "'unsafe-eval'" in value:
            issues.append("Contains 'unsafe-eval' directive")
            recommendations.append("Remove 'unsafe-eval' to prevent eval() usage")
        
        # Check for wildcard in script-src
        if re.search(r"script-src[^;]*\*", value):
            issues.append("Wildcard (*) in script-src")
            recommendations.append("Restrict script-src to specific domains")
        
        # Check for default-src
        if 'default-src' not in value:
            issues.append("Missing default-src directive")
            recommendations.append("Add default-src as a fallback")
        
        # Grade based on issues
        if len(issues) == 0:
            return "A", issues, recommendations
        elif len(issues) == 1:
            return "B", issues, recommendations
        elif len(issues) == 2:
            return "C", issues, recommendations
        else:
            return "D", issues, recommendations
    
    def _grade_x_frame_options(self, value: str) -> tuple[str, List[str], List[str]]:
        """Grade X-Frame-Options header."""
        issues = []
        recommendations = []
        
        value_upper = value.upper()
        
        if value_upper == "DENY":
            return "A", issues, recommendations
        elif value_upper == "SAMEORIGIN":
            return "B", issues, recommendations
        elif value_upper.startswith("ALLOW-FROM"):
            issues.append("ALLOW-FROM is deprecated")
            recommendations.append("Use CSP frame-ancestors instead")
            return "C", issues, recommendations
        else:
            issues.append(f"Invalid value: {value}")
            recommendations.append("Use DENY or SAMEORIGIN")
            return "F", issues, recommendations
    
    def _grade_x_content_type_options(self, value: str) -> tuple[str, List[str], List[str]]:
        """Grade X-Content-Type-Options header."""
        issues = []
        recommendations = []
        
        if value.lower() == "nosniff":
            return "A", issues, recommendations
        else:
            issues.append(f"Invalid value: {value}")
            recommendations.append("Set to 'nosniff'")
            return "F", issues, recommendations
    
    def _grade_referrer_policy(self, value: str) -> tuple[str, List[str], List[str]]:
        """Grade Referrer-Policy header."""
        issues = []
        recommendations = []
        
        # Recommended values in order of preference
        excellent = ["no-referrer", "same-origin"]
        good = ["strict-origin-when-cross-origin", "strict-origin"]
        acceptable = ["no-referrer-when-downgrade", "origin-when-cross-origin"]
        
        value_lower = value.lower()
        
        if value_lower in excellent:
            return "A", issues, recommendations
        elif value_lower in good:
            return "B", issues, recommendations
        elif value_lower in acceptable:
            return "C", issues, recommendations
        else:
            issues.append(f"Weak policy: {value}")
            recommendations.append("Use 'strict-origin-when-cross-origin' or 'no-referrer'")
            return "D", issues, recommendations
    
    def _grade_permissions_policy(self, value: str) -> tuple[str, List[str], List[str]]:
        """Grade Permissions-Policy header."""
        issues = []
        recommendations = []
        
        # Check if features are restricted
        dangerous_features = ["camera", "microphone", "geolocation", "payment"]
        unrestricted = []
        
        for feature in dangerous_features:
            # Check if feature is explicitly disabled: feature=()
            if f"{feature}=()" not in value and f"{feature}=" in value:
                unrestricted.append(feature)
        
        if unrestricted:
            issues.append(f"Unrestricted features: {', '.join(unrestricted)}")
            recommendations.append("Restrict sensitive features with feature=()")
        
        # Grade based on how well features are restricted
        if len(unrestricted) == 0:
            return "A", issues, recommendations
        elif len(unrestricted) <= 1:
            return "B", issues, recommendations
        elif len(unrestricted) <= 2:
            return "C", issues, recommendations
        else:
            return "D", issues, recommendations
    
    def _analyze_cookies(self, cookies) -> List[CookieAnalysis]:
        """Analyze security attributes of cookies."""
        cookie_analyses = []
        
        for cookie_name, cookie_value in cookies.items():
            # Note: httpx.Cookies doesn't expose flags directly
            # This is a simplified version - full implementation would need raw headers
            analysis = CookieAnalysis(cookie_name=cookie_name)
            
            # Check for common security issues
            # In a real implementation, parse Set-Cookie headers for flags
            # For now, mark as potential issue
            analysis.issues.append("Cookie security flags not verified (requires Set-Cookie header analysis)")
            
            cookie_analyses.append(analysis)
        
        return cookie_analyses
    
    def _analyze_cors(self, headers: httpx.Headers) -> List[str]:
        """Analyze CORS configuration for issues."""
        issues = []
        
        acao = headers.get("Access-Control-Allow-Origin")
        acac = headers.get("Access-Control-Allow-Credentials")
        
        if acao:
            # Wildcard with credentials is dangerous
            if acao == "*" and acac == "true":
                issues.append("CORS allows all origins (*) with credentials - severe security risk")
            elif acao == "*":
                issues.append("CORS allows all origins (*) - may expose sensitive data")
            elif acao == "null":
                issues.append("CORS allows 'null' origin - can be exploited")
        
        return issues
    
    def _detect_information_disclosure(self, headers: httpx.Headers) -> Dict[str, str]:
        """Detect information disclosure in headers."""
        disclosure = {}
        
        for header_name in self.DISCLOSURE_HEADERS:
            value = headers.get(header_name)
            if value:
                disclosure[header_name] = value
        
        return disclosure
    
    def _calculate_overall_grade(self, result: HeaderAnalysisResult) -> str:
        """Calculate overall security grade."""
        grade_values = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1, "N/A": 0}
        
        grades = [h.grade for h in result.headers.values() if h.grade != "N/A"]
        
        if not grades:
            return "F"
        
        # Average grade
        avg_value = sum(grade_values.get(g, 0) for g in grades) / len(grades)
        
        # Apply penalties
        if result.cors_issues:
            avg_value -= 1  # CORS issues are serious
        
        if result.information_disclosure:
            avg_value -= 0.5  # Information disclosure is moderate
        
        # Convert back to letter grade
        if avg_value >= 4.5:
            return "A"
        elif avg_value >= 3.5:
            return "B"
        elif avg_value >= 2.5:
            return "C"
        elif avg_value >= 1.5:
            return "D"
        else:
            return "F"
    
    def _count_findings(self, result: HeaderAnalysisResult) -> int:
        """Count total security findings."""
        count = 0
        
        # Count header issues
        for header_analysis in result.headers.values():
            count += len(header_analysis.issues)
            if not header_analysis.present:
                count += 1  # Missing header is a finding
        
        # Count CORS issues
        count += len(result.cors_issues)
        
        # Count information disclosure
        count += len(result.information_disclosure)
        
        # Count cookie issues
        for cookie in result.cookies:
            count += len(cookie.issues)
        
        return count
    
    async def batch_check(self, urls: List[str], max_concurrent: int = 5) -> List[HeaderAnalysisResult]:
        """
        Analyze security headers for multiple URLs concurrently.
        
        Args:
            urls: List of URLs to analyze
            max_concurrent: Maximum concurrent requests
        
        Returns:
            List of HeaderAnalysisResult objects
        """
        results: List[HeaderAnalysisResult] = []
        # Process in chunks so pending-task count is bounded by max_concurrent
        for i in range(0, len(urls), max_concurrent):
            chunk = urls[i:i + max_concurrent]
            chunk_results = await asyncio.gather(
                *[self.check_headers(url) for url in chunk],
                return_exceptions=True,
            )
            for r in chunk_results:
                if isinstance(r, HeaderAnalysisResult):
                    results.append(r)
        return results
