"""
OWASP Top 10 2021 & 2025 remediation database.

This module contains remediation guidance, code examples, and reference
documentation for OWASP Top 10 vulnerabilities with technology-specific solutions.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class RemediationInfo:
    """Remediation information for a specific vulnerability."""
    
    description: str
    severity_rationale: str
    steps: List[str]
    code_examples: Dict[str, str]  # tech_stack -> code example
    references: List[str]
    cwe_ids: List[int]


# OWASP Top 10 2021 Category Metadata
OWASP_CATEGORIES = {
    "A01": {
        "name": "Broken Access Control",
        "description": "Failures in enforcing proper authorization, allowing users to access unauthorized resources",
        "testable": True,
    },
    "A02": {
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography exposing sensitive data",
        "testable": True,
    },
    "A03": {
        "name": "Injection",
        "description": "SQL, NoSQL, OS command, LDAP injections due to lack of input validation",
        "testable": True,
    },
    "A04": {
        "name": "Insecure Design",
        "description": "Architectural and design flaws, missing or ineffective security controls",
        "testable": True,
    },
    "A05": {
        "name": "Security Misconfiguration",
        "description": "Missing security hardening, unnecessary features, default accounts, verbose errors",
        "testable": True,
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "description": "Using libraries, frameworks, software with known vulnerabilities",
        "testable": True,
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "description": "Broken authentication, session management flaws, credential stuffing vulnerabilities",
        "testable": True,
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "description": "Missing integrity checks for code/infrastructure, insecure CI/CD, untrusted sources",
        "testable": True,
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, monitoring, and incident response",
        "testable": False,
        "not_testable_reason": "Cannot be detected via external scanning - requires internal access to logging infrastructure",
    },
    "A10": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Fetching remote resources without validating user-supplied URL",
        "testable": True,
    },
    # OWASP Top 10 2025 New Categories
    "A03_2025": {
        "name": "Software Supply Chain Failures",
        "description": "Vulnerabilities in software supply chain including compromised dependencies, insecure package sources",
        "testable": True,
        "version": "2025",
    },
    "A10_2025": {
        "name": "Mishandling of Exceptional Conditions",
        "description": "Improper error handling exposing sensitive information or causing security failures",
        "testable": True,
        "version": "2025",
    },
}


# Remediation Database
REMEDIATION_DB: Dict[str, RemediationInfo] = {
    # A02: Cryptographic Failures
    "missing_hsts": RemediationInfo(
        description="HTTP Strict Transport Security (HSTS) header is missing",
        severity_rationale="Without HSTS, browsers may access the site via insecure HTTP, exposing traffic to interception",
        steps=[
            "Add the Strict-Transport-Security header to all HTTPS responses",
            "Set max-age to at least 31536000 (1 year)",
            "Consider including subdomains with includeSubDomains directive",
            "Optionally add preload directive for HSTS preload list inclusion",
        ],
        code_examples={
            "apache": """# Add to Apache configuration (httpd.conf or .htaccess)
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
""",
            "nginx": """# Add to Nginx server block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
""",
            "iis": """<!-- Add to web.config -->
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
""",
            "cloudflare": """# Enable HSTS in Cloudflare Dashboard:
# SSL/TLS > Edge Certificates > Enable HSTS
# Or use Page Rules to set custom header
""",
            "generic": """# Framework-specific examples:

# Express.js (Node.js)
const helmet = require('helmet');
app.use(helmet.hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
}));

# Django (Python)
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
""",
        },
        references=[
            "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
            "https://hstspreload.org/",
        ],
        cwe_ids=[319, 311],
    ),
    
    "weak_tls_version": RemediationInfo(
        description="Weak or outdated TLS protocol version detected",
        severity_rationale="Older TLS versions (1.0, 1.1) have known vulnerabilities and should be disabled",
        steps=[
            "Disable TLS 1.0 and TLS 1.1 protocols",
            "Enable only TLS 1.2 and TLS 1.3",
            "Remove support for SSLv2 and SSLv3 if present",
            "Test configuration with SSL Labs or similar tools",
        ],
        code_examples={
            "apache": """# Apache 2.4.x configuration
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
SSLHonorCipherOrder on
""",
            "nginx": """# Nginx configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;
""",
            "iis": """# PowerShell script for IIS
# Disable TLS 1.0
New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force
New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord'

# Disable TLS 1.1
New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Force
New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord'
""",
            "cloudflare": """# Cloudflare automatically handles TLS versions
# Set minimum TLS version in dashboard:
# SSL/TLS > Edge Certificates > Minimum TLS Version > TLS 1.2 or higher
""",
            "generic": """# Check OpenSSL configuration
openssl s_client -connect example.com:443 -tls1
openssl s_client -connect example.com:443 -tls1_1
# These should fail if properly configured
""",
        },
        references=[
            "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
            "https://wiki.mozilla.org/Security/Server_Side_TLS",
            "https://www.ssllabs.com/ssltest/",
        ],
        cwe_ids=[326, 327],
    ),
    
    "weak_cipher_suite": RemediationInfo(
        description="Weak or insecure cipher suites enabled",
        severity_rationale="Weak ciphers (DES, 3DES, RC4, MD5) can be broken by attackers",
        steps=[
            "Disable weak cipher suites (DES, 3DES, RC4, NULL, EXPORT)",
            "Enable only strong ciphers (AES-GCM, ChaCha20-Poly1305)",
            "Prefer ECDHE for forward secrecy",
            "Set server cipher preference",
        ],
        code_examples={
            "apache": """SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder on
""",
            "nginx": """ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers on;
""",
            "generic": """# Mozilla SSL Configuration Generator
# https://ssl-config.mozilla.org/
# Use 'Modern' or 'Intermediate' configuration
""",
        },
        references=[
            "https://wiki.mozilla.org/Security/Server_Side_TLS",
            "https://ciphersuite.info/",
        ],
        cwe_ids=[327],
    ),
    
    "insecure_cookie": RemediationInfo(
        description="Cookies missing security flags (Secure, HttpOnly, SameSite)",
        severity_rationale="Insecure cookies can be stolen via XSS or man-in-the-middle attacks",
        steps=[
            "Add Secure flag to all cookies (HTTPS only)",
            "Add HttpOnly flag to prevent JavaScript access",
            "Add SameSite flag to prevent CSRF attacks",
            "Use SameSite=Strict or SameSite=Lax as appropriate",
        ],
        code_examples={
            "generic": """# Set-Cookie header format
Set-Cookie: sessionId=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600

# Express.js
app.use(session({
  secret: 'your-secret',
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 3600000
  }
}));

# Django
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'

# PHP
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
""",
        },
        references=[
            "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
        cwe_ids=[614, 1004],
    ),
    
    # A05: Security Misconfiguration
    "missing_csp": RemediationInfo(
        description="Content-Security-Policy header is missing",
        severity_rationale="Without CSP, the application is more vulnerable to XSS and data injection attacks",
        steps=[
            "Define a Content-Security-Policy that restricts resource loading",
            "Start with a restrictive policy and gradually relax as needed",
            "Use nonces or hashes for inline scripts/styles",
            "Monitor CSP violations via report-uri or report-to",
        ],
        code_examples={
            "apache": """Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
""",
            "nginx": """add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'" always;
""",
            "generic": """# Strict CSP example
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'

# CSP with nonce (recommended for inline scripts)
Content-Security-Policy: script-src 'nonce-{random-value}'
<script nonce="{random-value}">...</script>
""",
        },
        references=[
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            "https://csp.withgoogle.com/docs/index.html",
        ],
        cwe_ids=[1021],
    ),
    
    "missing_x_content_type_options": RemediationInfo(
        description="X-Content-Type-Options header is missing",
        severity_rationale="Without this header, browsers may MIME-sniff responses, leading to XSS vulnerabilities",
        steps=[
            "Add X-Content-Type-Options: nosniff header to all responses",
        ],
        code_examples={
            "apache": """Header always set X-Content-Type-Options "nosniff"
""",
            "nginx": """add_header X-Content-Type-Options "nosniff" always;
""",
            "iis": """<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="X-Content-Type-Options" value="nosniff" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
""",
            "generic": """# Express.js
const helmet = require('helmet');
app.use(helmet.noSniff());

# Django
SECURE_CONTENT_TYPE_NOSNIFF = True
""",
        },
        references=[
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        ],
        cwe_ids=[16],
    ),
    
    "missing_x_frame_options": RemediationInfo(
        description="X-Frame-Options header is missing",
        severity_rationale="Without this header, the application may be vulnerable to clickjacking attacks",
        steps=[
            "Add X-Frame-Options header with DENY or SAMEORIGIN",
            "Alternatively, use frame-ancestors directive in CSP",
        ],
        code_examples={
            "apache": """Header always set X-Frame-Options "DENY"
# Or for same-origin framing:
# Header always set X-Frame-Options "SAMEORIGIN"
""",
            "nginx": """add_header X-Frame-Options "DENY" always;
# Or: add_header X-Frame-Options "SAMEORIGIN" always;
""",
            "generic": """# Express.js
app.use(helmet.frameguard({ action: 'deny' }));

# Django
X_FRAME_OPTIONS = 'DENY'

# Or use CSP (preferred)
Content-Security-Policy: frame-ancestors 'none'
""",
        },
        references=[
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        ],
        cwe_ids=[1021],
    ),
    
    "missing_referrer_policy": RemediationInfo(
        description="Referrer-Policy header is missing",
        severity_rationale="Referrer leakage can expose sensitive information in URLs to third parties",
        steps=[
            "Add Referrer-Policy header to control referrer information",
            "Use 'no-referrer' or 'strict-origin-when-cross-origin' for best security",
        ],
        code_examples={
            "apache": """Header always set Referrer-Policy "strict-origin-when-cross-origin"
""",
            "nginx": """add_header Referrer-Policy "strict-origin-when-cross-origin" always;
""",
            "generic": """# Recommended values:
# - no-referrer: Never send referrer
# - no-referrer-when-downgrade: Send referrer only on same security level
# - strict-origin-when-cross-origin: Send origin only for cross-origin requests
# - same-origin: Send referrer only for same-origin requests

Referrer-Policy: strict-origin-when-cross-origin
""",
        },
        references=[
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
        ],
        cwe_ids=[200],
    ),
    
    "missing_permissions_policy": RemediationInfo(
        description="Permissions-Policy header is missing",
        severity_rationale="Without this header, embedded content may access sensitive browser features",
        steps=[
            "Add Permissions-Policy header to restrict feature access",
            "Disable unnecessary features like camera, microphone, geolocation",
        ],
        code_examples={
            "apache": """Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
""",
            "nginx": """add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
""",
            "generic": """# Deny all features
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()

# Allow specific features for same-origin only
Permissions-Policy: camera=(self), microphone=(self), geolocation=(self)
""",
        },
        references=[
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
            "https://www.w3.org/TR/permissions-policy-1/",
        ],
        cwe_ids=[1021],
    ),
    
    "information_disclosure_server_header": RemediationInfo(
        description="Server header reveals version information",
        severity_rationale="Version disclosure helps attackers identify known vulnerabilities",
        steps=[
            "Remove or obfuscate the Server header",
            "Configure web server to not reveal version information",
        ],
        code_examples={
            "apache": """# Hide Apache version
ServerTokens Prod
ServerSignature Off
""",
            "nginx": """# Hide Nginx version
server_tokens off;
""",
            "iis": """<!-- Remove Server header in web.config -->
<system.webServer>
  <security>
    <requestFiltering removeServerHeader="true" />
  </security>
</system.webServer>
""",
            "generic": """# Ideally remove the header entirely or set generic value
Server: WebServer
""",
        },
        references=[
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
            "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
        ],
        cwe_ids=[200],
    ),
    
    "information_disclosure_x_powered_by": RemediationInfo(
        description="X-Powered-By header reveals technology stack information",
        severity_rationale="Technology disclosure helps attackers identify known vulnerabilities",
        steps=[
            "Remove X-Powered-By header from responses",
            "Configure application framework to not send this header",
        ],
        code_examples={
            "apache": """Header unset X-Powered-By
""",
            "nginx": """# Nginx doesn't set X-Powered-By by default
# If using PHP-FPM, add to php.ini:
expose_php = Off
""",
            "generic": """# Express.js
app.disable('x-powered-by');

# ASP.NET (web.config)
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <remove name="X-Powered-By" />
    </customHeaders>
  </httpProtocol>
</system.webServer>

# PHP (php.ini)
expose_php = Off
""",
        },
        references=[
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
        ],
        cwe_ids=[200],
    ),
    
    "cors_misconfiguration": RemediationInfo(
        description="Permissive CORS policy detected (Access-Control-Allow-Origin: *)",
        severity_rationale="Wildcard CORS allows any website to read sensitive data from your API",
        steps=[
            "Restrict Access-Control-Allow-Origin to specific trusted domains",
            "Never use wildcard (*) with credentials",
            "Validate Origin header before reflecting it",
            "Use Access-Control-Allow-Credentials carefully",
        ],
        code_examples={
            "apache": """# Dynamic origin validation (use server-side logic)
# Do NOT use:
# Header set Access-Control-Allow-Origin "*"

# Instead, validate and set specific origins:
SetEnvIf Origin "^https://trusted-domain\\.com$" AccessControlAllowOrigin=$0
Header set Access-Control-Allow-Origin %{AccessControlAllowOrigin}e env=AccessControlAllowOrigin
""",
            "nginx": """# Validate origin in Nginx
set $cors_origin "";
if ($http_origin ~* "^https://(www\\.)?trusted-domain\\.com$") {
    set $cors_origin $http_origin;
}
add_header Access-Control-Allow-Origin $cors_origin always;
""",
            "generic": """# Express.js with CORS middleware
const cors = require('cors');
const allowedOrigins = ['https://trusted-domain.com'];
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
""",
        },
        references=[
            "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
        ],
        cwe_ids=[942],
    ),
    
    # A06: Vulnerable and Outdated Components
    "outdated_server_version": RemediationInfo(
        description="Outdated server software version detected",
        severity_rationale="Outdated software may contain known vulnerabilities with public exploits",
        steps=[
            "Update server software to the latest stable version",
            "Subscribe to security mailing lists for your software",
            "Implement a patch management process",
            "Test updates in staging before production deployment",
        ],
        code_examples={
            "generic": """# Check for updates
# Apache
httpd -v
# Update via package manager (e.g., apt, yum)

# Nginx
nginx -v
# Update via package manager

# Automate security updates (Debian/Ubuntu)
sudo apt install unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
""",
        },
        references=[
            "https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components",
            "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
        ],
        cwe_ids=[1104],
    ),
    
    # A03_2025: Software Supply Chain Failures
    "software_supply_chain": RemediationInfo(
        description="Software supply chain vulnerabilities detected",
        severity_rationale="Compromised dependencies can lead to full application compromise",
        steps=[
            "Implement Software Bill of Materials (SBOM) tracking",
            "Use dependency scanning tools (Dependabot, Snyk, etc.)",
            "Pin dependency versions and verify checksums",
            "Monitor security advisories for all dependencies",
            "Implement secure package repository policies",
        ],
        code_examples={
            "generic": """# Package.json with integrity checks
{
  "dependencies": {
    "express": "^4.18.2"
  },
  "devDependencies": {
    "audit-ci": "^6.6.1"
  }
}

# Add to CI/CD pipeline
npm audit --audit-level=high
npm audit fix

# Python requirements.txt with hashes
pip install --require-hashes -r requirements.txt""",
            "nginx": """# Not applicable - use application-level dependency management
# Ensure nginx modules are from trusted sources
# Example: compile with verified third-party modules
./configure --add-module=/path/to/verified-module
make
make install""",
            "apache": """# Not applicable - use application-level dependency management
# Verify Apache module sources
# Example: use only official repositories
apt-get install apache2 libapache2-mod-security2""",
            "iis": """<!-- Not applicable - use application-level dependency management -->
<!-- Ensure all IIS modules are digitally signed -->
<!-- Verify module signatures before deployment -->""",
            "cloudflare": """// Verify Worker dependencies
// Use Cloudflare's curated packages
// Example package.json with lockfile
npm ci --production""",
        },
        references=[
            "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
            "https://slsa.dev/",
            "https://www.cisa.gov/sbom",
            "https://owasp.org/www-project-dependency-check/",
        ],
        cwe_ids=[1395, 829],
    ),
    
    # A10_2025: Mishandling of Exceptional Conditions  
    "exception_handling": RemediationInfo(
        description="Improper exception and error handling detected",
        severity_rationale="Exposed error messages can reveal system internals and aid attackers",
        steps=[
            "Implement centralized error handling",
            "Never expose stack traces to users",
            "Log errors securely without sensitive data",
            "Use custom error pages",
            "Validate all error paths for security implications",
        ],
        code_examples={
            "apache": """# Custom error pages in httpd.conf or .htaccess
ErrorDocument 404 /errors/404.html
ErrorDocument 500 /errors/500.html
ErrorDocument 403 /errors/403.html

# Hide server version
ServerTokens Prod
ServerSignature Off

# Disable directory listing
Options -Indexes""",
            "nginx": """# Custom error pages in nginx.conf
error_page 404 /errors/404.html;
error_page 500 502 503 504 /errors/50x.html;
error_page 403 /errors/403.html;

location = /errors/404.html {
    internal;
}

location = /errors/50x.html {
    internal;
}

# Hide version
server_tokens off;

# Disable directory listing
autoindex off;""",
            "iis": """<!-- web.config -->
<system.webServer>
  <httpErrors errorMode="Custom" existingResponse="Replace">
    <remove statusCode="404"/>
    <error statusCode="404" path="/errors/404.html" responseMode="File"/>
    <remove statusCode="500"/>
    <error statusCode="500" path="/errors/500.html" responseMode="File"/>
    <remove statusCode="403"/>
    <error statusCode="403" path="/errors/403.html" responseMode="File"/>
  </httpErrors>
  <security>
    <requestFiltering removeServerHeader="true"/>
  </security>
  <httpProtocol>
    <customHeaders>
      <remove name="X-Powered-By"/>
    </customHeaders>
  </httpProtocol>
</system.webServer>""",
            "cloudflare": """// Cloudflare Workers secure error handling
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  try {
    const response = await fetch(request)
    return response
  } catch (error) {
    // Log error securely (structured logging)
    console.error({
      timestamp: new Date().toISOString(),
      error: error.name,
      path: new URL(request.url).pathname
    })
    
    // Never expose error details to users
    return new Response('An error occurred', { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    })
  }
}""",
            "generic": """# Application-level secure error handling

# Python example
import logging

logger = logging.getLogger(__name__)

def secure_operation():
    try:
        # Your code here
        result = risky_operation()
        return result
    except ValueError as e:
        # Log error securely (no sensitive data)
        logger.error(f"Operation failed: {type(e).__name__}")
        # Return generic message to user
        return {"error": "Invalid input. Please try again."}
    except Exception as e:
        # Log unexpected errors
        logger.exception("Unexpected error occurred")
        # Generic error message
        return {"error": "An error occurred. Please contact support."}""",
        },
        references=[
            "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/703.html",
        ],
        cwe_ids=[703, 209, 248],
    ),
}


def get_remediation(remediation_key: str, tech_stack: str = "generic") -> Optional[RemediationInfo]:
    """
    Get remediation information for a specific finding.
    
    Args:
        remediation_key: Key identifying the remediation in REMEDIATION_DB
        tech_stack: Technology stack to filter code examples (apache/nginx/iis/cloudflare/generic)
    
    Returns:
        RemediationInfo object with filtered code examples, or None if not found
    """
    if remediation_key not in REMEDIATION_DB:
        return None
    
    remediation = REMEDIATION_DB[remediation_key]
    
    # If tech_stack specified and available, filter to that stack + generic
    if tech_stack != "generic" and tech_stack in remediation.code_examples:
        filtered_examples = {
            tech_stack: remediation.code_examples[tech_stack],
        }
        # Also include generic if available
        if "generic" in remediation.code_examples:
            filtered_examples["generic"] = remediation.code_examples["generic"]
    else:
        filtered_examples = remediation.code_examples
    
    # Return a copy with filtered examples
    return RemediationInfo(
        description=remediation.description,
        severity_rationale=remediation.severity_rationale,
        steps=remediation.steps,
        code_examples=filtered_examples,
        references=remediation.references,
        cwe_ids=remediation.cwe_ids,
    )


def get_category_info(category_id: str) -> Optional[Dict]:
    """Get information about an OWASP category."""
    return OWASP_CATEGORIES.get(category_id)


def list_all_remediation_keys() -> List[str]:
    """List all available remediation keys."""
    return list(REMEDIATION_DB.keys())
