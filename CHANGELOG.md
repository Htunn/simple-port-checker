# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] - 2025-09-21

### Fixed
- **🔧 Critical Dependency Fix**: Added missing `cryptography>=41.0.0` dependency
  - Fixed `ModuleNotFoundError: No module named 'cryptography'` in certificate analysis
  - Added OpenSSL system dependency for GitHub Actions integration tests
  - Ensured certificate chain extraction works properly in all environments
- **🚀 CI/CD Improvements**: Enhanced integration testing environment
  - Fixed PyPI package installation and testing workflow
  - Added proper system dependencies for certificate analysis functionality

## [0.5.0] - 2025-09-21

### Added
- **🔒 SSL/TLS Certificate Analysis**: Comprehensive certificate chain analysis and validation
  - **`cert-check`**: Analyze SSL/TLS certificate chain for target hosts
  - **`cert-chain`**: Complete certificate chain and trust path analysis  
  - **`cert-info`**: Detailed certificate information and signing hierarchy
- **🏛️ Certificate Authority Identification**: "Who signed my cert?" functionality
  - Certificate signing chain visualization
  - Intermediate CA detection and validation
  - Root CA identification and trust validation
- **⚠️ Missing Intermediate Detection**: Identify incomplete certificate chains
  - Browser compatibility warnings
  - Missing intermediate certificate alerts
  - Chain completeness validation
- **🔗 Chain of Trust Validation**: Complete trust path verification
  - Signature validation throughout the chain
  - Certificate hierarchy analysis
  - Trust issue identification
- **🛡️ Security Analysis Features**:
  - Hostname verification against certificates (including wildcards)
  - Certificate expiration checking
  - Key algorithm and signature algorithm analysis
  - Subject Alternative Names (SAN) extraction
- **📋 Certificate Information Extraction**:
  - Certificate fingerprints (SHA-1, SHA-256)
  - Serial numbers and validity periods
  - Key usage and extended key usage details
  - Certificate extensions analysis
- **🔄 Revocation Infrastructure**: OCSP and CRL URL extraction for future validation
- **📊 Rich Output**: Beautiful certificate analysis tables with status indicators
- **💾 Export Capabilities**: JSON output support for programmatic integration

### Enhanced
- **CLI Interface**: Added three new certificate analysis commands to main CLI
- **Documentation**: Integrated best practices from DigiCert and Red Hat security guidelines
- **Error Handling**: Robust certificate parsing with multiple fallback methods
- **Async Support**: Asynchronous certificate chain analysis for better performance

### Technical
- **Certificate Parser**: Built on cryptography library for robust certificate handling
- **Chain Extraction**: Uses OpenSSL for comprehensive certificate chain retrieval
- **Timezone Handling**: Proper UTC datetime handling for certificate validity
- **Security Context**: Appropriate SSL context configuration for certificate analysis

## [0.4.2] - 2025-09-19

### Fixed
- **CHANGELOG Correction**: Fixed changelog entry accuracy for 0.4.1 release
- **Version Update**: Updated version consistency across pyproject.toml and __init__.py

### Maintenance
- **Documentation**: Minor improvements to changelog formatting and accuracy

## [0.4.1] - 2025-09-19

### Fixed
- **L7 Detection Bug**: Fixed critical false positive where CloudFront-protected sites were incorrectly identified as F5 Big-IP
- **Via Header Detection**: Corrected F5 detection logic to check via header content instead of just presence
- **AWS WAF Detection**: Fixed fallback detection path that was incorrectly flagging any via header as F5

### Enhanced
- **CloudFront Differentiation**: AWS WAF detection now distinguishes between "CloudFront - AWS WAF" and pure "AWS WAF"
- **Display Names**: Enhanced service name display logic to show more specific protection service information
- **Detection Accuracy**: Improved confidence scoring and indicator analysis for AWS CloudFront services

### Improved
- **Detection Logic**: Refined F5 Big-IP detection to avoid false positives with CloudFront via headers
- **Service Identification**: More precise identification of AWS protection services (CloudFront vs WAF)
- **User Experience**: Clearer service names in CLI output and JSON results

## [0.4.0] - 2025-09-19

### Added
- **Docker Support**: Official Docker images now available on Docker Hub
- Enhanced README.md with comprehensive Docker usage examples and Docker Hub integration
- Docker workflow configured for manual deployment to PyPI environment
- Multi-architecture Docker image support (AMD64, ARM64)
- Automated Docker builds with GitHub Actions

### Improved
- Updated project documentation to highlight Docker availability
- Added Docker Hub badges and links for better discoverability
- Enhanced installation documentation with Docker Hub examples
- Updated version references throughout documentation

### Fixed
- Docker workflow environment configuration for proper secret management
- GitHub Actions workflow to use PyPI environment for Docker registry credentials

## [0.2.0] - 2025-09-15

### Major Refactoring and Cleanup
- **BREAKING**: Removed standalone scripts directory and integrated all functionality into main CLI
- **BREAKING**: Moved all tests to top-level `tests/` directory following Python packaging standards
- **BREAKING**: Removed `run.py` entry point (use `python -m simple_port_checker` or installed CLI commands)

### Added
- Unified CLI interface with all functionality accessible via main commands
- DNS trace functionality integrated into `dns-trace` command and `l7-check --trace-dns`
- Type hint support with `py.typed` file for better IDE and tooling support
- Security policy documentation (`SECURITY.md`)
- Production-ready project structure following Python packaging best practices

### Improved
- Clean and consistent project organization under `src/simple_port_checker/`
- Better error handling in DNS trace functionality
- Fixed undefined variable issues in L7 detector
- Updated documentation and project structure guide
- Enhanced code organization and maintainability

### Fixed
- Method signature issues in `_check_ip_for_protection`
- Variable scope problems in DNS tracing
- Import path issues after test file reorganization
- Duplicate test directories cleanup

### Removed
- `src/simple_port_checker/scripts/` directory (functionality moved to main CLI)
- `run.py` standalone entry point
- Unnecessary script entry points from pyproject.toml
- Duplicate and outdated test files

## [0.3.0] - 2025-09-17

### Added - Production-Ready mTLS Authentication Support
- **Complete mTLS Implementation**: Production-grade mutual TLS authentication checking
  - Advanced error handling with retry logic and exponential backoff
  - Comprehensive input validation and sanitization
  - Performance metrics and reliability tracking
  - Enhanced logging with configurable verbosity levels
  - Resource cleanup and connection management
- **Enhanced CLI Commands**:
  - `mtls-check`: Advanced mTLS checking with retry logic, custom timeouts, and batch processing
  - `mtls-gen-cert`: Certificate generation with configurable key sizes and validity periods
  - `mtls-validate-cert`: Comprehensive certificate validation with detailed output
- **Production Features**:
  - Configurable retry attempts and delays (0.1-10.0s)
  - Custom timeout handling (1-300s)
  - Concurrent processing limits (1-50 connections)
  - Progress callbacks for batch operations
  - Detailed performance and error metrics
- **Enterprise Integration**:
  - CI/CD pipeline examples (GitHub Actions, Jenkins)
  - Kubernetes deployment health checks
  - Docker container security scanning
  - Enterprise audit scripts and automation
- **Security Enhancements**:
  - Input validation for hostnames, ports, and file paths
  - Certificate chain validation and expiration checking
  - Secure SSL context configuration (TLS 1.2+ requirement)
  - Proper error categorization (network, timeout, certificate errors)
- **Documentation**:
  - Comprehensive mTLS sequence diagram with mermaid
  - Production deployment examples and best practices
  - Security guidelines and troubleshooting guide
  - Enterprise integration patterns
  - API documentation with real-world examples

### Enhanced
- **MTLSChecker Class**: Production-ready with comprehensive error handling
  - Input validation for all parameters
  - Configurable retry logic with exponential backoff
  - Performance metrics collection and reporting
  - Enhanced logging with structured output
  - Resource cleanup and connection pooling
- **Batch Processing**: Improved concurrent processing with progress tracking
  - Support for mixed hostname/port formats
  - Progress callbacks for real-time updates
  - Enhanced error handling for individual targets
  - Performance optimization for large-scale scans
- **Certificate Handling**: Enhanced certificate parsing and validation
  - Support for various certificate formats
  - Detailed certificate information extraction
  - Chain validation and expiration checking
  - Secure file permission recommendations
- **CLI Interface**: Production-ready command interface
  - Comprehensive help documentation with examples
  - Enhanced parameter validation and error messages
  - Rich output formatting with progress bars
  - JSON export with detailed metrics
- **Error Handling**: Comprehensive error management
  - Categorized error types (network, timeout, certificate)
  - Graceful degradation for missing dependencies
  - Detailed error messages with troubleshooting hints
  - Metrics tracking for reliability monitoring

### Dependencies
- **Updated**: `cryptography>=41.0.0` for enhanced certificate handling
- **Updated**: `certifi>=2023.7.22` for CA bundle management
- **Added**: Enhanced error handling for optional dependencies

## [Unreleased]
  - `mtls-check`: Advanced mTLS checking with retry logic, custom timeouts, and batch processing
  - `mtls-gen-cert`: Certificate generation with configurable key sizes and validity periods
  - `mtls-validate-cert`: Comprehensive certificate validation with detailed output
- **Production Features**:
  - Configurable retry attempts and delays (0.1-10.0s)
  - Custom timeout handling (1-300s)
  - Concurrent processing limits (1-50 connections)
  - Progress callbacks for batch operations
  - Detailed performance and error metrics
- **Enterprise Integration**:
  - CI/CD pipeline examples (GitHub Actions, Jenkins)
  - Kubernetes deployment health checks
  - Docker container security scanning
  - Enterprise audit scripts and automation
- **Security Enhancements**:
  - Input validation for hostnames, ports, and file paths
  - Certificate chain validation and expiration checking
  - Secure SSL context configuration (TLS 1.2+ requirement)
  - Proper error categorization (network, timeout, certificate errors)
- **Documentation**:
  - Comprehensive mTLS sequence diagram with mermaid
  - Production deployment examples and best practices
  - Security guidelines and troubleshooting guide
  - Enterprise integration patterns
  - API documentation with real-world examples

### Enhanced
- **MTLSChecker Class**: Production-ready with comprehensive error handling
  - Input validation for all parameters
  - Configurable retry logic with exponential backoff
  - Performance metrics collection and reporting
  - Enhanced logging with structured output
  - Resource cleanup and connection pooling
- **Batch Processing**: Improved concurrent processing with progress tracking
  - Support for mixed hostname/port formats
  - Progress callbacks for real-time updates
  - Enhanced error handling for individual targets
  - Performance optimization for large-scale scans
- **Certificate Handling**: Enhanced certificate parsing and validation
  - Support for various certificate formats
  - Detailed certificate information extraction
  - Chain validation and expiration checking
  - Secure file permission recommendations
- **CLI Interface**: Production-ready command interface
  - Comprehensive help documentation with examples
  - Enhanced parameter validation and error messages
  - Rich output formatting with progress bars
  - JSON export with detailed metrics
- **Error Handling**: Comprehensive error management
  - Categorized error types (network, timeout, certificate)
  - Graceful degradation for missing dependencies
  - Detailed error messages with troubleshooting hints
  - Metrics tracking for reliability monitoring

### Dependencies
- **Updated**: `cryptography>=41.0.0` for enhanced certificate handling
- **Updated**: `certifi>=2023.7.22` for CA bundle management
- **Added**: Enhanced error handling for optional dependencies

## [0.1.11] - 2025-01-16

### Fixed
- Enhanced F5 BIG-IP detection logic for volt-adc and F5 Edge Services
- Improved header pattern matching for case-insensitive detection
- Added more extensive F5 signature patterns for better detection
- Improved fallback analysis with more comprehensive detection logic
- Added better detection of numeric cookie patterns characteristic of F5
- Enhanced detection for sites with specific server headers like "volt-adc"
- Fixed issues in full-scan mode when detecting L7 protection services

## [0.1.10] - 2025-01-16

### Fixed
- Enhanced handling of websites with extremely large headers (e.g., www.ntu.edu.sg)
- Increased header size limit to 128KB for better compatibility with complex sites
- Added brotli compression support for sites that use br content encoding
- Improved detection algorithm for educational (.edu) domains
- Enhanced fallback mechanisms with more robust error handling
- Added more comprehensive domain detection patterns for problematic sites
- Improved requests library fallback to handle different compression methods
- Fixed SSL verification warnings in fallback methods
- Enhanced detection patterns for Cloudflare, Akamai, F5, and other CDN/WAF providers

## [0.1.9] - 2025-01-15

### Fixed
- Added fallback mechanism using requests library for problematic sites with extremely large headers
- Implemented automatic switching between aiohttp and requests for problematic domains
- Enhanced detection of WAF/CDN services even when primary detection fails
- Improved handling of .sg domains that commonly use Akamai with large headers
- Added sophisticated header analysis for fallback cases

## [0.1.8] - 2025-01-15

### Fixed
- Significantly improved handling of sites with extremely large HTTP headers
- Increased header size limit to 64KB to support the most complex WAF configurations
- Added resilient HTTP request handling with graceful header processing
- Enhanced WAF detection for sites that use oversized headers as security measures
- Added special detection patterns for Singapore (.sg) domains with large headers
- Implemented SSL bypass option to avoid certificate validation issues

## [0.1.7] - 2025-01-15

### Fixed
- Increased maximum header size limit to 32KB to handle websites with very large response headers
- Improved error handling for "Header value too long" errors to better identify potential WAF/CDN
- Enhanced HTTP client configuration for better handling of complex network scenarios
- Added support for compressed responses to handle CDN-optimized content

## [0.1.6] - 2025-01-15

### Fixed
- Fixed "Header value too long" errors during L7 detection
- Improved handling of large HTTP responses
- Enhanced error handling for various HTTP client errors
- Optimized response body processing to prevent excessive memory usage

## [0.1.5] - 2025-01-15

### Added
- Improved F5 BIG-IP WAF detection for different F5 implementations
- Added detection for F5 Edge Services via VES.IO domain patterns
- Enhanced F5 cookie pattern detection
- Added additional status code and response body patterns for F5 detection

## [0.1.4] - 2025-01-15

### Added
- Explicit notification when a target is not protected by L7 services in CLI output
- Added a dedicated table in summary displaying all unprotected hosts
- Improved visibility of unprotected hosts in scan results

## [0.1.3] - 2025-01-15

### Added
- Support for Azure Front Door detection

## [0.1.2] - 2025-01-15

### Fixed
- Updated GitHub Actions to use latest versions

## [0.1.0] - 2025-01-14

### Added
- Basic port scanning functionality with async support
- L7 protection detection for major WAF/CDN services
- Command-line interface with multiple commands
- Support for batch scanning multiple hosts
- Service version detection capabilities
- WAF bypass testing functionality
- Rich terminal output with progress bars
- JSON output format support
- Comprehensive test suite
- GitHub Actions CI/CD pipeline
- PyPI publishing workflow
- Development environment setup scripts
- Pre-commit hooks for code quality
- Type hints and mypy support
- Detailed documentation and examples

### Features
- **Port Scanning**: Async scanning with configurable concurrency
- **L7 Detection**: Identify Cloudflare, AWS WAF, Azure WAF, F5, Akamai, and more
- **CLI Interface**: Easy-to-use command-line tools
- **Service Detection**: Banner grabbing and service identification
- **Batch Operations**: Scan multiple hosts efficiently
- **Configuration**: Customizable timeouts, concurrency, and more
- **Output Formats**: JSON export and terminal display
- **Security Testing**: WAF detection and bypass testing

### Technical Details
- Python 3.12+ support
- Async/await architecture for high performance
- Type-safe codebase with mypy
- Comprehensive error handling
- Modular and extensible design
- Well-tested with pytest
- Production-ready packaging

### Dependencies
- aiohttp: Async HTTP client
- click: Command-line interface
- rich: Terminal output formatting
- pydantic: Data validation
- dnspython: DNS resolution
- python-nmap: Network mapping
- asyncio-throttle: Rate limiting
- cryptography: For certificate handling
- certifi: For CA bundle management

[Unreleased]: https://github.com/yourusername/simple-port-checker/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/simple-port-checker/releases/tag/v0.1.0
