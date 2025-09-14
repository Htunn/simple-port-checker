# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project setup and structure

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

[Unreleased]: https://github.com/yourusername/simple-port-checker/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/simple-port-checker/releases/tag/v0.1.0
