# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project setup and structure

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
