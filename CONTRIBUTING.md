# Contributing to Simple Port Checker

Thank you for your interest in contributing to Simple Port Checker! This guide will help you get started.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please be respectful and professional in all interactions.

## Getting Started

### Development Environment Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/yourusername/simple-port-checker.git
   cd simple-port-checker
   ```

2. **Set up development environment**
   ```bash
   ./setup_dev.sh
   # Or manually:
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

4. **Verify setup**
   ```bash
   make test
   port-checker --help
   ```

### Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following the existing style
   - Add tests for new functionality
   - Update documentation as needed

3. **Run quality checks**
   ```bash
   make dev  # Runs format, lint, and test
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add: description of your changes"
   ```

5. **Push and create a pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style and Standards

### Python Code Style

- **PEP 8**: Follow Python style guidelines
- **Black**: Code formatting (line length: 88)
- **isort**: Import sorting
- **Type hints**: Use type annotations for all functions
- **Docstrings**: Use Google-style docstrings

Example:
```python
async def scan_port(host: str, port: int, timeout: float = 3.0) -> PortResult:
    """
    Scan a single port on a target host.
    
    Args:
        host: Target hostname or IP address
        port: Port number to scan
        timeout: Connection timeout in seconds
        
    Returns:
        PortResult containing scan information
        
    Raises:
        ConnectionError: If unable to connect to host
    """
    # Implementation here
```

### Code Organization

```
src/simple_port_checker/
├── __init__.py           # Package exports
├── core/                 # Core functionality
│   ├── port_scanner.py   # Port scanning logic
│   └── l7_detector.py    # L7 protection detection
├── models/               # Data models
│   ├── scan_result.py    # Scan result models
│   └── l7_result.py      # L7 detection models
├── utils/                # Utility functions
│   ├── common_ports.py   # Port definitions
│   └── l7_signatures.py  # L7 service signatures
└── cli.py               # Command-line interface
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test file
pytest tests/test_port_scanner.py -v

# Run specific test
pytest tests/test_port_scanner.py::TestPortChecker::test_scan_host_success -v
```

### Writing Tests

- Use `pytest` for all tests
- Write tests for both success and failure cases
- Use async tests for async code
- Mock external dependencies
- Aim for >90% code coverage

Example test:
```python
@pytest.mark.asyncio
async def test_scan_host_success(self):
    """Test successful host scanning."""
    checker = PortChecker()
    
    with patch('socket.gethostbyname', return_value='127.0.0.1'):
        with patch('asyncio.open_connection') as mock_conn:
            mock_conn.return_value = (AsyncMock(), AsyncMock())
            
            result = await checker.scan_host("example.com", [80])
            
            assert result.host == "example.com"
            assert len(result.ports) == 1
```

## Adding New Features

### New L7 Protection Service

1. **Add to L7Protection enum** in `models/l7_result.py`:
   ```python
   NEW_SERVICE = "new_service"
   ```

2. **Add signatures** in `utils/l7_signatures.py`:
   ```python
   L7Protection.NEW_SERVICE: {
       "headers": {
           "X-New-Service": [r".*"],
           "Server": [r"NewService.*"],
       },
       "server": [r"NewService.*"],
       "body": [r"blocked by new service"],
       "status_codes": [403],
       "description": "New Service WAF"
   }
   ```

3. **Add tests** in `tests/test_l7_detector.py`

4. **Update documentation**

### New Port Scanning Feature

1. **Add functionality** to `core/port_scanner.py`
2. **Add models** if needed in `models/`
3. **Add CLI command** in `cli.py`
4. **Add tests** in `tests/`
5. **Update documentation**

## Documentation

### Updating Documentation

- **README.md**: Main project documentation
- **docs/quickstart.md**: Quick start guide
- **Docstrings**: Inline code documentation
- **Examples**: Add to `examples/` directory

### Documentation Style

- Use clear, concise language
- Include code examples
- Keep examples up-to-date
- Document breaking changes

## Submitting Changes

### Pull Request Process

1. **Ensure CI passes**: All tests and checks must pass
2. **Update documentation**: Include relevant documentation updates
3. **Add tests**: New features must include tests
4. **Follow commit conventions**: Use clear, descriptive commit messages
5. **Update CHANGELOG.md**: Add entry for your changes

### Commit Message Format

```
Type: Brief description

Longer description if needed

- Detail 1
- Detail 2

Fixes #123
```

Types:
- `Add`: New feature
- `Fix`: Bug fix
- `Update`: Modify existing feature
- `Remove`: Remove feature
- `Docs`: Documentation changes
- `Test`: Test changes
- `Refactor`: Code refactoring

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] New tests added
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
```

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Steps

1. **Update version** in `pyproject.toml`
2. **Update CHANGELOG.md**
3. **Create release tag**: `git tag v1.0.0`
4. **Push tag**: `git push origin v1.0.0`
5. **GitHub Actions** will automatically publish to PyPI

## Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Pull Requests**: Code review and collaboration

### Issue Templates

**Bug Report:**
- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment details
- Relevant logs/screenshots

**Feature Request:**
- Clear description of the feature
- Use case and motivation
- Proposed implementation (if any)
- Alternative solutions considered

## Security

### Reporting Security Issues

**Do not** open public issues for security vulnerabilities. Instead:

1. Email security concerns to: [security@example.com]
2. Include detailed description
3. Provide steps to reproduce
4. Allow reasonable time for response

### Security Best Practices

- Never commit secrets or credentials
- Validate all user inputs
- Use secure defaults
- Follow principle of least privilege
- Keep dependencies updated

## Recognition

Contributors will be recognized in:
- **CONTRIBUTORS.md** file
- **Release notes** for significant contributions
- **GitHub contributors** page

Thank you for contributing to Simple Port Checker! 🎉
