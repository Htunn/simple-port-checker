.PHONY: help install install-dev test lint format type-check clean build publish docs dev-setup

# Default target
help:
	@echo "Simple Port Checker - Development Commands"
	@echo ""
	@echo "Available commands:"
	@echo "  install      Install package for production"
	@echo "  install-dev  Install package for development"
	@echo "  test         Run tests"
	@echo "  test-cov     Run tests with coverage"
	@echo "  lint         Run linting checks"
	@echo "  format       Format code with black and isort"
	@echo "  type-check   Run type checking with mypy"
	@echo "  clean        Clean build artifacts"
	@echo "  build        Build package"
	@echo "  publish      Publish to PyPI (requires credentials)"
	@echo "  docs         Generate documentation"
	@echo "  dev-setup    Set up development environment"
	@echo "  pre-commit   Run pre-commit hooks"

install:
	pip install .

install-dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=src/simple_port_checker --cov-report=html --cov-report=term

lint:
	flake8 src/ tests/ examples/
	mypy src/

format:
	black src/ tests/ examples/
	isort src/ tests/ examples/

type-check:
	mypy src/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

publish: build
	twine upload dist/*

docs:
	@echo "Documentation is available in docs/ directory"
	@echo "Quick start: docs/quickstart.md"

dev-setup:
	./setup_dev.sh

pre-commit:
	pre-commit run --all-files

# Development workflow
dev: format lint test
	@echo "Development checks completed successfully!"

# CI workflow
ci: lint type-check test-cov
	@echo "CI checks completed successfully!"

# Quick test
quick:
	pytest tests/test_port_scanner.py -v

# Example usage
example:
	python examples/usage_examples.py

# CLI help
cli-help:
	port-checker --help
