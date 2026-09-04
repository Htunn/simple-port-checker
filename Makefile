.PHONY: help install install-dev test lint format type-check clean build publish docs dev-setup docker-build docker-run docker-dev docker-push docker-test

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
	@echo ""
	@echo "Docker commands:"
	@echo "  docker-build    Build Docker image"
	@echo "  docker-dev      Build development Docker image"
	@echo "  docker-run      Run Docker image with example command"
	@echo "  docker-test     Test Docker image"
	@echo "  docker-push     Push Docker image to registry"
	@echo "  docker-compose  Run with docker-compose"

install:
	pip install .

install-dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=src/offensive_ai --cov-report=html --cov-report=term --cov-fail-under=60

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
	offensive-ai --help

# Docker commands
# Docker commands
docker-build:  ## Build Docker image
	docker build -t offensive-ai:latest .

docker-build-no-cache:  ## Build Docker image without cache
	docker build --no-cache -t offensive-ai:latest .

docker-run:  ## Run Docker container with help
	docker run --rm offensive-ai:latest --help

docker-test:  ## Test Docker container
	docker run --rm offensive-ai:latest --help
	docker run --rm offensive-ai:latest --version

docker-scan:  ## Run vulnerability scan on Docker image
	@command -v trivy >/dev/null 2>&1 || { echo "trivy is required for security scanning. Install from https://trivy.dev/"; exit 1; }
	trivy image offensive-ai:latest

docker-clean:  ## Clean Docker artifacts
	docker system prune -f
	docker image prune -f

# Docker multi-arch build (requires buildx)
docker-build-multi:  ## Build multi-architecture image
	docker buildx build --platform linux/amd64,linux/arm64 -t offensive-ai:latest .

# Docker push to Docker Hub
# Usage: make docker-push DOCKER_USERNAME=youruser
DOCKER_USERNAME ?= htunnthuthu
DOCKER_VERSION := $(shell python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])")

docker-push: docker-build  ## Build and push image to Docker Hub
	docker tag offensive-ai:latest $(DOCKER_USERNAME)/offensive-ai:$(DOCKER_VERSION)
	docker tag offensive-ai:latest $(DOCKER_USERNAME)/offensive-ai:latest
	docker push $(DOCKER_USERNAME)/offensive-ai:$(DOCKER_VERSION)
	docker push $(DOCKER_USERNAME)/offensive-ai:latest

docker-release: docker-push  ## Full release: build → tag → push to Docker Hub