#!/bin/bash
# offensive-ai Development Setup Script

set -e

echo "Setting up offensive-ai development environment..."

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.12"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "ERROR: Python 3.12 or higher is required. Found: Python $python_version"
    exit 1
fi

echo "Python $python_version detected"

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install package in development mode with all extras
echo "Installing package in development mode..."
pip install -e ".[dev,ai]"

# Install pre-commit hooks
echo "Setting up pre-commit hooks..."
pre-commit install

# Run initial code formatting
echo "Running initial code formatting..."
black src/ tests/ examples/
isort src/ tests/ examples/

# Run tests to ensure everything works
echo "Running tests..."
pytest tests/ -v

echo ""
echo "Development environment setup complete!"
echo ""
echo "To get started:"
echo "  1. Activate the virtual environment: source .venv/bin/activate"
echo "  2. Run tests: pytest"
echo "  3. Run the CLI: offensive-ai --help"
echo "  4. Check code style: pre-commit run --all-files"
