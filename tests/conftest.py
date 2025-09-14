"""Test configuration and fixtures."""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock

# Test configuration
TEST_TIMEOUT = 1.0
TEST_HOST = "example.com"
TEST_PORTS = [80, 443, 22, 21]


@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_session():
    """Mock aiohttp session."""
    session = AsyncMock()
    response = AsyncMock()
    response.status = 200
    response.headers = {"Server": "nginx/1.18.0"}
    response.text = AsyncMock(return_value="<html><body>Test</body></html>")
    session.get.return_value.__aenter__.return_value = response
    return session


@pytest.fixture
def sample_headers():
    """Sample HTTP headers for testing."""
    return {
        "Server": "nginx/1.18.0",
        "Content-Type": "text/html",
        "Content-Length": "1234",
        "Date": "Mon, 01 Jan 2024 00:00:00 GMT",
    }
