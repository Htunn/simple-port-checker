"""Package-wide constants — centralises magic strings that were previously scattered across modules."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    _VERSION = _pkg_version("offsec-ai")
except PackageNotFoundError:  # pragma: no cover
    _VERSION = "unknown"

#: HTTP User-Agent header sent by every scanner and attacker.
USER_AGENT: str = f"offsec-ai/{_VERSION}"

#: MCP JSON-RPC protocol version used in initialize handshakes.
MCP_PROTOCOL_VERSION: str = "2024-11-05"

#: Client name declared during MCP initialize.
MCP_CLIENT_NAME: str = "offsec-ai"
