"""
Tool registry for the agentic REPL.

Wraps every scanner/attacker module as a ``ToolSpec`` the LLM can invoke via
native tool/function calling. Scanner tools are read-only and always
available; attacker tools set ``requires_authorization=True`` and are only
executed by ``AgentSession`` after the session-level ``--i-have-authorization``
flag AND a per-call interactive confirmation both pass.

Every handler catches its own exceptions and returns ``{"error": ...}``
instead of raising, so a single failed tool call never kills the REPL loop.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from .a2a_attacker import A2AAttacker
from .a2a_scanner import A2AScanner
from .agent_llm import ToolSpec
from .ai_owasp_scanner import LLMOwaspScanner
from .auth_attacker import AuthAttacker
from .auth_scanner import AuthScanner
from .blockchain_attacker import BlockchainAttacker
from .blockchain_scanner import BlockchainScanner
from .guardrail_bench import GuardrailBench
from .hybrid_identity_checker import HybridIdentityChecker
from .k8s_attacker import K8sAttacker
from .k8s_scanner import K8sScanner
from .l7_detector import L7Detector
from .llm_conversation_attacker import LLMConversationAttacker
from .mcp_attacker import MCPAttacker
from .mcp_scanner import MCPScanner
from .mtls_checker import MTLSChecker
from .openclaw_attacker import OpenClawAttacker
from .openclaw_scanner import OpenClawScanner
from .owasp_scanner import OwaspScanner
from .port_scanner import PortChecker
from .postman_attacker import PostmanAttacker
from .postman_scanner import PostmanScanner


def _dump(result: Any) -> dict[str, Any]:
    """Best-effort JSON-serializable dict from a Pydantic model or dataclass result."""
    if hasattr(result, "model_dump"):
        dumped: dict[str, Any] = result.model_dump(mode="json")
        return dumped
    if dataclasses.is_dataclass(result) and not isinstance(result, type):
        return dataclasses.asdict(result)
    return {"result": str(result)}


def _schema(properties: dict[str, dict[str, Any]], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required}


# ---------------------------------------------------------------------------
# Scanner tool handlers (read-only, no authorization required)
# ---------------------------------------------------------------------------


async def _scan_a2a(target: str, timeout: float = 15.0) -> dict[str, Any]:
    try:
        return _dump(await A2AScanner(target=target, timeout=timeout).scan())
    except Exception as exc:
        return {"error": str(exc)}


async def _scan_auth(target: str, protocol: str = "auto", timeout: float = 15.0) -> dict[str, Any]:
    try:
        return _dump(await AuthScanner(target=target, protocol=protocol, timeout=timeout).scan())
    except Exception as exc:
        return {"error": str(exc)}


async def _scan_blockchain(target: str, port: int = 8545, timeout: float = 15.0) -> dict[str, Any]:
    try:
        return _dump(await BlockchainScanner(target=target, port=port, timeout=timeout).scan())
    except Exception as exc:
        return {"error": str(exc)}


async def _scan_k8s(target: str, timeout: float = 15.0) -> dict[str, Any]:
    try:
        return _dump(await K8sScanner(target=target, timeout=timeout).scan())
    except Exception as exc:
        return {"error": str(exc)}


async def _scan_mcp(target: str, transport: str = "http", timeout: float = 15.0) -> dict[str, Any]:
    try:
        return _dump(await MCPScanner(target=target, transport=transport, timeout=timeout).scan())
    except Exception as exc:
        return {"error": str(exc)}


async def _scan_openclaw(target: str, port: int = 18789, timeout: float = 15.0, use_tls: bool = False) -> dict[str, Any]:
    try:
        return _dump(await OpenClawScanner(target=target, port=port, timeout=timeout, use_tls=use_tls).scan())
    except Exception as exc:
        return {"error": str(exc)}


async def _scan_postman(
    collection_path: str,
    environment_path: str | None = None,
    target_override: str | None = None,
    max_endpoints: int | None = None,
) -> dict[str, Any]:
    try:
        scanner = PostmanScanner(
            collection_path=collection_path,
            environment_path=environment_path,
            target_override=target_override,
            max_endpoints=max_endpoints,
        )
        return _dump(await scanner.scan())
    except Exception as exc:
        return {"error": str(exc)}


async def _scan_ai_owasp(endpoint: str, mode: str = "safe", timeout: float = 30.0) -> dict[str, Any]:
    try:
        scanner = LLMOwaspScanner(endpoint=endpoint, mode=mode, timeout=timeout)
        return _dump(await scanner.scan())
    except Exception as exc:
        return {"error": str(exc)}


async def _scan_owasp(target: str, mode: str = "safe", timeout: float = 10.0) -> dict[str, Any]:
    try:
        scanner = OwaspScanner(mode=mode, timeout=timeout)
        return _dump(await scanner.scan(target))
    except Exception as exc:
        return {"error": str(exc)}


async def _check_hybrid_identity(fqdn: str, timeout: float = 10.0) -> dict[str, Any]:
    try:
        return _dump(await HybridIdentityChecker(timeout=timeout).check(fqdn))
    except Exception as exc:
        return {"error": str(exc)}


async def _check_mtls(target: str, port: int = 443, timeout: int = 10) -> dict[str, Any]:
    try:
        return _dump(await MTLSChecker(timeout=timeout).check_mtls(target, port=port))
    except Exception as exc:
        return {"error": str(exc)}


async def _detect_l7(host: str, port: int | None = None, path: str = "/", timeout: float = 10.0) -> dict[str, Any]:
    try:
        detector = L7Detector(timeout=timeout)
        result = await detector.detect(host, port=port, path=path)  # type: ignore[arg-type]
        return _dump(result)
    except Exception as exc:
        return {"error": str(exc)}


async def _scan_ports(host: str, timeout: float = 3.0) -> dict[str, Any]:
    try:
        return _dump(await PortChecker().scan_host(host, timeout=timeout))
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Attacker tool handlers (requires_authorization=True — gated by AgentSession)
# ---------------------------------------------------------------------------


async def _attack_a2a(target: str, mode: str = "safe", timeout: float = 15.0) -> dict[str, Any]:
    try:
        return _dump(await A2AAttacker(authorized=True).attack(target, mode=mode, timeout=timeout))
    except Exception as exc:
        return {"error": str(exc)}


async def _attack_auth(target: str, mode: str = "safe", protocol: str = "auto", timeout: float = 15.0) -> dict[str, Any]:
    try:
        return _dump(await AuthAttacker(authorized=True).attack(target, mode=mode, protocol=protocol, timeout=timeout))
    except Exception as exc:
        return {"error": str(exc)}


async def _attack_blockchain(target: str, port: int = 8545, mode: str = "safe", timeout: float = 15.0) -> dict[str, Any]:
    try:
        return _dump(await BlockchainAttacker(authorized=True).attack(target, port=port, mode=mode, timeout=timeout))
    except Exception as exc:
        return {"error": str(exc)}


async def _attack_k8s(target: str, mode: str = "safe", timeout: float = 15.0) -> dict[str, Any]:
    try:
        return _dump(await K8sAttacker(authorized=True).attack(target, mode=mode, timeout=timeout))
    except Exception as exc:
        return {"error": str(exc)}


async def _attack_mcp(target: str, transport: str = "http", mode: str = "safe", timeout: float = 15.0) -> dict[str, Any]:
    try:
        return _dump(await MCPAttacker(authorized=True).attack(target, transport=transport, mode=mode, timeout=timeout))
    except Exception as exc:
        return {"error": str(exc)}


async def _attack_openclaw(target: str, port: int = 18789, mode: str = "safe", timeout: float = 15.0, use_tls: bool = False) -> dict[str, Any]:
    try:
        return _dump(
            await OpenClawAttacker(authorized=True).attack(target, port=port, mode=mode, timeout=timeout, use_tls=use_tls)
        )
    except Exception as exc:
        return {"error": str(exc)}


async def _attack_postman(
    collection_path: str,
    environment_path: str | None = None,
    target_override: str | None = None,
    mode: str = "safe",
) -> dict[str, Any]:
    try:
        attacker = PostmanAttacker(authorized=True)
        return _dump(
            await attacker.attack(
                collection_path,
                environment_path=environment_path,
                target_override=target_override,
                mode=mode,
            )
        )
    except Exception as exc:
        return {"error": str(exc)}


async def _guardrail_bench(endpoint: str, api_key: str | None = None, timeout: float = 30.0) -> dict[str, Any]:
    try:
        bench = GuardrailBench(authorized=True, timeout=timeout)
        return _dump(await bench.run(endpoint, api_key=api_key))
    except Exception as exc:
        return {"error": str(exc)}


async def _llm_conversation_attack(
    endpoint: str,
    payload: str,
    api_key: str | None = None,
    mode: str = "safe",
    timeout: float = 30.0,
) -> dict[str, Any]:
    try:
        attacker = LLMConversationAttacker(authorized=True, timeout=timeout)
        return _dump(await attacker.attack(endpoint, payload, api_key=api_key, mode=mode))
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_TARGET_TIMEOUT = _schema(
    {"target": {"type": "string", "description": "Target hostname or base URL"},
     "timeout": {"type": "number", "description": "Per-request timeout in seconds"}},
    ["target"],
)

SCANNER_TOOLS: list[ToolSpec] = [
    ToolSpec("scan_a2a", "Passively scan an A2A (Agent-to-Agent) protocol endpoint for security issues.", _TARGET_TIMEOUT, _scan_a2a),
    ToolSpec(
        "scan_auth",
        "Passively scan an OIDC/OAuth2/SAML auth endpoint for security issues.",
        _schema(
            {"target": {"type": "string"}, "protocol": {"type": "string", "enum": ["auto", "oidc", "oauth2", "saml"]},
             "timeout": {"type": "number"}},
            ["target"],
        ),
        _scan_auth,
    ),
    ToolSpec(
        "scan_blockchain",
        "Passively scan a blockchain JSON-RPC node (Ethereum/EVM) for security issues.",
        _schema({"target": {"type": "string"}, "port": {"type": "integer"}, "timeout": {"type": "number"}}, ["target"]),
        _scan_blockchain,
    ),
    ToolSpec("scan_k8s", "Passively scan a Kubernetes cluster's exposed components for security issues.", _TARGET_TIMEOUT, _scan_k8s),
    ToolSpec(
        "scan_mcp",
        "Passively scan an MCP (Model Context Protocol) server endpoint for security issues.",
        _schema(
            {"target": {"type": "string"}, "transport": {"type": "string", "enum": ["http", "sse", "stdio"]},
             "timeout": {"type": "number"}},
            ["target"],
        ),
        _scan_mcp,
    ),
    ToolSpec(
        "scan_openclaw",
        "Passively scan an OpenClaw AI gateway for security issues.",
        _schema(
            {"target": {"type": "string"}, "port": {"type": "integer"}, "timeout": {"type": "number"},
             "use_tls": {"type": "boolean"}},
            ["target"],
        ),
        _scan_openclaw,
    ),
    ToolSpec(
        "scan_postman",
        "Passively scan every endpoint defined in a Postman Collection JSON export for security issues.",
        _schema(
            {"collection_path": {"type": "string", "description": "Path to a Postman Collection v2.x JSON file"},
             "environment_path": {"type": "string"}, "target_override": {"type": "string"},
             "max_endpoints": {"type": "integer"}},
            ["collection_path"],
        ),
        _scan_postman,
    ),
    ToolSpec(
        "scan_ai_owasp",
        "Black-box probe an LLM chat-completions endpoint against the OWASP LLM Top 10.",
        _schema(
            {"endpoint": {"type": "string"}, "mode": {"type": "string", "enum": ["safe", "deep"]},
             "timeout": {"type": "number"}},
            ["endpoint"],
        ),
        _scan_ai_owasp,
    ),
    ToolSpec(
        "scan_owasp",
        "Scan a web target against the OWASP Top 10 2021 (headers, TLS, cookies, version detection).",
        _schema(
            {"target": {"type": "string"}, "mode": {"type": "string", "enum": ["safe", "deep"]},
             "timeout": {"type": "number"}},
            ["target"],
        ),
        _scan_owasp,
    ),
    ToolSpec(
        "check_hybrid_identity",
        "Check whether a domain has hybrid identity / ADFS / Azure AD federation configured.",
        _schema({"fqdn": {"type": "string"}, "timeout": {"type": "number"}}, ["fqdn"]),
        _check_hybrid_identity,
    ),
    ToolSpec(
        "check_mtls",
        "Check whether a target host supports mutual TLS (client certificate) authentication.",
        _schema({"target": {"type": "string"}, "port": {"type": "integer"}, "timeout": {"type": "integer"}}, ["target"]),
        _check_mtls,
    ),
    ToolSpec(
        "detect_l7",
        "Detect the L7/WAF/CDN protection in front of a target host (Cloudflare, Akamai, etc.).",
        _schema(
            {"host": {"type": "string"}, "port": {"type": "integer"}, "path": {"type": "string"},
             "timeout": {"type": "number"}},
            ["host"],
        ),
        _detect_l7,
    ),
    ToolSpec(
        "scan_ports",
        "Scan a host's common TCP ports to discover open services.",
        _schema({"host": {"type": "string"}, "timeout": {"type": "number"}}, ["host"]),
        _scan_ports,
    ),
]

_ATTACK_TARGET_MODE = _schema(
    {"target": {"type": "string"}, "mode": {"type": "string", "enum": ["safe", "deep"]}, "timeout": {"type": "number"}},
    ["target"],
)

ATTACKER_TOOLS: list[ToolSpec] = [
    ToolSpec("attack_a2a", "Actively attack an A2A agent endpoint (auth bypass, injection probes).", _ATTACK_TARGET_MODE, _attack_a2a, requires_authorization=True),
    ToolSpec(
        "attack_auth",
        "Actively attack an OIDC/OAuth2/SAML auth endpoint.",
        _schema(
            {"target": {"type": "string"}, "mode": {"type": "string", "enum": ["safe", "deep"]},
             "protocol": {"type": "string", "enum": ["auto", "oidc", "oauth2", "saml"]}, "timeout": {"type": "number"}},
            ["target"],
        ),
        _attack_auth,
        requires_authorization=True,
    ),
    ToolSpec(
        "attack_blockchain",
        "Actively attack a blockchain JSON-RPC node (admin/debug/txpool probes).",
        _schema(
            {"target": {"type": "string"}, "port": {"type": "integer"}, "mode": {"type": "string", "enum": ["safe", "deep"]},
             "timeout": {"type": "number"}},
            ["target"],
        ),
        _attack_blockchain,
        requires_authorization=True,
    ),
    ToolSpec("attack_k8s", "Actively attack exposed Kubernetes cluster components.", _ATTACK_TARGET_MODE, _attack_k8s, requires_authorization=True),
    ToolSpec(
        "attack_mcp",
        "Actively attack an MCP server endpoint (auth bypass, tool/command injection).",
        _schema(
            {"target": {"type": "string"}, "transport": {"type": "string", "enum": ["http", "sse", "stdio"]},
             "mode": {"type": "string", "enum": ["safe", "deep"]}, "timeout": {"type": "number"}},
            ["target"],
        ),
        _attack_mcp,
        requires_authorization=True,
    ),
    ToolSpec(
        "attack_openclaw",
        "Actively attack an OpenClaw AI gateway (SSRF, message/DM injection, WebSocket upgrade).",
        _schema(
            {"target": {"type": "string"}, "port": {"type": "integer"}, "mode": {"type": "string", "enum": ["safe", "deep"]},
             "timeout": {"type": "number"}, "use_tls": {"type": "boolean"}},
            ["target"],
        ),
        _attack_openclaw,
        requires_authorization=True,
    ),
    ToolSpec(
        "attack_postman",
        "Actively attack every endpoint defined in a Postman Collection JSON export.",
        _schema(
            {"collection_path": {"type": "string"}, "environment_path": {"type": "string"},
             "target_override": {"type": "string"}, "mode": {"type": "string", "enum": ["safe", "deep"]}},
            ["collection_path"],
        ),
        _attack_postman,
        requires_authorization=True,
    ),
    ToolSpec(
        "guardrail_bench",
        "Benchmark an LLM endpoint's content-filter/guardrail refusal rate against harmful probes.",
        _schema(
            {"endpoint": {"type": "string"}, "api_key": {"type": "string"}, "timeout": {"type": "number"}},
            ["endpoint"],
        ),
        _guardrail_bench,
        requires_authorization=True,
    ),
    ToolSpec(
        "llm_conversation_attack",
        "Run a multi-turn jailbreak attack (crescendo/many-shot/context-priming/goal-hijack) against an LLM endpoint.",
        _schema(
            {"endpoint": {"type": "string"}, "payload": {"type": "string", "description": "Harmful request to embed"},
             "api_key": {"type": "string"}, "mode": {"type": "string", "enum": ["safe", "deep"]},
             "timeout": {"type": "number"}},
            ["endpoint", "payload"],
        ),
        _llm_conversation_attack,
        requires_authorization=True,
    ),
]

ALL_TOOLS: list[ToolSpec] = SCANNER_TOOLS + ATTACKER_TOOLS
