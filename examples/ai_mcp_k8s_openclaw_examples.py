"""
Examples: AI/LLM OWASP, MCP, Kubernetes, and OpenClaw scanning and attacks.

These examples demonstrate the core security assessment capabilities of offensive-ai
for AI/LLM endpoints, MCP servers, Kubernetes clusters, and OpenClaw gateways.

WARNING: Attack examples (MCPAttacker, K8sAttacker, OpenClawAttacker) require
explicit written authorization from the system owner. Unauthorized use is illegal.

Run a specific example:
    python examples/ai_mcp_k8s_openclaw_examples.py
"""

from __future__ import annotations

import asyncio
import json
import logging

logging.basicConfig(level=logging.WARNING)

# ---------------------------------------------------------------------------
# AI / LLM OWASP Top 10 (2025) Examples
# ---------------------------------------------------------------------------


async def llm_owasp_safe_scan():
    """
    Basic LLM OWASP scan in safe mode against an OpenAI-compatible endpoint.

    Safe mode tests LLM02 (Insecure Output Handling), LLM07 (System Prompt
    Leakage), and LLM09 (Misinformation) — low-risk probes only.
    """
    from offensive_ai.core.ai_owasp_scanner import LLMOwaspScanner

    scanner = LLMOwaspScanner(
        endpoint="https://api.example.com/v1/chat/completions",
        mode="safe",
        api_format="openai",
        headers={"Authorization": "Bearer sk-your-api-key-here"},
        timeout=30.0,
    )
    result = await scanner.scan()

    print(f"Target: {result.endpoint}")
    print(f"Mode:   {result.mode}")
    print(f"Score:  {result.overall_score:.1f}/10  ({result.risk_level})")
    print(f"Scan duration: {result.scan_duration:.2f}s")
    print()

    for cat in result.categories:
        status = "PASS" if cat.passed else "FAIL"
        print(f"  [{status}] {cat.category_id}: {cat.category_name}  score={cat.score:.1f}")
        for finding in cat.findings:
            print(f"         {finding.severity.value.upper():8s}  {finding.title}")

    return result


async def llm_owasp_deep_scan():
    """
    Deep LLM OWASP scan covering the full OWASP LLM Top 10 suite.

    Deep mode adds: LLM01 (Prompt Injection), LLM05 (Insecure Plugin Design),
    LLM06 (Excessive Agency), LLM10 (Unbounded Consumption).
    """
    from offensive_ai.core.ai_owasp_scanner import LLMOwaspScanner

    scanner = LLMOwaspScanner(
        endpoint="https://api.example.com/v1/chat/completions",
        mode="deep",
        api_format="openai",
        headers={"Authorization": "Bearer sk-your-api-key-here"},
        timeout=45.0,
    )
    result = await scanner.scan()

    print(f"Deep scan complete — {len(result.categories)} categories evaluated")
    failed = [c for c in result.categories if not c.passed]
    print(f"Failed categories: {len(failed)}")
    for cat in failed:
        print(f"  {cat.category_id}: {cat.category_name}  ({len(cat.findings)} findings)")

    return result


async def llm_owasp_with_llm_judge():
    """
    LLM OWASP scan with an LLM judge for AI-assisted triage.

    The judge evaluates ambiguous findings and can promote LOW → MEDIUM
    when confidence > 0.7.
    """
    from offensive_ai.core.ai_owasp_scanner import LLMOwaspScanner
    from offensive_ai.core.llm_judge import LLMJudge

    judge = LLMJudge.from_env()
    if not judge.is_available():
        print("No LLM judge available — set OPENAI_API_KEY, ANTHROPIC_API_KEY, or GEMINI_API_KEY")
        return None

    scanner = LLMOwaspScanner(
        endpoint="https://api.example.com/v1/chat/completions",
        mode="deep",
        api_format="openai",
        headers={"Authorization": "Bearer sk-your-api-key-here"},
        judge=judge,
    )
    result = await scanner.scan()

    print(f"LLM-triaged scan — risk: {result.risk_level}  score: {result.overall_score:.1f}/10")
    for cat in result.categories:
        for finding in cat.findings:
            if finding.llm_reasoning:
                print(f"  [{finding.severity.value}] {finding.title}")
                print(f"    LLM ({finding.llm_confidence * 100:.0f}%): {finding.llm_reasoning}")

    return result


async def llm_owasp_batch_scan():
    """
    Batch scan multiple LLM endpoints in parallel.

    Useful for scanning multiple model deployments or API gateways at once.
    """
    from offensive_ai.core.ai_owasp_scanner import LLMOwaspScanner

    endpoints = [
        "https://api.example.com/v1/chat/completions",
        "https://api.staging.example.com/v1/chat/completions",
        "https://internal-llm.corp.example.com/v1/chat/completions",
    ]
    headers = {"Authorization": "Bearer sk-your-api-key-here"}

    scanners = [
        LLMOwaspScanner(endpoint=ep, mode="safe", api_format="openai", headers=headers)
        for ep in endpoints
    ]

    results = await asyncio.gather(*[s.scan() for s in scanners], return_exceptions=True)

    for ep, result in zip(endpoints, results):
        if isinstance(result, Exception):
            print(f"  ERROR  {ep}: {result}")
        else:
            print(f"  {result.risk_level:8s}  score={result.overall_score:.1f}  {ep}")

    return results


async def llm_owasp_custom_categories():
    """
    Scan only specific OWASP LLM categories — e.g. focus on prompt injection
    and excessive agency for a production deployment review.
    """
    from offensive_ai.core.ai_owasp_scanner import LLMOwaspScanner

    scanner = LLMOwaspScanner(
        endpoint="https://api.example.com/v1/chat/completions",
        mode="safe",
        categories=["LLM01", "LLM06"],  # Prompt Injection, Excessive Agency
        api_format="openai",
        headers={"Authorization": "Bearer sk-your-api-key-here"},
    )
    result = await scanner.scan()

    print("Focused scan results:")
    for cat in result.categories:
        print(f"  {cat.category_id}: {cat.category_name} — {'PASS' if cat.passed else 'FAIL'}")

    return result


async def llm_owasp_export_json():
    """
    Run a scan and export the full result as JSON for pipeline integration.
    """
    from offensive_ai.core.ai_owasp_scanner import LLMOwaspScanner

    scanner = LLMOwaspScanner(
        endpoint="https://api.example.com/v1/chat/completions",
        mode="safe",
        api_format="openai",
        headers={"Authorization": "Bearer sk-your-api-key-here"},
    )
    result = await scanner.scan()

    output = result.model_dump(mode="json")
    print(json.dumps(output, indent=2, default=str))
    return result


# ---------------------------------------------------------------------------
# MCP Scanner Examples
# ---------------------------------------------------------------------------


async def mcp_basic_scan():
    """
    Basic MCP (Model Context Protocol) server security scan via HTTP.

    Enumerates tools, resources, and prompts; checks authentication posture;
    and matches findings against known CVEs and misconfigurations.
    """
    from offensive_ai.core.mcp_scanner import MCPScanner

    scanner = MCPScanner(
        target="http://localhost:6277/mcp",
        transport="http",
        timeout=15.0,
    )
    result = await scanner.scan()

    print(f"Target: {result.target}")
    print(f"Transport: {result.transport.value}")
    print(f"Auth posture: {result.auth_posture.value}")
    print(f"Tools: {len(result.tools)}  Resources: {len(result.resources)}  Prompts: {len(result.prompts)}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")
    print()

    for tool in result.tools:
        print(f"  Tool: {tool.name}")
        if tool.description:
            print(f"         {tool.description[:80]}")

    print()
    for vuln in result.vulnerabilities:
        print(f"  [{vuln.severity.value.upper():8s}] {vuln.title}")
        if vuln.cve_id:
            print(f"             CVE: {vuln.cve_id}")

    return result


async def mcp_scan_with_auth():
    """
    Scan an authenticated MCP server (bearer token or API key).
    """
    from offensive_ai.core.mcp_scanner import MCPScanner

    scanner = MCPScanner(
        target="https://mcp.example.com/mcp",
        transport="http",
        headers={"Authorization": "Bearer mcp-token-here"},
        timeout=20.0,
    )
    result = await scanner.scan()

    print(f"Authenticated scan — server: {result.server_info.name if result.server_info else 'unknown'}")
    print(f"Auth posture: {result.auth_posture.value}")
    print(f"CVEs matched: {sum(1 for v in result.vulnerabilities if v.cve_id)}")

    return result


async def mcp_scan_with_judge():
    """
    MCP scan with LLM judge for AI-assisted vulnerability triage.
    """
    from offensive_ai.core.mcp_scanner import MCPScanner
    from offensive_ai.core.llm_judge import LLMJudge

    judge = LLMJudge.from_env()
    if not judge.is_available():
        print("No LLM judge configured.")
        return None

    scanner = MCPScanner(
        target="http://localhost:6277/mcp",
        transport="http",
        judge=judge,
    )
    result = await scanner.scan()

    print(f"LLM-triaged MCP scan — {len(result.vulnerabilities)} vulnerabilities")
    for vuln in result.vulnerabilities:
        print(f"  [{vuln.severity.value}] {vuln.title}")

    return result


async def mcp_scan_stdio():
    """
    Scan a local MCP server running over stdio (e.g. a Python MCP server).

    The `cmd` argument is the command used to launch the server process.
    """
    from offensive_ai.core.mcp_scanner import MCPScanner

    scanner = MCPScanner(
        target="stdio://localhost",
        transport="stdio",
        cmd=["python", "-m", "my_mcp_server", "--port", "0"],
        timeout=10.0,
    )
    result = await scanner.scan()

    print(f"stdio scan complete — tools: {len(result.tools)}")
    return result


async def mcp_attack_authorized():
    """
    Active MCP attack for authorized red-team engagements.

    Requires explicit written authorization from the system owner.
    Tests: auth bypass, path traversal, tool injection, command injection,
    prompt injection.
    """
    from offensive_ai.core.mcp_attacker import MCPAttacker

    # authorized=True asserts you have explicit written authorization
    attacker = MCPAttacker(authorized=True)

    report = await attacker.attack(
        target="http://localhost:6277/mcp",
        transport="http",
        mode="safe",   # "safe" = non-destructive probes; "deep" = full suite
        headers={},
        timeout=15.0,
    )

    print(f"MCP Attack Report — target: {report.target}")
    print(f"Attacks run: {report.attacks_run}  Triggered: {report.attacks_triggered}")
    print(f"Duration: {report.scan_duration:.2f}s")
    print()

    triggered = [r for r in report.results if r.triggered]
    for result in triggered:
        print(f"  [TRIGGERED] [{result.severity.value.upper():8s}] {result.title}")
        print(f"               {result.description}")
        if result.evidence:
            print(f"               Evidence: {result.evidence[:120]}")

    return report


async def mcp_scan_then_attack():
    """
    Scan first, then use the scan result to guide a targeted attack.

    The scan result provides tool/resource context to the attacker for
    more focused attack payload selection.
    """
    from offensive_ai.core.mcp_scanner import MCPScanner
    from offensive_ai.core.mcp_attacker import MCPAttacker

    target = "http://localhost:6277/mcp"

    # Phase 1: passive reconnaissance
    scanner = MCPScanner(target=target, transport="http")
    scan_result = await scanner.scan()
    print(f"Scan: {len(scan_result.tools)} tools, {len(scan_result.vulnerabilities)} findings")

    # Phase 2: targeted attack using scan intelligence
    attacker = MCPAttacker(authorized=True)
    report = await attacker.attack(
        target=target,
        transport="http",
        mode="deep",
        scan_result=scan_result,  # feeds tool names into attack payloads
    )
    print(f"Attack: {report.attacks_triggered}/{report.attacks_run} triggered")

    return scan_result, report


# ---------------------------------------------------------------------------
# Kubernetes Examples
# ---------------------------------------------------------------------------


async def k8s_basic_scan():
    """
    Basic Kubernetes cluster security scan.

    Probes all default K8s ports: API server (6443/8080), kubelet (10250/10255),
    etcd (2379), scheduler (10259), controller-manager (10257), dashboard (8443).
    """
    from offensive_ai.core.k8s_scanner import K8sScanner

    scanner = K8sScanner("192.168.1.100")
    result = await scanner.scan()

    print(f"Cluster: {result.target}")
    print(f"Risk level: {result.risk_level}  Score: {result.risk_score:.1f}/10")
    print(f"Exposed components: {len(result.exposed_components)}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")
    print()

    for comp in result.exposed_components:
        print(f"  {comp.component.value:25s}  port={comp.port}  anon={comp.anonymous_access}")
    print()

    for vuln in result.vulnerabilities:
        cve = f"  [{vuln.cve_id}]" if vuln.cve_id else ""
        print(f"  [{vuln.severity.value.upper():8s}] {vuln.title}{cve}")

    return result


async def k8s_custom_ports_scan():
    """
    Scan a Kubernetes cluster with custom port ranges (e.g. non-standard setup).
    """
    from offensive_ai.core.k8s_scanner import K8sScanner

    scanner = K8sScanner(
        target="k8s.internal.example.com",
        ports=[6443, 10250, 2379, 8443, 30000],  # explicit port list
        timeout=10.0,
    )
    result = await scanner.scan()

    print(f"Custom port scan — {len(result.exposed_components)} components exposed")
    return result


async def k8s_scan_with_judge():
    """
    Kubernetes scan with LLM judge for AI-assisted triage and remediation.
    """
    from offensive_ai.core.k8s_scanner import K8sScanner
    from offensive_ai.core.llm_judge import LLMJudge

    judge = LLMJudge.from_env()
    if not judge.is_available():
        print("No LLM judge configured.")
        return None

    scanner = K8sScanner(
        target="192.168.1.100",
        judge=judge,
    )
    result = await scanner.scan()

    print(f"K8s scan (LLM triaged) — {result.risk_level}  {len(result.vulnerabilities)} vulns")
    for vuln in result.vulnerabilities:
        if getattr(vuln, "llm_reasoning", None):
            print(f"  LLM: {vuln.llm_reasoning[:100]}")

    return result


async def k8s_attack_authorized():
    """
    Active Kubernetes cluster attack for authorized red-team engagements.

    Safe mode: anonymous API read probes, kubelet /pods, RBAC reviews, etcd health.
    Deep mode: kubelet /exec RCE, Secret extraction, etcd key dump, cloud SSRF (K08).

    Requires explicit written authorization from the cluster owner.
    """
    from offensive_ai.core.k8s_attacker import K8sAttacker

    attacker = K8sAttacker(authorized=True)

    report = await attacker.attack(
        target="192.168.1.100",
        mode="safe",   # use "deep" for full destructive test suite
        timeout=20.0,
    )

    print(f"K8s Attack Report — {report.attacks_triggered}/{report.attacks_run} triggered")
    print(f"Duration: {report.scan_duration:.2f}s")

    triggered = [r for r in report.results if r.triggered]
    for result in triggered:
        print(f"  [TRIGGERED] [{result.severity.value.upper():8s}] {result.title}")
        if result.evidence:
            preview = result.evidence[:150].replace("\n", " ")
            print(f"               Evidence: {preview}")

    return report


async def k8s_scan_then_attack():
    """
    Reconnaissance scan followed by a targeted Kubernetes attack.
    """
    from offensive_ai.core.k8s_scanner import K8sScanner
    from offensive_ai.core.k8s_attacker import K8sAttacker

    target = "192.168.1.100"

    scan = await K8sScanner(target).scan()
    print(f"Scan: {len(scan.exposed_components)} exposed components, risk={scan.risk_level}")

    attacker = K8sAttacker(authorized=True)
    report = await attacker.attack(target=target, mode="deep", scan_result=scan)
    print(f"Attack: {report.attacks_triggered}/{report.attacks_run} triggered")

    return scan, report


async def k8s_batch_scan():
    """
    Scan multiple Kubernetes nodes or clusters in parallel.
    """
    from offensive_ai.core.k8s_scanner import K8sScanner

    targets = [
        "192.168.1.100",
        "192.168.1.101",
        "10.0.0.50",
    ]

    results = await asyncio.gather(
        *[K8sScanner(t).scan() for t in targets],
        return_exceptions=True,
    )

    for target, result in zip(targets, results):
        if isinstance(result, Exception):
            print(f"  ERROR  {target}: {result}")
        else:
            print(f"  {result.risk_level:8s}  score={result.risk_score:.1f}  {target}")

    return results


# ---------------------------------------------------------------------------
# OpenClaw Examples
# ---------------------------------------------------------------------------


async def openclaw_basic_scan():
    """
    Basic OpenClaw gateway security scan.

    Fingerprints the instance, enumerates accessible API endpoints, checks
    DM (Direct Message) policy, sandbox mode, and authentication posture.
    """
    from offensive_ai.core.openclaw_scanner import OpenClawScanner

    scanner = OpenClawScanner(
        target="192.168.1.50",
        port=18789,
        timeout=15.0,
    )
    result = await scanner.scan()

    print(f"Target: {result.target}:{result.port}")
    print(f"Auth posture: {result.auth_posture.value}")
    print(f"DM policy: {result.dm_policy.value}")
    print(f"Sandbox: {result.sandbox_info.enabled if result.sandbox_info else 'unknown'}")
    print(f"Accessible endpoints: {len(result.accessible_endpoints)}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")
    print()

    for ep in result.accessible_endpoints:
        print(f"  {ep.method:6s} {ep.path}  (status {ep.status_code})")
    print()

    for vuln in result.vulnerabilities:
        cve = f"  [{vuln.cve_id}]" if vuln.cve_id else ""
        print(f"  [{vuln.severity.value.upper():8s}] {vuln.title}{cve}")

    return result


async def openclaw_tls_scan():
    """
    Scan an OpenClaw gateway running HTTPS.
    """
    from offensive_ai.core.openclaw_scanner import OpenClawScanner

    scanner = OpenClawScanner(
        target="openclaw.example.com",
        port=18789,
        use_tls=True,
        timeout=20.0,
    )
    result = await scanner.scan()

    print(f"TLS scan — auth: {result.auth_posture.value}  vulns: {len(result.vulnerabilities)}")
    return result


async def openclaw_authenticated_scan():
    """
    Scan an OpenClaw gateway that requires an API token.
    """
    from offensive_ai.core.openclaw_scanner import OpenClawScanner

    scanner = OpenClawScanner(
        target="openclaw.example.com",
        port=18789,
        headers={"Authorization": "Bearer oc-your-token-here"},
        use_tls=True,
    )
    result = await scanner.scan()

    print(f"Authenticated scan — DM policy: {result.dm_policy.value}")
    return result


async def openclaw_scan_with_judge():
    """
    OpenClaw scan with LLM judge triage.
    """
    from offensive_ai.core.openclaw_scanner import OpenClawScanner
    from offensive_ai.core.llm_judge import LLMJudge

    judge = LLMJudge.from_env()
    if not judge.is_available():
        print("No LLM judge configured.")
        return None

    scanner = OpenClawScanner(
        target="192.168.1.50",
        port=18789,
        judge=judge,
    )
    result = await scanner.scan()

    print(f"OpenClaw (LLM triaged) — {len(result.vulnerabilities)} vulnerabilities")
    return result


async def openclaw_attack_authorized():
    """
    Active OpenClaw gateway attack for authorized red-team engagements.

    Tests: API auth bypass, DM prompt injection, message injection,
    SSRF via webhook callbacks, WebSocket probes.

    Requires explicit written authorization from the system owner.
    """
    from offensive_ai.core.openclaw_attacker import OpenClawAttacker

    attacker = OpenClawAttacker(authorized=True)

    report = await attacker.attack(
        target="192.168.1.50",
        port=18789,
        mode="safe",   # "deep" for full injection and SSRF suite
        timeout=15.0,
    )

    print(f"OpenClaw Attack Report — {report.attacks_triggered}/{report.attacks_run} triggered")
    print(f"Duration: {report.scan_duration:.2f}s")

    triggered = [r for r in report.results if r.triggered]
    for result in triggered:
        print(f"  [TRIGGERED] [{result.severity.value.upper():8s}] {result.title}")
        if result.evidence:
            preview = result.evidence[:150].replace("\n", " ")
            print(f"               Evidence: {preview}")

    return report


async def openclaw_scan_then_attack():
    """
    Reconnaissance scan followed by a targeted OpenClaw attack.
    """
    from offensive_ai.core.openclaw_scanner import OpenClawScanner
    from offensive_ai.core.openclaw_attacker import OpenClawAttacker

    target = "192.168.1.50"
    port = 18789

    scan = await OpenClawScanner(target=target, port=port).scan()
    print(f"Scan: {len(scan.accessible_endpoints)} endpoints, {len(scan.vulnerabilities)} vulns, auth={scan.auth_posture.value}")

    attacker = OpenClawAttacker(authorized=True)
    report = await attacker.attack(
        target=target,
        port=port,
        mode="deep",
        scan_result=scan,
    )
    print(f"Attack: {report.attacks_triggered}/{report.attacks_run} triggered")

    return scan, report


# ---------------------------------------------------------------------------
# Combined pipeline: AI + MCP + K8s + OpenClaw
# ---------------------------------------------------------------------------


async def full_ai_infrastructure_assessment():
    """
    End-to-end AI infrastructure security assessment covering all four surfaces:
    LLM endpoint, MCP server, Kubernetes cluster, and OpenClaw gateway.

    Designed for teams running a full AI stack in a test environment.
    """
    from offensive_ai.core.ai_owasp_scanner import LLMOwaspScanner
    from offensive_ai.core.mcp_scanner import MCPScanner
    from offensive_ai.core.k8s_scanner import K8sScanner
    from offensive_ai.core.openclaw_scanner import OpenClawScanner
    from offensive_ai.core.llm_judge import LLMJudge

    judge = LLMJudge.from_env() if LLMJudge.from_env().is_available() else None
    judge_label = judge.provider if judge else "disabled"
    print(f"LLM Judge: {judge_label}")
    print()

    # Run all four scans in parallel
    llm_scan, mcp_scan, k8s_scan, oc_scan = await asyncio.gather(
        LLMOwaspScanner(
            endpoint="https://api.example.com/v1/chat/completions",
            mode="safe",
            api_format="openai",
            headers={"Authorization": "Bearer sk-your-key"},
            judge=judge,
        ).scan(),
        MCPScanner("http://localhost:6277/mcp", judge=judge).scan(),
        K8sScanner("192.168.1.100", judge=judge).scan(),
        OpenClawScanner("192.168.1.50", port=18789, judge=judge).scan(),
        return_exceptions=True,
    )

    print("=" * 60)
    print("AI Infrastructure Assessment Summary")
    print("=" * 60)

    surfaces = [
        ("LLM OWASP",  llm_scan,  "overall_score", "risk_level"),
        ("MCP Server",  mcp_scan,  None,            None),
        ("Kubernetes",  k8s_scan,  "risk_score",    "risk_level"),
        ("OpenClaw",    oc_scan,   None,            None),
    ]

    for label, result, score_attr, level_attr in surfaces:
        if isinstance(result, Exception):
            print(f"  {label:12s}  ERROR: {result}")
        else:
            vuln_count = len(result.vulnerabilities) if hasattr(result, "vulnerabilities") else "n/a"
            score = f"{getattr(result, score_attr, 0):.1f}/10" if score_attr and not isinstance(result, Exception) else ""
            level = getattr(result, level_attr, "") if level_attr and not isinstance(result, Exception) else ""
            print(f"  {label:12s}  {level:8s}  {score:8s}  vulns={vuln_count}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main():
    print("offensive-ai: AI / MCP / Kubernetes / OpenClaw Examples")
    print("=" * 60)
    print()
    print("These examples require real target endpoints.")
    print("Replace placeholder hostnames/IPs/tokens before running.")
    print()
    print("Available example functions:")
    examples = [
        ("AI/LLM OWASP", [
            "llm_owasp_safe_scan",
            "llm_owasp_deep_scan",
            "llm_owasp_with_llm_judge",
            "llm_owasp_batch_scan",
            "llm_owasp_custom_categories",
            "llm_owasp_export_json",
        ]),
        ("MCP", [
            "mcp_basic_scan",
            "mcp_scan_with_auth",
            "mcp_scan_with_judge",
            "mcp_scan_stdio",
            "mcp_attack_authorized",
            "mcp_scan_then_attack",
        ]),
        ("Kubernetes", [
            "k8s_basic_scan",
            "k8s_custom_ports_scan",
            "k8s_scan_with_judge",
            "k8s_attack_authorized",
            "k8s_scan_then_attack",
            "k8s_batch_scan",
        ]),
        ("OpenClaw", [
            "openclaw_basic_scan",
            "openclaw_tls_scan",
            "openclaw_authenticated_scan",
            "openclaw_scan_with_judge",
            "openclaw_attack_authorized",
            "openclaw_scan_then_attack",
        ]),
        ("Combined", [
            "full_ai_infrastructure_assessment",
        ]),
    ]
    for section, funcs in examples:
        print(f"\n  {section}:")
        for fn in funcs:
            print(f"    {fn}()")


if __name__ == "__main__":
    asyncio.run(main())
