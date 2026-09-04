"""
Examples: Blockchain JSON-RPC node security scanning, attacking, and smart
contract static analysis.

WARNING: BlockchainAttacker examples require explicit written authorization
from the node owner. Every payload used here is engineered to be
non-destructive (see BlockchainAttacker's module docstring), but running
active tests against systems you do not own or have authorization to test
is illegal.

Run:
    python examples/blockchain_scan_example.py
"""

from __future__ import annotations

import asyncio
import json
import logging

logging.basicConfig(level=logging.WARNING)


async def blockchain_passive_scan():
    """Passive recon: fingerprint client/chain and check exposed RPC namespaces."""
    from offsec_ai.core.blockchain_scanner import BlockchainScanner

    scanner = BlockchainScanner(
        target="node.example.com",
        port=8545,
        timeout=15.0,
    )
    result = await scanner.scan()

    print(f"Target:      {result.target}:{result.port}")
    if result.error:
        print(f"Error:       {result.error}")
        return result

    print(f"Client:      {result.node_info.client_version or '—'}")
    print(f"Chain:       {result.node_info.chain_type.value}  (id={result.node_info.chain_id})")
    print(f"Admin API:   {'EXPOSED' if result.admin_api_exposed else 'not exposed'}")
    print(f"Debug API:   {'EXPOSED' if result.debug_api_exposed else 'not exposed'}")
    print(f"Wallets:     {result.wallet_addresses or 'none disclosed'}")
    print(f"Duration:    {result.scan_duration:.2f}s")
    print()

    for vuln in result.all_vulns:
        print(f"  [{vuln.severity.value.upper():8s}] {vuln.vuln_id}: {vuln.title}")

    return result


async def blockchain_scan_with_llm_judge():
    """Passive scan with LLM judge enrichment of ambiguous findings."""
    from offsec_ai.core.blockchain_scanner import BlockchainScanner
    from offsec_ai.core.llm_judge import LLMJudge

    judge = LLMJudge.from_env()
    if not judge.is_available():
        print("No LLM provider configured (set OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY).")
        return None

    scanner = BlockchainScanner(target="node.example.com", port=8545, judge=judge)
    result = await scanner.scan()
    for vuln in result.vulnerabilities:
        if vuln.llm_reasoning:
            print(f"  {vuln.vuln_id}: LLM ({vuln.llm_confidence:.0%}) {vuln.llm_reasoning}")
    return result


async def blockchain_authorized_attack():
    """
    Authorized active testing (safe mode): read-only admin/peer exposure probes.

    Requires authorized=True — only run against nodes you own or have
    explicit written authorization to test.
    """
    from offsec_ai.core.blockchain_attacker import BlockchainAttacker

    attacker = BlockchainAttacker(authorized=True)
    report = await attacker.attack(target="node.example.com", port=8545, mode="safe")

    print(f"Attacks run:      {report.attacks_run}")
    print(f"Attacks triggered: {report.attacks_triggered}")
    for r in report.successful_attacks:
        print(f"  [{r.severity.value.upper()}] {r.attack_id} ({r.attack_type}): {r.title}")

    return report


async def blockchain_authorized_attack_deep():
    """
    Deep mode: adds debug/txpool leak checks and unrestricted signing tests.

    All payloads are non-destructive — see BlockchainAttacker's docstring.
    """
    from offsec_ai.core.blockchain_scanner import BlockchainScanner
    from offsec_ai.core.blockchain_attacker import BlockchainAttacker

    scan_result = await BlockchainScanner(target="node.example.com", port=8545).scan()

    attacker = BlockchainAttacker(authorized=True)
    report = await attacker.attack(
        target="node.example.com", port=8545, mode="deep", scan_result=scan_result,
    )

    print(json.dumps(report.model_dump(mode="json"), indent=2, default=str))
    return report


def smart_contract_audit_example():
    """Offline heuristic static analysis of a contract ABI and bytecode."""
    from offsec_ai.core.blockchain_scanner import analyze_contract

    abi = [
        {"type": "function", "name": "withdraw", "inputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "kill", "inputs": [], "stateMutability": "nonpayable"},
    ]
    # A tiny illustrative bytecode fragment: PUSH1 0x00, SELFDESTRUCT
    bytecode = "0x6000ff"

    result = analyze_contract(abi=abi, bytecode=bytecode, target="MyToken.sol")

    print(f"Findings:   {len(result.findings)}")
    print(f"Risk score: {result.risk_score:.0f}")
    for finding in result.findings:
        print(f"  [{finding.severity.value.upper()}] {finding.finding_id}: {finding.title}")

    return result


async def main():
    """List available examples (does not run them — they need a real target)."""
    examples = {
        "Blockchain Scanner": [
            blockchain_passive_scan.__name__,
            blockchain_scan_with_llm_judge.__name__,
        ],
        "Blockchain Attacker (requires authorization)": [
            blockchain_authorized_attack.__name__,
            blockchain_authorized_attack_deep.__name__,
        ],
        "Smart Contract Static Analysis (offline, no target needed)": [
            smart_contract_audit_example.__name__,
        ],
    }
    print("Available examples (edit this file to call them against a real target):\n")
    for section, funcs in examples.items():
        print(f"  {section}:")
        for fn in funcs:
            print(f"    {fn}()")

    # The contract audit example needs no network target, so it's safe to run directly:
    print("\n--- Running smart_contract_audit_example() ---\n")
    smart_contract_audit_example()


if __name__ == "__main__":
    asyncio.run(main())
