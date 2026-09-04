"""Authorization banner factory shared by all attacker modules."""

from __future__ import annotations

_INNER_WIDTH = 70  # chars between the two ║ borders


def make_authorization_banner(module_name: str) -> str:
    """Return a formatted authorization warning banner for *module_name*."""
    header = f"\u26a0  OAI-AI {module_name.upper()} ATTACK MODULE \u26a0"
    return (
        "\n"
        "\u2554" + "\u2550" * _INNER_WIDTH + "\u2557\n"
        f"\u2551{header.center(_INNER_WIDTH)}\u2551\n"
        f"\u2551{' ' * _INNER_WIDTH}\u2551\n"
        "\u2551  You have declared that you have EXPLICIT WRITTEN AUTHORIZATION"
        "      \u2551\n"
        "\u2551  to perform active security testing against this target."
        "             \u2551\n"
        f"\u2551{' ' * _INNER_WIDTH}\u2551\n"
        "\u2551  Unauthorized use of this module is illegal and unethical."
        "           \u2551\n"
        "\u2551  The authors assume no liability for unauthorized use."
        "               \u2551\n"
        "\u255a" + "\u2550" * _INNER_WIDTH + "\u255d\n"
    )
