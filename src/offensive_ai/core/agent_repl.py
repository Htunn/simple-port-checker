"""
``prompt_toolkit``-based REPL front-end for ``AgentSession``.

Thin I/O layer only — all reasoning and tool dispatch lives in
``AgentSession``; this module just wires up input history, slash-commands,
and the rich-based y/N confirmation UI for attack tools.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.prompt import Confirm

from .agent_session import AgentSession
from .agent_tools import ATTACKER_TOOLS, SCANNER_TOOLS

_HISTORY_FILE = Path.home() / ".offensive_ai_agent_history"

_HELP_TEXT = """[bold]Slash commands[/bold]
  /help     Show this help text
  /tools    List available tools
  /history  Show conversation turn count
  /clear    Clear conversation history
  /exit     Quit the agent"""


def _make_confirm_callback(console: Console) -> Callable[[str, dict[str, Any]], Awaitable[bool]]:
    async def _confirm(name: str, arguments: dict[str, Any]) -> bool:
        console.print(
            f"[yellow]Agent wants to run attack tool[/yellow] [bold]{escape(name)}[/bold]({escape(str(arguments))})"
        )
        return Confirm.ask("Proceed?", default=False)

    return _confirm


async def run(session: AgentSession, authorized: bool) -> None:
    """Run the interactive agent REPL until the user exits."""
    try:
        from prompt_toolkit import PromptSession  # type: ignore[import-not-found]
        from prompt_toolkit.history import FileHistory  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ImportError(
            "The agent REPL requires 'prompt_toolkit'. Install with: pip install offensive-ai[agent]"
        ) from exc

    console = Console()
    session.confirm_callback = _make_confirm_callback(console)
    prompt_session: PromptSession[str] = PromptSession(history=FileHistory(str(_HISTORY_FILE)))

    console.print("[bold red]offensive-ai agent[/bold red] — type /help for commands, /exit to quit.")
    if authorized:
        console.print("[yellow]Attack tools enabled for this session — each call still requires confirmation.[/yellow]")
    else:
        console.print("[dim]Attack tools disabled — restart with --i-have-authorization to enable them.[/dim]")

    while True:
        try:
            user_input = await prompt_session.prompt_async("agent> ")
        except (EOFError, KeyboardInterrupt):
            break

        text = user_input.strip()
        if not text:
            continue
        if text in ("/exit", "/quit"):
            break
        if text == "/help":
            console.print(_HELP_TEXT)
            continue
        if text == "/tools":
            for tool in SCANNER_TOOLS + ATTACKER_TOOLS:
                tag = "[red]attack[/red]" if tool.requires_authorization else "[green]scan[/green]"
                console.print(f"  {tag} [bold]{escape(tool.name)}[/bold] — {escape(tool.description)}")
            continue
        if text == "/history":
            console.print(f"{len(session.messages)} messages in history.")
            continue
        if text == "/clear":
            session.clear()
            console.print("History cleared.")
            continue

        try:
            with console.status("[bold green]thinking..."):
                reply = await session.step(text)
        except Exception as exc:
            console.print(f"[red]Error:[/red] {escape(str(exc))}")
            continue
        console.print(escape(reply))
