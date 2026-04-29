"""
main.py
=======
Interactive CLI entry point for the HAYO AI Coding Agent.

Provides a beautiful Rich terminal UI that shows the agent's internal state
in real time:  which node is active, tool calls being made, terminal output,
and the final result.

Usage
-----
    export ANTHROPIC_API_KEY="sk-ant-..."
    python main.py --working-dir /path/to/project

Press Ctrl+C to exit cleanly.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from rich import box
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Rich theme & console
# ---------------------------------------------------------------------------

HAYO_THEME = Theme(
    {
        "info":     "cyan",
        "success":  "bold green",
        "error":    "bold red",
        "warning":  "bold yellow",
        "planner":  "bold blue",
        "coder":    "bold magenta",
        "executor": "bold cyan",
        "reviewer": "bold yellow",
        "tool":     "dim cyan",
        "header":   "bold white on dark_blue",
        "muted":    "dim white",
    }
)

console = Console(theme=HAYO_THEME, highlight=True)

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = """
[bold blue]
██╗  ██╗ █████╗ ██╗   ██╗ ██████╗      █████╗ ██╗
██║  ██║██╔══██╗╚██╗ ██╔╝██╔═══██╗    ██╔══██╗██║
███████║███████║ ╚████╔╝ ██║   ██║    ███████║██║
██╔══██║██╔══██║  ╚██╔╝  ██║   ██║    ██╔══██║██║
██║  ██║██║  ██║   ██║   ╚██████╔╝    ██║  ██║██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝     ╚═╝  ╚═╝╚═╝
[/bold blue]
[muted]  Autonomous AI Coding Agent  •  Powered by Claude Sonnet 4.6[/muted]
"""

NODE_ICONS: Dict[str, str] = {
    "planner":  "📋",
    "coder":    "💻",
    "executor": "⚡",
    "reviewer": "🔍",
}

NODE_STYLES: Dict[str, str] = {
    "planner":  "planner",
    "coder":    "coder",
    "executor": "executor",
    "reviewer": "reviewer",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _api_key_check() -> None:
    """Abort with a helpful message if ANTHROPIC_API_KEY is not set."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        console.print(
            Panel(
                "[error]ANTHROPIC_API_KEY is not set.[/error]\n\n"
                "Export it before running:\n"
                "  [bold]export ANTHROPIC_API_KEY='sk-ant-...'[/bold]",
                title="Missing API Key",
                border_style="red",
            )
        )
        sys.exit(1)


def _make_initial_state(task: str, working_dir: str) -> Dict[str, Any]:
    """Return a fresh AgentState dict for a new task."""
    return {
        "messages": [HumanMessage(content=task)],
        "current_plan": [],
        "working_directory": working_dir,
        "terminal_outputs": [],
        "error_count": 0,
        "current_step": "start",
        "last_error": None,
        "final_answer": None,
        "task_complete": False,
    }


def _render_node_panel(node_name: str, content: str) -> Panel:
    """Render a Rich Panel for a node's output."""
    icon = NODE_ICONS.get(node_name, "🤖")
    style = NODE_STYLES.get(node_name, "info")
    return Panel(
        Markdown(content) if len(content) < 4000 else Text(content),
        title=f"[{style}]{icon}  {node_name.upper()}[/{style}]",
        border_style=style,
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _render_tool_call(tool_name: str, args: Dict[str, Any]) -> str:
    """Format a tool call for display."""
    args_display = ", ".join(
        f"{k}={str(v)[:60]!r}" for k, v in args.items()
    )
    return f"[tool]⚙  {tool_name}({args_display})[/tool]"


def _render_status_bar(step: str, error_count: int, plan_len: int) -> Table:
    """Small status table shown beneath each node panel."""
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column(style="muted")
    table.add_column(style="muted")
    table.add_column(style="muted")
    table.add_row(
        f"Step: [bold]{step}[/bold]",
        f"Errors: [{'error' if error_count > 0 else 'success'}]{error_count}[/{'error' if error_count > 0 else 'success'}]",
        f"Plan steps: {plan_len}",
    )
    return table


# ---------------------------------------------------------------------------
# Streaming event loop
# ---------------------------------------------------------------------------

def _stream_agent(
    task: str,
    working_dir: str,
    thread_id: str,
) -> None:
    """
    Stream the agent graph and render each event with Rich panels.

    Parameters
    ----------
    task : str
        The user's request.
    working_dir : str
        Absolute path to the project the agent may modify.
    thread_id : str
        Unique thread ID for state persistence.
    """
    # Import here to keep startup fast (these modules are heavy)
    from agent.graph import agent_graph, get_config

    initial_state = _make_initial_state(task, working_dir)
    config = get_config(thread_id)

    console.print(Rule("[muted]Agent starting[/muted]"))
    start_time = time.time()

    try:
        stream: Iterator[Dict[str, Any]] = agent_graph.stream(
            initial_state,
            config=config,
            stream_mode="updates",
        )

        current_error_count = 0
        current_plan_len = 0

        for event in stream:
            # Each event is a dict: {node_name: state_delta}
            for node_name, state_delta in event.items():
                if node_name == "__end__":
                    continue

                # Update running counters from state delta
                current_error_count = state_delta.get("error_count", current_error_count)
                plan = state_delta.get("current_plan", [])
                if plan:
                    current_plan_len = len(plan)

                # Render messages produced by this node
                messages = state_delta.get("messages", [])
                for msg in messages:
                    if isinstance(msg, AIMessage):
                        # Show tool calls inline before the text
                        if msg.tool_calls:
                            for tc in msg.tool_calls:
                                console.print(
                                    _render_tool_call(tc["name"], tc["args"])
                                )
                        if msg.content:
                            console.print(
                                _render_node_panel(node_name, str(msg.content))
                            )
                    elif isinstance(msg, ToolMessage):
                        # Collapse long tool output
                        content = str(msg.content)
                        if len(content) > 800:
                            content = content[:800] + "\n[dim]... (truncated)[/dim]"
                        console.print(
                            Panel(
                                Text(content, style="tool"),
                                title=f"[tool]⚙  Tool result: {msg.name}[/tool]",
                                border_style="dim cyan",
                                box=box.SIMPLE,
                                padding=(0, 1),
                            )
                        )

                # Render terminal outputs captured in this delta
                terminal_outputs = state_delta.get("terminal_outputs", [])
                if terminal_outputs:
                    latest = terminal_outputs[-1]
                    if len(latest) > 1200:
                        latest = latest[:1200] + "\n[dim]... (truncated)[/dim]"
                    console.print(
                        Panel(
                            Text(latest, style="dim"),
                            title="[executor]⚡  Terminal Output[/executor]",
                            border_style="dim",
                            box=box.SIMPLE,
                            padding=(0, 1),
                        )
                    )

                # Status bar
                console.print(
                    _render_status_bar(node_name, current_error_count, current_plan_len),
                    end="",
                )
                console.print()

    except KeyboardInterrupt:
        console.print("\n[warning]Interrupted by user.[/warning]")
        return

    elapsed = time.time() - start_time
    console.print(
        Rule(f"[muted]Completed in {elapsed:.1f}s[/muted]")
    )

    # Show final state
    try:
        final_state = agent_graph.get_state(config)
        if final_state and final_state.values:
            answer = final_state.values.get("final_answer")
            if answer:
                console.print(
                    Panel(
                        Markdown(answer),
                        title="[success]✅  Final Answer[/success]",
                        border_style="green",
                        box=box.DOUBLE,
                    )
                )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main interactive loop
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entry point: parse arguments, show banner, then run the interactive loop.
    """
    parser = argparse.ArgumentParser(
        description="HAYO AI Coding Agent — powered by Claude Sonnet 4.6"
    )
    parser.add_argument(
        "--working-dir",
        default=str(Path.cwd()),
        help="Absolute path to the project the agent may modify (default: cwd)",
    )
    parser.add_argument(
        "--thread-id",
        default=None,
        help="Session thread ID for state persistence (auto-generated if omitted)",
    )
    args = parser.parse_args()

    _api_key_check()

    working_dir = str(Path(args.working_dir).resolve())
    if not Path(working_dir).is_dir():
        console.print(f"[error]Working directory does not exist: {working_dir}[/error]")
        sys.exit(1)

    thread_id = args.thread_id or str(uuid.uuid4())[:8]

    console.print(BANNER)
    console.print(
        Panel(
            f"[info]Working directory:[/info] {working_dir}\n"
            f"[info]Thread ID:[/info] {thread_id}\n"
            f"[info]Model:[/info] claude-sonnet-4-6\n"
            f"[muted]Type your task and press Enter.  Type 'exit' to quit.[/muted]",
            title="[header]  HAYO AI Agent  [/header]",
            border_style="blue",
            box=box.DOUBLE_EDGE,
        )
    )

    while True:
        try:
            console.print()
            task = Prompt.ask("[bold cyan]You[/bold cyan]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[muted]Goodbye.[/muted]")
            break

        if not task:
            continue
        if task.lower() in {"exit", "quit", "q", "bye"}:
            console.print("[muted]Goodbye.[/muted]")
            break

        _stream_agent(task, working_dir, thread_id)


if __name__ == "__main__":
    main()
