"""
tools/terminal.py
=================
LangChain @tool for executing bash commands inside the agent's sandboxed
working directory.

Design decisions
----------------
* ``subprocess.run`` is used (not ``Popen``) so the call blocks until the
  process exits or the timeout fires.  This keeps tool invocations simple
  and predictable from the LangGraph node perspective.
* stdout and stderr are captured separately and returned together in a
  structured format so the ReviewerNode can distinguish output from errors.
* Dangerous commands (rm -rf /, format, ...) are blocked by a denylist.
* A configurable timeout (default 60 s) prevents hanging processes from
  stalling the graph indefinitely.
* The tool is synchronous; ``asyncio.to_thread`` is used in nodes.py when
  async execution is preferred.
"""

from __future__ import annotations

import subprocess
import shlex
from pathlib import Path
from typing import List

from langchain_core.tools import tool

# ---------------------------------------------------------------------------
# Safety denylist — commands that must never be executed
# ---------------------------------------------------------------------------

_DENIED_PATTERNS: List[str] = [
    "rm -rf /",
    "rm -rf ~",
    "mkfs",
    "dd if=",
    ":(){:|:&};:",   # fork bomb
    "chmod -R 777 /",
    "chown -R",
    "shutdown",
    "reboot",
    "halt",
    "passwd",
    "sudo rm",
    "sudo dd",
]

_DEFAULT_TIMEOUT_SECONDS: int = 60
_MAX_OUTPUT_CHARS: int = 8_000  # Truncate output to keep prompts lean


def _is_denied(command: str) -> bool:
    """Return True if *command* matches any entry in the safety denylist."""
    cmd_lower = command.lower().strip()
    return any(denied in cmd_lower for denied in _DENIED_PATTERNS)


def _truncate(text: str, limit: int = _MAX_OUTPUT_CHARS) -> str:
    """Truncate *text* to *limit* characters with a trailing notice."""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[... output truncated at {limit} chars ...]"


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

@tool
def execute_bash_command(
    command: str,
    working_directory: str = ".",
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """
    Execute a bash shell command inside *working_directory* and return
    the combined stdout, stderr, and exit-code information.

    The tool is intentionally synchronous.  For long-running commands
    (compilation, package install) increase *timeout_seconds* up to 300.

    Parameters
    ----------
    command : str
        The shell command to run.  Supports pipes, redirections, and
        multi-statement commands (``&&``, ``;``).
    working_directory : str
        Absolute path to the directory where the command should run.
        Relative paths are resolved against the current working directory
        of the Python process.
    timeout_seconds : int
        Maximum wall-clock seconds to wait before killing the process
        (default 60, max allowed 300).

    Returns
    -------
    str
        A structured block with:
        * ``COMMAND``   — the command that was run
        * ``EXIT CODE`` — numeric exit status (0 = success)
        * ``STDOUT``    — standard output (may be truncated)
        * ``STDERR``    — standard error  (may be truncated)
        * ``STATUS``    — "SUCCESS" or "ERROR"
    """
    # ── Safety checks ────────────────────────────────────────────────────────
    if not command or not command.strip():
        return "[ERROR] Empty command provided."

    if _is_denied(command):
        return (
            "[ERROR] Command blocked by safety policy.\n"
            f"Denied pattern matched in: {command!r}"
        )

    # Enforce a hard cap on timeout to prevent runaway processes
    effective_timeout = min(int(timeout_seconds), 300)

    # ── Resolve working directory ─────────────────────────────────────────────
    cwd = Path(working_directory).resolve()
    if not cwd.exists():
        return (
            f"[ERROR] Working directory does not exist: {working_directory}"
        )
    if not cwd.is_dir():
        return (
            f"[ERROR] Working directory path is not a directory: {working_directory}"
        )

    # ── Execute ───────────────────────────────────────────────────────────────
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=str(cwd),
            timeout=effective_timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return (
            f"COMMAND: {command}\n"
            f"EXIT CODE: -1 (TIMEOUT)\n"
            f"STDOUT: [no output — process killed after {effective_timeout}s]\n"
            f"STDERR: TimeoutExpired — the command took longer than {effective_timeout} seconds.\n"
            f"STATUS: ERROR\n"
            "HINT: Break the command into smaller steps, or increase timeout_seconds."
        )
    except FileNotFoundError as exc:
        return (
            f"COMMAND: {command}\n"
            f"EXIT CODE: -1\n"
            f"STDOUT: \n"
            f"STDERR: {exc}\n"
            f"STATUS: ERROR"
        )
    except OSError as exc:
        return (
            f"COMMAND: {command}\n"
            f"EXIT CODE: -1\n"
            f"STDOUT: \n"
            f"STDERR: OSError: {exc}\n"
            f"STATUS: ERROR"
        )

    # ── Format output ─────────────────────────────────────────────────────────
    stdout = _truncate(result.stdout.strip())
    stderr = _truncate(result.stderr.strip())
    status = "SUCCESS" if result.returncode == 0 else "ERROR"

    return (
        f"COMMAND: {command}\n"
        f"EXIT CODE: {result.returncode}\n"
        f"STDOUT:\n{stdout if stdout else '(empty)'}\n"
        f"STDERR:\n{stderr if stderr else '(empty)'}\n"
        f"STATUS: {status}"
    )
