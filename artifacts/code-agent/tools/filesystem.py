"""
tools/filesystem.py
===================
LangChain @tool functions for safe, sandboxed file-system access.

Every tool validates that the requested path is inside the agent's
``working_directory`` before performing any I/O.  Errors are returned
as plain strings so the LLM can read and reason about them.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import List, Optional

from langchain_core.tools import tool

# ---------------------------------------------------------------------------
# Path safety helper
# ---------------------------------------------------------------------------

_IGNORED_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", ".cache",
    "__pycache__", ".turbo", "coverage", ".venv", "venv", ".mypy_cache",
}

_ALLOWED_TEXT_EXTENSIONS = {
    ".ts", ".tsx", ".js", ".jsx", ".py", ".css", ".scss",
    ".json", ".html", ".md", ".txt", ".yaml", ".yml",
    ".env.example", ".toml", ".ini", ".cfg", ".sh", ".bash",
    ".sql", ".prisma", ".graphql", ".xml", ".csv",
}


def _resolve_safe(file_path: str, working_directory: str) -> Path | None:
    """
    Resolve *file_path* relative to *working_directory* and return the
    absolute ``Path`` only if it remains inside the working directory.

    Returns ``None`` when the path escapes the sandbox (path traversal).
    """
    base = Path(working_directory).resolve()
    candidate = (base / file_path).resolve()
    try:
        candidate.relative_to(base)
        return candidate
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool
def read_file(file_path: str, working_directory: str = ".") -> str:
    """
    Read and return the text content of a file inside the project.

    Parameters
    ----------
    file_path : str
        Path to the file relative to the working directory.
    working_directory : str
        Absolute path to the sandboxed project root.

    Returns
    -------
    str
        File content with a header line showing the resolved path,
        or an error message prefixed with ``[ERROR]``.
    """
    resolved = _resolve_safe(file_path, working_directory)
    if resolved is None:
        return f"[ERROR] Path '{file_path}' is outside the working directory."

    if not resolved.exists():
        return f"[ERROR] File not found: {file_path}"

    if resolved.is_dir():
        return (
            f"[ERROR] '{file_path}' is a directory. "
            "Use list_directory to inspect its contents."
        )

    ext = resolved.suffix.lower()
    if ext not in _ALLOWED_TEXT_EXTENSIONS and ext != "":
        return (
            f"[ERROR] Extension '{ext}' is not in the allowed text-file list. "
            "Only source-code and configuration files may be read."
        )

    try:
        content = resolved.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return f"[ERROR] Permission denied reading '{file_path}'."
    except OSError as exc:
        return f"[ERROR] OS error reading '{file_path}': {exc}"

    lines = content.splitlines()
    total = len(lines)
    # Truncate very large files to avoid flooding the context window
    if total > 600:
        snippet = "\n".join(lines[:600])
        return (
            f"--- {file_path} ({total} lines, showing first 600) ---\n"
            f"{snippet}\n[... truncated ...]"
        )

    return f"--- {file_path} ({total} lines) ---\n{content}"


@tool
def write_file(file_path: str, content: str, working_directory: str = ".") -> str:
    """
    Write *content* to *file_path* (creates the file and any missing parent
    directories if needed).

    Parameters
    ----------
    file_path : str
        Destination path relative to the working directory.
    content : str
        Full text content to write (UTF-8 encoded).
    working_directory : str
        Absolute path to the sandboxed project root.

    Returns
    -------
    str
        Success message with the number of bytes written, or an ``[ERROR]``
        message.
    """
    resolved = _resolve_safe(file_path, working_directory)
    if resolved is None:
        return f"[ERROR] Path '{file_path}' is outside the working directory."

    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        size = resolved.stat().st_size
        return f"[OK] Written {size:,} bytes to '{file_path}'."
    except PermissionError:
        return f"[ERROR] Permission denied writing to '{file_path}'."
    except OSError as exc:
        return f"[ERROR] OS error writing '{file_path}': {exc}"


@tool
def list_directory(
    dir_path: str,
    working_directory: str = ".",
    max_depth: int = 3,
) -> str:
    """
    Return a recursive directory tree for *dir_path* (similar to the ``tree``
    command), skipping ignored directories.

    Parameters
    ----------
    dir_path : str
        Path to the directory relative to the working directory.
        Pass ``"."`` to list the root.
    working_directory : str
        Absolute path to the sandboxed project root.
    max_depth : int
        Maximum recursion depth (default 3).

    Returns
    -------
    str
        Indented tree representation or an ``[ERROR]`` message.
    """
    resolved = _resolve_safe(dir_path, working_directory)
    if resolved is None:
        return f"[ERROR] Path '{dir_path}' is outside the working directory."
    if not resolved.exists():
        return f"[ERROR] Directory not found: {dir_path}"
    if not resolved.is_dir():
        return f"[ERROR] '{dir_path}' is a file, not a directory."

    lines: List[str] = [f"📁 {dir_path}/"]

    def _walk(current: Path, prefix: str, depth: int) -> None:
        if depth > max_depth:
            lines.append(f"{prefix}  ...")
            return
        try:
            entries = sorted(
                current.iterdir(),
                key=lambda e: (not e.is_dir(), e.name.lower()),
            )
        except PermissionError:
            lines.append(f"{prefix}  [permission denied]")
            return

        for i, entry in enumerate(entries):
            if entry.name.startswith(".") or entry.name in _IGNORED_DIRS:
                continue
            connector = "└── " if i == len(entries) - 1 else "├── "
            if entry.is_dir():
                lines.append(f"{prefix}{connector}📁 {entry.name}/")
                child_prefix = prefix + ("    " if i == len(entries) - 1 else "│   ")
                _walk(entry, child_prefix, depth + 1)
            else:
                size = entry.stat().st_size if entry.exists() else 0
                lines.append(f"{prefix}{connector}📄 {entry.name} ({size / 1024:.1f} KB)")

    _walk(resolved, "", 1)
    return "\n".join(lines)


@tool
def search_in_files(
    pattern: str,
    working_directory: str = ".",
    search_path: str = ".",
    file_glob: str = "*.ts,*.tsx,*.py,*.js,*.jsx,*.json",
    max_results: int = 40,
    use_regex: bool = False,
) -> str:
    """
    Search for *pattern* in all matching files under *search_path* — a
    grep-like tool for the agent to locate relevant code.

    Parameters
    ----------
    pattern : str
        The text string (or regex if *use_regex* is True) to search for.
    working_directory : str
        Absolute path to the sandboxed project root.
    search_path : str
        Subdirectory to search (relative to working_directory). Use ``"."``
        for the entire project.
    file_glob : str
        Comma-separated glob patterns for file extensions to include.
        Default covers common source-code types.
    max_results : int
        Maximum number of matching lines to return (prevents context floods).
    use_regex : bool
        When ``True``, compile *pattern* as a regular expression.

    Returns
    -------
    str
        Formatted list of matches (file:line: content) or ``[ERROR]`` / a
        "no matches" message.
    """
    resolved_search = _resolve_safe(search_path, working_directory)
    if resolved_search is None:
        return f"[ERROR] Search path '{search_path}' is outside the working directory."
    if not resolved_search.exists():
        return f"[ERROR] Search path '{search_path}' does not exist."

    globs = [g.strip() for g in file_glob.split(",") if g.strip()]

    if use_regex:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            match_fn = lambda line: compiled.search(line) is not None
        except re.error as exc:
            return f"[ERROR] Invalid regex '{pattern}': {exc}"
    else:
        lower_pat = pattern.lower()
        match_fn = lambda line: lower_pat in line.lower()

    results: List[str] = []
    scanned_files = 0

    for root, dirs, files in os.walk(resolved_search):
        # Prune ignored directories in-place so os.walk skips them
        dirs[:] = [
            d for d in sorted(dirs)
            if d not in _IGNORED_DIRS and not d.startswith(".")
        ]
        for fname in sorted(files):
            if not any(fnmatch.fnmatch(fname, g) for g in globs):
                continue
            fpath = Path(root) / fname
            rel = fpath.relative_to(Path(working_directory).resolve())
            scanned_files += 1
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if match_fn(line):
                    results.append(
                        f"{rel}:{lineno}: {line.rstrip()}"
                    )
                    if len(results) >= max_results:
                        results.append(
                            f"[TRUNCATED — reached {max_results} matches across "
                            f"{scanned_files} files scanned]"
                        )
                        return "\n".join(results)

    if not results:
        return (
            f"No matches for '{pattern}' in {scanned_files} files "
            f"under '{search_path}'."
        )

    header = (
        f"Found {len(results)} match(es) for '{pattern}' "
        f"across {scanned_files} files:\n"
    )
    return header + "\n".join(results)
