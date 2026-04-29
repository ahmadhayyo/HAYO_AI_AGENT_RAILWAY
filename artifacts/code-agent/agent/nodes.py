"""
agent/nodes.py
==============
LangGraph node implementations for the AI coding agent.

Each node receives the current ``AgentState``, performs its work by calling
the LLM (with or without tools), mutates only the fields it owns, and
returns a partial-state dict that LangGraph merges back into the shared state.

Node pipeline
-------------
    PlannerNode  →  CoderNode  →  ExecutorNode  →  ReviewerNode
                         ↑______(self-healing loop)______|

* PlannerNode   — analyses the user request and writes an ordered plan.
* CoderNode     — executes the plan step-by-step, calling file/terminal tools.
* ExecutorNode  — runs any pending bash commands and collects output.
* ReviewerNode  — decides: task complete → END | error found → loop to Coder.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool

from core.state import AgentState, MAX_RETRIES, MAX_TERMINAL_HISTORY
from tools.filesystem import list_directory, read_file, search_in_files, write_file
from tools.terminal import execute_bash_command

# ---------------------------------------------------------------------------
# Model & tool setup
# ---------------------------------------------------------------------------

MODEL_NAME = "claude-sonnet-4-6"

_ALL_TOOLS: List[BaseTool] = [
    read_file,
    write_file,
    list_directory,
    search_in_files,
    execute_bash_command,
]

_TOOL_MAP: Dict[str, BaseTool] = {t.name: t for t in _ALL_TOOLS}


def _build_llm(*, temperature: float = 0.2, max_tokens: int = 8192) -> ChatAnthropic:
    """Instantiate the Claude model used by all nodes."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    return ChatAnthropic(
        model=MODEL_NAME,
        anthropic_api_key=api_key,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def _invoke_tools(tool_calls: list) -> List[ToolMessage]:
    """
    Execute a list of tool-call dicts returned by the model and collect
    ``ToolMessage`` results.

    Parameters
    ----------
    tool_calls : list
        List of ``tool_call`` objects from an ``AIMessage``.

    Returns
    -------
    List[ToolMessage]
        One ToolMessage per tool call, containing the tool's output.
    """
    results: List[ToolMessage] = []
    for call in tool_calls:
        name = call["name"]
        args = call["args"]
        tool_id = call["id"]

        tool_fn = _TOOL_MAP.get(name)
        if tool_fn is None:
            output = f"[ERROR] Unknown tool '{name}'."
        else:
            try:
                output = tool_fn.invoke(args)
            except Exception as exc:  # noqa: BLE001
                output = f"[ERROR] Tool '{name}' raised an exception: {exc}"

        results.append(
            ToolMessage(content=str(output), tool_call_id=tool_id, name=name)
        )
    return results


# ---------------------------------------------------------------------------
# ── PlannerNode ──────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

PLANNER_SYSTEM = """You are the Planner component of an autonomous AI software engineering agent.

Your ONLY job is to analyse the user's request and produce a concise, ordered
action plan — a numbered list of concrete steps the Coder will follow.

Rules:
- Be specific about file paths, function names, and technology stack.
- Each step must be a single actionable task (read a file, write a function, run a command).
- Do NOT write any code here.  Just the plan.
- Limit the plan to 10 steps maximum; merge related work where sensible.
- Output the plan as a JSON array of strings, with no extra text.

Example output:
["Read artifacts/hayo-ai/src/App.tsx to understand routing.",
 "Create artifacts/hayo-ai/src/pages/NewPage.tsx with skeleton component.",
 "Add /new-page route to App.tsx router."]
"""


def planner_node(state: AgentState) -> Dict[str, Any]:
    """
    Analyse the latest user message and produce an ordered plan.

    Reads
    -----
    state["messages"] — takes the last HumanMessage as the task description.

    Writes
    ------
    state["current_plan"]  — list of step strings.
    state["current_step"]  — set to "planner".
    state["error_count"]   — reset to 0 (fresh task).
    state["task_complete"] — reset to False.
    state["last_error"]    — reset to None.
    """
    llm = _build_llm(temperature=0.1, max_tokens=2048)

    # Extract the latest human request
    human_msgs = [m for m in state["messages"] if isinstance(m, HumanMessage)]
    task = human_msgs[-1].content if human_msgs else "No task provided."

    working_dir = state.get("working_directory", ".")

    messages = [
        SystemMessage(content=PLANNER_SYSTEM),
        HumanMessage(
            content=(
                f"Working directory: {working_dir}\n\n"
                f"User task:\n{task}"
            )
        ),
    ]

    response: AIMessage = llm.invoke(messages)  # type: ignore[assignment]
    raw = response.content

    # Parse JSON plan; fall back to a single-step plan on parse failure
    try:
        # Strip markdown fences if present
        cleaned = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        plan: List[str] = json.loads(cleaned)
        if not isinstance(plan, list):
            raise ValueError("Plan is not a list")
    except (json.JSONDecodeError, ValueError):
        plan = [f"Complete the task: {task}"]

    return {
        "messages": [AIMessage(content=f"📋 Plan created ({len(plan)} steps):\n" + "\n".join(f"{i+1}. {s}" for i, s in enumerate(plan)))],
        "current_plan": plan,
        "current_step": "planner",
        "error_count": 0,
        "task_complete": False,
        "last_error": None,
        "terminal_outputs": [],
    }


# ---------------------------------------------------------------------------
# ── CoderNode ────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

CODER_SYSTEM = """You are the Coder component of an autonomous AI software engineering agent.

You execute the plan step-by-step by calling the available tools:
- read_file        — read source files for context
- write_file       — create or overwrite files
- list_directory   — explore the project tree
- search_in_files  — grep across the codebase
- execute_bash_command — run shell commands (npm install, pnpm build, etc.)

Rules:
- Call ONE tool at a time; wait for its output before deciding the next call.
- Always read a file before overwriting it so you have full context.
- When writing files, produce COMPLETE file content — no placeholders.
- After all plan steps are done, reply with a plain text summary starting with DONE:.
- If you hit an error, describe it clearly; the Reviewer will route accordingly.
- Working directory is provided; use it as the root for all relative paths.
- Respect the project's technology stack (TypeScript / React / tRPC / pnpm).
"""

SELF_HEAL_SUFFIX = """
⚠️  SELF-HEALING ROUND
The previous execution attempt produced the following error:

{last_error}

Analyse the error carefully, then fix it using the available tools.
After the fix, run the relevant command again to confirm it passes.
"""


def coder_node(state: AgentState) -> Dict[str, Any]:
    """
    Execute the plan by iteratively calling tools.

    This node runs the LLM in an agentic loop: the model calls a tool,
    receives its output, decides the next tool call, and so on until it
    produces a final text response (no more tool calls).

    Reads
    -----
    state["current_plan"]      — ordered list of steps to execute.
    state["working_directory"] — sandbox root for all tools.
    state["last_error"]        — populated on self-healing rounds.
    state["terminal_outputs"]  — prior execution history for context.

    Writes
    ------
    state["messages"]      — all intermediate tool calls + final AI reply.
    state["current_step"]  — "coder".
    """
    llm = _build_llm(temperature=0.2, max_tokens=8192).bind_tools(_ALL_TOOLS)

    working_dir = state.get("working_directory", ".")
    plan = state.get("current_plan", [])
    last_error = state.get("last_error")
    terminal_history = state.get("terminal_outputs", [])[-MAX_TERMINAL_HISTORY:]

    # Build system prompt
    plan_text = "\n".join(f"{i+1}. {s}" for i, s in enumerate(plan))
    history_text = "\n---\n".join(terminal_history) if terminal_history else "(none)"

    system_content = (
        CODER_SYSTEM
        + f"\n\nWorking directory: {working_dir}\n\n"
        + f"## Current Plan:\n{plan_text}\n\n"
        + f"## Previous Terminal Output (last {MAX_TERMINAL_HISTORY} entries):\n{history_text}"
    )
    if last_error:
        system_content += SELF_HEAL_SUFFIX.format(last_error=last_error)

    # Seed the message list with the user task + all prior messages
    chat_messages: list = [SystemMessage(content=system_content)]
    for msg in state["messages"]:
        if not isinstance(msg, SystemMessage):
            chat_messages.append(msg)

    new_messages: list = []
    max_tool_rounds = 30  # Hard cap to prevent run-away agentic loops

    for _round in range(max_tool_rounds):
        response: AIMessage = llm.invoke(chat_messages)  # type: ignore[assignment]
        chat_messages.append(response)
        new_messages.append(response)

        if not response.tool_calls:
            # Model produced a final text answer — exit the loop
            break

        # Execute all tool calls in this round
        tool_messages = _invoke_tools(response.tool_calls)
        chat_messages.extend(tool_messages)
        new_messages.extend(tool_messages)
    else:
        # Safety valve: model kept calling tools without concluding
        fallback = AIMessage(
            content="[AGENT] Reached maximum tool-call rounds without a conclusion. "
                    "Returning partial results."
        )
        new_messages.append(fallback)

    return {
        "messages": new_messages,
        "current_step": "coder",
    }


# ---------------------------------------------------------------------------
# ── ExecutorNode ─────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

EXECUTOR_SYSTEM = """You are the Executor component of an AI software engineering agent.

Your job is to run any final verification commands needed after the Coder has
finished writing code.  Typical tasks:
- Run `pnpm build` or `npm run build` to verify the build succeeds.
- Run `pnpm lint` or `npx tsc --noEmit` to check types.
- Run test suites if tests exist.
- Print the relevant output so the Reviewer can assess success or failure.

If the Coder's last message already shows a successful build/test, simply
output: SKIP — no additional execution needed.

Always use execute_bash_command for shell work.
Working directory is provided.
"""


def executor_node(state: AgentState) -> Dict[str, Any]:
    """
    Run post-coding verification commands (build, lint, type-check, tests).

    Reads
    -----
    state["messages"]          — determines what verification is needed.
    state["working_directory"] — sandbox root.

    Writes
    ------
    state["messages"]         — appends executor AI reply + tool results.
    state["terminal_outputs"] — appends the latest execution output.
    state["current_step"]     — "executor".
    """
    llm = _build_llm(temperature=0.0, max_tokens=4096).bind_tools(
        [execute_bash_command]
    )

    working_dir = state.get("working_directory", ".")
    terminal_history = state.get("terminal_outputs", [])

    system_content = (
        EXECUTOR_SYSTEM
        + f"\n\nWorking directory: {working_dir}"
    )

    chat_messages: list = [SystemMessage(content=system_content)]
    for msg in state["messages"]:
        if not isinstance(msg, SystemMessage):
            chat_messages.append(msg)

    new_messages: list = []
    new_terminal_outputs: list = []
    max_rounds = 5

    for _ in range(max_rounds):
        response: AIMessage = llm.invoke(chat_messages)  # type: ignore[assignment]
        chat_messages.append(response)
        new_messages.append(response)

        if not response.tool_calls:
            break

        tool_messages = _invoke_tools(response.tool_calls)
        chat_messages.extend(tool_messages)
        new_messages.extend(tool_messages)

        # Collect terminal output for state
        for tm in tool_messages:
            if isinstance(tm, ToolMessage):
                new_terminal_outputs.append(tm.content)

    updated_terminal = (terminal_history + new_terminal_outputs)[-MAX_TERMINAL_HISTORY:]

    return {
        "messages": new_messages,
        "terminal_outputs": updated_terminal,
        "current_step": "executor",
    }


# ---------------------------------------------------------------------------
# ── ReviewerNode ─────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

REVIEWER_SYSTEM = """You are the Reviewer component of an AI software engineering agent.

Analyse the conversation so far — particularly the most recent executor output —
and determine whether the task has been completed successfully.

Respond with EXACTLY one of the following JSON objects (no other text):

If the task is COMPLETE and there are no errors:
{"status": "complete", "summary": "<brief summary of what was accomplished>"}

If there is an ERROR that should be fixed:
{"status": "error", "error": "<exact error message or description>", "suggestion": "<what the Coder should do to fix it>"}

If the error count is already at the maximum retries, respond with:
{"status": "give_up", "reason": "<why the agent could not complete the task>"}

Be strict: only mark "complete" if the terminal output shows a clean build /
success / no errors.  Do not mark complete on partial progress.
"""


def reviewer_node(state: AgentState) -> Dict[str, Any]:
    """
    Evaluate the execution results and route: complete → END, error → Coder.

    Reads
    -----
    state["messages"]          — full conversation for analysis.
    state["error_count"]       — current retry count.
    state["terminal_outputs"]  — raw terminal output for review.

    Writes
    ------
    state["task_complete"] — True when the task is done.
    state["last_error"]    — error description for next Coder round.
    state["error_count"]   — incremented on error.
    state["final_answer"]  — set when task_complete is True.
    state["current_step"]  — "reviewer".
    state["messages"]      — appends the reviewer's verdict message.
    """
    llm = _build_llm(temperature=0.0, max_tokens=1024)

    error_count = state.get("error_count", 0)
    terminal_outputs = state.get("terminal_outputs", [])

    system_content = (
        REVIEWER_SYSTEM
        + f"\n\nCurrent error_count: {error_count} / {MAX_RETRIES}"
    )

    chat_messages: list = [SystemMessage(content=system_content)]
    for msg in state["messages"]:
        if not isinstance(msg, SystemMessage):
            chat_messages.append(msg)

    # Add a prompt to force the reviewer to act now
    chat_messages.append(
        HumanMessage(
            content=(
                "Latest terminal outputs:\n"
                + "\n---\n".join(terminal_outputs[-5:] if terminal_outputs else ["(none)"])
                + "\n\nProvide your JSON verdict now."
            )
        )
    )

    response: AIMessage = llm.invoke(chat_messages)  # type: ignore[assignment]
    raw = response.content.strip()

    # Parse reviewer verdict
    try:
        cleaned = raw.lstrip("```json").lstrip("```").rstrip("```").strip()
        verdict: Dict[str, Any] = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        # If the model produced non-JSON, treat as an unresolvable error
        verdict = {
            "status": "error",
            "error": f"Reviewer produced unparseable output: {raw[:300]}",
            "suggestion": "Review the latest terminal output manually.",
        }

    status = verdict.get("status", "error")

    if status == "complete":
        summary = verdict.get("summary", "Task completed successfully.")
        return {
            "messages": [AIMessage(content=f"✅ COMPLETE: {summary}")],
            "task_complete": True,
            "final_answer": summary,
            "current_step": "reviewer",
        }

    if status == "give_up" or error_count >= MAX_RETRIES:
        reason = verdict.get("reason", verdict.get("error", "Unknown reason."))
        return {
            "messages": [
                AIMessage(
                    content=(
                        f"❌ AGENT GAVE UP after {error_count} retries.\n"
                        f"Reason: {reason}"
                    )
                )
            ],
            "task_complete": True,  # End the graph — don't loop further
            "final_answer": f"Failed: {reason}",
            "current_step": "reviewer",
        }

    # status == "error" — loop back to Coder
    error_msg = verdict.get("error", "Unknown error.")
    suggestion = verdict.get("suggestion", "")
    combined_error = f"{error_msg}\nSuggestion: {suggestion}" if suggestion else error_msg

    return {
        "messages": [
            AIMessage(
                content=(
                    f"⚠️  Error detected (attempt {error_count + 1}/{MAX_RETRIES}):\n"
                    f"{combined_error}"
                )
            )
        ],
        "task_complete": False,
        "last_error": combined_error,
        "error_count": error_count + 1,
        "current_step": "reviewer",
    }
