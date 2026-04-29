"""
agent/graph.py
==============
Assembles the LangGraph StateGraph for the AI coding agent and exposes a
compiled graph object that can be invoked or streamed.

Graph topology
--------------

    START ──► planner ──► coder ──► executor ──► reviewer ──► END
                                       ▲              │
                                       └── (error) ───┘

The conditional edge out of ``reviewer`` routes to:
* ``END``   — when ``task_complete`` is True (success or give-up).
* ``coder`` — when ``task_complete`` is False and ``error_count < MAX_RETRIES``.

A ``MemorySaver`` checkpointer is attached so that graph state persists across
multiple ``invoke`` calls that share the same ``thread_id``, enabling
multi-turn interactions without re-running earlier steps.
"""

from __future__ import annotations

from typing import Any, Dict, Literal

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from core.state import AgentState
from agent.nodes import coder_node, executor_node, planner_node, reviewer_node

# ---------------------------------------------------------------------------
# Conditional router
# ---------------------------------------------------------------------------


def _reviewer_router(
    state: AgentState,
) -> Literal["coder", "__end__"]:
    """
    Decide the next node after the reviewer has assessed execution results.

    Returns ``"__end__"`` when the task is marked complete (either success or
    the agent gave up after MAX_RETRIES), and ``"coder"`` to trigger a
    self-healing iteration.
    """
    if state.get("task_complete", False):
        return END  # type: ignore[return-value]
    return "coder"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_graph() -> Any:
    """
    Build and compile the agent StateGraph.

    Returns
    -------
    CompiledGraph
        A LangGraph compiled graph ready to be invoked or streamed.
        The attached MemorySaver enables persistent state between calls
        that share the same ``config["configurable"]["thread_id"]``.
    """
    builder: StateGraph = StateGraph(AgentState)

    # ── Register nodes ────────────────────────────────────────────────────────
    builder.add_node("planner", planner_node)
    builder.add_node("coder", coder_node)
    builder.add_node("executor", executor_node)
    builder.add_node("reviewer", reviewer_node)

    # ── Static edges ──────────────────────────────────────────────────────────
    builder.add_edge(START, "planner")
    builder.add_edge("planner", "coder")
    builder.add_edge("coder", "executor")
    builder.add_edge("executor", "reviewer")

    # ── Conditional edge out of reviewer ─────────────────────────────────────
    builder.add_conditional_edges(
        "reviewer",
        _reviewer_router,
        {
            "coder": "coder",
            END: END,
        },
    )

    # ── Compile with in-memory checkpointer ───────────────────────────────────
    memory = MemorySaver()
    compiled = builder.compile(checkpointer=memory)
    return compiled


# ---------------------------------------------------------------------------
# Module-level singleton (imported by main.py)
# ---------------------------------------------------------------------------

agent_graph = build_graph()
"""Compiled LangGraph agent.  Import and invoke this directly."""


def get_config(thread_id: str = "default") -> Dict[str, Any]:
    """
    Return a LangGraph run config that scopes state to a specific thread.

    Each unique *thread_id* maintains independent state, so multiple
    concurrent users or sessions can share the same compiled graph safely.

    Parameters
    ----------
    thread_id : str
        Unique identifier for the conversation thread (e.g. session ID).

    Returns
    -------
    Dict[str, Any]
        Config dict to pass as ``config=`` to ``agent_graph.invoke()`` or
        ``agent_graph.stream()``.
    """
    return {"configurable": {"thread_id": thread_id}}
