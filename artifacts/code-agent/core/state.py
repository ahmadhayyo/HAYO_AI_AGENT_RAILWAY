"""
core/state.py
=============
Defines the central AgentState TypedDict that flows through every node
in the LangGraph state machine.  All fields are typed explicitly so that
LangGraph can serialize / deserialize state correctly when a checkpointer
is attached.
"""

from __future__ import annotations

from typing import Annotated, List, Optional
from typing_extensions import TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


# ---------------------------------------------------------------------------
# Main agent state
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    """
    Shared state container passed between every node in the graph.

    Fields
    ------
    messages : List[BaseMessage]
        Full conversation history (human + AI turns).  The ``add_messages``
        reducer appends new messages instead of replacing the list, which is
        the expected LangGraph behaviour.

    current_plan : List[str]
        Ordered list of actionable steps produced by the PlannerNode.
        Each entry is a human-readable description of one concrete task.

    working_directory : str
        Absolute path to the project root the agent is allowed to modify.
        All file-system tools validate that the target path is inside this
        directory to prevent accidental writes elsewhere.

    terminal_outputs : List[str]
        Accumulated stdout / stderr from every bash command executed so far
        in the current session.  Kept for the ReviewerNode to diagnose
        errors across multiple execution rounds.

    error_count : int
        Number of consecutive errors detected by the ReviewerNode.
        Used as a circuit breaker: if ``error_count >= MAX_RETRIES`` the
        graph routes to END instead of looping back to CoderNode, preventing
        infinite self-correction loops.

    current_step : str
        Human-readable label of the graph node currently executing
        (e.g. "planner", "coder", "executor", "reviewer").
        Used by the Rich UI to display a contextual spinner.

    last_error : Optional[str]
        The most recent error message / stack trace captured by the
        ReviewerNode.  Passed back to CoderNode so it can self-heal with
        full context.

    final_answer : Optional[str]
        The agent's concluding summary once the task is complete.
        Set by the ReviewerNode when it determines no further action is
        needed.

    task_complete : bool
        Flag set to ``True`` by the ReviewerNode when the task has been
        successfully accomplished.  The conditional edge on the graph reads
        this flag to decide whether to route to END or loop back to Coder.
    """

    messages: Annotated[List[BaseMessage], add_messages]
    current_plan: List[str]
    working_directory: str
    terminal_outputs: List[str]
    error_count: int
    current_step: str
    last_error: Optional[str]
    final_answer: Optional[str]
    task_complete: bool


# ---------------------------------------------------------------------------
# Constants shared across the graph
# ---------------------------------------------------------------------------

MAX_RETRIES: int = 5
"""Maximum number of consecutive self-correction attempts before giving up."""

MAX_TERMINAL_HISTORY: int = 20
"""How many past terminal outputs to retain in state to avoid prompt bloat."""
