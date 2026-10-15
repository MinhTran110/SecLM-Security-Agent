"""GraphState definition for LangGraph workflow."""

from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict


class AgentState(TypedDict, total=False):
    """Represents the complete state of the Security Agent graph."""
    messages: List[Dict[str, Any]]
    security_context: Dict[str, Any]
    retrieved_docs: List[Dict[str, Any]]
    tool_calls: List[Dict[str, Any]]
    tool_results: List[Dict[str, Any]]
    next_action: Optional[str]
    iteration_count: int
    final_response: Optional[str]
