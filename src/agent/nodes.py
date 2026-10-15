"""Node logic functions for the LangGraph state machine."""

from typing import Any, Dict
from src.agent.state import AgentState


async def call_model_node(state: AgentState) -> Dict[str, Any]:
    """Invoke the LLM to analyze security context and decide tool invocation."""
    iteration = state.get("iteration_count", 0) + 1
    # Node logic skeleton
    return {
        "iteration_count": iteration,
        "next_action": "format_response" if iteration >= 1 else "execute_tools",
    }


async def execute_tools_node(state: AgentState) -> Dict[str, Any]:
    """Execute tools selected by the model."""
    # Execute required tools from tool registry
    return {
        "tool_results": [{"tool": "code_analyzer", "status": "executed", "findings": []}],
        "next_action": "format_response",
    }


async def retrieve_context_node(state: AgentState) -> Dict[str, Any]:
    """Retrieve security knowledge from vector store and CWE catalogs."""
    return {
        "retrieved_docs": [{"title": "CWE Catalog", "content": "Security guideline"}]
    }


async def format_response_node(state: AgentState) -> Dict[str, Any]:
    """Synthesize final security assessment and recommendations."""
    return {
        "final_response": "Kết quả thẩm định bảo mật hoàn tất.",
        "next_action": "__end__",
    }
