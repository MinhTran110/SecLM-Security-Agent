"""Construct and compile the LangGraph StateGraph workflow."""

from typing import Any
from src.agent.state import AgentState
from src.agent.nodes import (
    call_model_node,
    execute_tools_node,
    retrieve_context_node,
    format_response_node,
)


def route_next_step(state: AgentState) -> str:
    """Conditional edge router determining the next node."""
    next_action = state.get("next_action")
    if next_action == "execute_tools":
        return "execute_tools"
    if next_action == "retrieve_context":
        return "retrieve_context"
    return "format_response"


def create_agent_graph():
    """Create and return the compiled LangGraph workflow.
    
    Returns a configured graph or runnable placeholder.
    """
    try:
        from langgraph.graph import StateGraph, END

        workflow = StateGraph(AgentState)

        workflow.add_node("call_model", call_model_node)
        workflow.add_node("execute_tools", execute_tools_node)
        workflow.add_node("retrieve_context", retrieve_context_node)
        workflow.add_node("format_response", format_response_node)

        workflow.set_entry_point("call_model")

        workflow.add_conditional_edges(
            "call_model",
            route_next_step,
            {
                "execute_tools": "execute_tools",
                "retrieve_context": "retrieve_context",
                "format_response": "format_response",
            },
        )
        workflow.add_edge("execute_tools", "call_model")
        workflow.add_edge("retrieve_context", "call_model")
        workflow.add_edge("format_response", END)

        return workflow.compile()
    except ImportError:
        # Fallback placeholder when dependencies are not yet installed
        return None
