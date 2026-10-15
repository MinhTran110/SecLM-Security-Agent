"""Unit tests for agent workflow, state transitions, and node logic."""

import pytest
from src.agent.state import AgentState
from src.agent.graph import route_next_step
from src.agent.nodes import call_model_node, format_response_node


def test_route_next_step():
    """Verify conditional edge routing logic."""
    state_tools: AgentState = {"next_action": "execute_tools"}
    assert route_next_step(state_tools) == "execute_tools"

    state_retrieve: AgentState = {"next_action": "retrieve_context"}
    assert route_next_step(state_retrieve) == "retrieve_context"

    state_format: AgentState = {"next_action": "format_response"}
    assert route_next_step(state_format) == "format_response"


@pytest.mark.asyncio
async def test_call_model_node_increments_iteration():
    """Verify call_model_node updates iteration counter."""
    initial_state: AgentState = {"iteration_count": 0}
    new_state = await call_model_node(initial_state)
    assert new_state["iteration_count"] == 1


@pytest.mark.asyncio
async def test_format_response_node():
    """Verify format_response_node finalizes response."""
    initial_state: AgentState = {"messages": []}
    result = await format_response_node(initial_state)
    assert "final_response" in result
    assert result["next_action"] == "__end__"
