"""Unit tests for LangGraph agent state graph workflow."""
import pytest

from app.modules.agent.graph import build_investigation_graph, AgentState
from app.modules.agent.investigation_agent import run_investigation_agent


@pytest.mark.asyncio
async def test_langgraph_workflow_execution():
    graph = build_investigation_graph()
    initial_state = AgentState(
        investigation_id="test-inv-123",
        conversation_id="test-conv-123",
        nl_query="Investigate failed logins from 185.220.101.45 during the last 24 hours",
    )

    final_state = await graph.run(initial_state)
    assert final_state.status == "completed"
    assert len(final_state.executed_nodes) >= 5
    assert "nlp_extract" in final_state.executed_nodes
    assert "evidence_grounding" in final_state.executed_nodes
    assert final_state.conclusion != ""


@pytest.mark.asyncio
async def test_run_investigation_agent_flow():
    state = await run_investigation_agent(
        nl_query="Show active brute force attempts",
        conversation_id="test-conv-456",
    )
    assert state.status in ("completed", "awaiting_approval")
    assert len(state.tool_calls) >= 1
