import pytest
from src.agent.core import SecurityAgent

def test_agent_initialization():
    agent = SecurityAgent()
    assert agent.max_iterations == 5
    assert len(agent.fallback_models) >= 1

def test_agent_calls_cve_tool(monkeypatch):
    agent = SecurityAgent()

    iteration_count = 0
    def mock_call(contents, config):
        nonlocal iteration_count
        iteration_count += 1
        
        class MockCandidate:
            content = "Mock Candidate Content"
        class MockCall:
            name = "lookup_cve_details"
            args = {"cve_id": "CVE-2024-5510"}
        class MockToolResponse:
            text = "Lỗ hổng CVE-2024-5510 có điểm CVSS 9.8 thuộc nhóm CRITICAL."
            function_calls = [MockCall()]
            candidates = [MockCandidate()]
        class MockFinalResponse:
            text = "Lỗ hổng CVE-2024-5510 có điểm CVSS 9.8 thuộc nhóm CRITICAL SQL Injection."
            function_calls = []
            candidates = [MockCandidate()]

        if iteration_count == 1:
            return MockToolResponse()
        return MockFinalResponse()

    monkeypatch.setattr(agent, "_call_llm_with_fallback", mock_call)
    result = agent.run("Cho tôi biết mức độ nghiêm trọng của CVE-2024-5510")
    
    assert len(result["tools_used"]) >= 1
    assert result["tools_used"][0]["tool"] == "lookup_cve_details"
    assert result["tools_used"][0]["args"]["cve_id"] == "CVE-2024-5510"
    assert "9.8" in result["answer"] or "CRITICAL" in result["answer"]
