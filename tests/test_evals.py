"""Unit and benchmark evaluation tests for Security Agent."""

import json
from pathlib import Path
import pytest
from src.evals.judge import SecurityAgentJudge, EvaluationResult
from src.evals.metrics import AgentMetrics


def test_eval_dataset_structure():
    """Ensure evaluation benchmark dataset is well-formed and structured."""
    dataset_file = Path("tests/eval_dataset.json")
    assert dataset_file.exists(), "eval_dataset.json must exist"
    
    with open(dataset_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert len(data) >= 10
    for item in data:
        assert "id" in item
        assert "category" in item
        assert "query" in item
        assert "should_contain_tool" in item


def test_judge_rule_based_evaluation():
    """Verify Judge deterministic evaluation for CI/CD gates."""
    judge = SecurityAgentJudge()
    tools_used = [
        {"iteration": 1, "tool": "lookup_cve_details", "args": {"cve_id": "CVE-2024-5510"}, "output": {"cvss": 9.8}}
    ]
    answer = "Lỗ hổng CVE-2024-5510 là lỗi SQL Injection nguy hiểm (CVSS 9.8). Bạn cần dùng Parameterized Queries để vá lỗi."

    result = judge.evaluate_rule_based(
        user_query="Kiểm tra CVE-2024-5510",
        tools_used=tools_used,
        agent_answer=answer,
        expected_tool="lookup_cve_details",
        expected_keywords=["CWE-89", "SQL Injection", "9.8"]
    )

    assert isinstance(result, EvaluationResult)
    assert result.tool_accuracy_score == 5
    assert result.faithfulness_score >= 4
    assert result.hallucination_detected is False


def test_agent_metrics_tracking():
    """Verify observability metrics recording and summary computation."""
    metrics = AgentMetrics()
    metrics.record_run(
        duration_seconds=0.85,
        tools_used=[{"tool": "lookup_cve_details", "output": {"status": "FOUND"}}],
        success=True
    )
    summary = metrics.summary()
    assert summary["total_requests"] == 1
    assert summary["average_latency_sec"] == 0.85
    assert summary["tool_success_rate"] == 100.0
    assert "lookup_cve_details" in summary["tool_usage_breakdown"]
