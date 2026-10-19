"""Unit tests for Multi-turn Session Memory and Automated Shadow Evaluation."""

import json
from pathlib import Path
from fastapi.testclient import TestClient
from src.main import app
from src.agent.memory import SessionMemoryManager
import src.evals.shadow as shadow_module
from src.evals.judge import EvaluationResult
from src.evals.metrics import agent_metrics

client = TestClient(app)


def test_session_memory_persistence(tmp_path):
    """Verify session memory persists turns to SQLite and can clear session."""
    db_file = tmp_path / "test_sessions.db"
    mgr = SessionMemoryManager(db_path=db_file, max_turns=4)

    sess_id = "soc_analyst_001"
    mgr.add_turn(sess_id, "user", "Phân tích mã CVE-2024-5510")
    mgr.add_turn(sess_id, "model", "Lỗ hổng CVE-2024-5510 là SQL Injection CVSS 9.8.")

    history = mgr.get_history(sess_id)
    assert len(history) == 2
    assert history[0]["role"] == "user"
    assert "CVE-2024-5510" in history[0]["content"]
    assert history[1]["role"] == "model"
    assert "SQL Injection" in history[1]["content"]

    mgr.clear_session(sess_id)
    assert len(mgr.get_history(sess_id)) == 0


def test_session_memory_sliding_window(tmp_path):
    """Verify sliding window bounds memory to the last max_turns pairs."""
    db_file = tmp_path / "test_sliding.db"
    mgr = SessionMemoryManager(db_path=db_file, max_turns=2)  # Max 2 turns = 4 messages

    sess_id = "sliding_sess"
    for i in range(5):
        mgr.add_turn(sess_id, "user", f"Question {i}")
        mgr.add_turn(sess_id, "model", f"Answer {i}")

    history = mgr.get_history(sess_id)
    assert len(history) == 4
    assert history[0]["content"] == "Question 3"
    assert history[1]["content"] == "Answer 3"
    assert history[2]["content"] == "Question 4"
    assert history[3]["content"] == "Answer 4"


def test_gemini_contents_conversion(tmp_path):
    """Verify conversion to Gemini Content objects with current query appended."""
    db_file = tmp_path / "test_gemini.db"
    mgr = SessionMemoryManager(db_path=db_file, max_turns=2)

    sess_id = "gemini_sess"
    mgr.add_turn(sess_id, "user", "Đoạn mã này có lỗ hổng gì?")
    mgr.add_turn(sess_id, "model", "Lỗ hổng Command Injection.")

    contents = mgr.get_gemini_contents(sess_id, "Làm sao để sửa nó?")
    assert len(contents) == 3
    assert contents[0].role == "user"
    assert contents[1].role == "model"
    assert contents[2].role == "user"
    assert contents[2].parts[0].text == "Làm sao để sửa nó?"


def test_shadow_evaluation_golden_harvesting(tmp_path, monkeypatch):
    """Verify high-quality evaluations are harvested to sft_golden.jsonl."""
    harvest_dir = tmp_path / "harvested"
    monkeypatch.setattr(shadow_module, "HARVESTED_DIR", harvest_dir)

    # Mock judge to return a perfect score
    def mock_eval(*args, **kwargs):
        return EvaluationResult(
            tool_accuracy_score=5,
            faithfulness_score=5,
            remediation_quality_score=5,
            hallucination_detected=False,
            critique="Hoàn hảo và chuẩn xác tuyệt đối."
        )

    monkeypatch.setattr(shadow_module.judge, "evaluate", mock_eval)

    shadow_module.shadow_evaluate_and_harvest(
        session_id="sess_golden_01",
        user_query="Hướng dẫn sửa SQL Injection",
        tools_used=[{"tool": "search_security_knowledge", "output": {"status": "FOUND"}}],
        agent_answer="Sử dụng Parameterized Queries theo chuẩn OWASP.",
        latency_seconds=0.45
    )

    golden_file = harvest_dir / "sft_golden.jsonl"
    assert golden_file.exists()
    with open(golden_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["session_id"] == "sess_golden_01"
        assert len(data["messages"]) == 2
        assert data["evaluation"]["faithfulness"] == 5


def test_shadow_evaluation_review_queue(tmp_path, monkeypatch):
    """Verify hallucinated or low-score executions are routed to review_queue.jsonl."""
    harvest_dir = tmp_path / "harvested_review"
    monkeypatch.setattr(shadow_module, "HARVESTED_DIR", harvest_dir)

    def mock_eval_bad(*args, **kwargs):
        return EvaluationResult(
            tool_accuracy_score=2,
            faithfulness_score=2,
            remediation_quality_score=2,
            hallucination_detected=True,
            critique="Phát hiện ảo giác: mã CVE không tồn tại."
        )

    monkeypatch.setattr(shadow_module.judge, "evaluate", mock_eval_bad)

    shadow_module.shadow_evaluate_and_harvest(
        session_id="sess_bad_01",
        user_query="Kiểm tra mã CVE-9999-9999",
        tools_used=[],
        agent_answer="Mã CVE-9999-9999 là lỗ hổng nghiêm trọng.",
        latency_seconds=0.88
    )

    review_file = harvest_dir / "review_queue.jsonl"
    assert review_file.exists()
    with open(review_file, "r", encoding="utf-8") as f:
        data = json.loads(f.readline())
        assert data["evaluation"]["hallucination_detected"] is True


def test_api_session_endpoints():
    """Verify API session inspection and deletion endpoints."""
    sess_id = "api_test_session_xyz"
    # 1. Clear initially
    del_res = client.delete(f"/api/v1/agent/session/{sess_id}")
    assert del_res.status_code == 200

    # 2. Get history (should be empty)
    get_res = client.get(f"/api/v1/agent/session/{sess_id}")
    assert get_res.status_code == 200
    assert get_res.json()["total_messages"] == 0

    # 3. Add turn through agent memory
    from src.agent.memory import session_memory
    session_memory.add_turn(sess_id, "user", "Tin nhắn kiểm thử")
    session_memory.add_turn(sess_id, "model", "Phản hồi kiểm thử")

    # 4. Get history again
    get_res2 = client.get(f"/api/v1/agent/session/{sess_id}")
    assert get_res2.status_code == 200
    assert get_res2.json()["total_messages"] == 2

    # 5. Clean up
    client.delete(f"/api/v1/agent/session/{sess_id}")
