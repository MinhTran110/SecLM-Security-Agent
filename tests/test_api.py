from fastapi.testclient import TestClient
from src.main import app
from src.api.routes import agent

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_list_tools_endpoint():
    response = client.get("/api/v1/tools")
    assert response.status_code == 200
    tools = response.json()["tools"]
    assert any(t["name"] == "lookup_cve_details" for t in tools)
    assert any(t["name"] == "analyze_source_code" for t in tools)
    assert any(t["name"] == "scan_file_hash" for t in tools)

def test_metrics_endpoint():
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert "governance" in data

def test_feedback_endpoint():
    payload = {
        "session_id": "test-session-01",
        "rating": 5,
        "is_positive": True,
        "comments": "Phân tích chuẩn xác!"
    }
    response = client.post("/api/v1/feedback", json=payload)
    assert response.status_code == 201
    assert response.json()["status"] == "recorded"

def test_agent_chat_endpoint(monkeypatch):
    def mock_run(query: str):
        return {
            "answer": "Mock phân tích: Lỗ hổng CVE-2024-5510 là SQL Injection.",
            "tools_used": [
                {"iteration": 1, "tool": "lookup_cve_details", "args": {"cve_id": "CVE-2024-5510"}, "output": {}}
            ],
            "iterations": 1,
            "latency_seconds": 0.45
        }

    monkeypatch.setattr(agent, "run", mock_run)

    payload = {
        "query": "Kiểm tra nhanh mã CVE-2024-5510 thuộc loại lỗ hổng gì?",
        "session_id": "test-session-01"
    }
    response = client.post("/api/v1/agent/chat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["session_id"] == "test-session-01"
    assert len(data["tools_used"]) >= 1
    assert data["tools_used"][0]["tool"] == "lookup_cve_details"
