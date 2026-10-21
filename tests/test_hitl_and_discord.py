import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.agent.approval_store import approval_store
from src.integrations.discord_notifier import discord_notifier, DiscordNotifier, SEVERITY_COLORS


@pytest.fixture(autouse=True)
def clean_approval_store():
    """Tự động dọn sạch store trước và sau mỗi test case."""
    approval_store.clear()
    yield
    approval_store.clear()


client = TestClient(app)


def test_approval_store_lifecycle():
    """Kiểm tra toàn bộ vòng đời của một hành động HITL: Tạo -> Duyệt -> Audit."""
    action = approval_store.create_action(
        action_type="BLOCK_PORT",
        target="192.168.1.100",
        severity="CRITICAL",
        proposed_script="ufw deny 6379/tcp",
        description="Đóng cổng Redis lộ lọt",
    )
    action_id = action["action_id"]
    assert action["status"] == "PENDING"
    assert len(approval_store.list_pending()) == 1

    # Phê duyệt
    approved = approval_store.approve_action(action_id, approver="soc_lead_01")
    assert approved["status"] == "APPROVED"
    assert approved["approver"] == "soc_lead_01"
    assert approved["execution_status"] == "SUCCESS_SIMULATED"
    assert len(approval_store.list_pending()) == 0

    # Phê duyệt lại phải báo lỗi
    with pytest.raises(ValueError, match="không thể phê duyệt lại"):
        approval_store.approve_action(action_id)


def test_approval_store_rejection():
    """Kiểm tra từ chối hành động an ninh (False Positive)."""
    action = approval_store.create_action(
        action_type="ISOLATE_IP",
        target="10.0.0.50",
        severity="HIGH",
        proposed_script="iptables -A INPUT -s 10.0.0.50 -j DROP",
        description="Chặn IP nội bộ",
    )
    action_id = action["action_id"]

    rejected = approval_store.reject_action(action_id, reason="IP của hệ thống CI/CD Jenkins", approver="soc_lead_02")
    assert rejected["status"] == "REJECTED"
    assert rejected["rejection_reason"] == "IP của hệ thống CI/CD Jenkins"
    assert rejected["execution_status"] == "CANCELLED"
    assert len(approval_store.list_pending()) == 0


def test_discord_notifier_embed_generation():
    """Kiểm tra tạo cấu trúc Discord Rich Embed và mã màu chuẩn."""
    embed = discord_notifier.build_embed(
        title="Test Alert",
        severity="CRITICAL",
        description="Mô tả cảnh báo thử nghiệm",
        action_id="act-12345",
        remediation_script="ufw deny 22/tcp",
    )
    assert embed["color"] == SEVERITY_COLORS["CRITICAL"]
    assert "act-12345" in embed["fields"][-1]["value"]
    assert "ufw deny 22/tcp" in embed["fields"][-2]["value"]

    # Chế độ gửi mô phỏng khi chưa có webhook
    mock_notifier = DiscordNotifier(webhook_url="")
    send_res = mock_notifier.send_alert(
        title="Test Alert",
        severity="CRITICAL",
        description="Mô tả",
        action_id="act-12345",
    )
    assert send_res["status"] == "SIMULATED"
    assert send_res["webhook_configured"] is False


def test_api_network_audit_ports_triggers_hitl():
    """Kiểm tra gọi API audit cổng mạng phát hiện vi phạm và sinh action HITL."""
    payload = {
        "host": "srv-db-prod",
        "open_ports": [80, 443, 6379],
        "notify_discord": True,
    }
    response = client.post("/api/v1/network/audit-ports", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "COMPLETED"
    assert data["overall_status"] == "CRITICAL_VIOLATIONS_FOUND"
    assert data["requires_hitl_approval"] is True
    assert data["action_id"] is not None

    action_id = data["action_id"]

    # Kiểm tra API pending actions
    pending_res = client.get("/api/v1/actions/pending")
    assert pending_res.status_code == 200
    pending_data = pending_res.json()
    assert pending_data["total_pending"] == 1
    assert pending_data["actions"][0]["action_id"] == action_id

    # Gọi API phê duyệt
    approve_res = client.post(f"/api/v1/actions/{action_id}/approve", json={"approver": "tech_lead_minh"})
    assert approve_res.status_code == 200
    approve_data = approve_res.json()
    assert approve_data["status"] == "approved"
    assert approve_data["action"]["status"] == "APPROVED"
    assert approve_data["action"]["approver"] == "tech_lead_minh"

    # Hàng đợi pending giờ phải rỗng
    pending_after = client.get("/api/v1/actions/pending").json()
    assert pending_after["total_pending"] == 0


def test_api_network_detect_anomalies_triggers_hitl():
    """Kiểm tra gọi API phân tích log phát hiện rà quét và cho phép từ chối (reject)."""
    log_text = """
    2026-10-21 [UFW BLOCK] SRC=198.51.100.22 DPT=22 PROTO=TCP
    2026-10-21 [UFW BLOCK] SRC=198.51.100.22 DPT=80 PROTO=TCP
    2026-10-21 [UFW BLOCK] SRC=198.51.100.22 DPT=443 PROTO=TCP
    2026-10-21 [UFW BLOCK] SRC=198.51.100.22 DPT=8080 PROTO=TCP
    """
    payload = {
        "log_snippet": log_text,
        "notify_discord": True,
    }
    response = client.post("/api/v1/network/detect-anomalies", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["anomalies_detected"] >= 1
    assert len(data["action_ids"]) >= 1

    action_id = data["action_ids"][0]

    # Từ chối action vì đây là bài kiểm thử thâm nhập (Penetration Test) có kế hoạch
    reject_res = client.post(
        f"/api/v1/actions/{action_id}/reject",
        json={"reason": "Penetration Testing theo kế hoạch quý 4", "approver": "lead_auditor"}
    )
    assert reject_res.status_code == 200
    reject_data = reject_res.json()
    assert reject_data["status"] == "rejected"
    assert reject_data["action"]["status"] == "REJECTED"
    assert reject_data["action"]["rejection_reason"] == "Penetration Testing theo kế hoạch quý 4"


def test_api_approve_non_existent_action():
    """Kiểm tra gọi API approve mã action không tồn tại trả về lỗi 404."""
    response = client.post("/api/v1/actions/fake-uuid-9999/approve", json={"approver": "admin"})
    assert response.status_code == 404
