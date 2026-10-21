import pytest
from src.tools.registry import registry
import src.tools.port_scanner


def test_audit_port_security_fully_compliant():
    """Kiểm tra máy chủ chỉ mở cổng 80, 443 thì hoàn toàn tuân thủ chính sách."""
    res = registry.execute("audit_port_security", host="10.0.0.1", open_ports=[80, 443])
    assert res["status"] == "COMPLETED"
    assert res["overall_status"] == "FULLY_COMPLIANT"
    assert res["requires_hitl_approval"] is False
    assert all(f["status"] == "COMPLIANT" for f in res["findings"])


def test_audit_port_security_critical_database_exposed():
    """Kiểm tra phát hiện mở nhầm cổng Redis 6379 và MySQL 3306 ra ngoài."""
    res = registry.execute("audit_port_security", host="srv-payment-01", open_ports=[80, 443, 6379, 3306])
    assert res["status"] == "COMPLETED"
    assert res["overall_status"] == "CRITICAL_VIOLATIONS_FOUND"
    assert res["requires_hitl_approval"] is True

    # Tìm finding cho cổng 6379
    redis_finding = next(f for f in res["findings"] if f["port"] == 6379)
    assert redis_finding["status"] == "CRITICAL_VIOLATION"
    assert redis_finding["severity"] == "CRITICAL"
    assert "Redis" in redis_finding["service"]
    assert "ufw deny 6379/tcp" in res["suggested_remediation_script"]


def test_audit_port_security_unauthorized_port():
    """Kiểm tra cổng không nằm trong danh mục cho phép mở Public."""
    res = registry.execute("audit_port_security", host="srv-dev-01", open_ports=[80, 8088])
    assert res["overall_status"] == "VIOLATIONS_FOUND"
    unauth_finding = next(f for f in res["findings"] if f["port"] == 8088)
    assert unauth_finding["status"] == "UNAUTHORIZED_PORT"
    assert unauth_finding["severity"] == "MEDIUM"


def test_audit_port_security_invalid_input():
    """Kiểm tra ném lỗi khi đầu vào không phải danh sách."""
    with pytest.raises(ValueError, match="open_ports phải là một danh sách"):
        registry.execute("audit_port_security", host="127.0.0.1", open_ports="80,443")


def test_detect_network_anomalies_port_scan():
    """Kiểm tra phát hiện rà quét cổng dồn dập (MITRE ATT&CK T1046)."""
    mock_log = """
    2026-10-21 10:15:01 [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.5 DPT=21 PROTO=TCP
    2026-10-21 10:15:02 [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.5 DPT=22 PROTO=TCP
    2026-10-21 10:15:03 [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.5 DPT=80 PROTO=TCP
    2026-10-21 10:15:04 [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.5 DPT=445 PROTO=TCP
    2026-10-21 10:15:05 [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.5 DPT=3389 PROTO=TCP
    """
    res = registry.execute("detect_network_anomalies", log_snippet=mock_log)
    assert res["status"] == "COMPLETED"
    assert res["anomalies_detected"] >= 1
    threat = res["threats"][0]
    assert threat["type"] == "PORT_SCANNING"
    assert threat["attacker_ip"] == "185.220.101.5"
    assert threat["severity"] == "HIGH"
    assert 21 in threat["targeted_ports"]
    assert "ufw insert 1 deny from 185.220.101.5" in threat["suggested_action"]


def test_detect_network_anomalies_ssh_brute_force():
    """Kiểm tra phát hiện tấn công vét cạn mật khẩu SSH (MITRE ATT&CK T1110)."""
    mock_log = """
    Failed password for invalid user admin from 45.155.205.10 port 22 ssh2
    Failed password for root from 45.155.205.10 port 22 ssh2
    Failed password for invalid user test from 45.155.205.10 port 22 ssh2
    Failed password for ubuntu from 45.155.205.10 port 22 ssh2
    """
    res = registry.execute("detect_network_anomalies", log_snippet=mock_log)
    assert res["status"] == "COMPLETED"
    assert res["anomalies_detected"] >= 1
    threat = res["threats"][0]
    assert threat["type"] == "BRUTE_FORCE"
    assert threat["attacker_ip"] == "45.155.205.10"
    assert threat["severity"] == "CRITICAL"


def test_detect_network_anomalies_empty_log():
    """Kiểm tra ném lỗi khi chuỗi log rỗng."""
    with pytest.raises(ValueError, match="không được để trống"):
        registry.execute("detect_network_anomalies", log_snippet="   ")
