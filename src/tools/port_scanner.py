"""Network & Port Security Tool for Enterprise Baseline Auditing and Anomaly Detection."""

import re
from typing import Dict, Any, List, Optional
from src.tools.registry import registry
from src.config import settings

# Danh mục ánh xạ tên dịch vụ cho các cổng phổ biến
PORT_SERVICE_MAP: Dict[int, str] = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Shell)",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Traffic)",
    110: "POP3 (Mail)",
    143: "IMAP (Mail)",
    443: "HTTPS (Encrypted Web Traffic)",
    445: "SMB (File Sharing)",
    1433: "MSSQL (Microsoft SQL Server)",
    1521: "Oracle DB",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    6379: "Redis In-Memory Cache/DB",
    8080: "HTTP-Alt / Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch REST API",
    27017: "MongoDB Database",
}


def _parse_port_list(ports_str: str) -> List[int]:
    """Chuyển chuỗi cổng phân cách bằng dấu phẩy sang danh sách số nguyên."""
    if not ports_str:
        return []
    res = []
    for item in ports_str.split(","):
        item = item.strip()
        if item.isdigit():
            res.append(int(item))
    return res


@registry.register(
    name="audit_port_security",
    description="Kiểm tra đối chiếu danh sách cổng mạng đang mở trên máy chủ với Chính sách An ninh Doanh nghiệp (Enterprise Port Policy) để phát hiện mở nhầm cổng nhạy cảm (Redis, MySQL, SSH...).",
)
def audit_port_security(host: str, open_ports: List[int]) -> Dict[str, Any]:
    """Đối chiếu cổng đang mở với chính sách an ninh doanh nghiệp."""
    if not isinstance(open_ports, list):
        raise ValueError("open_ports phải là một danh sách các số cổng (List[int]).")

    allowed_public = set(_parse_port_list(settings.ALLOWED_PUBLIC_PORTS))
    critical_restricted = set(_parse_port_list(settings.CRITICAL_RESTRICTED_PORTS))

    findings = []
    has_critical = False
    remediation_commands = []

    for port in open_ports:
        service_name = PORT_SERVICE_MAP.get(port, f"Cổng dịch vụ tùy chỉnh {port}")

        if port in critical_restricted:
            has_critical = True
            finding = {
                "port": port,
                "service": service_name,
                "status": "CRITICAL_VIOLATION",
                "severity": "CRITICAL",
                "risk_description": (
                    f"Cổng nhạy cảm {port} ({service_name}) đang mở public ra ngoài Internet. "
                    "Vi phạm nghiêm trọng chính sách cách ly dịch vụ cốt lõi, nguy cơ rò rỉ dữ liệu hoặc bị khai thác tống tiền (Ransomware)."
                ),
                "remediation": f"ufw deny {port}/tcp && ufw reload",
            }
            findings.append(finding)
            remediation_commands.append(f"ufw deny {port}/tcp")
        elif port not in allowed_public:
            finding = {
                "port": port,
                "service": service_name,
                "status": "UNAUTHORIZED_PORT",
                "severity": "MEDIUM",
                "risk_description": (
                    f"Cổng {port} ({service_name}) không nằm trong danh mục được phép mở Public ({settings.ALLOWED_PUBLIC_PORTS}). "
                    "Cần rà soát xem đây có phải dịch vụ dev thử nghiệm bị bỏ quên không."
                ),
                "remediation": f"ufw deny {port}/tcp",
            }
            findings.append(finding)
            remediation_commands.append(f"ufw deny {port}/tcp")
        else:
            findings.append({
                "port": port,
                "service": service_name,
                "status": "COMPLIANT",
                "severity": "SAFE",
                "risk_description": f"Cổng {port} ({service_name}) tuân thủ chính sách cho phép mở public.",
                "remediation": None,
            })

    overall_status = "CRITICAL_VIOLATIONS_FOUND" if has_critical else ("VIOLATIONS_FOUND" if any(f["status"] != "COMPLIANT" for f in findings) else "FULLY_COMPLIANT")

    combined_script = " && ".join(remediation_commands) + " && ufw reload" if remediation_commands else None

    return {
        "status": "COMPLETED",
        "host": host,
        "overall_status": overall_status,
        "scanned_ports_count": len(open_ports),
        "policy_allowed_ports": sorted(list(allowed_public)),
        "policy_restricted_ports": sorted(list(critical_restricted)),
        "findings": findings,
        "requires_hitl_approval": has_critical or bool(remediation_commands),
        "suggested_remediation_script": combined_script,
    }


@registry.register(
    name="detect_network_anomalies",
    description="Phân tích đoạn trích log mạng (tường lửa IPTables/UFW/Nginx/Syslog) để phát hiện hành vi rà quét cổng dồn dập (Port Scan - MITRE ATT&CK T1046) hoặc Brute Force.",
)
def detect_network_anomalies(log_snippet: str) -> Dict[str, Any]:
    """Phân tích log mạng phát hiện các mẫu rà quét cổng và tấn công vét cạn."""
    if not log_snippet or not log_snippet.strip():
        raise ValueError("log_snippet không được để trống.")

    lines = log_snippet.strip().splitlines()

    # Regex trích xuất IP và Port từ các mẫu log phổ biến (UFW BLOCK, Nginx, iptables, syslog)
    ip_pattern = re.compile(r"(?:SRC=|from\s+|ip\s+)?(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)")
    port_pattern = re.compile(r"(?:DPT=|port\s+|to\s+port\s+)(\d{1,5})", re.IGNORECASE)

    # Thống kê IP -> tập hợp các cổng bị gõ cửa
    ip_to_ports: Dict[str, set] = {}
    ip_to_fail_counts: Dict[str, int] = {}

    for line in lines:
        ips = ip_pattern.findall(line)
        ports = port_pattern.findall(line)

        # Lấy IP nguồn (nếu có)
        src_ip = None
        for ip in ips:
            # Loại trừ localhost
            if not ip.startswith("127."):
                src_ip = ip
                break

        if src_ip:
            if src_ip not in ip_to_ports:
                ip_to_ports[src_ip] = set()
            for p in ports:
                try:
                    ip_to_ports[src_ip].add(int(p))
                except ValueError:
                    pass

            if any(term in line.lower() for term in ["failed", "invalid user", "drop", "block", "refused"]):
                ip_to_fail_counts[src_ip] = ip_to_fail_counts.get(src_ip, 0) + 1

    anomalies = []

    for ip, ports in ip_to_ports.items():
        # Dấu hiệu Port Scan: 1 IP thăm dò từ 3 cổng trở lên hoặc chứa từ khóa scan
        if len(ports) >= 3 or any("scan" in l.lower() for l in lines if ip in l):
            sorted_ports = sorted(list(ports))
            anomalies.append({
                "type": "PORT_SCANNING",
                "mitre_technique": "T1046 (Network Service Discovery)",
                "attacker_ip": ip,
                "targeted_ports": sorted_ports,
                "severity": "HIGH",
                "confidence": 0.95,
                "details": f"Phát hiện IP {ip} rà quét liên tiếp {len(sorted_ports)} cổng: {sorted_ports}",
                "suggested_action": f"ufw insert 1 deny from {ip} to any comment 'SecLM Auto-defense: Port Scan'",
            })
        # Dấu hiệu Brute Force nếu dồn dập vào cổng SSH 22 hoặc RDP 3389
        elif ip_to_fail_counts.get(ip, 0) >= 3 and any(p in ports for p in [22, 3389]):
            anomalies.append({
                "type": "BRUTE_FORCE",
                "mitre_technique": "T1110 (Brute Force)",
                "attacker_ip": ip,
                "targeted_ports": sorted(list(ports)),
                "severity": "CRITICAL",
                "confidence": 0.92,
                "details": f"Phát hiện IP {ip} liên tiếp thử đăng nhập thất bại {ip_to_fail_counts[ip]} lần vào cổng dịch vụ quản trị.",
                "suggested_action": f"ufw insert 1 deny from {ip} to any comment 'SecLM Auto-defense: Brute Force'",
            })

    # Nếu không trích xuất được dạng log chi tiết nhưng có từ khóa scan
    if not anomalies and any(k in log_snippet.lower() for k in ["nmap", "masscan", "port scan", "syn flood"]):
        anomalies.append({
            "type": "SUSPECTED_RECONNAISSANCE",
            "mitre_technique": "T1046 (Network Service Discovery)",
            "attacker_ip": "UNKNOWN",
            "targeted_ports": [],
            "severity": "MEDIUM",
            "confidence": 0.75,
            "details": "Đoạn log chứa dấu hiệu công cụ dò quét mạng (Nmap/Masscan). Cần tăng cường giám sát tường lửa.",
            "suggested_action": "ufw status verbose",
        })

    return {
        "status": "COMPLETED",
        "analyzed_lines": len(lines),
        "anomalies_detected": len(anomalies),
        "threats": anomalies,
        "requires_mitigation": len(anomalies) > 0,
    }
