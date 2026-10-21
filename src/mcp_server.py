"""SecLM Enterprise Security Agent - Model Context Protocol (MCP) Server.

Exposes security tools, enterprise policies, and incident response prompts
to any MCP-compliant client (Claude Desktop, Cursor, Antigravity, or peer agents).
"""

import sys
import argparse
from typing import List, Dict, Any, Optional

try:
    from mcp.server import MCPServer
except ImportError:
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError:
        raise ImportError("Thư viện 'mcp' chưa được cài đặt. Hãy cài bằng 'pip install mcp'.")

from src.tools.registry import registry
from src.config import settings
from src.agent.prompts import SECLM_SYSTEM_PROMPT
import src.tools  # Tự động nạp toàn bộ tools vào registry

# 1. Khởi tạo MCP Server chuẩn hóa
mcp_server = MCPServer(
    name="SecLM-Security-Agent",
    instructions=(
        "SecLM Enterprise Security MCP Server cung cấp kho công cụ an ninh mạng, "
        "rà soát mã nguồn, phân tích CVE, quét cổng mạng và phát hiện bất thường kết nối."
    ),
)


# =========================================================================
# 2. MCP Tools: 6 Công cụ Điều tra & Phòng thủ An ninh Mạng
# =========================================================================

@mcp_server.tool()
def lookup_cve_details(cve_id: str) -> Dict[str, Any]:
    """Tra cứu thông tin chi tiết, điểm CVSS, mã CWE và hướng dẫn khắc phục của một mã lỗ hổng CVE chuẩn.

    Args:
        cve_id: Mã định danh CVE (ví dụ: 'CVE-2024-5510' hoặc 'CVE-2021-44228').
    """
    return registry.execute("lookup_cve_details", cve_id=cve_id)


@mcp_server.tool()
def analyze_source_code(source_code: str) -> Dict[str, Any]:
    """Phân tích tĩnh mã nguồn Python bằng AST để phát hiện lỗ hổng SQLi (CWE-89), Eval RCE (CWE-95), lộ Secret (CWE-798).

    Args:
        source_code: Chuỗi mã nguồn Python cần quét an ninh.
    """
    return registry.execute("analyze_source_code", source_code=source_code)


@mcp_server.tool()
def scan_file_hash(file_hash: str) -> Dict[str, Any]:
    """Quét mã băm SHA256 hoặc MD5 của tập tin đáng ngờ để đối chiếu với kho mẫu mã độc (Malware Threat Intel).

    Args:
        file_hash: Chuỗi hash SHA256 (64 ký tự) hoặc MD5 (32 ký tự).
    """
    return registry.execute("scan_file_hash", file_hash=file_hash)


@mcp_server.tool()
def audit_port_security(host: str, open_ports: List[int]) -> Dict[str, Any]:
    """Đối chiếu danh sách cổng mạng đang mở trên máy chủ với Chính sách An ninh Doanh nghiệp (Enterprise Port Policy).

    Phát hiện các cổng dịch vụ nhạy cảm (Redis 6379, MySQL 3306, PostgreSQL 5432, SSH 22) bị mở public ra Internet
    và tự động tạo lệnh đóng cổng trên tường lửa UFW/IPTables.

    Args:
        host: Tên hoặc IP máy chủ mục tiêu (ví dụ: 'srv-payment-prod-01' hoặc '103.27.60.15').
        open_ports: Danh sách các số cổng TCP/UDP đang mở (ví dụ: [80, 443, 6379]).
    """
    return registry.execute("audit_port_security", host=host, open_ports=open_ports)


@mcp_server.tool()
def detect_network_anomalies(log_snippet: str) -> Dict[str, Any]:
    """Phân tích log mạng hoặc tường lửa (UFW, IPTables, Syslog) để phát hiện Port Scan (MITRE T1046) hoặc SSH Brute Force (T1110).

    Args:
        log_snippet: Đoạn trích các dòng log kết nối mạng hoặc cảnh báo tường lửa.
    """
    return registry.execute("detect_network_anomalies", log_snippet=log_snippet)


@mcp_server.tool()
def search_security_knowledge(topic: str) -> Dict[str, Any]:
    """Tra cứu kho tri thức bảo mật chuẩn CWE, OWASP Top 10 và hướng dẫn phòng chống bằng Hybrid RAG.

    Args:
        topic: Từ khóa lỗ hổng hoặc mã phân loại (ví dụ: 'SQL Injection', 'CWE-89', 'SSRF', 'XSS').
    """
    return registry.execute("search_security_knowledge", topic=topic)


# =========================================================================
# 3. MCP Resources: Tài nguyên Dữ liệu Chuẩn Hóa (`security://...`)
# =========================================================================

@mcp_server.resource("security://policies/port-baseline")
def get_enterprise_port_policy() -> str:
    """Trả về chính sách an ninh mạng và cổng dịch vụ chuẩn của doanh nghiệp."""
    return f"""# CHÍNH SÁCH BẢO MẬT CỔNG MẠNG DOANH NGHIỆP (PORT SECURITY BASELINE)
Phiên bản: 2.0 - Trạng thái: BẮT BUỘC ÁP DỤNG

1. CỔNG MỞ CÔNG KHAI (ALLOWED_PUBLIC_PORTS):
- Danh sách cho phép: [{settings.ALLOWED_PUBLIC_PORTS}]
- Quy định: Chỉ các cổng phục vụ Web Traffic mã hóa (HTTPS 443, HTTP 80 redirect) được phép lắng nghe trên 0.0.0.0/0.

2. CỔNG NHẠY CẢM CẤM MỞ RA INTERNET (CRITICAL_RESTRICTED_PORTS):
- Danh sách cấm tuyệt đối: [{settings.CRITICAL_RESTRICTED_PORTS}]
- Cổng Database: 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL), 27017 (MongoDB).
- Cổng Cache / Message Queue: 6379 (Redis).
- Cổng Quản trị từ xa: 22 (SSH), 3389 (RDP).
- Xử lý vi phạm: Bắt buộc kích hoạt Human-in-the-Loop và thực thi lệnh đóng cổng ngay lập tức.

3. QUY TRÌNH PHÊ DUYỆT (HITL):
- Cờ kiểm soát: ENABLE_HUMAN_IN_THE_LOOP={settings.ENABLE_HUMAN_IN_THE_LOOP}
- Mọi lệnh can thiệp tường lửa phải có chữ ký xác nhận của Chuyên viên SOC L2 trở lên.
"""


@mcp_server.resource("security://mitre/attack-matrix")
def get_mitre_attack_matrix() -> str:
    """Trả về bảng ánh xạ phân loại kỹ thuật tấn công MITRE ATT&CK phổ biến."""
    return """# BẢNG ÁNH XẠ KỸ THUẬT TẤN CÔNG MITRE ATT&CK
1. T1046 - Network Service Discovery (Port Scan / Reconnaissance):
   - Mô tả: Kẻ tấn công thăm dò các cổng và dịch vụ đang lắng nghe trên máy chủ.
   - Ứng phó: Chặn IP nguồn trên tường lửa, tăng cường rate-limiting.

2. T1110 - Brute Force (Password Guessing):
   - Mô tả: Thử mật khẩu dồn dập vào cổng quản trị SSH (22) hoặc RDP (3389).
   - Ứng phó: Kích hoạt Fail2ban, đổi cổng mặc định, bắt buộc dùng SSH Key.

3. T1190 - Exploit Public-Facing Application:
   - Mô tả: Khai thác lỗ hổng ứng dụng web (SQLi, SSRF, RCE) thông qua đầu vào người dùng.
   - Ứng phó: Áp dụng WAF, vá code parameterized queries, cập nhật thư viện phụ thuộc.
"""


@mcp_server.resource("security://agent/system-prompt")
def get_security_agent_prompt() -> str:
    """Trả về System Prompt chỉ dẫn phân tích an ninh chuyên sâu của SecLM."""
    return SECLM_SYSTEM_PROMPT


# =========================================================================
# 4. MCP Prompts: Các Mẫu Quy trình Ứng cứu & Đánh giá Sự cố Dựng Sẵn
# =========================================================================

@mcp_server.prompt()
def triage_security_incident(cve_or_alert: str, target_system: str = "production-server") -> str:
    """Tạo mẫu hướng dẫn AI điều tra sự cố an ninh toàn diện theo quy trình SOC L2."""
    return f"""Bạn là Chuyên gia An ninh Cấp cao (SOC Lead) đang ứng cứu sự cố bảo mật.
Mục tiêu bị ảnh hưởng: {target_system}
Thông tin cảnh báo / Lỗ hổng: {cve_or_alert}

Hãy thực hiện điều tra theo quy trình 4 bước chuẩn hóa:
1. Xác minh: Sử dụng tool `lookup_cve_details` hoặc `search_security_knowledge` để hiểu bản chất kỹ thuật.
2. Đánh giá tác động: Xác định nguy cơ True Positive, CVSS score và mức độ thiệt hại tiềm tàng.
3. Soạn thảo khắc phục: Viết lệnh hoặc code patch an toàn, không gây gián đoạn dịch vụ.
4. Kiểm soát HITL: Đưa ra đề xuất rõ ràng để Kỹ sư phê duyệt trước khi áp dụng.
"""


@mcp_server.prompt()
def audit_code_vulnerability(source_code: str, language: str = "python") -> str:
    """Tạo mẫu hướng dẫn AI rà soát mã nguồn tìm lỗ hổng bảo mật và đề xuất code vá chuẩn."""
    return f"""Hãy thực hiện kiểm tra an ninh mã nguồn tĩnh (SAST) cho đoạn mã {language} sau:
```
{source_code}
```

Nhiệm vụ:
1. Gọi tool `analyze_source_code` để phân tích các hàm nguy hiểm.
2. Chỉ rõ số dòng, loại lỗ hổng (CWE-89, CWE-95, CWE-798...) và mức độ rủi ro.
3. Cung cấp khối mã thay thế an toàn (Secure Implementation) theo tiêu chuẩn OWASP.
"""


@mcp_server.prompt()
def remediate_port_violation(host: str, open_ports: str) -> str:
    """Tạo mẫu hướng dẫn AI xử lý máy chủ mở nhầm cổng mạng vi phạm chính sách."""
    return f"""Máy chủ {host} được báo cáo đang mở danh sách cổng sau ra ngoài Internet: [{open_ports}].

Nhiệm vụ:
1. Đọc chính sách từ resource `security://policies/port-baseline`.
2. Gọi tool `audit_port_security` để đối chiếu vi phạm.
3. Soạn thảo kịch bản lệnh đóng cổng an toàn trên tường lửa UFW và xuất Action ID chờ người duyệt.
"""


# =========================================================================
# 5. CLI Entrypoint: Hỗ trợ Chạy stdio (IDE / Local) hoặc SSE (Remote Network)
# =========================================================================

def main():
    parser = argparse.ArgumentParser(description="SecLM Model Context Protocol (MCP) Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Giao thức truyền tin MCP: 'stdio' (cho Claude Desktop/IDE) hoặc 'sse' (cho network HTTP microservice)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Địa chỉ host khi chạy chế độ SSE")
    parser.add_argument("--port", type=int, default=8001, help="Cổng lắng nghe khi chạy chế độ SSE")

    args = parser.parse_args()

    if args.transport == "sse":
        print(f"[SecLM MCP] Khởi chạy MCP Server qua giao thức SSE tại http://{args.host}:{args.port}/sse ...")
        mcp_server.run(transport="sse")
    else:
        # Chế độ mặc định: stdio
        mcp_server.run(transport="stdio")


if __name__ == "__main__":
    main()
