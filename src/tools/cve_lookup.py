import re
from typing import Dict, Any, Optional
from src.tools.registry import registry

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

MOCK_CVE_DB = {
    "CVE-2024-5510": {
        "cve_id": "CVE-2024-5510",
        "cwe": "CWE-89",
        "vulnerability_type": "SQL Injection",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "remediation": "Sử dụng Parameterized Queries thay vì nối chuỗi trực tiếp."
    },
    "CVE-2023-44487": {
        "cve_id": "CVE-2023-44487",
        "cwe": "CWE-400",
        "vulnerability_type": "HTTP/2 Rapid Reset DDoS",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "remediation": "Cập nhật bản vá cho Web Server và giới hạn concurrent streams."
    },
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "cwe": "CWE-502",
        "vulnerability_type": "Log4Shell JNDI Remote Code Execution",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "remediation": "Nâng cấp Log4j lên phiên bản >= 2.17.1 hoặc thiết lập log4j2.formatMsgNoLookups=true."
    },
    "CVE-2022-22965": {
        "cve_id": "CVE-2022-22965",
        "cwe": "CWE-94",
        "vulnerability_type": "Spring4Shell Remote Code Execution",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "remediation": "Nâng cấp Spring Framework lên 5.3.18+ hoặc 5.2.20+."
    }
}

@registry.register(
    name="lookup_cve_details",
    description="Tra cứu thông tin chi tiết, điểm CVSS, mã CWE và cách khắc phục của một mã lỗ hổng CVE."
)
def lookup_cve_details(cve_id: str) -> Dict[str, Any]:
    """Tra cứu thông tin lỗ hổng bảo mật theo mã CVE chuẩn.

    Args:
        cve_id: Mã định danh CVE (ví dụ: CVE-2024-5510).
    """
    normalized_id = cve_id.strip().upper()
    if not CVE_REGEX.match(normalized_id):
        raise ValueError(f"Mã '{cve_id}' sai định dạng chuẩn (CVE-YYYY-NNNN).")

    if normalized_id in MOCK_CVE_DB:
        return {"status": "FOUND", "data": MOCK_CVE_DB[normalized_id]}

    return {"status": "NOT_FOUND", "message": f"Không tìm thấy dữ liệu cho mã {normalized_id}."}

# Alias tương thích ngược cho test cũ
def cve_lookup_tool(query: str, cve_id: Optional[str] = None) -> Dict[str, Any]:
    target = cve_id if cve_id else query
    try:
        res = lookup_cve_details(target)
        if res["status"] == "FOUND":
            return {"status": "success", "results": [res["data"]]}
        return {"status": "success", "results": []}
    except Exception:
        return {"status": "error", "results": []}
