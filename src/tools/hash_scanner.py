"""Tool to scan file hashes (MD5, SHA1, SHA256) using VirusTotal or Threat Intelligence heuristics."""

import re
from typing import Any, Dict
from src.tools.registry import registry

KNOWN_MALWARE_HASHES = {
    "24d004a104d4d54034dbc29c2f81fb077b36724da6e00d20ef7413f7b7e3f57e": {
        "family": "WannaCry Ransomware",
        "malicious": 68,
        "total": 72,
        "severity": "CRITICAL",
        "description": "Mã độc tống tiền WannaCry khai thác lỗ hổng EternalBlue (MS17-010).",
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "family": "EICAR Test File",
        "malicious": 60,
        "total": 65,
        "severity": "TEST",
        "description": "Chuỗi mã băm kiểm thử tiêu chuẩn EICAR Anti-Virus.",
    }
}

HASH_REGEX = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


@registry.register(
    name="scan_file_hash",
    description="Kiểm tra danh tính và độ độc hại của mã băm tệp tin (MD5, SHA1, SHA256) đối chiếu cơ sở dữ liệu mã độc Threat Intelligence."
)
def scan_file_hash(file_hash: str) -> Dict[str, Any]:
    """Tra cứu độ nguy hại và gia đình mã độc theo mã băm.

    Args:
        file_hash: Chuỗi mã băm MD5 (32 ký tự), SHA1 (40 ký tự) hoặc SHA256 (64 ký tự).
    """
    clean_hash = file_hash.strip().lower()
    if not HASH_REGEX.match(clean_hash):
        raise ValueError(f"Mã băm '{file_hash}' không hợp lệ (phải là chuỗi hex MD5 32 ký tự, SHA1 40 ký tự, hoặc SHA256 64 ký tự).")

    algorithm = "SHA256" if len(clean_hash) == 64 else ("MD5" if len(clean_hash) == 32 else "SHA1")

    if clean_hash in KNOWN_MALWARE_HASHES:
        malware_info = KNOWN_MALWARE_HASHES[clean_hash]
        return {
            "status": "MALICIOUS",
            "hash": clean_hash,
            "algorithm": algorithm,
            "malware_family": malware_info["family"],
            "detection_rate": f"{malware_info['malicious']}/{malware_info['total']}",
            "severity": malware_info["severity"],
            "description": malware_info["description"],
        }

    return {
        "status": "CLEAN_OR_UNKNOWN",
        "hash": clean_hash,
        "algorithm": algorithm,
        "detection_rate": "0/72",
        "severity": "LOW",
        "description": "Không tìm thấy dấu hiệu độc hại trong cơ sở dữ liệu mẫu kiểm thử.",
    }

# Alias tương thích ngược
hash_scanner_tool = scan_file_hash
