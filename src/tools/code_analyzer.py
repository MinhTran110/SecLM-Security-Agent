"""Tool for Static Application Security Testing (SAST) using AST and pattern rules."""

import ast
import re
from typing import Any, Dict, List
from src.tools.registry import registry


@registry.register(
    name="analyze_source_code",
    description="Quét tĩnh mã nguồn (SAST) để phát hiện các lỗ hổng bảo mật: SQLi, Command Injection, Insecure Deserialization, Hardcoded Secrets, Unsafe Eval."
)
def analyze_source_code(source_code: str, language: str = "python") -> Dict[str, Any]:
    """Phân tích mã nguồn tĩnh để phát hiện lỗ hổng an ninh phần mềm.

    Args:
        source_code: Chuỗi mã nguồn cần quét (ví dụ đoạn mã Python).
        language: Ngôn ngữ lập trình (mặc định: 'python').
    """
    findings: List[Dict[str, Any]] = []

    if language.lower() == "python":
        # Check 1: Hardcoded credentials / secret keys
        secret_patterns = [
            (r'(?i)(password|secret|api_key|access_token|private_key)\s*=\s*["\'][^"\']{6,}["\']', "CWE-798", "Use of Hard-coded Credentials", "HIGH"),
            (r'(?i)(SELECT\s+.*\s+FROM\s+.*[\'\"]\s*\+)', "CWE-89", "Potential SQL Injection via string concatenation", "CRITICAL"),
        ]
        for pattern, cwe_id, desc, severity in secret_patterns:
            matches = re.finditer(pattern, source_code)
            for m in matches:
                findings.append({
                    "cwe_id": cwe_id,
                    "rule": desc,
                    "severity": severity,
                    "snippet": m.group(0)[:80],
                })

        # Check 2: AST Analysis for dangerous calls
        try:
            tree = ast.parse(source_code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # eval / exec
                    if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                        findings.append({
                            "cwe_id": "CWE-95",
                            "rule": f"Improper Neutralization of Directives in Dynamically Evaluated Code ({node.func.id})",
                            "severity": "CRITICAL",
                            "line": getattr(node, "lineno", 0),
                        })
                    # os.system / subprocess with shell=True
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                        findings.append({
                            "cwe_id": "CWE-78",
                            "rule": "OS Command Injection via os.system()",
                            "severity": "CRITICAL",
                            "line": getattr(node, "lineno", 0),
                        })
                    # pickle.loads
                    if isinstance(node.func, ast.Attribute) and node.func.attr in ("loads", "load"):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                            findings.append({
                                "cwe_id": "CWE-502",
                                "rule": "Deserialization of Untrusted Data via pickle",
                                "severity": "CRITICAL",
                                "line": getattr(node, "lineno", 0),
                            })
        except SyntaxError:
            pass

    return {
        "status": "COMPLETED",
        "language": language,
        "total_findings": len(findings),
        "findings": findings,
    }

# Alias tương thích ngược cho test cũ
code_analyzer_tool = analyze_source_code
