import pytest
from src.tools.registry import registry
import src.tools.cve_lookup
import src.tools.code_analyzer
import src.tools.hash_scanner

def test_tools_are_registered():
    schemas = registry.list_schemas()
    tool_names = [t["name"] for t in schemas]
    assert "lookup_cve_details" in tool_names
    assert "analyze_source_code" in tool_names
    assert "scan_file_hash" in tool_names

def test_lookup_cve_found():
    result = registry.execute("lookup_cve_details", cve_id="cve-2024-5510")
    assert result["status"] == "FOUND"
    assert result["data"]["cwe"] == "CWE-89"

def test_lookup_cve_invalid_format():
    with pytest.raises(ValueError, match="sai định dạng chuẩn"):
        registry.execute("lookup_cve_details", cve_id="SQL-INJECTION-123")

def test_code_analyzer_detects_eval():
    code = "def test(x): return eval(x)"
    res = registry.execute("analyze_source_code", source_code=code)
    assert res["status"] == "COMPLETED"
    assert any(f["cwe_id"] == "CWE-95" for f in res["findings"])

def test_code_analyzer_detects_hardcoded_secret():
    code = "api_key = 'super_secret_token_123456'"
    res = registry.execute("analyze_source_code", source_code=code)
    assert res["status"] == "COMPLETED"
    assert any(f["cwe_id"] == "CWE-798" for f in res["findings"])

def test_hash_scanner_known_malware():
    wannacry = "24d004a104d4d54034dbc29c2f81fb077b36724da6e00d20ef7413f7b7e3f57e"
    res = registry.execute("scan_file_hash", file_hash=wannacry)
    assert res["status"] == "MALICIOUS"
    assert "WannaCry" in res["malware_family"]

def test_tool_governance_missing_required_params():
    with pytest.raises(ValueError, match="thiếu các tham số bắt buộc"):
        registry.execute("lookup_cve_details")

def test_execute_unregistered_tool():
    with pytest.raises(KeyError, match="chưa được đăng ký"):
        registry.execute("non_existent_tool", target="127.0.0.1")
