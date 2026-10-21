import pytest
from src.mcp_server import mcp_server, fastmcp_server, FastMCP
from src.tools.mcp_client import MCPClient


def test_fastmcp_export():
    """Kiểm tra export FastMCP và fastmcp_server đúng chuẩn."""
    assert FastMCP is not None
    assert fastmcp_server is not None
    assert fastmcp_server.name == "SecLM-Security-Agent"
    assert fastmcp_server is mcp_server


@pytest.mark.asyncio
async def test_mcp_server_lists_all_tools():
    """Kiểm tra MCP Server quảng bá đầy đủ 6 công cụ an ninh mạng."""
    tools = await mcp_server.list_tools()
    tool_names = [t.name for t in tools]

    expected_tools = [
        "lookup_cve_details",
        "analyze_source_code",
        "scan_file_hash",
        "audit_port_security",
        "detect_network_anomalies",
        "search_security_knowledge",
    ]
    for exp in expected_tools:
        assert exp in tool_names, f"Thiếu công cụ {exp} trong danh sách quảng bá MCP."


@pytest.mark.asyncio
async def test_mcp_server_call_cve_tool():
    """Kiểm tra gọi tool lookup_cve_details qua giao thức MCP."""
    res = await mcp_server.call_tool("lookup_cve_details", {"cve_id": "CVE-2024-5510"})
    assert not res.is_error
    assert len(res.content) > 0
    text = res.content[0].text
    assert "CWE-89" in text
    assert "SQL Injection" in text


@pytest.mark.asyncio
async def test_mcp_server_call_port_audit_tool():
    """Kiểm tra gọi tool audit_port_security qua giao thức MCP."""
    args = {
        "host": "srv-prod-01",
        "open_ports": [80, 443, 6379],
    }
    res = await mcp_server.call_tool("audit_port_security", args)
    assert not res.is_error
    text = res.content[0].text
    assert "CRITICAL_VIOLATIONS_FOUND" in text
    assert "Redis" in text


@pytest.mark.asyncio
async def test_mcp_server_resources():
    """Kiểm tra đọc các tài nguyên chuẩn hóa qua giao thức MCP (security://...)."""
    resources = await mcp_server.list_resources()
    uris = [str(r.uri) for r in resources]

    assert "security://policies/port-baseline" in uris
    assert "security://mitre/attack-matrix" in uris
    assert "security://agent/system-prompt" in uris

    # Đọc nội dung chính sách cổng mạng
    policy_contents = await mcp_server.read_resource("security://policies/port-baseline")
    assert len(policy_contents) > 0
    policy_text = policy_contents[0].content
    assert "ALLOWED_PUBLIC_PORTS" in policy_text
    assert "CRITICAL_RESTRICTED_PORTS" in policy_text


@pytest.mark.asyncio
async def test_mcp_server_prompts():
    """Kiểm tra các mẫu Prompt dựng sẵn phục vụ điều tra sự cố chuẩn SOC."""
    prompts = await mcp_server.list_prompts()
    prompt_names = [p.name for p in prompts]

    assert "triage_security_incident" in prompt_names
    assert "audit_code_vulnerability" in prompt_names
    assert "remediate_port_violation" in prompt_names

    # Lấy mẫu prompt xử lý sự cố
    prompt_res = await mcp_server.get_prompt(
        "triage_security_incident",
        {"cve_or_alert": "CVE-2024-5510", "target_system": "srv-payment"},
    )
    assert len(prompt_res.messages) > 0
    msg_text = prompt_res.messages[0].content.text
    assert "srv-payment" in msg_text
    assert "CVE-2024-5510" in msg_text


@pytest.mark.asyncio
async def test_mcp_client_integration():
    """Kiểm tra lớp MCPClient giao tiếp mượt mà với MCPServer."""
    client = MCPClient(server_instance=mcp_server)
    await client.connect()

    # Liệt kê tools qua client
    tools = await client.list_tools()
    assert len(tools) >= 6

    # Gọi tool qua client và kiểm tra parse JSON tự động
    res = await client.call_tool("lookup_cve_details", {"cve_id": "CVE-2024-5510"})
    assert isinstance(res, dict)
    assert res.get("status") == "FOUND"
    assert res["data"]["cwe"] == "CWE-89"

    await client.close()
