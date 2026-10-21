"""Model Context Protocol (MCP) client connector for internal and external security servers."""

import json
from typing import Any, Dict, List, Optional
from src.tools.registry import registry


class MCPClient:
    """Client interface for communicating with MCP servers via stdio, SSE, or direct server instance."""

    def __init__(self, server_url: Optional[str] = None, server_instance: Optional[Any] = None):
        self.server_url = server_url
        self._server = server_instance
        self._connected = False

    async def connect(self):
        """Establish connection to the MCP server."""
        if not self._server:
            try:
                from src.mcp_server import mcp_server
                self._server = mcp_server
            except Exception:
                pass
        self._connected = True
        return self._connected

    async def list_tools(self) -> List[Dict[str, Any]]:
        """Query MCP server for its advertised tools and schemas."""
        if not self._connected:
            await self.connect()

        if self._server and hasattr(self._server, "list_tools"):
            tools = await self._server.list_tools()
            result = []
            for t in tools:
                result.append({
                    "name": t.name,
                    "description": t.description or "",
                    "parameters": getattr(t, "inputSchema", {}),
                })
            return result
        return []

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Invoke an MCP tool remotely or in-process."""
        if not self._connected:
            await self.connect()

        if self._server and hasattr(self._server, "call_tool"):
            res = await self._server.call_tool(name, arguments)
            if hasattr(res, "content") and res.content:
                first_item = res.content[0]
                text_val = getattr(first_item, "text", str(first_item))
                try:
                    return json.loads(text_val)
                except Exception:
                    return {"result": text_val}
            return res

        return {"status": "mock_executed", "tool": name, "args": arguments}

    async def import_into_registry(self):
        """Tự động nhập tất cả tools từ MCP Server vào ToolRegistry của Agent."""
        tools = await self.list_tools()
        for t in tools:
            tool_name = t["name"]
            tool_desc = t["description"]

            # Bỏ qua nếu tool đã tồn tại trong registry
            if tool_name in registry._tools:
                continue

            async def make_invoker(t_name=tool_name):
                def invoker(**kwargs):
                    import asyncio
                    return asyncio.run(self.call_tool(t_name, kwargs))
                return invoker

            invoker_func = await make_invoker()
            registry._tools[tool_name] = invoker_func
            registry._metadata[tool_name] = {
                "name": tool_name,
                "description": tool_desc,
                "parameters": t.get("parameters", {}),
                "required": [],
            }
            registry._stats[tool_name] = {"calls": 0, "errors": 0}

    async def close(self):
        """Close connection to MCP server."""
        self._connected = False
