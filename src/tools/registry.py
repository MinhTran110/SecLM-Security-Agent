"""Central registry and governance for Security Agent tools."""

import inspect
import asyncio
import time
from typing import Callable, Dict, Any, List, Optional
from src.config import settings


class ToolRegistry:
    """Manages tool registration, metadata governance, input validation, and execution."""

    def __init__(self):
        self._tools: Dict[str, Callable] = {}
        self._metadata: Dict[str, Dict[str, Any]] = {}
        self._stats: Dict[str, Dict[str, int]] = {}

    def register(self, name: Optional[str] = None, description: Optional[str] = None):
        """Decorator to register a security tool with automated schema inspection."""
        def decorator(func: Callable):
            tool_name = name or func.__name__
            tool_desc = description or inspect.getdoc(func) or "Không có mô tả."
            self._tools[tool_name] = func

            sig = inspect.signature(func)
            parameters = {}
            required = []
            for param_name, param in sig.parameters.items():
                param_type = "string"
                if param.annotation in (int, float):
                    param_type = "number"
                elif param.annotation == bool:
                    param_type = "boolean"
                elif param.annotation in (list, List):
                    param_type = "array"
                elif param.annotation in (dict, Dict):
                    param_type = "object"

                parameters[param_name] = {
                    "type": param_type,
                    "default": None if param.default == inspect.Parameter.empty else param.default,
                }
                if param.default == inspect.Parameter.empty:
                    required.append(param_name)

            self._metadata[tool_name] = {
                "name": tool_name,
                "description": tool_desc.strip(),
                "parameters": parameters,
                "required": required,
            }
            self._stats[tool_name] = {"calls": 0, "errors": 0}
            return func
        return decorator

    def validate_inputs(self, tool_name: str, kwargs: Dict[str, Any]):
        """Governance: Validate required parameters before tool execution."""
        meta = self._metadata.get(tool_name)
        if not meta:
            raise KeyError(f"Tool '{tool_name}' chưa được đăng ký trong Governance Registry.")

        missing = [req for req in meta.get("required", []) if req not in kwargs or kwargs[req] is None]
        if missing:
            raise ValueError(f"Tool '{tool_name}' thiếu các tham số bắt buộc: {', '.join(missing)}")

    def execute(self, tool_name: str, **kwargs) -> Any:
        """Synchronously execute tool with governance checks."""
        if tool_name not in self._tools:
            raise KeyError(f"Tool '{tool_name}' chưa được đăng ký trong Governance Registry.")

        self.validate_inputs(tool_name, kwargs)
        self._stats[tool_name]["calls"] += 1

        func = self._tools[tool_name]
        try:
            if inspect.iscoroutinefunction(func):
                # Handle async tools in sync context
                try:
                    loop = asyncio.get_running_loop()
                    return loop.run_until_complete(func(**kwargs))
                except RuntimeError:
                    return asyncio.run(func(**kwargs))
            return func(**kwargs)
        except Exception as e:
            self._stats[tool_name]["errors"] += 1
            raise e

    def get_callable_tools(self) -> List[Callable]:
        """Return raw callable functions for Google GenAI / LangChain."""
        return list(self._tools.values())

    def list_schemas(self) -> List[Dict[str, Any]]:
        """Return OpenAPI-like JSON schemas for all registered tools."""
        return list(self._metadata.values())

    def get_governance_report(self) -> Dict[str, Any]:
        """Return operational governance statistics for tools."""
        return {
            "total_registered_tools": len(self._tools),
            "tool_stats": self._stats,
        }


registry = ToolRegistry()
tool_registry = registry  # Alias tương thích ngược
