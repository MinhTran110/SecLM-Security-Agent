"""Tools package initialization and automated tool discovery."""

import src.tools.cve_lookup
import src.tools.code_analyzer
import src.tools.hash_scanner
import src.tools.port_scanner
import src.rag.retriever
from src.tools.registry import registry, tool_registry

__all__ = [
    "registry",
    "tool_registry",
]
