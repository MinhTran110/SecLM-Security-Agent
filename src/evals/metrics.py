"""Operational Observability: Metrics tracking for latency, tool usage, and success rates."""

import time
from typing import Any, Dict, List
from collections import defaultdict


class AgentMetrics:
    """Tracks and calculates operational metrics for the agent in memory."""

    def __init__(self):
        self._latencies: List[float] = []
        self._tool_calls: List[Dict[str, Any]] = []
        self._tool_usage_count: Dict[str, int] = defaultdict(int)
        self._requests_count: int = 0
        self._errors_count: int = 0

    def record_run(self, duration_seconds: float, tools_used: List[Dict[str, Any]], success: bool = True):
        """Record an entire agent execution run."""
        self._requests_count += 1
        self._latencies.append(duration_seconds)
        if not success:
            self._errors_count += 1

        for t in tools_used:
            tool_name = t.get("tool", "unknown")
            is_err = "error" in t.get("output", {})
            self._tool_usage_count[tool_name] += 1
            self._tool_calls.append({"tool": tool_name, "success": not is_err})

    def record_latency(self, duration_seconds: float):
        """Record the turnaround latency of an agent run."""
        self._latencies.append(duration_seconds)

    def record_tool_call(self, tool_name: str, success: bool):
        """Record a tool invocation outcome."""
        self._tool_calls.append({"tool": tool_name, "success": success})
        self._tool_usage_count[tool_name] += 1

    def summary(self) -> Dict[str, Any]:
        """Compute aggregate metrics."""
        avg_latency = sum(self._latencies) / len(self._latencies) if self._latencies else 0.0
        success_tools = sum(1 for t in self._tool_calls if t["success"])
        total_tools = len(self._tool_calls)
        tool_accuracy = (success_tools / total_tools) if total_tools > 0 else 1.0

        return {
            "total_requests": self._requests_count or len(self._latencies),
            "errors_count": self._errors_count,
            "average_latency_sec": round(avg_latency, 3),
            "total_tool_calls": total_tools,
            "tool_success_rate": round(tool_accuracy * 100, 2),
            "tool_usage_breakdown": dict(self._tool_usage_count),
        }


agent_metrics = AgentMetrics()
