"""Operational Observability: Metrics tracking for latency, tool usage, success rates, and shadow evals."""

import time
from typing import Any, Dict, List
from collections import defaultdict


class AgentMetrics:
    """Tracks and calculates operational metrics for the agent in memory."""

    def __init__(self):
        self._latencies: List[float] = []
        self._tool_calls: List[Dict[str, Any]] = []
        self._tool_usage_count: Dict[str, int] = defaultdict(int)
        self._shadow_evals: List[Dict[str, Any]] = []
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

    def record_shadow_eval(self, tool_accuracy: int, faithfulness: int, remediation_quality: int, hallucination: bool):
        """Record a background LLM-as-a-judge shadow evaluation outcome."""
        self._shadow_evals.append({
            "tool_accuracy": tool_accuracy,
            "faithfulness": faithfulness,
            "remediation_quality": remediation_quality,
            "hallucination": hallucination,
            "timestamp": time.time(),
        })

    def summary(self) -> Dict[str, Any]:
        """Compute aggregate metrics."""
        avg_latency = sum(self._latencies) / len(self._latencies) if self._latencies else 0.0
        success_tools = sum(1 for t in self._tool_calls if t["success"])
        total_tools = len(self._tool_calls)
        tool_accuracy = (success_tools / total_tools) if total_tools > 0 else 1.0

        total_evals = len(self._shadow_evals)
        avg_faithfulness = (sum(e["faithfulness"] for e in self._shadow_evals) / total_evals) if total_evals > 0 else 5.0
        avg_tool_accuracy = (sum(e["tool_accuracy"] for e in self._shadow_evals) / total_evals) if total_evals > 0 else 5.0
        hallucinations = sum(1 for e in self._shadow_evals if e["hallucination"])
        hallucination_rate = (hallucinations / total_evals * 100) if total_evals > 0 else 0.0

        return {
            "total_requests": self._requests_count or len(self._latencies),
            "errors_count": self._errors_count,
            "average_latency_sec": round(avg_latency, 3),
            "total_tool_calls": total_tools,
            "tool_success_rate": round(tool_accuracy * 100, 2),
            "tool_usage_breakdown": dict(self._tool_usage_count),
            "shadow_evaluation": {
                "total_evaluations": total_evals,
                "avg_faithfulness_score": round(avg_faithfulness, 2),
                "avg_tool_score": round(avg_tool_accuracy, 2),
                "hallucination_rate": round(hallucination_rate, 2),
            }
        }


agent_metrics = AgentMetrics()
