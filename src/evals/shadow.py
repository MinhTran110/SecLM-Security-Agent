"""Automated Background Shadow Evaluation and Dataset Harvesting Engine."""

import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from src.evals.judge import SecurityAgentJudge
from src.evals.metrics import agent_metrics

HARVESTED_DIR = Path("data/harvested_datasets")
judge = SecurityAgentJudge()


def shadow_evaluate_and_harvest(
    session_id: str,
    user_query: str,
    tools_used: List[Dict[str, Any]],
    agent_answer: str,
    latency_seconds: float = 0.0,
):
    """Background task: Score agent execution against ground truth and harvest golden/review datasets."""
    if not user_query or not agent_answer:
        return

    try:
        HARVESTED_DIR.mkdir(parents=True, exist_ok=True)

        # 1. Run evaluation with LLM judge or deterministic fallback
        eval_result = judge.evaluate(
            user_query=user_query,
            tools_used=tools_used,
            agent_answer=agent_answer
        )

        # 2. Record observability metrics
        agent_metrics.record_shadow_eval(
            tool_accuracy=eval_result.tool_accuracy_score,
            faithfulness=eval_result.faithfulness_score,
            remediation_quality=eval_result.remediation_quality_score,
            hallucination=eval_result.hallucination_detected,
        )

        # 3. Quality threshold: Faithfulness >= 4, Tool Accuracy >= 4, No Hallucination
        is_golden = (
            eval_result.faithfulness_score >= 4
            and eval_result.tool_accuracy_score >= 4
            and not eval_result.hallucination_detected
        )

        timestamp = time.time()

        if is_golden:
            # SFT format ready for Gemini / OpenAI / HuggingFace fine-tuning
            golden_record = {
                "session_id": session_id,
                "timestamp": timestamp,
                "messages": [
                    {"role": "user", "content": user_query},
                    {"role": "model", "content": agent_answer}
                ],
                "evaluation": {
                    "tool_accuracy": eval_result.tool_accuracy_score,
                    "faithfulness": eval_result.faithfulness_score,
                    "remediation_quality": eval_result.remediation_quality_score,
                    "hallucination": False,
                    "latency_seconds": latency_seconds,
                    "tools_invoked": [t.get("tool") for t in tools_used]
                }
            }
            with open(HARVESTED_DIR / "sft_golden.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(golden_record, ensure_ascii=False) + "\n")
        else:
            # Flagged for Security Analyst Review & DPO Negative Pairs
            review_record = {
                "session_id": session_id,
                "timestamp": timestamp,
                "user_query": user_query,
                "tools_used": tools_used,
                "agent_answer": agent_answer,
                "evaluation": eval_result.model_dump(),
                "latency_seconds": latency_seconds,
            }
            with open(HARVESTED_DIR / "review_queue.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(review_record, ensure_ascii=False) + "\n")

    except Exception as e:
        print(f"[Shadow Evaluation Error] Không thể hoàn thành chấm điểm ngầm: {str(e)}")
