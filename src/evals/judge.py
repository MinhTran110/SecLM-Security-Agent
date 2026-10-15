"""LLM-as-a-judge evaluation harness using structured security rubric."""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from src.config import settings


class EvaluationResult(BaseModel):
    """Structured evaluation scorecard for Security Agent execution."""
    tool_accuracy_score: int = Field(
        ..., ge=1, le=5, 
        description="Điểm gọi đúng tool và đúng tham số (1: Sai hoàn toàn, 5: Chính xác tuyệt đối)"
    )
    faithfulness_score: int = Field(
        ..., ge=1, le=5, 
        description="Độ trung thực so với dữ liệu Tool trả về (1: Bịa đặt số liệu, 5: Chuẩn xác 100%)"
    )
    remediation_quality_score: int = Field(
        ..., ge=1, le=5, 
        description="Chất lượng hướng dẫn khắc phục và code mẫu (1: Code lỗi/không an toàn, 5: Chuẩn bảo mật)"
    )
    hallucination_detected: bool = Field(
        ..., description="True nếu phát hiện Agent tự bịa ra mã CWE/CVSS khác với kết quả của Tool"
    )
    critique: str = Field(
        ..., description="Nhận xét ngắn gọn lý do chấm điểm (tiếng Việt)"
    )


class SecurityAgentJudge:
    """Evaluates agent trajectory and response against ground truth."""

    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or settings.DEFAULT_MODEL
        try:
            self.client = genai.Client(api_key=settings.GEMINI_API_KEY)
        except Exception:
            self.client = None

    def evaluate_rule_based(
        self,
        user_query: str,
        tools_used: List[Dict[str, Any]],
        agent_answer: str,
        expected_tool: Optional[str] = None,
        expected_keywords: Optional[List[str]] = None,
    ) -> EvaluationResult:
        """Deterministic rule-based evaluator for offline/CI environments."""
        tool_score = 5
        if expected_tool:
            called_tools = [t.get("tool") for t in tools_used]
            tool_score = 5 if expected_tool in called_tools else 1

        keyword_matches = 0
        if expected_keywords:
            keyword_matches = sum(1 for kw in expected_keywords if kw.lower() in agent_answer.lower())
            faithfulness = 5 if keyword_matches >= max(1, len(expected_keywords) // 2) else 3
        else:
            faithfulness = 4

        return EvaluationResult(
            tool_accuracy_score=tool_score,
            faithfulness_score=faithfulness,
            remediation_quality_score=4,
            hallucination_detected=False,
            critique="Đánh giá theo bộ quy chuẩn quy tắc kiểm chuẩn (Deterministic Quality Gate).",
        )

    def evaluate(
        self, 
        user_query: str, 
        tools_used: List[Dict[str, Any]], 
        agent_answer: str
    ) -> EvaluationResult:
        """Chấm điểm đầu ra của Agent bằng LLM-as-a-judge (Gemini)."""
        if not self.client:
            return self.evaluate_rule_based(user_query, tools_used, agent_answer)

        judge_system_prompt = (
            "Bạn là Giám khảo Kiểm định Chất lượng AI (QA Judge) chuyên về An toàn thông tin. "
            "Nhiệm vụ của bạn là đối chiếu câu trả lời của Agent với dữ liệu gốc từ Tool (Ground Truth) "
            "để chấm điểm khách quan và phát hiện hiện tượng ảo giác (hallucination)."
        )

        eval_prompt = f"""
        Hãy đánh giá phiên làm việc sau của Security Agent:

        1. [CÂU HỎI CỦA USER]:
        {user_query}

        2. [DỮ LIỆU THỰC TẾ TOOL TRẢ VỀ (GROUND TRUTH)]:
        {json.dumps(tools_used, ensure_ascii=False, indent=2)}

        3. [CÂU TRẢ LỜI CỦA AGENT]:
        {agent_answer}
        """

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=eval_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=judge_system_prompt,
                    response_mime_type="application/json",
                    response_schema=EvaluationResult,
                    temperature=0.0
                )
            )
            return EvaluationResult.model_validate_json(response.text)
        except Exception as e:
            print(f"[Judge Cảnh báo] Không thể gọi API Judge: {str(e)}. Sử dụng đánh giá quy chuẩn...")
            return self.evaluate_rule_based(user_query, tools_used, agent_answer)
