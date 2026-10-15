from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class ChatRequest(BaseModel):
    query: str = Field(..., min_length=2, description="Câu hỏi hoặc yêu cầu bảo mật gửi tới Agent")
    session_id: Optional[str] = Field(default="default-session", description="Mã phiên hội thoại")

class ChatResponse(BaseModel):
    session_id: str
    answer: str
    tools_used: List[Dict[str, Any]]
    iterations: int
    latency_seconds: Optional[float] = None

class FeedbackRequest(BaseModel):
    session_id: str = Field(default="default-session", description="ID phiên hội thoại")
    rating: int = Field(default=5, ge=1, le=5, description="Đánh giá từ 1 đến 5 sao")
    is_positive: bool = Field(default=True, description="Thích (True) hoặc Không thích (False)")
    comments: Optional[str] = Field(default=None, description="Góp ý chi tiết")

class FeedbackResponse(BaseModel):
    status: str = "recorded"
    feedback_id: str
    message: str = "Phản hồi đã được ghi nhận vào hệ thống AgentOps."
