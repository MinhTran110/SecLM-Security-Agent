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


class PortAuditRequest(BaseModel):
    host: str = Field(default="127.0.0.1", description="Địa chỉ IP hoặc tên máy chủ cần kiểm tra")
    open_ports: List[int] = Field(..., description="Danh sách các cổng đang mở")
    notify_discord: bool = Field(default=True, description="Có gửi cảnh báo tới Discord hay không")


class PortAuditResponse(BaseModel):
    status: str
    host: str
    overall_status: str
    findings: List[Dict[str, Any]]
    requires_hitl_approval: bool
    action_id: Optional[str] = None
    discord_notification: Optional[Dict[str, Any]] = None


class NetworkAnomalyRequest(BaseModel):
    log_snippet: str = Field(..., min_length=5, description="Đoạn log tường lửa hoặc mạng cần phân tích")
    notify_discord: bool = Field(default=True, description="Có gửi cảnh báo tới Discord hay không")


class NetworkAnomalyResponse(BaseModel):
    status: str
    anomalies_detected: int
    threats: List[Dict[str, Any]]
    action_ids: List[str] = []
    discord_notification: Optional[Dict[str, Any]] = None


class ActionApprovalRequest(BaseModel):
    approver: str = Field(default="security_lead", description="Tên hoặc mã định danh của chuyên viên phê duyệt")
    simulate_execution: bool = Field(default=True, description="Mô phỏng thực thi thay vì can thiệp hạ tầng thật")


class ActionRejectRequest(BaseModel):
    reason: str = Field(default="False Positive / Whitelisted", description="Lý do từ chối hành động")
    approver: str = Field(default="security_lead", description="Tên chuyên viên từ chối")


class ActionResponse(BaseModel):
    status: str
    action: Dict[str, Any]
