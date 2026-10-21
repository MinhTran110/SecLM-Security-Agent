from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    APP_NAME: str = Field(default="SecLM Security Agent", description="Tên ứng dụng")
    GEMINI_API_KEY: str = Field(..., description="API Key từ Google AI Studio")
    ENVIRONMENT: str = Field(default="development", description="development / production")
    DEFAULT_MODEL: str = Field(default="gemini-3.5-flash", description="Mô hình LLM chính")
    TEMPERATURE: float = Field(default=0.0, ge=0.0, le=1.0, description="Độ ngẫu nhiên (bảo mật dùng 0.0)")
    MAX_ITERATIONS: int = Field(default=5, ge=1, le=15, description="Số vòng lặp tối đa của Agent")
    NVD_API_TIMEOUT: int = Field(default=10, description="Timeout khi gọi API ngoài (giây)")
    TOOL_TIMEOUT_SECONDS: float = Field(default=5.0, description="Timeout tối đa cho mỗi tool (giây)")
    GEMINI_API_KEYS: str = Field(default="", description="Danh sách nhiều API Key phân cách bởi dấu phẩy")
    EXCLUDED_KEY_SUFFIXES: str = Field(default="0ujA,xqhg", description="Đuôi các API Key cần loại trừ (ví dụ OpenClaw)")
    KEY_COOLDOWN_SECONDS: float = Field(default=60.0, description="Thời gian phạt cooldown (giây) khi key gặp 429")
    ALLOWED_PUBLIC_PORTS: str = Field(default="80,443", description="Danh sách cổng được phép mở Public")
    CRITICAL_RESTRICTED_PORTS: str = Field(default="22,3389,3306,5432,6379,27017", description="Cổng nhạy cảm cấm mở ra ngoài Internet")
    DISCORD_WEBHOOK_URL: str = Field(default="", description="Discord Webhook URL để gửi cảnh báo an ninh")
    ENABLE_HUMAN_IN_THE_LOOP: bool = Field(default=True, description="Kích hoạt cơ chế phê duyệt an ninh HITL")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
