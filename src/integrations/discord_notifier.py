"""Discord Webhook Notifier for Real-time Security Alerts and HITL Action Notifications."""

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from src.config import settings

logger = logging.getLogger("seclm.discord")

# Bảng mã màu Discord Embed chuẩn
SEVERITY_COLORS: Dict[str, int] = {
    "CRITICAL": 0xE74C3C,  # Đỏ tươi
    "HIGH": 0xE67E22,      # Cam đậm
    "MEDIUM": 0xF1C40F,    # Vàng
    "LOW": 0x3498DB,       # Xanh dương
    "SAFE": 0x2ECC71,      # Xanh lá
    "INFO": 0x95A5A6,      # Xám
}


class DiscordNotifier:
    """Quản lý việc định dạng và gửi cảnh báo an ninh thời gian thực tới Discord Webhook."""

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url if webhook_url is not None else settings.DISCORD_WEBHOOK_URL

    def build_embed(
        self,
        title: str,
        severity: str,
        description: str,
        fields: Optional[List[Dict[str, Any]]] = None,
        action_id: Optional[str] = None,
        remediation_script: Optional[str] = None,
        source_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Tạo cấu trúc Discord Rich Embed chuẩn hóa kèm đường dẫn nguồn (source_url)."""
        severity_upper = severity.upper()
        color = SEVERITY_COLORS.get(severity_upper, 0x3498DB)

        embed_fields = list(fields or [])

        if source_url:
            embed_fields.append({
                "name": "🔗 Nguồn tham chiếu / Dẫn chứng lỗ hổng",
                "value": f"[Xem chi tiết tại nguồn]({source_url})",
                "inline": False,
            })

        if remediation_script:
            embed_fields.append({
                "name": "🛠️ Lệnh đề xuất khắc phục (Remediation)",
                "value": f"```{remediation_script}```",
                "inline": False,
            })

        if action_id:
            embed_fields.append({
                "name": "🛡️ Phê duyệt Human-in-the-Loop (HITL)",
                "value": (
                    f"**Action ID**: `{action_id}`\n"
                    f"• Duyệt thực thi: `POST /api/v1/actions/{action_id}/approve`\n"
                    f"• Bỏ qua (False Positive): `POST /api/v1/actions/{action_id}/reject`"
                ),
                "inline": False,
            })

        embed = {
            "title": f"🚨 [SecLM {severity_upper}] {title}",
            "description": description,
            "color": color,
            "fields": embed_fields,
            "footer": {
                "text": "SecLM Enterprise Security Agent • Human-in-the-Loop Active Defense",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if source_url:
            embed["url"] = source_url

        return embed

    def send_alert(
        self,
        title: str,
        severity: str,
        description: str,
        fields: Optional[List[Dict[str, Any]]] = None,
        action_id: Optional[str] = None,
        remediation_script: Optional[str] = None,
        source_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Gửi cảnh báo đến Discord Webhook hoặc mô phỏng nếu chưa cấu hình URL."""
        embed = self.build_embed(
            title=title,
            severity=severity,
            description=description,
            fields=fields,
            action_id=action_id,
            remediation_script=remediation_script,
            source_url=source_url,
        )

        payload = {
            "username": "SecLM Security Sentinel",
            "avatar_url": "https://raw.githubusercontent.com/github/explore/80688e429a7d4ef2fca1e82350fe8e3517d3494d/topics/security/security.png",
            "embeds": [embed],
        }

        # Nếu không có URL webhook, chạy chế độ giả lập (Simulation Mode)
        if not self.webhook_url or not self.webhook_url.strip():
            logger.info(f"[Discord Simulation] {title} (Action: {action_id})")
            return {
                "status": "SIMULATED",
                "webhook_configured": False,
                "message": "Discord Webhook chưa cấu hình. Cảnh báo đã được tạo ở chế độ giả lập.",
                "payload": payload,
            }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "SecLM-Security-Agent/1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                status_code = response.getcode()
                return {
                    "status": "DELIVERED",
                    "webhook_configured": True,
                    "http_status": status_code,
                    "action_id": action_id,
                }
        except urllib.error.URLError as e:
            logger.error(f"Lỗi gửi Webhook Discord: {str(e)}")
            return {
                "status": "FAILED",
                "webhook_configured": True,
                "error": str(e),
                "payload": payload,
            }


discord_notifier = DiscordNotifier()
