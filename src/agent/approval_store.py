"""Approval Store for Human-in-the-Loop (HITL) Security Action Lifecycle Management."""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class ApprovalStore:
    """Quản lý danh sách và trạng thái các hành động an ninh cần người phê duyệt."""

    def __init__(self):
        self._actions: Dict[str, Dict[str, Any]] = {}

    def create_action(
        self,
        action_type: str,
        target: str,
        severity: str,
        proposed_script: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
        source_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Tạo một yêu cầu phê duyệt hành động an ninh mới."""
        action_id = str(uuid.uuid4())
        action_data = {
            "action_id": action_id,
            "action_type": action_type,
            "target": target,
            "severity": severity.upper(),
            "status": "PENDING",
            "proposed_script": proposed_script,
            "description": description,
            "source_url": source_url,
            "metadata": metadata or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
            "reviewed_at": None,
            "approver": None,
            "rejection_reason": None,
            "execution_status": "IDLE",
        }
        self._actions[action_id] = action_data
        return action_data

    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Lấy thông tin chi tiết một hành động theo ID."""
        return self._actions.get(action_id)

    def approve_action(
        self,
        action_id: str,
        approver: str = "soc_lead",
        simulate_execution: bool = True,
    ) -> Dict[str, Any]:
        """Phê duyệt hành động và ghi nhận nhật ký kiểm toán (Audit Trail)."""
        action = self.get_action(action_id)
        if not action:
            raise KeyError(f"Hành động với ID '{action_id}' không tồn tại.")

        if action["status"] != "PENDING":
            raise ValueError(f"Hành động '{action_id}' đã ở trạng thái '{action['status']}', không thể phê duyệt lại.")

        action["status"] = "APPROVED"
        action["approver"] = approver
        action["reviewed_at"] = datetime.now(timezone.utc).isoformat()
        action["execution_status"] = "SUCCESS_SIMULATED" if simulate_execution else "EXECUTED"
        action["audit_log"] = f"Hành động '{action['action_type']}' đã được phê duyệt bởi '{approver}'."

        return action

    def reject_action(
        self,
        action_id: str,
        reason: str = "False Positive / Expected Traffic",
        approver: str = "soc_lead",
    ) -> Dict[str, Any]:
        """Từ chối hành động và ghi nhận lý do (để Agent học hỏi tránh lặp lại cảnh báo giả)."""
        action = self.get_action(action_id)
        if not action:
            raise KeyError(f"Hành động với ID '{action_id}' không tồn tại.")

        if action["status"] != "PENDING":
            raise ValueError(f"Hành động '{action_id}' đã ở trạng thái '{action['status']}', không thể từ chối lại.")

        action["status"] = "REJECTED"
        action["approver"] = approver
        action["reviewed_at"] = datetime.now(timezone.utc).isoformat()
        action["rejection_reason"] = reason
        action["execution_status"] = "CANCELLED"
        action["audit_log"] = f"Hành động '{action['action_type']}' bị từ chối bởi '{approver}'. Lý do: {reason}."

        return action

    def list_pending(self) -> List[Dict[str, Any]]:
        """Liệt kê tất cả các hành động đang chờ phê duyệt (PENDING)."""
        return [a for a in self._actions.values() if a["status"] == "PENDING"]

    def list_all(self) -> List[Dict[str, Any]]:
        """Liệt kê toàn bộ lịch sử hành động."""
        return list(self._actions.values())

    def clear(self):
        """Xóa trắng store (dành cho Unit Test)."""
        self._actions.clear()


approval_store = ApprovalStore()
