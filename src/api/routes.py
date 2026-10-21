import json
import uuid
import asyncio
from fastapi import APIRouter, HTTPException, status, BackgroundTasks
from fastapi.responses import StreamingResponse
from src.api.schemas import (
    ChatRequest,
    ChatResponse,
    FeedbackRequest,
    FeedbackResponse,
    PortAuditRequest,
    PortAuditResponse,
    NetworkAnomalyRequest,
    NetworkAnomalyResponse,
    ActionApprovalRequest,
    ActionRejectRequest,
    ActionResponse,
)
from src.agent.core import SecurityAgent
from src.tools.registry import registry
from src.evals.metrics import agent_metrics
from src.evals.shadow import shadow_evaluate_and_harvest
from src.agent.memory import session_memory
from src.agent.key_rotator import key_rotator
from src.agent.approval_store import approval_store
from src.integrations.discord_notifier import discord_notifier

router = APIRouter(prefix="/api/v1", tags=["SecLM Agent"])
agent = SecurityAgent()
feedbacks = []


@router.get("/health")
async def health_check():
    """Kiểm tra trạng thái sống của API Server."""
    return {"status": "healthy", "service": "SecLM Security Agent"}


@router.get("/tools")
async def list_registered_tools():
    """Trả về danh sách các công cụ đã đăng ký trong ToolRegistry."""
    return {"tools": registry.list_schemas()}


@router.get("/metrics")
async def get_metrics():
    """Trả về các chỉ số vận hành Observability và Tool Governance."""
    return {
        "metrics": agent_metrics.summary(),
        "governance": registry.get_governance_report(),
        "key_rotation": key_rotator.get_stats(),
    }


@router.post("/feedback", response_model=FeedbackResponse, status_code=status.HTTP_201_CREATED)
async def submit_feedback(fb: FeedbackRequest):
    """Ghi nhận phản hồi và đánh giá từ người dùng phục vụ Human-in-the-loop."""
    feedback_id = str(uuid.uuid4())
    feedbacks.append({
        "feedback_id": feedback_id,
        "session_id": fb.session_id,
        "rating": fb.rating,
        "is_positive": fb.is_positive,
        "comments": fb.comments,
    })
    return FeedbackResponse(
        status="recorded",
        feedback_id=feedback_id,
        message="Cảm ơn bạn! Phản hồi đã được ghi nhận vào hệ thống AgentOps."
    )


@router.post("/agent/chat", response_model=ChatResponse)
async def chat_with_agent(req: ChatRequest, background_tasks: BackgroundTasks):
    """Gọi Agent xử lý đồng bộ và trả về kết quả tổng hợp với bộ nhớ đa lượt."""
    try:
        try:
            result = agent.run(req.query, session_id=req.session_id)
        except TypeError:
            result = agent.run(req.query)

        # Kích hoạt tác vụ chấm điểm ngầm và thu hoạch dataset (0ms latency overhead)
        background_tasks.add_task(
            shadow_evaluate_and_harvest,
            session_id=req.session_id,
            user_query=req.query,
            tools_used=result["tools_used"],
            agent_answer=result["answer"],
            latency_seconds=result.get("latency_seconds", 0.0)
        )

        return ChatResponse(
            session_id=req.session_id,
            answer=result["answer"],
            tools_used=result["tools_used"],
            iterations=result["iterations"],
            latency_seconds=result.get("latency_seconds"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi thực thi Agent: {str(e)}")


async def sse_event_generator(query: str, session_id: str, background_tasks: BackgroundTasks):
    """Generator bắn sự kiện theo chuẩn Server-Sent Events (SSE) kèm Real-time Progress & Keep-alive."""
    loop = asyncio.get_running_loop()
    event_queue: asyncio.Queue = asyncio.Queue()

    def on_progress(evt: dict):
        loop.call_soon_threadsafe(event_queue.put_nowait, evt)

    # Bước 1: Thông báo bắt đầu suy luận
    yield f"event: status\ndata: {json.dumps({'step': 'THINKING', 'message': 'Agent đang khởi động phân tích...'}, ensure_ascii=False)}\n\n"

    # Bước 2: Chạy Agent trong thread pool và đẩy sự kiện tiến trình vào event_queue
    async def run_agent_task():
        try:
            try:
                res = await asyncio.to_thread(agent.run, query, session_id, on_progress)
            except TypeError:
                try:
                    res = await asyncio.to_thread(agent.run, query, session_id)
                except TypeError:
                    res = await asyncio.to_thread(agent.run, query)
            await event_queue.put({"event": "agent_result", "data": res})
        except Exception as err:
            await event_queue.put({"event": "error", "data": {"error": str(err)}})

    asyncio.create_task(run_agent_task())

    while True:
        try:
            # Chờ sự kiện hoặc gửi keep-alive ping mỗi 2.5s để chống rớt mạng/proxy timeout
            item = await asyncio.wait_for(event_queue.get(), timeout=2.5)
            evt_type = item.get("event")
            evt_data = item.get("data")

            if evt_type == "status":
                yield f"event: status\ndata: {json.dumps(evt_data, ensure_ascii=False)}\n\n"
            elif evt_type == "tool_call":
                yield f"event: tool_call\ndata: {json.dumps(evt_data, ensure_ascii=False)}\n\n"
            elif evt_type == "error":
                yield f"event: error\ndata: {json.dumps(evt_data, ensure_ascii=False)}\n\n"
                break
            elif evt_type == "agent_result":
                result = evt_data
                # Kích hoạt chấm điểm ngầm và thu thập dataset
                background_tasks.add_task(
                    shadow_evaluate_and_harvest,
                    session_id=session_id,
                    user_query=query,
                    tools_used=result["tools_used"],
                    agent_answer=result["answer"],
                    latency_seconds=result.get("latency_seconds", 0.0)
                )

                # Stream câu trả lời theo từng cụm từ (word tokens)
                words = result["answer"].split(" ")
                for i in range(0, len(words), 3):
                    chunk = " ".join(words[i:i+3]) + " "
                    yield f"event: token\ndata: {json.dumps({'token': chunk}, ensure_ascii=False)}\n\n"
                    await asyncio.sleep(0.015)

                yield f"event: done\ndata: {json.dumps({'iterations': result['iterations'], 'latency': result.get('latency_seconds')})}\n\n"
                break
        except asyncio.TimeoutError:
            # Gửi comment keep-alive định kỳ giữ kết nối SSE luôn sống
            yield ": keep-alive\n\n"


@router.post("/agent/stream")
async def stream_with_agent(req: ChatRequest, background_tasks: BackgroundTasks):
    """Endpoint Real-time Streaming qua giao thức SSE với lưu trữ session."""
    return StreamingResponse(
        sse_event_generator(req.query, req.session_id, background_tasks),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@router.get("/agent/sessions")
async def list_chat_sessions():
    """Lấy danh sách các phiên trò chuyện gần nhất phục vụ thanh Sidebar Lịch sử."""
    sessions = session_memory.get_all_sessions(limit=30)
    return {
        "total": len(sessions),
        "sessions": sessions
    }


@router.get("/agent/session/{session_id}")
async def get_chat_session_history(session_id: str):
    """Lấy lịch sử đàm thoại của một session."""
    history = session_memory.get_history(session_id)
    return {
        "session_id": session_id,
        "total_messages": len(history),
        "history": history
    }


@router.delete("/agent/session/{session_id}")
async def clear_chat_session(session_id: str):
    """Xóa lịch sử đàm thoại của một session để bắt đầu phiên mới."""
    session_memory.clear_session(session_id)
    return {"status": "success", "message": f"Đã xóa toàn bộ lịch sử của phiên {session_id}"}


# =========================================================================
# Human-in-the-Loop (HITL) & Enterprise Network Security Endpoints
# =========================================================================

@router.post("/network/audit-ports", response_model=PortAuditResponse)
async def audit_network_ports(req: PortAuditRequest):
    """Đối chiếu cổng mạng đang mở với chính sách doanh nghiệp và tự động tạo HITL Action nếu có vi phạm."""
    try:
        audit_res = registry.execute("audit_port_security", host=req.host, open_ports=req.open_ports)
        action_id = None
        discord_res = None

        if audit_res.get("requires_hitl_approval"):
            severity = "CRITICAL" if audit_res.get("overall_status") == "CRITICAL_VIOLATIONS_FOUND" else "MEDIUM"
            action = approval_store.create_action(
                action_type="BLOCK_RESTRICTED_PORTS",
                target=req.host,
                severity=severity,
                proposed_script=audit_res.get("suggested_remediation_script") or "ufw reload",
                description=f"Phát hiện cổng mạng vi phạm chính sách an ninh doanh nghiệp trên host {req.host}.",
                metadata=audit_res,
            )
            action_id = action["action_id"]

            if req.notify_discord:
                discord_fields = [
                    {"name": "🖥️ Máy chủ mục tiêu", "value": f"`{req.host}`", "inline": True},
                    {"name": "📊 Trạng thái đánh giá", "value": f"**{audit_res['overall_status']}**", "inline": True},
                    {"name": "🔎 Cổng đã quét", "value": f"`{req.open_ports}`", "inline": True},
                ]
                violations_text = "\n".join([
                    f"• Cổng `{f['port']}` ({f['service']}): {f['status']} - {f['severity']}"
                    for f in audit_res.get("findings", []) if f["status"] != "COMPLIANT"
                ])
                if violations_text:
                    discord_fields.append({
                        "name": "⚠️ Chi tiết các vi phạm",
                        "value": violations_text[:1024],
                        "inline": False,
                    })

                discord_res = discord_notifier.send_alert(
                    title=f"Vi phạm chính sách cổng mạng trên {req.host}",
                    severity=severity,
                    description=f"Hệ thống phát hiện {len(audit_res.get('findings', []))} cổng đang mở cần rà soát an ninh.",
                    fields=discord_fields,
                    action_id=action_id,
                    remediation_script=audit_res.get("suggested_remediation_script"),
                )

        return PortAuditResponse(
            status=audit_res["status"],
            host=audit_res["host"],
            overall_status=audit_res["overall_status"],
            findings=audit_res["findings"],
            requires_hitl_approval=audit_res["requires_hitl_approval"],
            action_id=action_id,
            discord_notification=discord_res,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi rà soát cổng mạng: {str(e)}")


@router.post("/network/detect-anomalies", response_model=NetworkAnomalyResponse)
async def detect_anomalies(req: NetworkAnomalyRequest):
    """Phân tích log mạng phát hiện hành vi rà quét cổng dồn dập (Port Scan) hoặc tấn công Brute-force."""
    try:
        detect_res = registry.execute("detect_network_anomalies", log_snippet=req.log_snippet)
        action_ids = []
        discord_res = None

        threats = detect_res.get("threats", [])
        for threat in threats:
            action = approval_store.create_action(
                action_type=f"MITIGATE_{threat['type']}",
                target=threat.get("attacker_ip", "UNKNOWN"),
                severity=threat.get("severity", "HIGH"),
                proposed_script=threat.get("suggested_action") or "ufw status",
                description=threat.get("details", "Phát hiện bất thường mạng."),
                metadata=threat,
            )
            action_ids.append(action["action_id"])

        if threats and req.notify_discord:
            main_threat = threats[0]
            discord_fields = [
                {"name": "🎯 Loại tấn công", "value": f"**{main_threat['type']}** ({main_threat.get('mitre_technique', 'N/A')})", "inline": True},
                {"name": "🌐 IP nguồn nghi vấn", "value": f"`{main_threat.get('attacker_ip', 'UNKNOWN')}`", "inline": True},
                {"name": "⚠️ Mức độ nghiêm trọng", "value": f"**{main_threat.get('severity', 'HIGH')}**", "inline": True},
                {"name": "📝 Chi tiết", "value": main_threat.get("details", "")[:1024], "inline": False},
            ]
            primary_action_id = action_ids[0] if action_ids else None
            discord_res = discord_notifier.send_alert(
                title=f"Phát hiện bất thường mạng: {main_threat['type']}",
                severity=main_threat.get("severity", "HIGH"),
                description="SecLM Agent phân tích log và phát hiện hành vi tấn công mạng có chủ đích.",
                fields=discord_fields,
                action_id=primary_action_id,
                remediation_script=main_threat.get("suggested_action"),
            )

        return NetworkAnomalyResponse(
            status=detect_res["status"],
            anomalies_detected=detect_res["anomalies_detected"],
            threats=threats,
            action_ids=action_ids,
            discord_notification=discord_res,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi phân tích bất thường mạng: {str(e)}")


@router.get("/actions/pending")
async def list_pending_hitl_actions():
    """Lấy danh sách các hành động an ninh đang chờ chuyên viên duyệt (HITL Pending Queue)."""
    pending = approval_store.list_pending()
    return {
        "total_pending": len(pending),
        "actions": pending,
    }


@router.get("/actions/all")
async def list_all_hitl_actions():
    """Lấy toàn bộ lịch sử các hành động đã duyệt, từ chối hoặc chờ duyệt."""
    all_actions = approval_store.list_all()
    return {
        "total": len(all_actions),
        "actions": all_actions,
    }


@router.post("/actions/{action_id}/approve", response_model=ActionResponse)
async def approve_hitl_action(action_id: str, req: ActionApprovalRequest):
    """Chuyên viên SOC phê duyệt hành động an ninh để hệ thống tiến hành áp dụng bản vá/lệnh chặn."""
    try:
        approved = approval_store.approve_action(
            action_id=action_id,
            approver=req.approver,
            simulate_execution=req.simulate_execution,
        )
        # Gửi thông báo xác nhận tới Discord kèm đầy đủ thông tin người duyệt và audit trail
        discord_notifier.send_alert(
            title="Hành động an ninh đã được PHÊ DUYỆT",
            severity="SAFE",
            description=f"Chuyên viên **{req.approver}** đã chính thức phê duyệt hành động `{approved['action_type']}` trên target `{approved['target']}`.",
            fields=[
                {"name": "🆔 Action ID", "value": f"`{action_id}`", "inline": True},
                {"name": "👤 Người phê duyệt (Approver)", "value": f"**{req.approver}**", "inline": True},
                {"name": "⚙️ Trạng thái thực thi", "value": f"**{approved['execution_status']}**", "inline": True},
                {"name": "⏰ Thời gian duyệt", "value": f"`{approved.get('reviewed_at', 'Vừa xong')}`", "inline": True},
                {"name": "📋 Nhật ký kiểm toán (Audit Trail)", "value": f"`{approved.get('audit_log', '')}`", "inline": False},
            ],
            source_url=approved.get("source_url"),
            remediation_script=approved.get("proposed_script"),
        )
        return ActionResponse(status="approved", action=approved)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/actions/{action_id}/reject", response_model=ActionResponse)
async def reject_hitl_action(action_id: str, req: ActionRejectRequest):
    """Chuyên viên SOC từ chối hành động an ninh (False Positive) để hệ thống ghi nhận và học hỏi."""
    try:
        rejected = approval_store.reject_action(
            action_id=action_id,
            reason=req.reason,
            approver=req.approver,
        )
        # Gửi thông báo tới Discord về quyết định từ chối hành động
        discord_notifier.send_alert(
            title="Hành động an ninh đã bị TỪ CHỐI (False Positive)",
            severity="INFO",
            description=f"Chuyên viên **{req.approver}** đã từ chối thực thi hành động `{rejected['action_type']}`.",
            fields=[
                {"name": "🆔 Action ID", "value": f"`{action_id}`", "inline": True},
                {"name": "👤 Người từ chối", "value": f"**{req.approver}**", "inline": True},
                {"name": "📝 Lý do từ chối", "value": f"`{req.reason}`", "inline": False},
                {"name": "📋 Nhật ký kiểm toán", "value": f"`{rejected.get('audit_log', '')}`", "inline": False},
            ],
            source_url=rejected.get("source_url"),
        )
        return ActionResponse(status="rejected", action=rejected)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

