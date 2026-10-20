import json
import uuid
import asyncio
from fastapi import APIRouter, HTTPException, status, BackgroundTasks
from fastapi.responses import StreamingResponse
from src.api.schemas import ChatRequest, ChatResponse, FeedbackRequest, FeedbackResponse
from src.agent.core import SecurityAgent
from src.tools.registry import registry
from src.evals.metrics import agent_metrics
from src.evals.shadow import shadow_evaluate_and_harvest
from src.agent.memory import session_memory

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

