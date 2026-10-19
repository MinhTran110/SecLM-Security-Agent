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
    """Generator bắn sự kiện theo chuẩn Server-Sent Events (SSE)."""
    # Bước 1: Thông báo bắt đầu suy luận
    yield f"event: status\ndata: {json.dumps({'step': 'THINKING', 'message': 'Agent đang phân tích yêu cầu...'}, ensure_ascii=False)}\n\n"
    await asyncio.sleep(0.05)

    # Bước 2: Chạy Agent trong thread pool để không khóa event loop
    try:
        try:
            result = await asyncio.to_thread(agent.run, query, session_id)
        except TypeError:
            result = await asyncio.to_thread(agent.run, query)

        # Kích hoạt chấm điểm ngầm và thu thập dataset
        background_tasks.add_task(
            shadow_evaluate_and_harvest,
            session_id=session_id,
            user_query=query,
            tools_used=result["tools_used"],
            agent_answer=result["answer"],
            latency_seconds=result.get("latency_seconds", 0.0)
        )

        # Bước 3: Nếu Agent có gọi Tool, bắn thông tin từng Tool ra stream
        for tool_log in result["tools_used"]:
            yield f"event: tool_call\ndata: {json.dumps(tool_log, ensure_ascii=False)}\n\n"
            await asyncio.sleep(0.05)

        # Bước 4: Stream câu trả lời cuối cùng
        words = result["answer"].split(" ")
        for i in range(0, len(words), 3):
            chunk = " ".join(words[i:i+3]) + " "
            yield f"event: token\ndata: {json.dumps({'token': chunk}, ensure_ascii=False)}\n\n"
            await asyncio.sleep(0.02)

        # Bước 5: Báo hiệu hoàn tất
        yield f"event: done\ndata: {json.dumps({'iterations': result['iterations'], 'latency': result.get('latency_seconds')})}\n\n"
    except Exception as e:
        yield f"event: error\ndata: {json.dumps({'error': str(e)}, ensure_ascii=False)}\n\n"


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
