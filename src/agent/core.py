"""Core Agent Engine: ReAct loop, model fallback, and tool dispatching."""

import time
from typing import Dict, Any, List, Optional
from google import genai
from google.genai import types
from google.genai.errors import APIError
from src.config import settings
from src.tools.registry import registry
from src.agent.prompts import SECLM_SYSTEM_PROMPT
from src.evals.metrics import agent_metrics
from src.agent.memory import session_memory
from src.agent.key_rotator import key_rotator
import src.tools  # Tự động nạp toàn bộ các tools vào registry


class SecurityAgent:
    """Enterprise AI Security Analyst Agent with autonomous function calling."""

    def __init__(self, model_name: str = None):
        self.client = genai.Client(api_key=settings.GEMINI_API_KEY)
        selected_model = model_name or settings.DEFAULT_MODEL
        # Danh sách model dự phòng ưu tiên theo tốc độ và độ ổn định thực tế
        self.fallback_models = [
            selected_model,
            "gemini-3.5-flash",
            "gemini-3.5-flash-lite",
            "gemini-3-flash-preview",
            "gemini-3.1-flash-lite",
        ]
        # Loại bỏ trùng lặp giữ nguyên thứ tự
        self.fallback_models = list(dict.fromkeys(self.fallback_models))
        self.max_iterations = settings.MAX_ITERATIONS

    def _call_llm_with_fallback(self, contents: List[types.Content], config: types.GenerateContentConfig):
        last_error = None
        for model in self.fallback_models:
            max_key_retries = max(1, len(key_rotator._keys))
            for key_attempt in range(max_key_retries):
                try:
                    client, current_key = key_rotator.get_client()
                except Exception:
                    client, current_key = self.client, settings.GEMINI_API_KEY

                try:
                    masked = key_rotator.mask_key(current_key)
                    print(f"[SecLM Agent] Đang gọi model: {model} (Key: {masked})...")
                    return client.models.generate_content(
                        model=model,
                        contents=contents,
                        config=config
                    )
                except APIError as e:
                    last_error = e
                    if e.code == 429:
                        key_rotator.mark_exhausted(current_key, reason="429 Rate Limit / Quota Exceeded")
                        print(f"[SecLM Rotator] Key '{key_rotator.mask_key(current_key)}' chạm hạn mức 429. Đang chuyển sang key tiếp theo...")
                        continue  # Thử ngay key tiếp theo với cùng model
                    elif e.code == 503:
                        print(f"[SecLM Cảnh báo] Model '{model}' quá tải 503. Chuyển sang model kế tiếp...")
                        break  # Chuyển sang model dự phòng tiếp theo
                    else:
                        print(f"[SecLM Cảnh báo] Model '{model}' trả về lỗi API (mã {e.code}). Chuyển sang model kế tiếp...")
                        break
                except Exception as e:
                    last_error = e
                    print(f"[SecLM Lỗi mạng/Hệ thống] Model '{model}' gặp sự cố: {str(e)}. Đang thử model dự phòng...")
                    time.sleep(0.3)
                    break
        raise last_error

    def run(
        self,
        user_query: str,
        session_id: Optional[str] = None,
        on_progress: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Execute autonomous security analysis for a user query with optional session memory and real-time progress."""
        start_time = time.time()
        if session_id:
            contents: List[types.Content] = session_memory.get_gemini_contents(session_id, user_query)
        else:
            contents: List[types.Content] = [
                types.Content(role="user", parts=[types.Part.from_text(text=user_query)])
            ]
        
        tools_used = []
        
        config = types.GenerateContentConfig(
            system_instruction=SECLM_SYSTEM_PROMPT,
            tools=registry.get_callable_tools(),
            temperature=settings.TEMPERATURE,
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True)
        )

        success = True
        try:
            for iteration in range(self.max_iterations):
                if on_progress:
                    try:
                        on_progress({
                            "event": "status",
                            "data": {
                                "step": "THINKING",
                                "message": f"Agent đang suy luận (Vòng {iteration + 1}/{self.max_iterations})..."
                            }
                        })
                    except Exception:
                        pass

                response = self._call_llm_with_fallback(contents=contents, config=config)

                if response.function_calls:
                    contents.append(response.candidates[0].content)
                    
                    tool_response_parts = []
                    for call in response.function_calls:
                        tool_name = call.name
                        tool_args = call.args or {}
                        
                        try:
                            tool_output = registry.execute(tool_name, **tool_args)
                        except Exception as e:
                            tool_output = {"error": str(e), "status": "FAILED"}

                        tool_entry = {
                            "iteration": iteration + 1,
                            "tool": tool_name,
                            "args": tool_args,
                            "output": tool_output
                        }
                        tools_used.append(tool_entry)

                        if on_progress:
                            try:
                                on_progress({"event": "tool_call", "data": tool_entry})
                            except Exception:
                                pass

                        tool_response_parts.append(
                            types.Part.from_function_response(
                                name=tool_name,
                                response={"result": tool_output}
                            )
                        )
                    
                    contents.append(types.Content(role="user", parts=tool_response_parts))
                else:
                    duration = time.time() - start_time
                    agent_metrics.record_run(duration, tools_used, success=True)
                    if session_id and response.text:
                        session_memory.add_turn(session_id, "user", user_query)
                        session_memory.add_turn(session_id, "model", response.text)
                    return {
                        "answer": response.text,
                        "tools_used": tools_used,
                        "iterations": iteration + 1,
                        "latency_seconds": round(duration, 3),
                    }

            duration = time.time() - start_time
            agent_metrics.record_run(duration, tools_used, success=False)
            return {
                "answer": "Đã vượt quá số vòng lặp tối đa (MAX_ITERATIONS). Vui lòng thử lại với yêu cầu hẹp hơn.",
                "tools_used": tools_used,
                "iterations": self.max_iterations,
                "latency_seconds": round(duration, 3),
            }
        except Exception as e:
            duration = time.time() - start_time
            agent_metrics.record_run(duration, tools_used, success=False)
            raise e
