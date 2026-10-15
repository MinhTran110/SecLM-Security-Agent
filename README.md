# 🛡️ SecLM - Enterprise AI Security Agent

[![Security Agent CI/CD Quality Gate](https://github.com/MinhTran110/SecLM-Security-Agent/actions/workflows/agent_ci.yml/badge.svg)](https://github.com/MinhTran110/SecLM-Security-Agent/actions)
![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)
![Google GenAI](https://img.shields.io/badge/Gemini%20Flash%20Lite-SDK%20v2.0-8E75C2?logo=google&logoColor=white)
![AgentOps Quality Gate](https://img.shields.io/badge/AgentOps-Quality%20Gate%20Passed-success)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

SecLM là một nền tảng **Trí tuệ Nhân tạo Chuyên biệt cho An toàn Thông tin (Defensive AI Security Copilot)** được xây dựng theo chuẩn **5 bước AgentOps Lifecycle** (Discover $\rightarrow$ Governance $\rightarrow$ Evaluation $\rightarrow$ CI/CD $\rightarrow$ Monitoring). 

Hệ thống được trang bị bộ công cụ bảo mật thực chiến: **Tra cứu CVE**, **Quét tĩnh mã nguồn (SAST)**, **Kiểm tra mã độc Threat Intel**, và **Cơ sở tri thức CWE/OWASP RAG**.

---

## 🏗️ Kiến trúc Phân tầng (5 Tầng AgentOps)

```text
.
├── .github/workflows/           # TẦNG CI/CD: Automated Pipeline & Quality Gate (agent_ci.yml)
├── .env.example                 # Mẫu khai báo biến môi trường (API keys, DB host)
├── .gitignore                   # Loại trừ .env, __pycache__, logs, .venv
├── README.md                    # Tài liệu hướng dẫn setup, API specs, chạy Docker
├── LICENSE                      # Giấy phép nguồn mở MIT License
├── Dockerfile                   # Build production image cho FastAPI service
├── docker-compose.yml           # Khởi chạy cụm dịch vụ
├── requirements.txt             # Khai báo dependencies chính thức
│
├── data/                        # Dữ liệu phục vụ RAG / Fine-tuning
│   ├── raw/                     # Dữ liệu cào thô (advisories, writeups thô)
│   ├── processed/               # Dữ liệu đã làm sạch (.jsonl phục vụ fine-tune)
│   ├── cwe_knowledge.json       # Danh mục 10+ CWE cốt lõi chuẩn OWASP Top 10
│   └── cwe_catalog.json         # Danh mục CWE, MITRE định dạng cấu trúc
│
├── tests/                       # Kiểm thử tự động (CI/CD Quality Gates)
│   ├── eval_dataset.json        # Golden Benchmark Dataset (12 kịch bản an ninh thực chiến)
│   ├── test_tools.py            # Unit test từng Tool độc lập (output, schema)
│   ├── test_agent_graph.py      # Test luồng chuyển trạng thái (State Graph & Loop)
│   ├── test_api.py              # Test các endpoint FastAPI & SSE streaming
│   ├── test_rag.py              # Test độ chính xác tìm kiếm RAG
│   └── test_evals.py            # Benchmark LLM-as-a-judge chấm điểm
│
└── src/                         # Toàn bộ mã nguồn cốt lõi (Source code)
    ├── __init__.py
    ├── main.py                  # Entry point: Giao diện Web Cyber Copilot & FastAPI app
    ├── config.py                # Cấu hình Pydantic BaseSettings (load .env an toàn)
    │
    ├── api/                     # TẦNG 1: GIAO TIẾP VỚI CLIENT (REST API / SSE)
    │   ├── routes.py            # Các endpoints: /health, /tools, /metrics, /agent/chat, /agent/stream, /feedback
    │   ├── schemas.py           # Pydantic models cho Request & Response
    │   └── dependencies.py      # Dependency injection (Auth, DB session, Rate limiter)
    │
    ├── agent/                   # TẦNG 2: BỘ NÃO & LUỒNG SUY LUẬN (CORE WORKFLOW)
    │   ├── core.py              # Autonomous ReAct Loop + Model Fallback (gemini-3.1-flash-lite)
    │   ├── graph.py             # Dựng StateGraph (Nodes, Edges, Interrupts)
    │   ├── nodes.py             # Các hàm node logic (call_model, execute_tool, format)
    │   ├── prompts.py           # System prompts, Guardrails phòng thủ, dynamic templates
    │   └── state.py             # Định nghĩa GraphState / TypedDict của Agent
    │
    ├── tools/                   # TẦNG 3: CÔNG CỤ & QUẢN TRỊ (TOOL GOVERNANCE)
    │   ├── registry.py          # Quản lý tập trung: Schema Inspection & Parameter Validation
    │   ├── cve_lookup.py        # Tool tra cứu lỗ hổng bảo mật (NVD/GitHub)
    │   ├── code_analyzer.py     # Tool quét tĩnh mã nguồn (SAST AST: SQLi, eval, pickle, secrets)
    │   ├── hash_scanner.py      # Tool kiểm tra mã độc qua mã băm (Threat Intel)
    │   └── mcp_client.py        # Client kết nối giao thức MCP Server
    │
    ├── rag/                     # TẦNG 4: TRI THỨC NỀN TẢNG (RETRIEVAL)
    │   ├── retriever.py         # Search scoring ranking trên danh mục CWE/OWASP
    │   └── vector_store.py      # Module Vector Database Qdrant
    │
    └── evals/                   # TẦNG 5: GIÁM SÁT & ĐÁNH GIÁ (AGENTOPS OBSERVABILITY)
        ├── judge.py             # LLM-as-a-judge chấm điểm theo Rubric (Faithfulness, Hallucination)
        └── metrics.py           # Đo lường Tool Selection Accuracy, Latency, Token Cost
```

---

## 🚀 Hướng dẫn Cài đặt & Khởi chạy

### 1. Cài đặt môi trường ảo (Local Development)
```bash
# Clone repository
git clone https://github.com/MinhTran110/SecLM-Security-Agent.git
cd SecLM-Security-Agent

# Tạo và kích hoạt môi trường ảo
python3 -m venv .venv
source .venv/bin/activate

# Cài đặt thư viện
pip install -r requirements.txt

# Thiết lập biến môi trường
cp .env.example .env
# Chỉnh sửa file .env với GEMINI_API_KEY của bạn
```

### 2. Khởi chạy Server
```bash
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```
- Mở trình duyệt tại: `http://localhost:8000` để trải nghiệm **Giao diện Web Cyber Copilot** với Markdown rendering, tô màu code, thanh tiến trình suy luận và nút đánh giá phản hồi.
- Xem tài liệu API Swagger: `http://localhost:8000/docs`

---

## 📡 Danh sách API Endpoints

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/api/v1/health` | Kiểm tra tình trạng dịch vụ (Health Check) |
| `GET` | `/api/v1/tools` | Danh sách OpenAPI Schemas của các công cụ bảo mật đã đăng ký |
| `GET` | `/api/v1/metrics` | Chỉ số vận hành Observability (Độ trễ TB, Tỷ lệ gọi tool thành công) |
| `POST` | `/api/v1/agent/chat` | Phân tích an ninh đồng bộ (JSON Response) |
| `POST` | `/api/v1/agent/stream` | Stream suy luận thời gian thực qua Server-Sent Events (SSE) |
| `POST` | `/api/v1/feedback` | Ghi nhận phản hồi người dùng (Human-in-the-loop) |

---

## 🧪 Chạy Kiểm thử (Testing & Quality Gate)

```bash
# Chạy toàn bộ 23 bài test tự động
pytest tests/ -v
```

---

## 📄 License
Phát hành theo giấy phép [MIT License](LICENSE).
