# SecurityAgent - AI Security Analysis Platform

SecurityAgent là một nền tảng Trợ lý An toàn Thông tin (Security AI Agent) hoàn chỉnh với kiến trúc phân tầng (Multi-tier Architecture), tích hợp các công cụ quét lỗ hổng, phân tích mã độc, tra cứu CVE, quét mã nguồn tĩnh (SAST) và hệ thống RAG Hybrid Search.

---

## 🏗️ Cấu trúc dự án (Architecture Overview)

```text
.
├── .env.example                 # Mẫu khai báo biến môi trường (API keys, DB host)
├── .gitignore                   # Loại trừ .env, __pycache__, logs, .venv
├── README.md                    # Tài liệu hướng dẫn setup, API specs, chạy Docker
├── Dockerfile                   # Build production image cho FastAPI service
├── docker-compose.yml           # Khởi chạy cụm FastAPI + Redis + Qdrant (Vector DB)
├── requirements.txt             # Khai báo dependencies (fastapi, langgraph, mcp,...)
│
├── data/                        # Dữ liệu phục vụ RAG / Fine-tuning
│   ├── raw/                     # Dữ liệu cào thô (advisories, writeups thô)
│   ├── processed/               # Dữ liệu đã làm sạch (.jsonl phục vụ fine-tune)
│   └── cwe_catalog.json         # Danh mục CWE, MITRE định dạng cấu trúc
│
├── tests/                       # Kiểm thử tự động (CI/CD Quality Gates)
│   ├── test_tools.py            # Unit test từng Tool độc lập (output, schema)
│   ├── test_agent_graph.py      # Test luồng chuyển trạng thái (State Graph & Loop)
│   ├── test_api.py              # Test các endpoint FastAPI & SSE streaming
│   └── test_evals.py            # Benchmark LLM-as-a-judge chấm điểm
│
└── src/                         # Toàn bộ mã nguồn cốt lõi (Source code)
    ├── __init__.py
    ├── main.py                  # Entry point: Khởi tạo FastAPI app, CORS, Middleware
    ├── config.py                # Cấu hình Pydantic BaseSettings (load .env an toàn)
    │
    ├── api/                     # TẦNG 1: GIAO TIẾP VỚI CLIENT (REST API / SSE)
    │   ├── __init__.py
    │   ├── routes.py            # Các endpoints: /chat, /chat-stream, /feedback
    │   ├── schemas.py           # Pydantic models cho Request & Response
    │   └── dependencies.py      # Dependency injection (Auth, DB session, Rate limiter)
    │
    ├── agent/                   # TẦNG 2: BỘ NÃO & LUỒNG SUY LUẬN (CORE WORKFLOW)
    │   ├── __init__.py
    │   ├── state.py             # Định nghĩa GraphState / TypedDict của Agent
    │   ├── graph.py             # Dựng StateGraph (Nodes, Edges, Interrupts)
    │   ├── nodes.py             # Các hàm node logic (call_model, execute_tool, format)
    │   └── prompts.py           # System prompts, few-shot examples, dynamic templates
    │
    ├── tools/                   # TẦNG 3: CÔNG CỤ & TÍCH HỢP (TOOLS REGISTRY)
    │   ├── __init__.py
    │   ├── registry.py          # Quản lý tập trung: Đăng ký & tìm kiếm công cụ động
    │   ├── mcp_client.py        # Client kết nối giao thức MCP Server
    │   ├── cve_lookup.py        # Tool tra cứu lỗ hổng bảo mật (NVD/GitHub)
    │   ├── hash_scanner.py      # Tool kiểm tra mã độc (VirusTotal)
    │   └── code_analyzer.py     # Tool quét tĩnh mã nguồn (Semgrep/AST)
    │
    ├── rag/                     # TẦNG 4: TRI THỨC NỀN TẢNG (RETRIEVAL)
    │   ├── __init__.py
    │   ├── vector_store.py      # Kết nối Qdrant/Chroma và lưu embeddings
    │   └── retriever.py         # Hybrid Search (kết hợp Dense Vector + Sparse BM25)
    │
    └── evals/                   # TẦNG 5: GIÁM SÁT & ĐÁNH GIÁ (AGENTOPS / EVALUATION)
        ├── __init__.py
        ├── judge.py             # LLM-as-a-judge chấm điểm theo Rubric (Gemini)
        └── metrics.py           # Đo lường Tool Selection Accuracy, Latency, Token Cost
```

---

## 🚀 Hướng dẫn cài đặt & Khởi chạy

### 1. Yêu cầu hệ thống
- Python 3.11+
- Docker & Docker Compose (tùy chọn nhưng khuyến nghị)

### 2. Cài đặt môi trường ảo (Local Development)
```bash
# Clone hoặc điều hướng tới thư mục dự án
cd SecurityAgent

# Khởi tạo virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Cài đặt dependencies
pip install -r requirements.txt

# Thiết lập biến môi trường
cp .env.example .env
# Chỉnh sửa API keys trong .env (GEMINI_API_KEY, VIRUSTOTAL_API_KEY,...)
```

### 3. Khởi chạy ứng dụng
#### Chạy trực tiếp bằng Uvicorn:
```bash
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

#### Khởi chạy toàn bộ cụm qua Docker Compose:
```bash
docker compose up -d --build
```

---

## 📡 Danh sách API Endpoints

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/health` | Kiểm tra tình trạng dịch vụ (Health Check) |
| `POST` | `/api/v1/chat` | Gửi câu hỏi / yêu cầu phân tích bảo mật (phản hồi JSON) |
| `POST` | `/api/v1/chat-stream` | Phân tích thời gian thực qua Server-Sent Events (SSE) |
| `POST` | `/api/v1/feedback` | Ghi nhận phản hồi / đánh giá từ người dùng |

---

## 🧪 Chạy Kiểm thử (Testing & Evals)

```bash
# Chạy toàn bộ unit test
pytest tests/ -v

# Chạy kiểm thử cho từng phần
pytest tests/test_tools.py -v
pytest tests/test_agent_graph.py -v
pytest tests/test_api.py -v
pytest tests/test_evals.py -v
```
