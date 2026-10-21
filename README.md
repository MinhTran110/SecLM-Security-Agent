# 🛡️ SecLM - Enterprise AI Security Analyst Agent

[![Security Agent CI/CD Quality Gate](https://github.com/MinhTran110/SecLM-Security-Agent/actions/workflows/agent_ci.yml/badge.svg)](https://github.com/MinhTran110/SecLM-Security-Agent/actions)
![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)
![Google GenAI](https://img.shields.io/badge/Gemini%20Flash%20Lite-SDK%20v2.0-8E75C2?logo=google&logoColor=white)
![AgentOps Quality Gate](https://img.shields.io/badge/AgentOps-Quality%20Gate%20Passed-success)
![Tests](https://img.shields.io/badge/Tests-46%2F46%20Passing-brightgreen)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

**SecLM** là nền tảng Trí tuệ Nhân tạo Chuyên biệt cho **An toàn Thông tin Doanh nghiệp (Enterprise Defensive AI Security Copilot)**, được thiết kế và vận hành chuẩn mực theo **5 bước vòng đời AgentOps** (*Discover :arrow_right: Governance :arrow_right: Evaluation :arrow_right: CI/CD :arrow_right: Monitoring*).

Hệ thống được trang bị bộ công cụ bảo mật thực chiến: **Tra cứu CVE/CISA KEV**, **Quét tĩnh mã nguồn AST (SAST)**, **Kiểm tra mã độc qua Threat Intelligence (Hashes & IoCs)**, và **Cơ sở tri thức RAG đa tầng** từ OWASP, MITRE ATT&CK và PayloadsAllTheThings với tính năng trích xuất minh bạch nguồn tham chiếu có thể nhấp chuột được.

---

## 📌 1. Vấn đề Đặt ra (Problem Statement)

Trong kỷ nguyên số hóa và điện toán đám mây, các đội ngũ An toàn Thông tin (SOC, Blue Team, AppSec, DevSecOps) đang đối mặt với những thách thức chưa từng có:

1. **Quá tải Cảnh báo (Alert Fatigue):** Trung tâm SOC phải xử lý hàng trăm nghìn cảnh báo mỗi ngày từ SIEM, EDR và WAF. Việc phân tích thủ công mã băm độc hại (IoC), giải mã hành vi phần mềm độc hại và truy vết TTPs tốn quá nhiều thời gian.
2. **Lỗ hổng Ứng dụng & Phần mềm bùng nổ:** Hàng ngàn mã CVE mới được công bố hàng năm. Đội ngũ phát triển (Dev) thường xuyên viết code chứa các lỗi kinh điển như SQL Injection, Command Injection, SSRF, Deserialization do thiếu hướng dẫn cụ thể theo ngữ cảnh mã nguồn.
3. **Điểm yếu chí mạng của các mô hình LLM thông thường khi ứng dụng vào Bảo mật:**
   * **Ảo giác dữ liệu (Hallucination):** LLM thông thường tự suy diễn hoặc bịa đặt mã CVE không có thật, cung cấp sai điểm CVSS hoặc gợi ý các hàm bảo mật lỗi thời.
   * **Thiếu minh bạch (No Ground Truth Citations):** Không chỉ ra được nguồn gốc khuyến nghị đến từ tài liệu nào (NIST, MITRE, OWASP hay CISA).
   * **Thiếu Quản trị Công cụ (Tool Governance):** Thiếu cơ chế kiểm soát schema tham số, dễ bị tấn công Prompt Injection hoặc bị lợi dụng sinh mã khai thác vũ khí hóa (Weaponized Exploit / Ransomware Payload).
   * **Thiếu Vòng đời Vận hành (No AgentOps Lifecycle):** Không có bộ benchmark chấm điểm độc lập, không có cổng kiểm duyệt chất lượng (Quality Gate) tự động chặn đứng lỗi trước khi release.

👉 **SecLM được phát triển để giải quyết triệt để các vấn đề trên**, mang lại một trợ lý an ninh trung thực (Zero Hallucination), phòng thủ nghiêm ngặt (Strict Defensive) và kiểm soát hoàn toàn bằng bằng chứng thực tế (Evidence-based Reasoning).

---

## 🎯 2. Mục đích Sử dụng & Đối tượng Hướng tới (Core Mission & Use Cases)

SecLM đóng vai trò là một **Senior Security Analyst & Copilot** phục vụ các mục đích chính:

* 🛡️ **SOC Tier 1-3 Triage & Ứng cứu Sự cố (Incident Response):** Nhận diện nhanh danh tính phần mềm độc hại theo mã băm (MD5, SHA1, SHA256), bóc tách TTPs trong ma trận MITRE ATT&CK và gợi ý quy trình ứng phó theo chuẩn **NIST SP 800-61 Rev. 2**.
* 💻 **Kiểm thử Mã nguồn Tĩnh (SAST & Secure Code Review):** Quét trực tiếp cú pháp AST của mã nguồn Python/Web để phát hiện sớm các lỗ hổng nghiêm trọng (CWE-89, CWE-78, CWE-79, CWE-502, CWE-798), đồng thời viết lại đoạn mã đã được vá an toàn.
* 🔍 **Tra cứu & Đánh giá Rủi ro Lỗ hổng (Vulnerability Intelligence):** Tra cứu tức thì thông tin điểm CVSS v3.1, phân loại CWE, tình trạng khai thác thực tế (CISA KEV) và bản vá chính thức cho các mã CVE.
* 📚 **Tra cứu Chuẩn mực Phòng thủ (RAG Knowledge Retrieval):** Tự động kết hợp tri thức từ hàng ngàn tài liệu bảo mật uy tín, hiển thị kết quả bằng bảng Markdown kẻ viền chuyên nghiệp và kèm đường link trích dẫn chính thức tự động mở sang tab mới (`target="_blank"`).
* 🛑 **Rào chắn Phòng vệ Đạo đức (Defensive-Only Guardrails):** Tuyệt đối từ chối tạo mã độc tống tiền, trojan hoặc script tấn công phá hoại.

---

## 🏗️ 3. Kiến trúc 5 Bước AgentOps Lifecycle

Dự án tuân thủ nghiêm ngặt 5 giai đoạn vận hành Agentic AI chuẩn doanh nghiệp:

```
  ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
  │   1. DISCOVER   │ ───>  │  2. GOVERNANCE  │ ───>  │  3. EVALUATION  │
  │ Model Fallback  │       │ Tool Registry   │       │ Golden Benchmark│
  │ gemini-3.1-lite │       │ Input Validation│       │ Judge LLM Gate  │
  └─────────────────┘       └─────────────────┘       └─────────────────┘
                                                               │
                                                               ▼
  ┌─────────────────┐                                 ┌─────────────────┐
  │  5. MONITORING  │ <────────────────────────────── │   4. CI / CD    │
  │ Metrics API/UI  │                                 │ GitHub Actions  │
  │ Human Feedback  │                                 │ 41/41 Test Gate │
  └─────────────────┘                                 └─────────────────┘
```

1. **Discover & Prototype:** Bộ ReAct Loop tự trị sử dụng `gemini-3.1-flash-lite`, tích hợp cơ chế dự phòng đa tầng (Model Fallback) tự động chuyển model khi gặp quá tải hoặc lỗi mạng.
2. **Develop & Tool Governance:** Hệ thống `ToolRegistry` tự động thanh tra OpenAPI schema, bắt buộc validate kiểu dữ liệu tham số đầu vào và ghi vết lỗi thực thi.
3. **Agent Evaluation:** Bộ dữ liệu kiểm thử vàng `tests/eval_dataset.json` kết hợp cùng giám khảo `SecurityAgentJudge` tự động phát hiện ảo giác (Hallucination) và đối soát sự thật (Faithfulness).
4. **Deploy via CI/CD:** Pipeline tự động `.github/workflows/agent_ci.yml` kiểm duyệt cú pháp, chạy data pipeline và vượt qua toàn bộ **41/41 unit tests** trước khi build Docker.
5. **Observability & Monitoring:** Theo dõi thời gian thực độ trễ trung bình, tỷ lệ gọi tool thành công qua `/api/v1/metrics`, giao diện Cyber UI và cơ chế thu thập phản hồi Human-in-the-loop `/api/v1/feedback`.

---

## 📂 4. Cấu trúc Thư mục Dự án

```text
.
├── .github/workflows/           # TẦNG CI/CD: Automated Pipeline & Quality Gate (agent_ci.yml)
├── .env.example                 # Mẫu cấu hình biến môi trường
├── Dockerfile                   # Build production image cho FastAPI service
├── docker-compose.yml           # Khởi chạy cụm dịch vụ container
├── requirements.txt             # Khai báo dependencies chính thức
├── pytest.ini                   # Cấu hình kiểm thử tự động
│
├── data/                        # KHO DỮ LIỆU TRI THỨC BẢO MẬT
│   ├── raw/                     # Dữ liệu cào thô (OWASP, MITRE, PayloadsAllTheThings, CISA KEV)
│   ├── processed/               # Dữ liệu đã làm sạch & cắt chunk (Vector DB chunks & Fine-tune jsonl)
│   ├── harvested_datasets/      # Dữ liệu tự động thu thập từ Shadow Evaluation (SFT Golden & Review)
│   ├── chat_sessions.db         # Bộ nhớ lịch sử chat SQLite (quản lý session & sliding window)
│   ├── cwe_knowledge.json       # Cơ sở tri thức CWE & Threat Intelligence chuẩn hóa
│   └── cwe_catalog.json         # Danh mục CWE MITRE cấu trúc
│
├── scripts/                     # BỘ TOOL CÀO VÀ BÓC TÁCH TRI THỨC TỰ ĐỘNG
│   ├── crawl_security_data.py   # Bộ cào tổng hợp (OWASP, CISA, GitHub, MITRE, PayloadsAllTheThings)
│   ├── parse_stix_bundle.py     # Parser chuyên dụng trích xuất STIX 2.1 từ mitre-attack/attack-stix-data
│   └── scrape_webpage.py        # Web Scraper đa năng cào bài viết/advisory từ bất kỳ link web nào
│
├── tests/                       # HỆ THỐNG KIỂM THỬ CHẤT LƯỢNG (41 TESTS PASSING)
│   ├── eval_dataset.json        # Golden Benchmark Dataset (Kịch bản an ninh thực chiến)
│   ├── test_tools.py            # Test các công cụ tra cứu CVE, quét SAST, quét mã băm
│   ├── test_data_pipeline.py    # Test tẩy rửa dữ liệu, khử trùng lặp (Deduplication) và bóc tách STIX
│   ├── test_rag.py              # Test độ chính xác tìm kiếm RAG & trích xuất nguồn
│   ├── test_memory_and_shadow.py # Test bộ nhớ lịch sử chat session & chấm điểm ngầm
│   ├── test_agent.py            # Test luồng ReAct Engine và thực thi Function Calling
│   ├── test_agent_graph.py      # Test máy trạng thái StateGraph
│   ├── test_api.py              # Test các REST API & Server-Sent Events (SSE) streaming
│   └── test_evals.py            # Test giám khảo LLM-as-a-judge và đo lường metrics
│
└── src/                         # MÃ NGUỒN CỐT LÕI HỆ THỐNG
    ├── main.py                  # Entrypoint: Cyber Copilot Web UI & FastAPI App
    ├── config.py                # Cấu hình Pydantic Settings
    │
    ├── api/                     # TẦNG 1: REST API & STREAMING (routes, schemas, dependencies)
    ├── agent/                   # TẦNG 2: BỘ NÃO AGENTIC REACT (core, memory, graph, nodes, prompts, state)
    ├── tools/                   # TẦNG 3: TOOL GOVERNANCE (registry, cve_lookup, code_analyzer, hash_scanner)
    ├── rag/                     # TẦNG 4: HYBRID RAG RETRIEVAL (retriever, vector_store)
    ├── data_pipeline/           # BỘ NẠP & XỬ LÝ TRI THỨC (loaders, cleaner, chunker, processor)
    └── evals/                   # TẦNG 5: OBSERVABILITY & METRICS (judge, shadow, metrics)
```

---

## 🌐 5. Hướng dẫn Thu thập & Nạp Dữ liệu Tri thức (Data Ingestion & Crawler Guide)

SecLM sở hữu một hệ thống nạp và chuẩn hóa dữ liệu tự động, đa định dạng và an toàn tuyệt đối.

### 5.1. Cơ chế Data Pipeline thông minh (`src/data_pipeline`)
* **Hỗ trợ đa định dạng:** Tự động đọc `.md`, `.txt`, `.json`, `.pdf` và `.docx` (đọc docx bằng cơ chế giải nén XML nội bộ, zero-dependency).
* **Secret Scrubber:** Tự động phát hiện và che giấu (redact) các dữ liệu nhạy cảm trước khi nạp: API Keys, Passwords, Internal IPs (`192.168.x.x`, `10.x.x.x`, `169.254.169.254`).
* **Khử trùng lặp 2 lớp (Dual-Layer Deduplication):**
  1. *Khử trùng cấp Tệp (File-Level SHA-256):* Bỏ qua các file có nội dung giống nhau 100% dù khác tên file.
  2. *Khử trùng cấp Đoạn (Chunk-Level MD5):* Loại bỏ các đoạn văn bản/khuyến nghị trùng lặp giữa các tài liệu khác nhau để giữ Vector DB luôn tinh gọn.
* **Security-Aware Semantic Chunking:** Cắt nhỏ văn bản có độ gối đầu (overlap), tự động nhận diện và bảo toàn nguyên vẹn các khối mã nguồn (` ``` `), tránh tuyệt đối tình trạng cắt đứt gãy payload khai thác hoặc đoạn code mẫu vá lỗi.
* **Kiến trúc Hybrid Search Siêu nhẹ (Zero-GPU RAG):** Kết hợp Kênh 1 (*Fast-Path Exact Metadata Lookup $O(1)$* cho mã CWE/CVE) và Kênh 2 (*BM25 Okapi Inverted Index* tính điểm TF-IDF tức thì), hợp nhất thứ hạng qua giải thuật **Reciprocal Rank Fusion (RRF)** trả về kết quả trong $< 25\text{ms}$ mà không tốn GPU hay chi phí API Embedding.

---

### 5.2. Các công cụ Cào dữ liệu được tích hợp sẵn

#### 🔹 Tool 1: Bộ cào tự động tổng hợp (`scripts/crawl_security_data.py`)
Cho phép cào có chọn lọc từ các nguồn uy tín hàng đầu thế giới:

```bash
# Cú pháp chung trên Bash:
.venv/bin/python scripts/crawl_security_data.py --source <TÙY_CHỌN>
```

**Bảng tra cứu tham số `--source`:**
| Tham số `--source` | Nguồn dữ liệu & Ý nghĩa |
| :--- | :--- |
| `payloads` | **PayloadsAllTheThings** (swisskyrepo): Cẩm nang khai thác & bypass WAF (SQLi, XSS, SSRF, Deserialization, JWT...). |
| `owasp` | **OWASP CheatSheet Series**: Hướng dẫn nguyên lý phòng thủ chuẩn quốc tế từ dự án chính thức của OWASP. |
| `mitre` | **MITRE ATT&CK Software**: Danh mục mã độc và công cụ tấn công đối kháng (tự động ưu tiên GitHub STIX để tránh Cloudflare 503). |
| `cisa` | **CISA KEV Catalog**: Danh mục các lỗ hổng đang bị tin tặc khai thác thực tế do chính phủ Mỹ ban hành. |
| `github` | **GitHub Security Advisories**: Các bản tin cảnh báo bảo mật mức Critical gần nhất. |
| `all` | *(Mặc định)* Tự động cào **toàn bộ 5 nguồn trên** trong 1 lượt chạy. |

*Ví dụ cào riêng PayloadsAllTheThings:*
```bash
.venv/bin/python scripts/crawl_security_data.py --source payloads
```

---

#### 🔹 Tool 2: Bóc tách trực tiếp từ repo MITRE ATT&CK STIX (`scripts/parse_stix_bundle.py`)
Tránh hoàn toàn lỗi `503 Service Unavailable` từ Cloudflare web UI bằng cách tải trực tiếp kho dữ liệu chuẩn quốc tế STIX 2.1 từ repo [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data):

```bash
# Tự động tải từ GitHub STIX và bóc tách thành 3 tệp tri thức chuyên sâu:
.venv/bin/python scripts/parse_stix_bundle.py
```
*Kết quả sinh ra trong `data/raw/`:*
1. `mitre_attack_software.md`: Toàn bộ phần mềm độc hại & công cụ kèm link trích dẫn.
2. `mitre_attack_techniques.md`: Toàn bộ kỹ thuật tấn công TTPs.
3. `mitre_attack_groups.md`: Hồ sơ các nhóm tin tặc APT (APT28, Lazarus, FIN7...).

*Nếu bạn đã tải sẵn file `enterprise-attack.json` về máy cục bộ:*
```bash
.venv/bin/python scripts/parse_stix_bundle.py --file /đường/dẫn/tới/enterprise-attack.json
```

---

#### 🔹 Tool 3: Cào bài viết từ bất kỳ liên kết web nào (`scripts/scrape_webpage.py`)
Cho phép cào bài báo, blog an ninh, phân tích CVE từ The Hacker News, BleepingComputer, CISA... Tự động loại bỏ quảng cáo, script, header/footer và xuất thành Markdown chuẩn:

```bash
# Cào một bài báo phân tích bảo mật cụ thể:
.venv/bin/python scripts/scrape_webpage.py "https://thehackernews.com/2024/04/new-flaws-in-putty-ssh-client-could.html" --out data/raw/putty_advisory.md
```

---

### 5.3. Quy trình Nạp dữ liệu vào RAG sau khi cào
Sau khi cào hoặc bổ sung bất kỳ tài liệu mới nào vào `data/raw/`, bạn chỉ cần chạy lệnh sau để làm sạch, khử trùng lặp và cắt đoạn:

```bash
.venv/bin/python -m src.data_pipeline.processor
```
*Kết quả xuất ra:*
* `data/processed/rag_knowledge.json`: Kho tri thức cắt đoạn sẵn sàng cho Vector Search/RAG.
* `data/processed/fine_tune_train.jsonl`: Tập dữ liệu hỏi-đáp cấu trúc chuẩn phục vụ Fine-tuning LLM.

---

## 🚀 6. Hướng dẫn Cài đặt & Khởi chạy (Quickstart)

### 1. Chuẩn bị môi trường ảo
```bash
# Clone repository
git clone https://github.com/MinhTran110/SecLM-Security-Agent.git
cd SecLM-Security-Agent

# Tạo và kích hoạt virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Cài đặt toàn bộ dependencies
pip install -r requirements.txt

# Thiết lập biến môi trường
cp .env.example .env
# Thêm khóa GEMINI_API_KEY của bạn vào file .env
```

### 2. Khởi chạy Server
```bash
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```
* **Giao diện Web Cyber Copilot:** Truy cập `http://localhost:8000`
  * Hỗ trợ Markdown tables kẻ viền rõ ràng.
  * Tô màu cú pháp code blocks (Syntax highlighting).
  * Accordion mở rộng xem trực tiếp luồng suy nghĩ ReAct (`Thinking & Action Trace`).
  * Mọi đường link trích dẫn tự động mở trên tab mới (`target="_blank"`).
  * Nút chấm điểm phản hồi kết quả (Human-in-the-loop feedback).
* **Tài liệu API Swagger:** Truy cập `http://localhost:8000/docs`

---

## 📡 7. Danh sách API Endpoints

| Phương thức | Đường dẫn API | Chức năng chi tiết |
|---|---|---|
| `GET` | `/api/v1/health` | Kiểm tra trạng thái hoạt động của dịch vụ (Health check). |
| `GET` | `/api/v1/tools` | Trả về danh sách OpenAPI Schemas của các công cụ đã được quản trị. |
| `GET` | `/api/v1/metrics` | Lấy các chỉ số Observability: Độ trễ trung bình, tỷ lệ gọi tool thành công. |
| `POST` | `/api/v1/agent/chat` | Phân tích an ninh đồng bộ (Trả về JSON response đầy đủ, kích hoạt Shadow Eval ngầm). |
| `POST` | `/api/v1/agent/stream` | Stream suy luận thời gian thực qua Server-Sent Events (SSE). |
| `GET` | `/api/v1/agent/session/{session_id}` | Xem lịch sử hội thoại chi tiết theo phiên session. |
| `DELETE` | `/api/v1/agent/session/{session_id}` | Xóa trắng lịch sử hội thoại của phiên session tương ứng. |
| `POST` | `/api/v1/feedback` | Thu thập phản hồi từ người dùng (Đánh giá chuẩn xác / Chưa hài lòng). |

---

## 🧪 8. Kiểm thử Tự động & Quality Gate (46/46 Tests Passing)

Hệ thống tích hợp bộ kiểm thử toàn diện bảo vệ chất lượng ở mọi tầng kiến trúc:

```bash
# Chạy toàn bộ test suite
pytest -v --durations=10
```

```text
============================== test session starts ==============================
tests/test_agent.py ..                                                   [  4%]
tests/test_agent_graph.py ...                                            [ 10%]
tests/test_api.py .....                                                  [ 21%]
tests/test_data_pipeline.py ......                                       [ 34%]
tests/test_evals.py ...                                                  [ 41%]
tests/test_key_rotator.py .....                                          [ 52%]
tests/test_memory_and_shadow.py ......                                   [ 65%]
tests/test_rag.py ........                                               [ 82%]
tests/test_tools.py ........                                             [100%]
============================== 46 passed in 1.91s ==============================
```

---

## 🛡️ 9. Guardrail An ninh & Nguyên tắc Đạo đức (Strict Defensive)

SecLM được lập trình theo nguyên tắc phòng thủ tuyệt đối (**Defensive-by-Design**):
1. **Từ chối Vũ khí hóa:** Tuyệt đối từ chối tạo mã khai thác tấn công vũ khí hóa (Weaponized Exploit Payloads), phần mềm tống tiền (Ransomware) hoặc hướng dẫn phá hoại hệ thống.
2. **Tuân thủ Chuẩn mực:** Mọi khuyến nghị sửa lỗi đều bám sát tiêu chuẩn NIST SP 800-83, NIST SP 800-61, MITRE ATT&CK, CIS Benchmarks và OWASP Top 10.
3. **Minh bạch Nguồn dữ liệu:** Mọi câu trả lời của Agent luôn kết thúc bằng phần trích dẫn `### 📚 Nguồn dữ liệu` với đường link xác thực bấm được.

---

## 📄 10. Giấy phép (License)
Dự án được phân phối theo giấy phép [MIT License](LICENSE).
