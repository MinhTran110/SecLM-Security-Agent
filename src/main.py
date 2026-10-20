"""Entry point for the FastAPI SecurityAgent application with Live Cyber UI."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from src.config import settings
from src.api.routes import router

app = FastAPI(
    title=settings.APP_NAME,
    description="Hệ thống AI Agent chuyên biệt về An toàn thông tin & Thẩm định mã nguồn",
    version="1.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

HTML_CHAT_UI = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecLM - Security AI Copilot</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/marked/12.0.1/marked.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <style>
        :root {
            --bg-main: #090d16;
            --bg-sidebar: #0b1120;
            --bg-card: #131b2e;
            --bg-inner: #1c2742;
            --border: #263554;
            --accent: #00f2fe;
            --accent-grad: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg-main);
            color: var(--text-main);
            height: 100vh;
            overflow: hidden;
            display: flex;
        }
        
        /* Layout wrapper */
        .app-layout {
            display: flex;
            width: 100vw;
            height: 100vh;
            overflow: hidden;
        }

        /* Sidebar History */
        .sidebar {
            width: 280px;
            min-width: 280px;
            background: var(--bg-sidebar);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            height: 100vh;
            transition: transform 0.25s ease;
            z-index: 100;
        }
        .sidebar.collapsed {
            display: none;
        }
        .sidebar-header {
            padding: 16px 14px 12px;
            border-bottom: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .sidebar-title {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.95rem;
            font-weight: 700;
            color: var(--accent);
        }
        .new-chat-btn {
            background: rgba(0, 242, 254, 0.1);
            border: 1px solid rgba(0, 242, 254, 0.35);
            color: var(--accent);
            padding: 9px 12px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .new-chat-btn:hover {
            background: rgba(0, 242, 254, 0.2);
            box-shadow: 0 0 10px rgba(0, 242, 254, 0.2);
        }
        .session-list {
            flex: 1;
            overflow-y: auto;
            padding: 10px 8px;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .session-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 12px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85rem;
            color: var(--text-muted);
            transition: all 0.15s;
            border: 1px solid transparent;
            user-select: none;
        }
        .session-item:hover {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-main);
        }
        .session-item.active {
            background: rgba(0, 242, 254, 0.12);
            color: var(--accent);
            border-color: rgba(0, 242, 254, 0.3);
            font-weight: 600;
        }
        .session-item .session-title {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            margin-right: 6px;
        }
        .session-item .session-count {
            font-size: 0.7rem;
            color: #64748b;
            margin-right: 6px;
        }
        .session-item .del-btn {
            opacity: 0;
            background: none;
            border: none;
            color: #ef4444;
            cursor: pointer;
            padding: 2px 4px;
            border-radius: 4px;
            transition: opacity 0.15s;
            font-size: 0.85rem;
        }
        .session-item:hover .del-btn {
            opacity: 1;
        }
        .session-item .del-btn:hover {
            background: rgba(239, 68, 68, 0.2);
        }

        /* Main Container */
        .container {
            flex: 1;
            max-width: 1100px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            height: 100vh;
            padding: 16px 24px;
        }
        
        /* Header & Telemetry */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
        }
        .logo-area {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .toggle-btn {
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 6px 10px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
        }
        .toggle-btn:hover {
            color: var(--accent);
            border-color: var(--accent);
        }
        .logo-area h1 {
            font-size: 1.35rem;
            background: var(--accent-grad);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 800;
            letter-spacing: -0.5px;
        }
        .badge {
            font-size: 0.75rem;
            padding: 3px 8px;
            border-radius: 999px;
            background: rgba(0, 242, 254, 0.15);
            color: var(--accent);
            border: 1px solid rgba(0, 242, 254, 0.3);
            font-weight: 600;
        }
        
        .metrics-bar {
            display: flex;
            gap: 12px;
            font-size: 0.85rem;
            color: var(--text-muted);
            align-items: center;
        }
        .metric-item {
            background: var(--bg-card);
            padding: 5px 10px;
            border-radius: 6px;
            border: 1px solid var(--border);
        }
        .metric-item strong { color: var(--accent); }

        /* Chat box */
        #chat-box {
            flex: 1;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow-y: auto;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            scroll-behavior: smooth;
        }
        
        .message-row { display: flex; flex-direction: column; gap: 6px; max-width: 90%; }
        .message-row.user { align-self: flex-end; }
        .message-row.agent { align-self: flex-start; width: 100%; max-width: 100%; }

        .bubble { padding: 14px 18px; border-radius: 12px; font-size: 0.95rem; line-height: 1.6; position: relative; }
        .user-bubble {
            background: #2563eb;
            color: #ffffff;
            border-bottom-right-radius: 2px;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-wrap: break-word;
            font-family: inherit;
        }
        .agent-bubble { background: var(--bg-inner); border: 1px solid var(--border); border-bottom-left-radius: 2px; color: var(--text-main); }

        /* Collapsible tool traces */
        .thought-accordion { margin-bottom: 10px; border: 1px solid rgba(0, 242, 254, 0.25); border-radius: 8px; background: rgba(0, 242, 254, 0.05); overflow: hidden; }
        .thought-header { padding: 8px 12px; font-size: 0.85rem; font-weight: 600; color: var(--accent); display: flex; align-items: center; justify-content: space-between; cursor: pointer; user-select: none; }
        .thought-body { padding: 10px 12px; font-family: monospace; font-size: 0.8rem; background: rgba(0, 0, 0, 0.25); border-top: 1px solid var(--border); max-height: 220px; overflow-y: auto; color: #cbd5e1; }

        /* Markdown styling inside Agent bubble */
        .agent-bubble pre { background: #0f172a; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0; border: 1px solid var(--border); }
        .agent-bubble code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.88em; }
        .agent-bubble p { margin-bottom: 10px; }
        .agent-bubble h1, .agent-bubble h2, .agent-bubble h3, .agent-bubble h4 { color: var(--accent); margin: 16px 0 8px 0; }
        .agent-bubble ul, .agent-bubble ol { margin-left: 22px; margin-bottom: 12px; }
        .agent-bubble li { margin-bottom: 4px; }

        /* Tables styling */
        .agent-bubble table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 0.9rem; background: rgba(15, 23, 42, 0.7); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
        .agent-bubble th { background: #1e293b; color: var(--accent); text-align: left; padding: 10px 14px; font-weight: 700; border-bottom: 2px solid var(--border); border-right: 1px solid rgba(255, 255, 255, 0.06); }
        .agent-bubble td { padding: 10px 14px; border-bottom: 1px solid var(--border); border-right: 1px solid rgba(255, 255, 255, 0.06); color: #cbd5e1; }
        .agent-bubble tr:last-child td { border-bottom: none; }
        .agent-bubble tr:hover td { background: rgba(255, 255, 255, 0.03); }

        /* Clickable links */
        .agent-bubble a { color: var(--accent); text-decoration: underline; text-underline-offset: 3px; font-weight: 600; }
        .agent-bubble a:hover { color: #38bdf8; }
        .agent-bubble blockquote { border-left: 3px solid var(--accent); padding-left: 12px; margin: 10px 0; color: #94a3b8; font-style: italic; }

        /* Quick Suggestions */
        .quick-tags { display: flex; gap: 8px; margin: 10px 0; flex-wrap: wrap; }
        .tag-btn { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-muted); padding: 5px 11px; border-radius: 6px; font-size: 0.8rem; cursor: pointer; transition: all 0.2s; }
        .tag-btn:hover { border-color: var(--accent); color: var(--text-main); background: var(--bg-inner); }

        /* Input Controls */
        .input-bar {
            display: flex;
            gap: 12px;
            background: var(--bg-card);
            padding: 10px 14px;
            border-radius: 12px;
            border: 1px solid var(--border);
            align-items: flex-end;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .input-bar:focus-within {
            border-color: var(--accent);
            box-shadow: 0 0 0 2px rgba(0, 242, 254, 0.15);
        }
        textarea#query {
            flex: 1;
            background: transparent;
            border: none;
            outline: none;
            color: #ffffff;
            font-size: 0.95rem;
            font-family: inherit;
            line-height: 1.5;
            padding: 6px 4px;
            resize: none;
            min-height: 24px;
            max-height: 180px;
            overflow-y: auto;
        }
        textarea#query::placeholder { color: #64748b; }
        .input-actions {
            display: flex;
            flex-direction: column;
            gap: 4px;
            align-items: flex-end;
        }
        .input-hint {
            font-size: 0.7rem;
            color: #64748b;
            user-select: none;
            padding-right: 2px;
        }
        button#send-btn {
            background: var(--accent-grad);
            color: #000;
            border: none;
            border-radius: 8px;
            padding: 8px 18px;
            font-weight: 700;
            font-size: 0.9rem;
            cursor: pointer;
            transition: opacity 0.2s, transform 0.1s;
            white-space: nowrap;
            height: 36px;
        }
        button#send-btn:hover { opacity: 0.9; }
        button#send-btn:active { transform: scale(0.98); }
        button#send-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        /* Feedback controls */
        .feedback-row { display: flex; gap: 10px; margin-top: 8px; align-items: center; font-size: 0.8rem; color: var(--text-muted); }
        .fb-btn { background: transparent; border: 1px solid var(--border); color: var(--text-muted); padding: 3px 8px; border-radius: 4px; cursor: pointer; }
        .fb-btn:hover { color: var(--accent); border-color: var(--accent); }
    </style>
</head>
<body>
    <div class="app-layout">
        <!-- Sidebar Lịch sử Hội thoại -->
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-title">
                    <span>💬 Lịch sử Hội thoại</span>
                </div>
                <button class="new-chat-btn" onclick="createNewSession(true)">➕ Cuộc trò chuyện mới</button>
            </div>
            <div class="session-list" id="session-list">
                <!-- Danh sách phiên load từ API -->
            </div>
        </aside>

        <!-- Main Content -->
        <main class="container">
            <header>
                <div class="logo-area">
                    <button class="toggle-btn" onclick="toggleSidebar()" title="Đóng/Mở Sidebar">☰</button>
                    <span style="font-size: 1.5rem;">🛡️</span>
                    <h1>SecLM Security Agent</h1>
                    <span class="badge">gemini-3.5-flash</span>
                </div>
                <div class="metrics-bar" id="metrics-bar">
                    <div class="metric-item">Active Tools: <strong id="m-tools">4</strong></div>
                    <div class="metric-item">Latency Avg: <strong id="m-latency">0.0s</strong></div>
                    <div class="metric-item">Tool Success: <strong id="m-accuracy">100%</strong></div>
                    <button class="tag-btn" onclick="createNewSession(true)" style="color: var(--accent); border-color: rgba(0,242,254,0.4); font-weight: 600;">➕ Phiên mới</button>
                </div>
            </header>

            <div id="chat-box">
                <!-- Messages dynamically loaded -->
            </div>

            <div class="quick-tags">
                <span style="font-size: 0.8rem; color: var(--text-muted); align-self: center;">Thử nhanh:</span>
                <button class="tag-btn" onclick="applyTag('Phân tích chi tiết lỗ hổng CVE-2024-5510 và cách vá')">🔍 Tra cứu CVE-2024-5510</button>
                <button class="tag-btn" onclick="applyTag('Quét đoạn code này: def run(val): return eval(val)')">💻 Quét mã nguồn SAST</button>
                <button class="tag-btn" onclick="applyTag('Kiểm tra mã băm 24d004a104d4d54034dbc29c2f81fb077b36724da6e00d20ef7413f7b7e3f57e')">🦠 Quét mã băm độc hại</button>
                <button class="tag-btn" onclick="applyTag('Lỗ hổng SSRF là gì và quy tắc phòng thủ chuẩn?')">📚 Tri thức CWE/SSRF</button>
            </div>

            <div class="input-bar">
                <textarea id="query" rows="1" placeholder="Nhập câu hỏi, mã CVE, đoạn mã nguồn, hoặc mã băm tệp tin... (Nhấn Enter để gửi, Shift + Enter để xuống dòng)"></textarea>
                <div class="input-actions">
                    <button id="send-btn" onclick="sendQuery()">Phân tích</button>
                    <span class="input-hint">Shift + Enter: xuống dòng</span>
                </div>
            </div>
        </main>
    </div>

    <script>
        const queryInput = document.getElementById("query");
        const sendBtn = document.getElementById("send-btn");
        const chatBox = document.getElementById("chat-box");
        const sessionListEl = document.getElementById("session-list");
        const sidebar = document.getElementById("sidebar");

        let currentSessionId = localStorage.getItem("seclm_session_id");
        if (!currentSessionId) {
            currentSessionId = "session_" + Math.random().toString(36).substring(2, 10);
            localStorage.setItem("seclm_session_id", currentSessionId);
        }

        function toggleSidebar() {
            sidebar.classList.toggle("collapsed");
        }

        const WELCOME_HTML = `
            <div class="message-row agent">
                <div class="bubble agent-bubble">
                    👋 <strong>Chào bạn! Tôi là SecLM</strong> — Chuyên gia AI về An toàn Thông tin & Thẩm định Mã nguồn.<br>
                    Tôi được tích hợp bộ công cụ thực chiến: <strong>Tra cứu CVE</strong>, <strong>Quét tĩnh mã nguồn (SAST)</strong>, <strong>Kiểm tra mã độc qua mã băm</strong> và <strong>Tra cứu chuẩn CWE/OWASP</strong>.
                </div>
            </div>
        `;

        function renderWelcomeMessage() {
            chatBox.innerHTML = WELCOME_HTML;
        }

        async function loadSessionsList() {
            try {
                const res = await fetch('/api/v1/agent/sessions');
                if (!res.ok) return;
                const data = await res.json();
                sessionListEl.innerHTML = "";
                
                if (data.sessions.length === 0) {
                    sessionListEl.innerHTML = `<div style="font-size:0.8rem; color:#64748b; padding:12px; text-align:center;">Chưa có hội thoại nào</div>`;
                    return;
                }

                data.sessions.forEach(sess => {
                    const item = document.createElement("div");
                    item.className = "session-item" + (sess.session_id === currentSessionId ? " active" : "");
                    item.onclick = () => switchSession(sess.session_id);
                    item.innerHTML = `
                        <span class="session-title" title="${sess.title}">🛡️ ${sess.title}</span>
                        <span class="session-count">${sess.total_messages}</span>
                        <button class="del-btn" title="Xóa phiên này" onclick="deleteSession('${sess.session_id}', event)">🗑️</button>
                    `;
                    sessionListEl.appendChild(item);
                });
            } catch (e) {
                console.error("Lỗi nạp danh sách phiên:", e);
            }
        }

        async function switchSession(sessionId) {
            currentSessionId = sessionId;
            localStorage.setItem("seclm_session_id", sessionId);
            await loadSessionMessages(sessionId);
            loadSessionsList();
        }

        function createNewSession(shouldClearUi = true) {
            currentSessionId = "session_" + Math.random().toString(36).substring(2, 10);
            localStorage.setItem("seclm_session_id", currentSessionId);
            if (shouldClearUi) {
                chatBox.innerHTML = `
                    <div class="message-row agent">
                        <div class="bubble agent-bubble">
                            ✨ <strong>Đã bắt đầu cuộc trò chuyện mới!</strong> Lịch sử phiên trước đã được lưu lại trong thanh Sidebar. Mời bạn nhập yêu cầu phân tích an ninh.
                        </div>
                    </div>
                `;
            }
            loadSessionsList();
        }

        async function deleteSession(sessionId, event) {
            event.stopPropagation();
            if (!confirm("Bạn có chắc chắn muốn xóa phiên làm việc này khỏi lịch sử?")) return;
            try {
                await fetch(`/api/v1/agent/session/${sessionId}`, { method: 'DELETE' });
                if (sessionId === currentSessionId) {
                    createNewSession(true);
                } else {
                    loadSessionsList();
                }
            } catch (e) {
                alert("Lỗi khi xóa phiên: " + e.message);
            }
        }

        async function loadSessionMessages(sessionId) {
            try {
                const res = await fetch(`/api/v1/agent/session/${sessionId}`);
                if (!res.ok) {
                    renderWelcomeMessage();
                    return;
                }
                const data = await res.json();
                if (!data.history || data.history.length === 0) {
                    renderWelcomeMessage();
                    return;
                }

                chatBox.innerHTML = "";
                data.history.forEach(msg => {
                    const row = document.createElement("div");
                    row.className = "message-row " + (msg.role === "user" ? "user" : "agent");
                    const bubble = document.createElement("div");
                    bubble.className = "bubble " + (msg.role === "user" ? "user-bubble" : "agent-bubble");
                    
                    if (msg.role === "user") {
                        bubble.textContent = msg.content;
                    } else {
                        bubble.innerHTML = marked.parse(msg.content);
                        bubble.querySelectorAll('pre code').forEach((el) => {
                            hljs.highlightElement(el);
                        });
                        bubble.querySelectorAll('a').forEach(a => {
                            a.setAttribute('target', '_blank');
                            a.setAttribute('rel', 'noopener noreferrer');
                        });
                    }
                    row.appendChild(bubble);
                    chatBox.appendChild(row);
                });
                chatBox.scrollTop = chatBox.scrollHeight;
            } catch (e) {
                renderWelcomeMessage();
            }
        }

        function autoResizeTextarea() {
            queryInput.style.height = "auto";
            queryInput.style.height = Math.min(queryInput.scrollHeight, 180) + "px";
        }

        queryInput.addEventListener("input", autoResizeTextarea);

        queryInput.addEventListener("keydown", function(e) {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendQuery();
            }
        });

        function applyTag(text) {
            queryInput.value = text;
            autoResizeTextarea();
            sendQuery();
        }

        async function updateTelemetry() {
            try {
                const res = await fetch('/api/v1/metrics');
                if (res.ok) {
                    const data = await res.json();
                    document.getElementById('m-tools').innerText = data.governance.total_registered_tools || '4';
                    document.getElementById('m-latency').innerText = data.metrics.average_latency_sec + 's';
                    document.getElementById('m-accuracy').innerText = data.metrics.tool_success_rate + '%';
                }
            } catch (e) {}
        }
        setInterval(updateTelemetry, 5000);
        updateTelemetry();

        // Configure marked.js to open all links in a new tab
        const linkRenderer = {
            link(hrefOrToken, title, text) {
                let href = hrefOrToken;
                let linkTitle = title;
                let linkText = text;
                if (typeof hrefOrToken === 'object' && hrefOrToken !== null) {
                    href = hrefOrToken.href;
                    linkTitle = hrefOrToken.title;
                    linkText = hrefOrToken.text;
                }
                const titleAttr = linkTitle ? ` title="${linkTitle}"` : '';
                return `<a href="${href}"${titleAttr} target="_blank" rel="noopener noreferrer">${linkText}</a>`;
            }
        };
        marked.use({ renderer: linkRenderer });

        async function sendQuery() {
            const query = queryInput.value.trim();
            if (!query) return;
            
            queryInput.value = "";
            queryInput.style.height = "auto";
            sendBtn.disabled = true;
            sendBtn.innerText = "Đang xử lý...";

            // User bubble
            const userRow = document.createElement("div");
            userRow.className = "message-row user";
            const userBubble = document.createElement("div");
            userBubble.className = "bubble user-bubble";
            userBubble.textContent = query;
            userRow.appendChild(userBubble);
            chatBox.appendChild(userRow);

            // Agent wrapper
            const agentRow = document.createElement("div");
            agentRow.className = "message-row agent";
            
            const thoughtAccordion = document.createElement("div");
            thoughtAccordion.className = "thought-accordion";
            thoughtAccordion.innerHTML = `
                <div class="thought-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
                    <span>🧠 Tiến trình Agentic: <span id="status-text">Đang kết nối...</span></span>
                    <span style="font-size: 0.75rem;">▼ Thu gọn/Mở</span>
                </div>
                <div class="thought-body" id="thought-log">Bắt đầu phân tích...</div>
            `;
            agentRow.appendChild(thoughtAccordion);

            const bubble = document.createElement("div");
            bubble.className = "bubble agent-bubble";
            bubble.innerHTML = "<em>SecLM đang suy luận...</em>";
            agentRow.appendChild(bubble);
            chatBox.appendChild(agentRow);
            chatBox.scrollTop = chatBox.scrollHeight;

            let fullAnswer = "";
            const logBox = thoughtAccordion.querySelector("#thought-log");
            const statusText = thoughtAccordion.querySelector("#status-text");

            try {
                const response = await fetch("/api/v1/agent/stream", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ query: query, session_id: currentSessionId })
                });

                if (!response.ok) {
                    throw new Error("HTTP " + response.status + ": Không thể kết nối tới server");
                }

                const reader = response.body.getReader();
                const decoder = new TextDecoder("utf-8");
                let sseBuffer = "";

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    sseBuffer += decoder.decode(value, { stream: true });
                    const events = sseBuffer.split("\\n\\n");
                    sseBuffer = events.pop(); // keep trailing partial event

                    for (const evt of events) {
                        if (!evt.trim() || evt.startsWith(":")) continue; // ignore keep-alive
                        
                        if (evt.includes("event: status")) {
                            const data = JSON.parse(evt.split("data: ")[1]);
                            statusText.innerText = data.message;
                            logBox.innerHTML += `<div>⚙️ [Trạng thái]: ${data.message}</div>`;
                            logBox.scrollTop = logBox.scrollHeight;
                        } else if (evt.includes("event: tool_call")) {
                            const data = JSON.parse(evt.split("data: ")[1]);
                            statusText.innerText = `Kích hoạt tool: ${data.tool}`;
                            logBox.innerHTML += `<div>🔧 [Tool Call]: <strong>${data.tool}</strong>(${JSON.stringify(data.args)})</div>`;
                            logBox.innerHTML += `<div style="color: #6ee7b7;">↳ Kết quả: ${JSON.stringify(data.output).slice(0, 140)}...</div>`;
                            logBox.scrollTop = logBox.scrollHeight;
                        } else if (evt.includes("event: token")) {
                            const data = JSON.parse(evt.split("data: ")[1]);
                            fullAnswer += data.token;
                            bubble.innerHTML = marked.parse(fullAnswer);
                            bubble.querySelectorAll('a').forEach(a => {
                                a.setAttribute('target', '_blank');
                                a.setAttribute('rel', 'noopener noreferrer');
                            });
                            chatBox.scrollTop = chatBox.scrollHeight;
                        } else if (evt.includes("event: error")) {
                            const data = JSON.parse(evt.split("data: ")[1]);
                            statusText.innerText = "Lỗi xử lý ⚠️";
                            logBox.innerHTML += `<div style="color: #ef4444;">❌ [Lỗi]: ${data.error}</div>`;
                            bubble.innerHTML = `<span style="color: #ef4444; font-weight: 500;">⚠️ Đã xảy ra sự cố trong quá trình phân tích: ${data.error}</span>`;
                        } else if (evt.includes("event: done")) {
                            statusText.innerText = "Hoàn tất thẩm định ✅";
                            logBox.innerHTML += `<div>✅ [Hoàn tất]</div>`;
                        }
                    }
                }

                // Syntax highlight code blocks
                bubble.querySelectorAll('pre code').forEach((el) => {
                    hljs.highlightElement(el);
                });

                // Ensure all links open in a new tab
                bubble.querySelectorAll('a').forEach(a => {
                    a.setAttribute('target', '_blank');
                    a.setAttribute('rel', 'noopener noreferrer');
                });

                // Append feedback buttons if answer was generated
                if (fullAnswer) {
                    const fbDiv = document.createElement("div");
                    fbDiv.className = "feedback-row";
                    fbDiv.innerHTML = `
                        <span>Đánh giá kết quả:</span>
                        <button class="fb-btn" onclick="submitFb(true, this)">👍 Chuẩn xác</button>
                        <button class="fb-btn" onclick="submitFb(false, this)">👎 Chưa hài lòng</button>
                    `;
                    agentRow.appendChild(fbDiv);
                }

                updateTelemetry();
                loadSessionsList();
            } catch (err) {
                statusText.innerText = "Lỗi kết nối ❌";
                bubble.innerHTML = `<span style="color: #ef4444;">Đã xảy ra lỗi kết nối với Agent: ${err.message}</span>`;
            } finally {
                sendBtn.disabled = false;
                sendBtn.innerText = "Phân tích";
            }
        }

        async function submitFb(isPositive, btn) {
            await fetch('/api/v1/feedback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rating: isPositive ? 5 : 2, is_positive: isPositive })
            });
            btn.parentElement.innerHTML = '<span style="color: var(--accent);">✓ Cảm ơn đánh giá của bạn!</span>';
        }

        // Initialize on load
        window.addEventListener("DOMContentLoaded", () => {
            loadSessionsList();
            loadSessionMessages(currentSessionId);
        });
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def root_ui():
    """Hiển thị giao diện Web Cyber Copilot trực tiếp tại trang chủ."""
    return HTML_CHAT_UI

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
