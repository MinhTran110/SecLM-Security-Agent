"""Multi-turn Conversation Session Memory Manager with SQLite Persistence and Sliding Window."""

import sqlite3
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from google.genai import types

DB_PATH = Path("data/chat_sessions.db")


class SessionMemoryManager:
    """Manages chat history per session_id with SQLite persistence and sliding window."""

    def __init__(self, db_path: Path = DB_PATH, max_turns: int = 6):
        self.db_path = db_path
        self.max_turns = max_turns  # Each turn is (user, model) pair = max_turns * 2 messages
        self._init_db()

    def _init_db(self):
        """Ensure the chat_turns table exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_turns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_session ON chat_turns(session_id, id)")
            conn.commit()

    def add_turn(self, session_id: str, role: str, content: str):
        """Add a single message turn for a given session."""
        if not session_id or not content:
            return
        normalized_role = "model" if role in ["model", "assistant"] else "user"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO chat_turns (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
                (session_id, normalized_role, content, time.time())
            )
            conn.commit()

    def get_history(self, session_id: str, max_turns: Optional[int] = None) -> List[Dict[str, str]]:
        """Retrieve the conversation history for a session, limited by sliding window."""
        if not session_id:
            return []
        limit = (max_turns or self.max_turns) * 2
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT role, content FROM (
                    SELECT id, role, content FROM chat_turns
                    WHERE session_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                ) ORDER BY id ASC
                """,
                (session_id, limit)
            )
            rows = cursor.fetchall()
            return [{"role": r[0], "content": r[1]} for r in rows]

    def get_gemini_contents(self, session_id: str, current_query: str, max_turns: Optional[int] = None) -> List[types.Content]:
        """Build Gemini Content objects from sliding window history plus current user query."""
        history = self.get_history(session_id, max_turns=max_turns)
        contents: List[types.Content] = []
        for msg in history:
            role = "user" if msg["role"] == "user" else "model"
            contents.append(types.Content(role=role, parts=[types.Part.from_text(text=msg["content"])]))

        # Append current user query
        contents.append(types.Content(role="user", parts=[types.Part.from_text(text=current_query)]))
        return contents

    def get_all_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve list of distinct sessions with their first query as title, count, and last activity."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    session_id,
                    COUNT(id) as total_messages,
                    MAX(timestamp) as last_updated,
                    (
                        SELECT content FROM chat_turns t2 
                        WHERE t2.session_id = t1.session_id AND t2.role = 'user' 
                        ORDER BY t2.id ASC LIMIT 1
                    ) as first_query
                FROM chat_turns t1
                GROUP BY session_id
                ORDER BY last_updated DESC
                LIMIT ?
                """,
                (limit,)
            )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                session_id = r[0]
                total_messages = r[1]
                last_updated = r[2]
                first_query = r[3] or "Cuộc trò chuyện mới"
                title = first_query.strip().split("\n")[0][:45]
                if len(first_query.strip().split("\n")[0]) > 45:
                    title += "..."
                results.append({
                    "session_id": session_id,
                    "title": title,
                    "total_messages": total_messages,
                    "last_updated": last_updated
                })
            return results

    def clear_session(self, session_id: str):
        """Delete all conversation turns for a session."""
        if not session_id:
            return
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM chat_turns WHERE session_id = ?", (session_id,))
            conn.commit()


session_memory = SessionMemoryManager()
