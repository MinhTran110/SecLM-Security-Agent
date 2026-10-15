import json
from pathlib import Path
from typing import List, Dict, Any
from src.tools.registry import registry

KNOWLEDGE_PATH = Path("data/cwe_knowledge.json")
PROCESSED_RAG_PATH = Path("data/processed/rag_knowledge.json")


class SecurityKnowledgeRetriever:
    """Hybrid Retriever for CWE, OWASP, and Processed Document Knowledge Chunks."""

    def __init__(self, data_path: Path = KNOWLEDGE_PATH, processed_path: Path = PROCESSED_RAG_PATH):
        self.data_path = data_path
        self.processed_path = processed_path
        self.documents = self._load_data()

    def _load_data(self) -> List[Dict[str, Any]]:
        docs = []
        # Load baseline CWE knowledge
        if self.data_path.exists():
            try:
                with open(self.data_path, "r", encoding="utf-8") as f:
                    base_items = json.load(f)
                    for item in base_items:
                        item["source"] = "MITRE CWE / OWASP Catalog"
                        docs.append(item)
            except Exception:
                pass

        # Load processed RAG document chunks from data/processed
        if self.processed_path.exists():
            try:
                with open(self.processed_path, "r", encoding="utf-8") as f:
                    chunk_items = json.load(f)
                    for c in chunk_items:
                        docs.append({
                            "cwe_id": ", ".join(c.get("metadata", {}).get("cwe_ids", [])) or "DOCUMENT",
                            "name": c.get("metadata", {}).get("category", "Custom Advisory"),
                            "description": c.get("content", ""),
                            "secure_pattern": c.get("content", "")[:200],
                            "source": f"Tài liệu '{c.get('source_file')}' (Chunk {c.get('chunk_index', 0)})",
                            "chunk_id": c.get("chunk_id"),
                        })
            except Exception:
                pass

        return docs

    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Tìm kiếm kết hợp từ khóa và ngữ cảnh trên kho tri thức."""
        # Reload if new processed files appeared
        if self.processed_path.exists() and len(self.documents) < 5:
            self.documents = self._load_data()

        query_terms = [t.lower() for t in query.replace("-", " ").split()]
        scored_docs = []

        for doc in self.documents:
            cwe_id = str(doc.get("cwe_id", "")).lower()
            name = str(doc.get("name", "")).lower()
            desc = str(doc.get("description", "")).lower()
            secure_pattern = str(doc.get("secure_pattern", "")).lower()

            searchable_text = f"{cwe_id} {name} {desc} {secure_pattern}"
            
            score = 0
            for term in query_terms:
                if term in cwe_id.replace("-", " "):
                    score += 5
                elif term in name:
                    score += 3
                elif term in searchable_text:
                    score += 1

            if score > 0:
                scored_docs.append((score, doc))

        scored_docs.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored_docs[:top_k]]


retriever = SecurityKnowledgeRetriever()


@registry.register(
    name="search_security_knowledge",
    description="Tra cứu kho tri thức chuẩn CWE/OWASP và các tài liệu bảo mật đã nạp để tìm nguyên lý phòng chống và bản vá."
)
def search_security_knowledge(topic: str) -> Dict[str, Any]:
    """
    Tra cứu hướng dẫn bảo mật chuẩn theo tên lỗ hổng hoặc mã CWE.

    Args:
        topic: Từ khóa lỗ hổng hoặc mã CWE (ví dụ: 'SSRF', 'CWE-918', 'XSS', 'SQL Injection').
    """
    results = retriever.search(topic)
    if results:
        # Format transparent citations
        formatted = []
        for r in results:
            formatted.append({
                "cwe_id": r.get("cwe_id"),
                "name": r.get("name"),
                "source": r.get("source", "Knowledge Base"),
                "summary": r.get("description", "")[:280] + "...",
                "secure_pattern": r.get("secure_pattern", ""),
            })
        return {
            "status": "FOUND",
            "total": len(formatted),
            "results": formatted,
        }
    return {"status": "NOT_FOUND", "message": f"Không tìm thấy tài liệu chuẩn cho chủ đề '{topic}'."}
