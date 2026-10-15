import json
from pathlib import Path
from typing import List, Dict, Any
from src.tools.registry import registry

KNOWLEDGE_PATH = Path("data/cwe_knowledge.json")

class SecurityKnowledgeRetriever:
    """Retriever for CWE and OWASP security knowledge base."""

    def __init__(self, data_path: Path = KNOWLEDGE_PATH):
        self.data_path = data_path
        self.documents = self._load_data()

    def _load_data(self) -> List[Dict[str, Any]]:
        if not self.data_path.exists():
            return []
        with open(self.data_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Tìm kiếm kết hợp từ khóa và ngữ cảnh trên danh mục CWE/OWASP."""
        query_terms = [t.lower() for t in query.replace("-", " ").split()]
        scored_docs = []

        for doc in self.documents:
            cwe_id = doc.get("cwe_id", "").lower()
            name = doc.get("name", "").lower()
            owasp = doc.get("owasp", "").lower()
            desc = doc.get("description", "").lower()
            secure_pattern = doc.get("secure_pattern", "").lower()

            searchable_text = f"{cwe_id} {name} {owasp} {desc} {secure_pattern}"
            
            score = 0
            for term in query_terms:
                if term in cwe_id.replace("-", " "):
                    score += 5
                elif term in name:
                    score += 3
                elif term in owasp:
                    score += 2
                elif term in searchable_text:
                    score += 1

            if score > 0:
                scored_docs.append((score, doc))

        scored_docs.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored_docs[:top_k]]

retriever = SecurityKnowledgeRetriever()

@registry.register(
    name="search_security_knowledge",
    description="Tra cứu kho tri thức chuẩn CWE và OWASP để tìm nguyên lý phòng chống các loại lỗ hổng (XSS, SQLi, SSRF, Deserialization, Path Traversal...)."
)
def search_security_knowledge(topic: str) -> Dict[str, Any]:
    """
    Tra cứu hướng dẫn bảo mật chuẩn theo tên lỗ hổng hoặc mã CWE.

    Args:
        topic: Từ khóa lỗ hổng hoặc mã CWE (ví dụ: 'SSRF', 'CWE-918', 'XSS', 'SQL Injection').
    """
    results = retriever.search(topic)
    if results:
        return {"status": "FOUND", "total": len(results), "results": results}
    return {"status": "NOT_FOUND", "message": f"Không tìm thấy tài liệu chuẩn cho chủ đề '{topic}'."}
