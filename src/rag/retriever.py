"""Hybrid Knowledge Retriever for CWE, OWASP, and Processed Document Knowledge Chunks.

Integrates Fast-Path Exact Metadata Lookup, BM25 Okapi Inverted Index,
and Reciprocal Rank Fusion (RRF) for ultra-fast, zero-GPU security retrieval.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import numpy as np
from rank_bm25 import BM25Okapi
from src.tools.registry import registry

KNOWLEDGE_PATH = Path("data/cwe_knowledge.json")
PROCESSED_RAG_PATH = Path("data/processed/rag_knowledge.json")


def tokenize_security_text(text: str) -> List[str]:
    """Tokenize text into lowercase terms, splitting punctuation and expanding hyphens."""
    cleaned = re.sub(r"[^\w\-]", " ", str(text).lower())
    tokens = cleaned.split()
    expanded = []
    for t in tokens:
        expanded.append(t)
        if "-" in t:
            expanded.extend(t.split("-"))
    return [tok for tok in expanded if len(tok) >= 2]


class SecurityKnowledgeRetriever:
    """Multi-channel Hybrid Retriever integrating Exact Metadata matching and BM25 with RRF."""

    def __init__(self, data_path: Path = KNOWLEDGE_PATH, processed_path: Path = PROCESSED_RAG_PATH):
        self.data_path = data_path
        self.processed_path = processed_path
        self.documents: List[Dict[str, Any]] = []
        self.bm25: Optional[BM25Okapi] = None
        self._load_and_index()

    def _load_data(self) -> List[Dict[str, Any]]:
        docs = []
        # 1. Load baseline CWE / Threat Intel knowledge
        if self.data_path.exists():
            try:
                with open(self.data_path, "r", encoding="utf-8") as f:
                    base_items = json.load(f)
                    for item in base_items:
                        item["source"] = "MITRE CWE / OWASP Catalog"
                        docs.append(item)
            except Exception:
                pass

        # 2. Load processed RAG document chunks from data/processed
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

    def _load_and_index(self):
        """Load documents and build BM25 Okapi inverted index."""
        self.documents = self._load_data()
        if not self.documents:
            self.bm25 = None
            return

        corpus = []
        for d in self.documents:
            cid = str(d.get("cwe_id", ""))
            name = str(d.get("name", ""))
            desc = str(d.get("description", ""))[:800]
            sec = str(d.get("secure_pattern", ""))[:300]
            corpus.append(tokenize_security_text(f"{cid} {name} {desc} {sec}"))

        self.bm25 = BM25Okapi(corpus)

    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Perform Multi-channel Hybrid Search using Exact Metadata and BM25 with RRF."""
        if not query or not query.strip():
            return []

        # Reload if new processed files appeared
        if self.processed_path.exists() and len(self.documents) < 5:
            self._load_and_index()

        q_clean = query.strip().lower()
        q_tokens = tokenize_security_text(query)

        # -------------------------------------------------------------
        # Channel 1: Fast-Path Exact Metadata Match
        # -------------------------------------------------------------
        exact_scores: Dict[int, float] = {}
        for i, doc in enumerate(self.documents):
            cid = str(doc.get("cwe_id", "")).lower()
            name = str(doc.get("name", "")).lower()
            src = str(doc.get("source", ""))
            is_canonical = "MITRE CWE" in src

            score = 0.0
            # Direct match with CWE ID or numeric code (e.g. CWE-918 or 918)
            if q_clean == cid or f"cwe-{q_clean}" == cid:
                score += 100.0
            elif q_clean in cid.replace("-", " ").split():
                score += 80.0

            # Match acronyms in parentheses or exact name (e.g. (SSRF), (XSS))
            if f"({q_clean})" in name:
                score += 90.0
            elif name == q_clean or q_clean in name:
                score += 50.0
            elif any(t in name for t in q_tokens if len(t) > 2):
                score += 20.0

            # Authority weight for canonical catalog items
            if is_canonical and score > 0:
                score += 15.0

            if score > 0:
                exact_scores[i] = score

        # -------------------------------------------------------------
        # Channel 2: BM25 Okapi Inverted Index Match
        # -------------------------------------------------------------
        top_bm25_indices: List[int] = []
        bm25_scores = np.array([])
        if self.bm25 is not None and q_tokens:
            bm25_scores = np.array(self.bm25.get_scores(q_tokens))
            if bm25_scores.size > 0:
                top_bm25_indices = bm25_scores.argsort()[::-1][:50].tolist()

        # -------------------------------------------------------------
        # Channel 3: Reciprocal Rank Fusion (RRF) & Re-ranking
        # -------------------------------------------------------------
        k = 60
        rrf_scores: Dict[int, float] = {}

        # 1. Rank from Exact Channel
        sorted_exact = sorted(exact_scores.items(), key=lambda x: x[1], reverse=True)[:50]
        for rank, (idx, _) in enumerate(sorted_exact):
            rrf_scores[idx] = rrf_scores.get(idx, 0.0) + (1.5 / (k + rank + 1))

        # 2. Rank from BM25 Channel
        for rank, idx in enumerate(top_bm25_indices):
            if idx < len(bm25_scores) and bm25_scores[idx] > 0:
                rrf_scores[idx] = rrf_scores.get(idx, 0.0) + (1.0 / (k + rank + 1))

        # 3. Canonical tie-breaker boost
        for idx in rrf_scores:
            if "MITRE CWE" in str(self.documents[idx].get("source", "")):
                rrf_scores[idx] += 0.005

        if not rrf_scores:
            return []

        top_indices = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)[:top_k]

        max_rrf = top_indices[0][1] if top_indices else 1.0

        results = []
        for idx, score in top_indices:
            doc_copy = dict(self.documents[idx])
            norm_confidence = round(min(0.99, max(0.50, (score / max_rrf) * 0.95)), 2)
            doc_copy["relevance_score"] = norm_confidence
            results.append(doc_copy)

        return results


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
        formatted = []
        for r in results:
            formatted.append({
                "cwe_id": r.get("cwe_id"),
                "name": r.get("name"),
                "source": r.get("source", "Knowledge Base"),
                "summary": r.get("description", "")[:280] + "...",
                "secure_pattern": r.get("secure_pattern", ""),
                "relevance_score": r.get("relevance_score", 0.90),
            })
        return {
            "status": "FOUND",
            "total": len(formatted),
            "results": formatted,
        }
    return {"status": "NOT_FOUND", "message": f"Không tìm thấy tài liệu chuẩn cho chủ đề '{topic}'."}
