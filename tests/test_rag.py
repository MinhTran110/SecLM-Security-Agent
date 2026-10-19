from src.rag.retriever import search_security_knowledge, retriever
from src.data_pipeline.chunker import balance_code_fences, split_text_recursive


def test_rag_search_ssrf():
    res = search_security_knowledge("SSRF")
    assert res["status"] == "FOUND"
    assert res["results"][0]["cwe_id"] == "CWE-918"


def test_rag_search_cwe79():
    res = search_security_knowledge("CWE-79")
    assert res["status"] == "FOUND"
    assert "XSS" in res["results"][0]["name"]


def test_rag_search_malware_hashes():
    res = search_security_knowledge("mã băm")
    assert res["status"] == "FOUND"
    assert any("malware" in str(r.get("source", "")).lower() or "băm" in str(r).lower() for r in res["results"])


def test_hybrid_search_bm25_ranking():
    """Verify BM25 ranking prioritizes documents matching detailed technical keywords."""
    res = search_security_knowledge("SQL injection parameterized query prepared statements")
    assert res["status"] == "FOUND"
    top_result = res["results"][0]
    combined_text = (top_result.get("name", "") + " " + top_result.get("summary", "")).lower()
    assert "sql" in combined_text


def test_hybrid_search_exact_cwe_fastpath():
    """Verify exact CWE lookups match directly through fast-path."""
    res = search_security_knowledge("CWE-89")
    assert res["status"] == "FOUND"
    assert "CWE-89" in res["results"][0]["cwe_id"]


def test_hybrid_search_rrf_scoring():
    """Verify RRF assigns a normalized relevance_score between 0.50 and 0.99."""
    res = search_security_knowledge("Command Injection")
    assert res["status"] == "FOUND"
    for r in res["results"]:
        score = r.get("relevance_score")
        assert score is not None
        assert 0.50 <= score <= 1.0


def test_hybrid_search_empty_and_unknown_query():
    """Verify empty or non-existent queries return NOT_FOUND without throwing exceptions."""
    res_empty = search_security_knowledge("")
    assert res_empty["status"] == "NOT_FOUND"

    res_unknown = search_security_knowledge("xyzabc_completely_nonexistent_token_12345")
    assert res_unknown["status"] == "NOT_FOUND"


def test_security_aware_chunking_preserves_code_blocks():
    """Verify balance_code_fences fixes broken markdown code blocks."""
    broken_chunks = [
        "Hướng dẫn bảo mật:\n```python\ndef safe():\n    return True",
        "print('Done')\n```\nKết thúc."
    ]
    balanced = balance_code_fences(broken_chunks)
    assert balanced[0].endswith("```")
    assert balanced[1].startswith("```")
