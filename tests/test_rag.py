from src.rag.retriever import search_security_knowledge

def test_rag_search_ssrf():
    res = search_security_knowledge("SSRF")
    assert res["status"] == "FOUND"
    assert res["results"][0]["cwe_id"] == "CWE-918"

def test_rag_search_cwe79():
    res = search_security_knowledge("CWE-79")
    assert res["status"] == "FOUND"
    assert "XSS" in res["results"][0]["name"]
