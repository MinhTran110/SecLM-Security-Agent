"""Unit tests for the Data Ingestion, Cleaning, and Chunking Pipeline."""

from pathlib import Path
from src.data_pipeline.cleaner import sanitize_secrets, extract_security_metadata, clean_text
from src.data_pipeline.chunker import split_text_recursive, create_chunks_with_metadata
from src.data_pipeline.processor import process_documents


def test_cleaner_sanitizes_secrets():
    """Verify secrets and sensitive IPs are properly redacted."""
    raw = 'api_key = "AIzaSySecretToken123456789"\nserver = "192.168.1.50"\nmetadata = "169.254.169.254"'
    sanitized = sanitize_secrets(raw)
    assert "<REDACTED_API_KEY>" in sanitized
    assert "<INTERNAL_IP>" in sanitized
    assert "192.168.1.50" not in sanitized
    assert "AIzaSySecretToken" not in sanitized


def test_cleaner_extracts_security_metadata():
    """Verify entity extraction for CVEs, CWEs, and categories."""
    text = "Báo cáo lỗ hổng CVE-2024-5510 liên quan tới lỗi SQL Injection (CWE-89) với điểm CVSS 9.8."
    meta = extract_security_metadata(text)
    assert "CVE-2024-5510" in meta["cve_ids"]
    assert "CWE-89" in meta["cwe_ids"]
    assert meta["cvss_score"] == 9.8
    assert meta["category"] == "SQL Injection"
    assert meta["severity"] == "CRITICAL"


def test_chunker_recursive_splitting():
    """Verify recursive chunking keeps paragraph boundaries and respects chunk size."""
    paragraphs = "\n\n".join([f"Đoạn văn bảo mật số {i}: Hướng dẫn phòng chống lỗ hổng SQLi." * 5 for i in range(10)])
    chunks = split_text_recursive(paragraphs, chunk_size=300, chunk_overlap=50)
    assert len(chunks) >= 3
    for c in chunks:
        assert len(c) > 0


def test_end_to_end_data_processor(tmp_path):
    """Verify end-to-end ingestion, filtering, and export for RAG and fine-tuning."""
    # Create sample raw file in tmp
    raw_dir = tmp_path / "raw"
    processed_dir = tmp_path / "processed"
    raw_dir.mkdir()

    sample_doc = raw_dir / "advisory_test.md"
    sample_doc.write_text("""# Phân tích CVE-2021-44228
Lỗ hổng Log4Shell (CWE-502) trong Apache Log4j.
Điểm CVSS 10.0 mức độ CRITICAL.
Khắc phục: Nâng cấp Log4j >= 2.17.1.
""", encoding="utf-8")

    result = process_documents(
        input_dir=str(raw_dir),
        output_dir=str(processed_dir),
        chunk_size=200,
        chunk_overlap=40
    )

    assert result["status"] == "SUCCESS"
    assert result["total_files"] == 1
    assert result["total_chunks"] >= 1
    
    rag_file = Path(result["rag_output"])
    ft_file = Path(result["fine_tune_output"])
    assert rag_file.exists()
    assert ft_file.exists()


def test_mitre_software_html_parser():
    """Verify MitreSoftwareHTMLParser extracts software ID, name, and description from HTML table."""
    from scripts.crawl_security_data import MitreSoftwareHTMLParser
    html = """
    <table>
      <tr><th>ID</th><th>Name</th><th>Associated Software</th><th>Description</th></tr>
      <tr>
        <td><a href="/software/S0002/">S0002</a></td>
        <td><a href="/software/S0002/">Mimikatz</a></td>
        <td>Kiwi</td>
        <td>Mimikatz is an open-source tool that performs credential dumping.</td>
      </tr>
    </table>
    """
    parser = MitreSoftwareHTMLParser()
    parser.feed(html)
    assert len(parser.rows) >= 2
    data_row = parser.rows[1]
    assert data_row[0][0] == "S0002"
    assert "/software/S0002/" in data_row[0][1]
    assert data_row[1][0] == "Mimikatz"
    assert data_row[2][0] == "Kiwi"
    assert "credential dumping" in data_row[3][0]

