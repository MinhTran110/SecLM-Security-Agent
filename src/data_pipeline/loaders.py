"""Multi-format Document Loaders for Security Knowledge Ingestion."""

import json
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional


def load_text_file(file_path: Path) -> str:
    """Load plain text or markdown file."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def load_docx_file(file_path: Path) -> str:
    """Load text from DOCX file using python-docx if available, or built-in zipfile parser."""
    try:
        import docx
        doc = docx.Document(file_path)
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        return "\n\n".join(paragraphs)
    except ImportError:
        pass

    # Built-in zero-dependency parser for DOCX (standard ZIP archive)
    try:
        with zipfile.ZipFile(file_path) as z:
            xml_content = z.read("word/document.xml")
            tree = ET.fromstring(xml_content)
            # Namespace for wordprocessingML
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            paragraphs = []
            for p in tree.iterfind(".//w:p", ns):
                texts = [t.text for t in p.iterfind(".//w:t", ns) if t.text]
                if texts:
                    paragraphs.append("".join(texts))
            return "\n\n".join(paragraphs)
    except Exception as e:
        return f"[Lỗi đọc file DOCX {file_path.name}: {str(e)}]"


def load_pdf_file(file_path: Path) -> str:
    """Load text from PDF file using pypdf if available, or fallback text extraction."""
    try:
        import pypdf
        reader = pypdf.PdfReader(str(file_path))
        pages_text = []
        for idx, page in enumerate(reader.pages):
            txt = page.extract_text()
            if txt and txt.strip():
                pages_text.append(txt.strip())
        return "\n\n".join(pages_text)
    except ImportError:
        pass

    # Fallback when pypdf is not installed: read raw ASCII streams if available
    try:
        with open(file_path, "rb") as f:
            content = f.read().decode("latin1", errors="ignore")
            import re
            streams = re.findall(r"stream[\r\n]+(.*?)[\r\n]+endstream", content, re.DOTALL)
            extracted = []
            for s in streams:
                # Filter printable text
                text_chars = "".join([c for c in s if 32 <= ord(c) <= 126 or c in "\n\r\t"])
                if len(text_chars) > 40 and any(w in text_chars.lower() for w in ["security", "cve", "cwe", "vulnerability"]):
                    extracted.append(text_chars.strip())
            if extracted:
                return "\n\n".join(extracted)
    except Exception:
        pass

    return f"[Cảnh báo: Cần cài đặt 'pypdf' (pip install pypdf) để đọc tệp PDF '{file_path.name}' một cách tối ưu nhất]"


def load_json_file(file_path: Path) -> str:
    """Load structured security JSON or advisories."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    if isinstance(data, list):
        items = []
        for item in data:
            if isinstance(item, dict):
                # Flatten dictionary into readable narrative
                parts = [f"{k.upper()}: {v}" for k, v in item.items() if isinstance(v, (str, int, float))]
                items.append("\n".join(parts))
            else:
                items.append(str(item))
        return "\n\n---\n\n".join(items)
    elif isinstance(data, dict):
        return "\n".join([f"{k.upper()}: {v}" for k, v in data.items() if isinstance(v, (str, int, float))])
    return str(data)


def load_document(file_path: Path) -> Optional[Dict[str, Any]]:
    """Automatically detect file format and extract textual content with metadata."""
    suffix = file_path.suffix.lower()
    content = ""
    file_type = "unknown"

    if suffix in [".txt", ".md"]:
        content = load_text_file(file_path)
        file_type = "markdown" if suffix == ".md" else "text"
    elif suffix == ".docx":
        content = load_docx_file(file_path)
        file_type = "docx"
    elif suffix == ".pdf":
        content = load_pdf_file(file_path)
        file_type = "pdf"
    elif suffix in [".json", ".jsonl"]:
        content = load_json_file(file_path)
        file_type = "json"
    else:
        return None

    if not content or len(content.strip()) < 20:
        return None

    return {
        "file_name": file_path.name,
        "file_path": str(file_path),
        "file_type": file_type,
        "raw_content": content,
    }
