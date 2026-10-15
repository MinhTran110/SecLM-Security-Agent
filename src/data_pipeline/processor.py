"""Main Data Pipeline Processor: Orchestrates loading, sanitizing, chunking, and exporting."""

import json
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.data_pipeline.loaders import load_document
from src.data_pipeline.cleaner import process_and_sanitize
from src.data_pipeline.chunker import create_chunks_with_metadata


def process_documents(
    input_dir: str = "data/raw",
    output_dir: str = "data/processed",
    chunk_size: int = 500,
    chunk_overlap: int = 80,
) -> Dict[str, Any]:
    """Process all documents in input_dir and export structured datasets for RAG and Fine-tuning."""
    in_path = Path(input_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    if not in_path.exists():
        in_path.mkdir(parents=True, exist_ok=True)
        return {
            "status": "EMPTY",
            "message": f"Thư mục '{input_dir}' chưa có tài liệu. Vui lòng thả file vào thư mục này.",
            "total_files": 0,
            "total_chunks": 0,
        }

    supported_extensions = {".pdf", ".docx", ".txt", ".md", ".json", ".jsonl"}
    all_files = [f for f in in_path.iterdir() if f.is_file() and f.suffix.lower() in supported_extensions]

    if not all_files:
        return {
            "status": "EMPTY",
            "message": f"Không tìm thấy file hợp lệ trong '{input_dir}' (.pdf, .docx, .md, .txt, .json).",
            "total_files": 0,
            "total_chunks": 0,
        }

    all_chunks: List[Dict[str, Any]] = []
    fine_tune_records: List[Dict[str, Any]] = []
    processed_files_summary = []

    for file_path in all_files:
        doc = load_document(file_path)
        if not doc:
            continue

        doc_id = f"doc_{file_path.stem.lower()}_{str(uuid.uuid4())[:8]}"
        clean_content, metadata = process_and_sanitize(doc["raw_content"])

        # Create structured chunks for Vector DB
        chunks = create_chunks_with_metadata(
            doc_id=doc_id,
            source_file=file_path.name,
            clean_text=clean_content,
            doc_metadata=metadata,
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
        )
        all_chunks.extend(chunks)

        # Generate Fine-Tuning conversation pair for this document
        cwe_label = metadata["cwe_ids"][0] if metadata["cwe_ids"] else metadata["category"]
        fine_tune_records.append({
            "messages": [
                {
                    "role": "system",
                    "content": "Bạn là SecLM - Chuyên gia Trí tuệ Nhân tạo về An toàn Thông tin và Thẩm định Mã nguồn."
                },
                {
                    "role": "user",
                    "content": f"Phân tích nguyên lý và hướng dẫn khắc phục bảo mật cho chủ đề: {metadata['category']} ({', '.join(metadata['cwe_ids']) if metadata['cwe_ids'] else file_path.stem})."
                },
                {
                    "role": "assistant",
                    "content": f"### Báo cáo Thẩm định An ninh\n- **Phân loại**: {metadata['category']}\n- **Mức độ rủi ro**: {metadata['severity']}\n\n{clean_content[:1200]}\n\n### 📚 Nguồn tham chiếu: Tài liệu {file_path.name}"
                }
            ]
        })

        processed_files_summary.append({
            "file_name": file_path.name,
            "file_type": doc["file_type"],
            "chunks_count": len(chunks),
            "detected_cves": metadata["cve_ids"],
            "detected_cwes": metadata["cwe_ids"],
            "category": metadata["category"],
            "severity": metadata["severity"],
        })

    # Export RAG Chunks to JSON
    rag_output_file = out_path / "rag_knowledge.json"
    with open(rag_output_file, "w", encoding="utf-8") as f:
        json.dump(all_chunks, f, ensure_ascii=False, indent=2)

    # Export Fine-tuning dataset to JSONL
    ft_output_file = out_path / "fine_tune_train.jsonl"
    with open(ft_output_file, "w", encoding="utf-8") as f:
        for rec in fine_tune_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    return {
        "status": "SUCCESS",
        "total_files": len(processed_files_summary),
        "total_chunks": len(all_chunks),
        "rag_output": str(rag_output_file),
        "fine_tune_output": str(ft_output_file),
        "files": processed_files_summary,
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SecurityAgent Data Ingestion & Filtering Pipeline")
    parser.add_argument("--input", default="data/raw", help="Thư mục chứa tài liệu thô (.pdf, .docx, .md, .json)")
    parser.add_argument("--output", default="data/processed", help="Thư mục xuất kết quả")
    parser.add_argument("--chunk-size", type=int, default=500, help="Kích thước chunk tối đa")
    parser.add_argument("--overlap", type=int, default=80, help="Độ gối đầu giữa các chunks")
    args = parser.parse_args()

    print(f"[SecLM Data Pipeline] Bắt đầu quét và xử lý tài liệu từ '{args.input}'...")
    result = process_documents(args.input, args.output, args.chunk_size, args.overlap)
    print(f"✅ Hoàn tất! Đã xử lý {result['total_files']} tệp tin, sinh ra {result['total_chunks']} chunks chuẩn Vector DB.")
    if "rag_output" in result:
        print(f"📦 File RAG: {result['rag_output']}")
        print(f"🎯 File Fine-tuning: {result['fine_tune_output']}")
