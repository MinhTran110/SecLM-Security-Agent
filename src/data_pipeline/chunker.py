"""Recursive Semantic Character Chunking for Vector Databases and Hybrid Search.

Includes Security-Aware chunking to preserve code blocks and Markdown structures.
"""

from typing import List, Dict, Any


def balance_code_fences(chunks: List[str]) -> List[str]:
    """Ensure no chunk has dangling or unclosed markdown code fences."""
    balanced = []
    in_code_block = False
    for chunk in chunks:
        c = chunk
        if in_code_block:
            c = "```\n" + c

        fence_count = c.count("```")
        if fence_count % 2 != 0:
            c = c + "\n```"
            in_code_block = not in_code_block
        else:
            in_code_block = False
        balanced.append(c.strip())
    return [b for b in balanced if b]


def split_text_recursive(
    text: str,
    chunk_size: int = 500,
    chunk_overlap: int = 80,
    separators: List[str] = None
) -> List[str]:
    """Recursively split text by structural separators to preserve context."""
    if separators is None:
        separators = ["\n\n", "\n", ". ", ", ", " "]

    if len(text) <= chunk_size:
        return [text.strip()] if text.strip() else []

    # Find the highest priority separator present in the text
    chosen_sep = ""
    for sep in separators:
        if sep in text:
            chosen_sep = sep
            break

    if not chosen_sep:
        # Fallback to hard character slice if no separator matches
        chunks = []
        start = 0
        while start < len(text):
            end = min(start + chunk_size, len(text))
            chunks.append(text[start:end].strip())
            start += chunk_size - chunk_overlap
        return balance_code_fences(chunks)

    splits = text.split(chosen_sep)
    remaining_seps = separators[separators.index(chosen_sep) + 1:] if chosen_sep in separators else []

    chunks = []
    current_chunk = []
    current_length = 0

    for s in splits:
        piece = s.strip()
        if not piece:
            continue

        piece_len = len(piece) + len(chosen_sep)
        if current_length + piece_len <= chunk_size:
            current_chunk.append(piece)
            current_length += piece_len
        else:
            if current_chunk:
                merged = chosen_sep.join(current_chunk).strip()
                if merged:
                    chunks.append(merged)

                # Keep overlap pieces from the end of current_chunk
                overlap_pieces = []
                overlap_len = 0
                for item in reversed(current_chunk):
                    if overlap_len + len(item) <= chunk_overlap:
                        overlap_pieces.insert(0, item)
                        overlap_len += len(item)
                    else:
                        break
                current_chunk = overlap_pieces
                current_length = sum(len(p) for p in current_chunk)

            # If a single piece is bigger than chunk_size, recurse with finer separators
            if len(piece) > chunk_size and remaining_seps:
                sub_chunks = split_text_recursive(piece, chunk_size, chunk_overlap, remaining_seps)
                chunks.extend(sub_chunks)
            else:
                current_chunk.append(piece)
                current_length += len(piece)

    if current_chunk:
        merged = chosen_sep.join(current_chunk).strip()
        if merged:
            chunks.append(merged)

    return balance_code_fences(chunks)


def create_chunks_with_metadata(
    doc_id: str,
    source_file: str,
    clean_text: str,
    doc_metadata: Dict[str, Any],
    chunk_size: int = 500,
    chunk_overlap: int = 80
) -> List[Dict[str, Any]]:
    """Generate structured chunks ready for Vector DB upsert and RAG hybrid search."""
    raw_chunks = split_text_recursive(clean_text, chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    total_chunks = len(raw_chunks)
    results = []

    for idx, chunk in enumerate(raw_chunks):
        word_count = len(chunk.split())
        chunk_entry = {
            "chunk_id": f"{doc_id}_c{idx:03d}",
            "doc_id": doc_id,
            "source_file": source_file,
            "chunk_index": idx,
            "total_chunks": total_chunks,
            "content": chunk,
            "token_estimate": int(word_count * 1.3),
            "metadata": {
                **doc_metadata,
                "source_file": source_file,
                "chunk_index": idx,
            }
        }
        results.append(chunk_entry)

    return results
