"""Universal Web Scraper for SecLM Knowledge Base.

Hỗ trợ cào dữ liệu từ bất kỳ đường link website nào trên mạng:
- Trang danh mục bảng: MITRE ATT&CK Software (https://attack.mitre.org/software/)
- Trang bài viết bảo mật, Security Advisory, Blog, Tin tức lỗ hổng CVE

Usage:
  # Cào MITRE ATT&CK Software:
  python scripts/scrape_webpage.py https://attack.mitre.org/software/ --type mitre

  # Cào bất kỳ bài viết / link bảo mật trên mạng:
  python scripts/scrape_webpage.py "https://example.com/security-article" --out data/raw/my_article.md
"""

import sys
import re
import argparse
from pathlib import Path
from html.parser import HTMLParser

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    import httpx
except ImportError:
    print("❌ Vui lòng cài đặt httpx: pip install httpx")
    sys.exit(1)

from scripts.crawl_security_data import MitreSoftwareHTMLParser



class HTMLToMarkdownParser(HTMLParser):
    """Trích xuất nội dung bài viết HTML thành Markdown sạch (loại bỏ script, style, nav, footer)."""
    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.ignore_tags = {"script", "style", "noscript", "svg", "nav", "footer", "header"}
        self.current_ignore = 0
        self.in_h = None
        self.in_p = False
        self.in_a = False
        self.current_href = ""

    def handle_starttag(self, tag, attrs):
        tag_lower = tag.lower()
        if tag_lower in self.ignore_tags:
            self.current_ignore += 1
            return
        if self.current_ignore > 0:
            return

        attrs_dict = dict(attrs)
        if tag_lower in ["h1", "h2", "h3", "h4", "h5", "h6"]:
            level = int(tag_lower[1])
            self.text_parts.append(f"\n\n{'#' * level} ")
            self.in_h = level
        elif tag_lower == "p":
            self.text_parts.append("\n\n")
            self.in_p = True
        elif tag_lower in ["li"]:
            self.text_parts.append("\n- ")
        elif tag_lower == "a" and "href" in attrs_dict:
            self.in_a = True
            self.current_href = attrs_dict["href"]
            self.text_parts.append("[")

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower in self.ignore_tags:
            self.current_ignore = max(0, self.current_ignore - 1)
            return
        if self.current_ignore > 0:
            return

        if tag_lower in ["h1", "h2", "h3", "h4", "h5", "h6"]:
            self.text_parts.append("\n")
            self.in_h = None
        elif tag_lower == "p":
            self.in_p = False
        elif tag_lower == "a" and self.in_a:
            self.in_a = False
            self.text_parts.append(f"]({self.current_href})")

    def handle_data(self, data):
        if self.current_ignore > 0:
            return
        text = data.strip()
        if text:
            self.text_parts.append(data)

    def get_markdown(self) -> str:
        raw = "".join(self.text_parts)
        # Thu gọn khoảng trống thừa
        cleaned = re.sub(r"\n{3,}", "\n\n", raw).strip()
        return cleaned


MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def scrape_mitre(url: str, out_dir: Path):
    """Cào chuyên dụng cho MITRE ATT&CK Software Catalog (Ưu tiên GitHub STIX, tự động fallback HTML)."""
    import json
    from scripts.crawl_security_data import parse_mitre_stix

    # Cách 1: Thử GitHub STIX trước để tránh Cloudflare 503 WAF
    print(f"🌐 [1/2] Đang kết nối tới kho dữ liệu STIX chính thức của MITRE CTI...")
    try:
        with httpx.Client(timeout=60.0, follow_redirects=True) as client:
            resp = client.get(MITRE_STIX_URL)
            if resp.status_code == 200:
                stix_data = resp.json()
                software_list, md_lines = parse_mitre_stix(stix_data)

                json_path = out_dir / "mitre_attack_software.json"
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(software_list, f, ensure_ascii=False, indent=2)

                md_path = out_dir / "mitre_attack_software.md"
                md_path.write_text("\n".join(md_lines), encoding="utf-8")

                print(f"✅ Đã tải và trích xuất thành công {len(software_list)} mã độc & công cụ từ MITRE STIX!")
                print(f"📂 Đã lưu JSON: {json_path}")
                print(f"📂 Đã lưu Markdown: {md_path}")
                return
    except Exception as e:
        print(f"⚠️ Không tải được qua STIX ({str(e)}), thử cào HTML trực tiếp...")

    # Cách 2: Cào HTML trực tiếp
    print(f"🌐 [2/2] Đang cào bảng danh mục MITRE ATT&CK từ web: {url}")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    with httpx.Client(headers=headers, timeout=30.0, follow_redirects=True) as client:
        resp = client.get(url)
        if resp.status_code == 503:
            print("⚠️ HTTP 503 Service Unavailable: Trang web attack.mitre.org bật Cloudflare WAF chống Bot Scraping tự động.")
            # Kiểm tra dữ liệu local có sẵn
            local_md = out_dir / "mitre_attack_software.md"
            if local_md.exists():
                print(f"💡 Đã có sẵn dữ liệu nội bộ tại {local_md}. Sẵn sàng nạp vào RAG!")
                return
        resp.raise_for_status()

    parser = MitreSoftwareHTMLParser()
    parser.feed(resp.text)

    software_list = []
    md_lines = [
        "# MITRE ATT&CK Software & Malware Knowledge Base",
        "",
        f"> Nguồn dữ liệu: [{url}]({url})",
        "> Phân loại: Danh mục phần mềm độc hại (Malware) và công cụ tấn công (Adversary Tools).",
        "",
    ]

    for row in parser.rows:
        if len(row) < 4:
            continue
        id_text, id_link = row[0]
        name_text, _ = row[1]
        aliases, _ = row[2]
        desc, _ = row[3]

        if id_text.upper() in ["ID", "SOFTWARE"]:
            continue

        full_url = f"https://attack.mitre.org{id_link}" if id_link.startswith("/") else (id_link or f"https://attack.mitre.org/software/{id_text}/")

        software_list.append({
            "id": id_text,
            "name": name_text,
            "aliases": aliases,
            "url": full_url,
            "description": desc
        })

        md_lines.append(f"## {id_text} - {name_text}")
        md_lines.append(f"- **Mã định danh**: [{id_text}]({full_url})")
        md_lines.append(f"- **Tên phần mềm**: {name_text}")
        if aliases and aliases != "-":
            md_lines.append(f"- **Tên gọi khác / Aliases**: {aliases}")
        md_lines.append(f"- **Nguồn tham chiếu**: [{name_text} on MITRE ATT&CK]({full_url})")
        md_lines.append(f"- **Mô tả hành vi**: {desc}")
        md_lines.append("")

    json_path = out_dir / "mitre_attack_software.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(software_list, f, ensure_ascii=False, indent=2)

    md_path = out_dir / "mitre_attack_software.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    print(f"✅ Đã trích xuất {len(software_list)} mã độc & công cụ thành công!")
    print(f"📂 Đã lưu JSON: {json_path}")
    print(f"📂 Đã lưu Markdown: {md_path}")



def scrape_article(url: str, out_file: Path):
    """Cào bài viết / advisory từ một link bất kỳ trên mạng và chuyển đổi sang Markdown."""
    print(f"🌐 Đang cào bài viết từ link: {url}")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    with httpx.Client(headers=headers, timeout=25.0, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()

    parser = HTMLToMarkdownParser()
    parser.feed(resp.text)
    markdown_content = parser.get_markdown()

    # Thêm Metadata Header chuẩn cho RAG
    final_doc = f"""# Tài liệu tham khảo bảo mật

> **Nguồn trích dẫn gốc**: [{url}]({url})
> **Thời điểm cào**: Tự động qua SecLM Web Scraper

---

{markdown_content}
"""
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(final_doc, encoding="utf-8")
    print(f"✅ Đã lưu bài viết định dạng Markdown chuẩn vào: {out_file}")


def main():
    parser = argparse.ArgumentParser(description="SecLM Universal Web Scraper")
    parser.add_argument("url", help="URL website cần cào (ví dụ: https://attack.mitre.org/software/)")
    parser.add_argument(
        "--type",
        choices=["auto", "mitre", "article"],
        default="auto",
        help="Kiểu cấu trúc trang web: auto, mitre, article (mặc định: auto)"
    )
    parser.add_argument(
        "--out",
        help="Đường dẫn file lưu trữ (.md hoặc .json). Mặc định tự đặt tên trong data/raw/"
    )
    args = parser.parse_args()

    url = args.url.strip()

    if "..." in url:
        print("❌ Lỗi: URL chứa ký hiệu '...' (đây là ví dụ minh họa, không phải đường link thật).")
        print("👉 Vui lòng dán một đường link bài viết thực tế trên mạng. Ví dụ:")
        print("   .venv/bin/python scripts/scrape_webpage.py \"https://thehackernews.com/\" --out data/raw/hackernews_home.md")
        sys.exit(1)

    is_mitre = "attack.mitre.org/software" in url.lower() or args.type == "mitre"

    raw_dir = Path("data/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)


    try:
        if is_mitre:
            scrape_mitre(url, raw_dir)
        else:
            if args.out:
                out_path = Path(args.out)
            else:
                # Đặt tên file từ domain + path
                safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", url.split("://")[-1].replace("/", "_"))[:40]
                out_path = raw_dir / f"web_{safe_name}.md"
            scrape_article(url, out_path)

        print("\n🎉 Hoàn thành! Bước tiếp theo để đưa vào RAG:")
        print("👉 .venv/bin/python -m src.data_pipeline.processor")

    except Exception as e:
        print(f"❌ Xảy ra lỗi khi cào URL '{url}': {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
