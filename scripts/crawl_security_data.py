"""Automated Security Data Crawler for SecLM RAG Knowledge Base.

Sources:
1. CISA Known Exploited Vulnerabilities (KEV) Catalog (JSON)
2. OWASP Cheat Sheet Series (Markdown)
3. GitHub Security Advisories API (JSON)
"""

import sys
import json
import argparse
from pathlib import Path
from html.parser import HTMLParser


try:
    import httpx
except ImportError:
    print("❌ Vui lòng cài đặt httpx: pip install httpx")
    sys.exit(1)

RAW_DIR = Path("data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)

# 1. Danh sách OWASP Cheat Sheets chuẩn
OWASP_CHEATSHEETS = {
    "owasp_sqli_prevention.md": "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md",
    "owasp_xss_prevention.md": "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.md",
    "owasp_ssrf_prevention.md": "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md",
    "owasp_deserialization_prevention.md": "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Deserialization_Cheat_Sheet.md",
    "owasp_docker_security.md": "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Docker_Security_Cheat_Sheet.md",
}

# 2. CISA KEV Catalog
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# 3. GitHub Security Advisories
GITHUB_ADVISORY_URL = "https://api.github.com/advisories?severity=critical&per_page=30"

# 4. MITRE ATT&CK Software Catalog (Malware & Adversary Tools)
MITRE_SOFTWARE_URL = "https://attack.mitre.org/software/"
MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"



class MitreSoftwareHTMLParser(HTMLParser):
    """HTML Parser chuyên dụng để bóc tách bảng danh mục Malware / Tools từ MITRE ATT&CK."""
    def __init__(self):
        super().__init__()
        self.in_table = False
        self.in_tr = False
        self.in_td = False
        self.current_row = []
        self.current_cell = []
        self.current_link = ""
        self.rows = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "table":
            self.in_table = True
        elif tag == "tr" and self.in_table:
            self.in_tr = True
            self.current_row = []
        elif tag in ("td", "th") and self.in_tr:
            self.in_td = True
            self.current_cell = []
            self.current_link = ""
        elif tag == "a" and self.in_td:
            if "href" in attrs_dict and not self.current_link:
                self.current_link = attrs_dict["href"]

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.in_td:
            self.in_td = False
            cell_text = " ".join("".join(self.current_cell).split())
            self.current_row.append((cell_text, self.current_link))
        elif tag == "tr" and self.in_tr:
            self.in_tr = False
            if len(self.current_row) >= 4:
                self.rows.append(self.current_row)
        elif tag == "table":
            self.in_table = False

    def handle_data(self, data):
        if self.in_td:
            self.current_cell.append(data)



def fetch_owasp_cheatsheets():
    """Tải các tài liệu hướng dẫn phòng thủ chuẩn từ OWASP GitHub."""
    print("\n[1/3] 🌐 Đang cào tài liệu từ OWASP Cheat Sheet Series...")
    headers = {"User-Agent": "SecLM-SecurityAgent-Crawler/1.0"}
    success_count = 0
    with httpx.Client(headers=headers, timeout=20.0, follow_redirects=True) as client:
        for filename, url in OWASP_CHEATSHEETS.items():
            try:
                print(f"  ↳ Tải: {filename}...")
                resp = client.get(url)
                if resp.status_code == 200:
                    out_file = RAW_DIR / filename
                    out_file.write_text(resp.text, encoding="utf-8")
                    success_count += 1
                else:
                    print(f"    ⚠️ HTTP {resp.status_code} khi tải {url}")
            except Exception as e:
                print(f"    ❌ Lỗi kết nối {filename}: {str(e)}")
    print(f"  ✅ Đã tải thành công {success_count}/{len(OWASP_CHEATSHEETS)} tài liệu OWASP.")


def fetch_cisa_kev():
    """Tải danh mục các lỗ hổng đang bị khai thác thực tế (CISA KEV)."""
    print("\n[2/3] 🛡️ Đang tải CISA Known Exploited Vulnerabilities Catalog...")
    headers = {"User-Agent": "SecLM-SecurityAgent-Crawler/1.0"}
    try:
        with httpx.Client(headers=headers, timeout=30.0, follow_redirects=True) as client:
            resp = client.get(CISA_KEV_URL)
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                print(f"  ↳ Nhận diện được {len(vulnerabilities)} lỗ hổng KEV.")
                
                # Lưu top 50 lỗ hổng mới nhất để tối ưu dung lượng RAG
                top_vulnerabilities = vulnerabilities[:50]
                out_file = RAW_DIR / "cisa_known_exploited_vulnerabilities.json"
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(top_vulnerabilities, f, ensure_ascii=False, indent=2)
                print(f"  ✅ Đã lưu {len(top_vulnerabilities)} lỗ hổng CISA KEV vào: {out_file}")
            else:
                print(f"  ⚠️ HTTP {resp.status_code} khi tải CISA KEV.")
    except Exception as e:
        print(f"  ❌ Lỗi tải CISA KEV: {str(e)}")


def fetch_github_advisories():
    """Tải các bản tin bảo mật mức Critical gần nhất từ GitHub Advisory."""
    print("\n[3/3] 🐙 Đang cào các cảnh báo bảo mật Critical từ GitHub Advisory Database...")
    headers = {
        "User-Agent": "SecLM-SecurityAgent-Crawler/1.0",
        "Accept": "application/vnd.github+json"
    }
    try:
        with httpx.Client(headers=headers, timeout=20.0, follow_redirects=True) as client:
            resp = client.get(GITHUB_ADVISORY_URL)
            if resp.status_code == 200:
                advisories = resp.json()
                out_file = RAW_DIR / "github_critical_advisories.json"
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(advisories, f, ensure_ascii=False, indent=2)
                print(f"  ✅ Đã lưu {len(advisories)} bản tin bảo mật GitHub vào: {out_file}")
            else:
                print(f"  ⚠️ HTTP {resp.status_code} khi tải GitHub Advisories.")
    except Exception as e:
        print(f"  ❌ Lỗi tải GitHub Advisories: {str(e)}")


def parse_mitre_stix(stix_data: dict):
    """Trích xuất danh mục Malware và Tools từ định dạng chuẩn MITRE STIX 2.1."""
    software_list = []
    md_lines = [
        "# MITRE ATT&CK Software & Malware Catalog",
        "",
        "> Nguồn chính thức: [MITRE ATT&CK Software](https://attack.mitre.org/software/)",
        "> Phân loại: Danh mục phần mềm độc hại (Malware) và công cụ đối kháng (Adversary Tools) từ cơ sở dữ liệu MITRE STIX CTI.",
        "",
    ]
    for obj in stix_data.get("objects", []):
        if obj.get("type") in ["malware", "tool"] and not obj.get("revoked", False):
            name = obj.get("name", "Unknown")
            desc = obj.get("description", "").strip()
            aliases = ", ".join(obj.get("x_mitre_aliases", [])) or "-"

            software_id = None
            url = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    software_id = ref.get("external_id")
                    url = ref.get("url")
                    break

            if not software_id:
                continue

            url = url or f"https://attack.mitre.org/software/{software_id}/"
            item = {
                "id": software_id,
                "name": name,
                "aliases": aliases,
                "url": url,
                "description": desc
            }
            software_list.append(item)

            md_lines.append(f"## {software_id} - {name}")
            md_lines.append(f"- **Mã định danh**: [{software_id}]({url})")
            md_lines.append(f"- **Tên phần mềm**: {name}")
            if aliases and aliases != "-":
                md_lines.append(f"- **Tên gọi khác / Aliases**: {aliases}")
            md_lines.append(f"- **Nguồn tham chiếu**: [{name} on MITRE ATT&CK]({url})")
            md_lines.append(f"- **Mô tả hành vi**: {desc}")
            md_lines.append("")

    return software_list, md_lines


def fetch_mitre_software():
    """Tải và bóc tách danh mục Malware & Tools từ MITRE ATT&CK (Ưu tiên GitHub STIX API, tự động fallback HTML)."""
    print("\n[4/4] 🛡️ Đang tải danh mục Software (Malware & Tools) từ MITRE ATT&CK...")

    # Cách 1: Tải trực tiếp từ nguồn chính thức GitHub STIX CTI (Không bị Cloudflare 503 chặn bot)
    github_headers = {"User-Agent": "SecLM-SecurityAgent-Crawler/1.0"}
    try:
        print("  ↳ [Cách 1] Kết nối tới kho STIX chính thức của MITRE CTI trên GitHub...")
        with httpx.Client(headers=github_headers, timeout=60.0, follow_redirects=True) as client:
            resp = client.get(MITRE_STIX_URL)
            if resp.status_code == 200:
                stix_data = resp.json()
                software_list, md_lines = parse_mitre_stix(stix_data)

                json_file = RAW_DIR / "mitre_attack_software.json"
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(software_list, f, ensure_ascii=False, indent=2)

                md_file = RAW_DIR / "mitre_attack_software.md"
                md_file.write_text("\n".join(md_lines), encoding="utf-8")

                print(f"  ✅ Đã tải và trích xuất thành công {len(software_list)} mã độc & công cụ từ MITRE STIX!")
                print(f"  📂 File JSON: {json_file}")
                print(f"  📂 File Markdown: {md_file}")
                return
            else:
                print(f"  ⚠️ HTTP {resp.status_code} khi tải STIX GitHub.")
    except Exception as e:
        print(f"  ⚠️ Không tải được qua GitHub STIX ({str(e)}), chuyển sang thử cào web HTML...")

    # Cách 2: Cào web HTML (phòng khi người dùng dùng proxy/browser)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    try:
        print(f"  ↳ [Cách 2] Đang gửi yêu cầu tới {MITRE_SOFTWARE_URL}...")
        with httpx.Client(headers=headers, timeout=30.0, follow_redirects=True) as client:
            resp = client.get(MITRE_SOFTWARE_URL)
            if resp.status_code == 200:
                parser = MitreSoftwareHTMLParser()
                parser.feed(resp.text)

                software_list = []
                md_lines = [
                    "# MITRE ATT&CK Software & Malware Catalog",
                    "",
                    "> Nguồn chính thức: [MITRE ATT&CK Software](https://attack.mitre.org/software/)",
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
                    md_lines.append(f"## {id_text} - {name_text}\n- **Mã định danh**: [{id_text}]({full_url})\n- **Tên**: {name_text}\n- **Mô tả**: {desc}\n")

                json_file = RAW_DIR / "mitre_attack_software.json"
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(software_list, f, ensure_ascii=False, indent=2)

                md_file = RAW_DIR / "mitre_attack_software.md"
                md_file.write_text("\n".join(md_lines), encoding="utf-8")

                print(f"  ✅ Đã trích xuất thành công {len(software_list)} mã độc & công cụ từ HTML!")
                return
            elif resp.status_code == 503:
                print(f"  ⚠️ HTTP 503 Service Unavailable: Trang web attack.mitre.org bật Cloudflare WAF chống Bot Scraping tự động.")
            else:
                print(f"  ⚠️ HTTP {resp.status_code} khi tải {MITRE_SOFTWARE_URL}")
    except Exception as e:
        print(f"  ❌ Lỗi tải web HTML: {str(e)}")

    # Kiểm tra fallback dữ liệu nội bộ
    local_md = RAW_DIR / "mitre_attack_software.md"
    if local_md.exists():
        print(f"  💡 Đã có sẵn tệp danh mục MITRE ATT&CK ({local_md.name}) trong data/raw/.")
        print(f"  👉 Bạn có thể nạp ngay vào RAG bằng lệnh: .venv/bin/python -m src.data_pipeline.processor")



def main():
    parser = argparse.ArgumentParser(description="SecLM Automated Security Knowledge Crawler")
    parser.add_argument(
        "--source",
        choices=["all", "owasp", "cisa", "github", "mitre"],
        default="all",
        help="Nguồn dữ liệu muốn cào: all, owasp, cisa, github, mitre (mặc định: all)"
    )
    args = parser.parse_args()

    print("==================================================================")
    print("🚀 SEC-LM DATA CRAWLER - BẮT ĐẦU CÀO TRI THỨC BẢO MẬT")
    print(f"📂 Thư mục lưu trữ: {RAW_DIR.resolve()}")
    print("==================================================================")

    if args.source in ["all", "owasp"]:
        fetch_owasp_cheatsheets()
    if args.source in ["all", "cisa"]:
        fetch_cisa_kev()
    if args.source in ["all", "github"]:
        fetch_github_advisories()
    if args.source in ["all", "mitre"]:
        fetch_mitre_software()

    print("\n==================================================================")
    print("🎉 Hoàn tất cào dữ liệu! Hãy chạy lệnh sau để làm sạch và nạp vào RAG:")
    print("👉 .venv/bin/python -m src.data_pipeline.processor")
    print("==================================================================")


if __name__ == "__main__":
    main()

