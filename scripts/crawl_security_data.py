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


def main():
    parser = argparse.ArgumentParser(description="SecLM Automated Security Knowledge Crawler")
    parser.add_argument(
        "--source",
        choices=["all", "owasp", "cisa", "github"],
        default="all",
        help="Nguồn dữ liệu muốn cào: all, owasp, cisa, github (mặc định: all)"
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

    print("\n==================================================================")
    print("🎉 Hoàn tất cào dữ liệu! Hãy chạy lệnh sau để làm sạch và nạp vào RAG:")
    print("👉 .venv/bin/python -m src.data_pipeline.processor")
    print("==================================================================")


if __name__ == "__main__":
    main()
