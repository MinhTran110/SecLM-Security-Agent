"""Dedicated Parser for MITRE ATT&CK STIX 2.1 Datasets.

Source Repository: https://github.com/mitre-attack/attack-stix-data
Direct Raw URL: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

Tác dụng:
- Đọc file enterprise-attack.json từ repo attack-stix-data (local hoặc tải online).
- Tự động bóc tách sạch sẽ:
  1. Malware & Tools (Mã độc & Công cụ) -> data/raw/mitre_attack_software.md
  2. Techniques & Sub-techniques (Kỹ thuật TTP) -> data/raw/mitre_attack_techniques.md
  3. Threat Groups / APT Groups (Nhóm tin tặc) -> data/raw/mitre_attack_groups.md
"""

import sys
import json
import argparse
from pathlib import Path

RAW_DIR = Path("data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def parse_and_export_stix(stix_data: dict, out_dir: Path):
    """Trích xuất chi tiết Software, Techniques, và Threat Groups từ STIX bundle."""
    print("🔄 Đang phân tích các đối tượng STIX 2.1 từ MITRE ATT&CK...")

    software_list = []
    technique_list = []
    group_list = []

    for obj in stix_data.get("objects", []):
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        obj_type = obj.get("type")
        name = obj.get("name", "Unknown")
        desc = obj.get("description", "").strip()
        aliases = ", ".join(obj.get("x_mitre_aliases", [])) or "-"

        # Trích xuất External ID (S0002, T1003, G0007...) và URL chính thức
        ext_id, url = None, None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ["mitre-attack", "mitre-enterprise-attack"]:
                ext_id = ref.get("external_id")
                url = ref.get("url")
                break

        if not ext_id:
            continue

        item = {
            "id": ext_id,
            "name": name,
            "aliases": aliases,
            "url": url,
            "description": desc
        }

        if obj_type in ["malware", "tool"]:
            item["category"] = "Malware" if obj_type == "malware" else "Adversary Tool"
            software_list.append(item)
        elif obj_type == "attack-pattern":
            item["platforms"] = ", ".join(obj.get("x_mitre_platforms", [])) or "All"
            technique_list.append(item)
        elif obj_type == "intrusion-set":
            group_list.append(item)

    print(f"  ↳ Nhận diện được: {len(software_list)} Software, {len(technique_list)} Techniques, {len(group_list)} APT Groups.")

    # 1. Xuất Software
    if software_list:
        md_lines = [
            "# MITRE ATT&CK Software & Malware Catalog",
            "",
            "> **Nguồn chính thức**: [MITRE ATT&CK Software](https://attack.mitre.org/software/)",
            "> **Dữ liệu gốc**: `mitre-attack/attack-stix-data` (STIX 2.1)",
            "",
        ]
        for s in software_list:
            md_lines.append(f"## {s['id']} - {s['name']}")
            md_lines.append(f"- **Mã định danh**: [{s['id']}]({s['url']})")
            md_lines.append(f"- **Tên**: {s['name']} ({s.get('category', 'Tool')})")
            if s['aliases'] and s['aliases'] != "-":
                md_lines.append(f"- **Tên gọi khác / Aliases**: {s['aliases']}")
            md_lines.append(f"- **Nguồn tham chiếu**: [{s['name']} on MITRE ATT&CK]({s['url']})")
            md_lines.append(f"- **Mô tả hành vi**: {s['description']}")
            md_lines.append("")

        out_file = out_dir / "mitre_attack_software.md"
        out_file.write_text("\n".join(md_lines), encoding="utf-8")
        print(f"  ✅ Đã lưu {len(software_list)} Software vào: {out_file}")

    # 2. Xuất Techniques
    if technique_list:
        md_lines = [
            "# MITRE ATT&CK Techniques & TTPs Catalog",
            "",
            "> **Nguồn chính thức**: [MITRE ATT&CK Techniques](https://attack.mitre.org/techniques/)",
            "> **Dữ liệu gốc**: `mitre-attack/attack-stix-data` (STIX 2.1)",
            "",
        ]
        for t in technique_list:
            md_lines.append(f"## {t['id']} - {t['name']}")
            md_lines.append(f"- **Mã kỹ thuật**: [{t['id']}]({t['url']})")
            md_lines.append(f"- **Tên kỹ thuật**: {t['name']}")
            md_lines.append(f"- **Nền tảng ảnh hưởng**: {t.get('platforms', 'All')}")
            md_lines.append(f"- **Nguồn tham chiếu**: [{t['name']} on MITRE ATT&CK]({t['url']})")
            md_lines.append(f"- **Mô tả kỹ thuật**: {t['description']}")
            md_lines.append("")

        out_file = out_dir / "mitre_attack_techniques.md"
        out_file.write_text("\n".join(md_lines), encoding="utf-8")
        print(f"  ✅ Đã lưu {len(technique_list)} Techniques vào: {out_file}")

    # 3. Xuất Threat Groups
    if group_list:
        md_lines = [
            "# MITRE ATT&CK Threat Groups (APT Groups) Catalog",
            "",
            "> **Nguồn chính thức**: [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)",
            "> **Dữ liệu gốc**: `mitre-attack/attack-stix-data` (STIX 2.1)",
            "",
        ]
        for g in group_list:
            md_lines.append(f"## {g['id']} - {g['name']}")
            md_lines.append(f"- **Mã nhóm**: [{g['id']}]({g['url']})")
            md_lines.append(f"- **Tên nhóm APT**: {g['name']}")
            if g['aliases'] and g['aliases'] != "-":
                md_lines.append(f"- **Tên gọi khác / Aliases**: {g['aliases']}")
            md_lines.append(f"- **Nguồn tham chiếu**: [{g['name']} on MITRE ATT&CK]({g['url']})")
            md_lines.append(f"- **Hồ sơ hoạt động**: {g['description']}")
            md_lines.append("")

        out_file = out_dir / "mitre_attack_groups.md"
        out_file.write_text("\n".join(md_lines), encoding="utf-8")
        print(f"  ✅ Đã lưu {len(group_list)} APT Groups vào: {out_file}")


def main():
    parser = argparse.ArgumentParser(description="MITRE ATT&CK STIX Data Ingestion")
    parser.add_argument(
        "--file",
        help="Đường dẫn tới file enterprise-attack.json local (nếu đã tải về)"
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_STIX_URL,
        help="URL tải STIX JSON trực tiếp từ GitHub repo attack-stix-data"
    )
    args = parser.parse_args()

    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"❌ Không tìm thấy file: {file_path}")
            sys.exit(1)
        print(f"📂 Đang đọc dữ liệu từ tệp cục bộ: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            stix_data = json.load(f)
        parse_and_export_stix(stix_data, RAW_DIR)
    else:
        print(f"🌐 Đang tải dữ liệu STIX từ: {args.url}")
        try:
            import httpx
            with httpx.Client(timeout=60.0, follow_redirects=True) as client:
                resp = client.get(args.url)
                resp.raise_for_status()
                stix_data = resp.json()
            parse_and_export_stix(stix_data, RAW_DIR)
        except Exception as e:
            print(f"❌ Lỗi tải STIX từ {args.url}: {str(e)}")
            print("👉 Bạn có thể tải file trước bằng lệnh:")
            print(f"   curl -L -o data/raw/enterprise-attack.json \"{DEFAULT_STIX_URL}\"")
            print("   sau đó chạy: .venv/bin/python scripts/parse_stix_bundle.py --file data/raw/enterprise-attack.json")
            sys.exit(1)

    print("\n🎉 Hoàn thành bóc tách STIX! Bước tiếp theo để nạp vào RAG:")
    print("👉 .venv/bin/python -m src.data_pipeline.processor")


if __name__ == "__main__":
    main()
