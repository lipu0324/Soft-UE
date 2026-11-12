#!/usr/bin/env python3
"""Extract page-linked normative candidates for manual review, never mark compliance."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def extract(text):
    records = []
    section = "unclassified"
    for page, content in enumerate(text.split("\f"), 1):
        if page < 28 or page > 762:
            continue  # Exclude contents/indexes and release notes.
        counter = 0
        paragraphs = re.split(r"\n\s*\n", content)
        for paragraph in paragraphs:
            lines = [line.strip() for line in paragraph.splitlines()
                     if line.strip() and not line.strip().startswith("Copyright") and not line.strip().isdigit()]
            if not lines:
                continue
            heading = re.match(r"^(\d+(?:\.\d+){0,5})\s+[A-Za-z]", lines[0])
            if heading:
                section = heading.group(1)
            statement = " ".join(lines)
            keywords = sorted(set(re.findall(r"\b(?:MUST NOT|MUST|SHALL NOT|SHALL|REQUIRED)\b", statement)))
            if not keywords:
                continue
            counter += 1
            records.append({"id": f"UE11-p{page:04d}-{counter:03d}", "pdf_page": page,
                            "section_candidate": section, "keywords": keywords, "text": statement,
                            "review_required": True, "informative_classification": "unreviewed"})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text", required=True, type=Path, help="pdftotext -layout output of the supplied UE 1.1 PDF")
    parser.add_argument("--output", required=True, type=Path, help="generated inventory; use build/ to avoid republishing the standard")
    args = parser.parse_args()
    raw = args.text.read_bytes()
    records = extract(raw.decode())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"schema_version": 1, "text_sha256": hashlib.sha256(raw).hexdigest(),
                                    "inventory_complete": False, "candidates": records}, ensure_ascii=False, indent=2) + "\n")
    print(f"Extracted {len(records)} candidates; all require normative/informative and profile review")


if __name__ == "__main__":
    main()
