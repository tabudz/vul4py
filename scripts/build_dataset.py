#!/usr/bin/env python3
"""
build_dataset.py

Build dataset/vul4py.csv from dataset/ok.txt by looking up (repo_url, fix_commit)
in an OSV-derived matches.jsonl.

ok.txt  : one vulnerability ID per line (CVE-* or GHSA-*), 100 IDs total.
matches : JSONL where each record has fields:
            cve_id          (e.g. CVE-2024-11042) -- may be empty
            osv_id          (e.g. GHSA-227r-w5j2-6243)
            repo_url        (GitHub clone URL)
            fix_commit      (40-char SHA)

Output CSV columns: vuln_id,repo_url,fix_commit

Run: python3 scripts/build_dataset.py
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
DEFAULT_OK = HERE / "dataset" / "ok.txt"
DEFAULT_MATCHES = HERE.parent / "matches.jsonl"
DEFAULT_OUT = HERE / "dataset" / "vul4py.csv"


def load_matches(path: Path) -> dict:
    by_id = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = rec.get("repo_url")
            commit = rec.get("fix_commit")
            if not url or not commit:
                continue
            for key in (rec.get("cve_id"), rec.get("osv_id")):
                if key:
                    by_id.setdefault(key, (url, commit))
    return by_id


def main():
    ap = argparse.ArgumentParser(description="Build vul4py.csv from ok.txt + matches.jsonl")
    ap.add_argument("--ok", type=Path, default=DEFAULT_OK)
    ap.add_argument("--matches", type=Path, default=DEFAULT_MATCHES)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    if not args.ok.exists():
        sys.exit(f"missing ok file: {args.ok}")
    if not args.matches.exists():
        sys.exit(f"missing matches file: {args.matches}")

    ids = []
    for line in args.ok.read_text(encoding="utf-8").splitlines():
        vid = line.strip()
        if vid:
            ids.append(vid)

    by_id = load_matches(args.matches)

    rows, missing = [], []
    for vid in ids:
        hit = by_id.get(vid)
        if hit is None:
            missing.append(vid)
            continue
        repo_url, fix_commit = hit
        rows.append((vid, repo_url, fix_commit))

    if missing:
        print(f"[!] {len(missing)} IDs not found in matches:")
        for m in missing:
            print(f"    {m}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["vuln_id", "repo_url", "fix_commit"])
        for row in rows:
            w.writerow(row)

    print(f"[+] wrote {args.out} ({len(rows)} rows, {len(missing)} missing)")


if __name__ == "__main__":
    main()
