#!/usr/bin/env python3
"""
prepare.py

Build per-vulnerability workspaces from dataset/vul4py.csv.

Input CSV columns: vuln_id,repo_url,fix_commit

For each row, creates workspaces/<vuln_id>/:
    vulnerable/                # checkout at parent of fix_commit
    fixed/                     # checkout at fix_commit
    logs/
    vulnerable/backported_tests/
    vulnerable/backported_support/
    meta.json

meta.json schema is the one consumed by vul4py.py.

Heuristics:
- A "test-like" file is any .py whose path or filename contains "test".
- baseline_test_files  : all test-like .py files in the vulnerable checkout.
- new_test_files       : A/M .py files between parent..fix that look like tests.
- new_code_files       : A/M .py files between parent..fix that are NOT tests.

Resumable: skips any <vuln_id> dir that already exists.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from tqdm import tqdm
except Exception:
    def tqdm(it, total=None, desc=None):
        return it


def run(cmd, cwd=None, capture=False, check=True):
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=check,
        text=True,
        capture_output=capture,
    )


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def clone_and_checkout(target: Path, repo_url: str, ref: str):
    if target.exists():
        raise RuntimeError(f"{target} already exists")
    ensure_dir(target.parent)
    run(["git", "clone", repo_url, str(target)], check=True)
    run(["git", "-C", str(target), "checkout", ref], check=True)


def parent_commit(repo: Path, fix_commit: str) -> str:
    cp = run(["git", "-C", str(repo), "rev-parse", f"{fix_commit}^"], capture=True)
    return cp.stdout.strip()


def is_test_path(p: str) -> bool:
    lo = p.lower()
    if "test" in lo:
        return True
    return any("test" in c for c in lo.split("/"))


def collect_baseline_tests(vuln: Path) -> List[str]:
    out: List[str] = []
    for root, _, files in os.walk(vuln):
        rel_root = os.path.relpath(root, vuln)
        if rel_root == ".":
            rel_root = ""
        for fn in files:
            if not fn.endswith(".py"):
                continue
            rel = os.path.normpath(os.path.join(rel_root, fn))
            if rel.startswith(".."):
                continue
            if is_test_path(rel) and rel not in out:
                out.append(rel)
    return out


def diff_changed(fixed: Path, parent: str, fix: str) -> Tuple[List[str], List[str]]:
    cp = run(
        ["git", "-C", str(fixed), "diff", "--name-status", parent, fix],
        capture=True,
    )
    tests: List[str] = []
    code: List[str] = []
    for line in cp.stdout.splitlines():
        parts = line.strip().split("\t")
        if not parts or not parts[0]:
            continue
        status = parts[0]
        path = parts[1] if len(parts) == 2 else parts[-1]
        if status[0] not in ("A", "M"):
            continue
        if not path.endswith(".py"):
            continue
        bucket = tests if is_test_path(path) else code
        if path not in bucket:
            bucket.append(path)
    return tests, code


def write_meta(case_dir: Path, vuln_id: str, repo_url: str, fix: str, parent: str,
               baseline: List[str], new_tests: List[str], new_code: List[str]) -> Path:
    meta = {
        "cve_id": vuln_id,  # kept for backward-compat with vul4py.py runner
        "repo_url": repo_url,
        "fix_commit": fix,
        "vulnerable_ref": parent,
        "fixed_ref": fix,
        "versions": {
            "vulnerable": {"git_ref": parent},
            "fixed": {"git_ref": fix},
        },
        "python_version": "3.11",
        "install_cmds": [
            "python -m pip install -U pip wheel",
            "pip install -e .",
        ],
        "functional_test_cmd_base": "pytest -q",
        "baseline_test_files": baseline,
        "exploit_test_cmd_base": "pytest -q",
        "new_test_files": new_tests,
        "new_code_files": new_code,
        "exploit_expectation": {
            "vulnerable_should_fail": True,
            "fixed_should_pass": True,
        },
        "notes": "",
    }
    p = case_dir / "meta.json"
    p.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return p


def prepare_one(workspace_root: Path, vuln_id: str, repo_url: str, fix: str) -> Dict[str, Any]:
    case_dir = workspace_root / vuln_id
    if case_dir.exists():
        return {"vuln_id": vuln_id, "status": "SKIP_EXISTS", "message": str(case_dir)}

    fixed = case_dir / "fixed"
    vuln = case_dir / "vulnerable"

    clone_and_checkout(fixed, repo_url, fix)
    parent = parent_commit(fixed, fix)
    clone_and_checkout(vuln, repo_url, parent)

    baseline = collect_baseline_tests(vuln)
    new_tests, new_code = diff_changed(fixed, parent, fix)

    ensure_dir(case_dir / "logs")
    ensure_dir(vuln / "backported_tests")
    ensure_dir(vuln / "backported_support")

    meta_path = write_meta(case_dir, vuln_id, repo_url, fix, parent, baseline, new_tests, new_code)
    return {"vuln_id": vuln_id, "status": "OK", "message": str(meta_path)}


def _worker(t):
    workspace_root_str, vuln_id, repo_url, fix = t
    try:
        return prepare_one(Path(workspace_root_str), vuln_id, repo_url, fix)
    except Exception as e:
        return {"vuln_id": vuln_id, "status": "ERROR", "message": str(e)}


def main():
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="Build vul4py per-vuln workspaces from CSV.")
    ap.add_argument("--csv", type=Path, default=here / "dataset" / "vul4py.csv")
    ap.add_argument("--workspace-root", type=Path, default=here / "workspaces")
    ap.add_argument("--jobs", type=int, default=None)
    args = ap.parse_args()

    ws = args.workspace_root.resolve()
    ensure_dir(ws)
    jobs = args.jobs or max(cpu_count() - 1, 1)

    tasks: List[Tuple[str, str, str, str]] = []
    with open(args.csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tasks.append(
                (str(ws), row["vuln_id"].strip(), row["repo_url"].strip(), row["fix_commit"].strip())
            )

    results: List[Dict[str, Any]] = []
    with Pool(processes=jobs) as pool:
        async_results = [pool.apply_async(_worker, (t,)) for t in tasks]
        pool.close()
        for ar in tqdm(async_results, total=len(async_results), desc="prepare"):
            results.append(ar.get())
        pool.join()

    ok = [r for r in results if r["status"] == "OK"]
    sk = [r for r in results if r["status"] == "SKIP_EXISTS"]
    er = [r for r in results if r["status"] == "ERROR"]

    print(f"OK={len(ok)}  SKIP={len(sk)}  ERROR={len(er)}")
    for r in er:
        print(f"  ERROR {r['vuln_id']}: {r['message']}")

    summary = ws / "prepare_summary.tsv"
    with open(summary, "w", encoding="utf-8") as f:
        f.write("vuln_id\tstatus\tmessage\n")
        for r in results:
            msg = r["message"].replace("\n", "\\n").replace("\t", "    ")
            f.write(f"{r['vuln_id']}\t{r['status']}\t{msg}\n")
    print(f"[+] wrote {summary}")


if __name__ == "__main__":
    main()
