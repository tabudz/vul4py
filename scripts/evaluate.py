#!/usr/bin/env python3
"""
evaluate.py

For one or more agents, for one or more vulns:
  1. Fork the vulnerable/ checkout into <case>/<agent>_candidate/
  2. Apply runs/<agent>/<vuln_id>/patch.diff
  3. Install + run baseline functional tests (must still pass)
  4. Run exploit/regression tests (must now pass)
  5. Write runs/<agent>/<vuln_id>/eval.json with verdict

Verdict fields:
    apply_ok            -- did the patch apply cleanly?
    functional_rc       -- exit code of baseline tests on candidate (0 = pass)
    exploit_rc          -- exit code of exploit tests on candidate
    plausible           -- apply_ok AND functional_rc in (0,999) AND exploit_rc == 0
    notes               -- error string if any

This script wraps scripts/vul4py.py for actual setup / test / fork / patch work,
so the harness behavior matches the rest of the pipeline.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"
VUL4PY = Path(__file__).resolve().parent / "vul4py.py"


def cleanup_candidate(case_dir: Path, dst_name: str):
    p = case_dir / dst_name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def run_vul4py(args: List[str], log_lines: list) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(VUL4PY)] + args
    log_lines.append("$ " + " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    log_lines.append(f"[exit {cp.returncode}]")
    if cp.stdout:
        log_lines.append(cp.stdout)
    if cp.stderr:
        log_lines.append(cp.stderr)
    return cp


def evaluate_one(workspaces: Path, runs: Path, agent: str, vuln_id: str) -> dict:
    case_dir = workspaces / vuln_id
    run_dir = runs / agent / vuln_id
    patch = run_dir / "patch.diff"
    eval_path = run_dir / "eval.json"
    log_path = run_dir / "eval.log"

    verdict = {
        "agent": agent,
        "vuln_id": vuln_id,
        "apply_ok": False,
        "functional_rc": None,
        "exploit_rc": None,
        "plausible": False,
        "elapsed_s": None,
        "notes": "",
    }
    log: list = []
    t0 = time.time()

    if not case_dir.exists() or not (case_dir / "meta.json").exists():
        verdict["notes"] = f"no workspace at {case_dir}"
        eval_path.parent.mkdir(parents=True, exist_ok=True)
        eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
        return verdict
    if not patch.exists():
        verdict["notes"] = f"no patch at {patch}"
        eval_path.parent.mkdir(parents=True, exist_ok=True)
        eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
        return verdict

    dst_name = f"{agent}_candidate"
    cleanup_candidate(case_dir, dst_name)

    fork = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "fork",
            "--src", "vulnerable",
            "--dst", dst_name,
            "--patch", str(patch.resolve()),
        ],
        log,
    )
    if fork.returncode != 0:
        verdict["notes"] = "patch did not apply"
        log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
        verdict["elapsed_s"] = round(time.time() - t0, 1)
        eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
        cleanup_candidate(case_dir, dst_name)
        return verdict

    verdict["apply_ok"] = True

    func = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "functional",
            "--target", dst_name,
        ],
        log,
    )
    # The CLI doesn't surface the inner rc cleanly; parse it from stdout.
    func_rc = parse_rc(func.stdout, "rc=")
    verdict["functional_rc"] = func_rc

    expl = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "exploit",
            "--targets", dst_name,
        ],
        log,
    )
    expl_rc = parse_rc(expl.stdout, "rc=")
    verdict["exploit_rc"] = expl_rc

    verdict["plausible"] = (
        verdict["apply_ok"]
        and (verdict["functional_rc"] in (0, 999))
        and (verdict["exploit_rc"] == 0)
    )

    cleanup_candidate(case_dir, dst_name)
    log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
    verdict["elapsed_s"] = round(time.time() - t0, 1)
    eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
    return verdict


def parse_rc(stdout: str, marker: str) -> Optional[int]:
    for line in stdout.splitlines():
        if marker in line:
            try:
                return int(line.split(marker, 1)[1].strip().split()[0])
            except Exception:
                continue
    return None


def main():
    ap = argparse.ArgumentParser(description="Evaluate agent-produced patches against baseline + exploit tests.")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--vuln-id", help="Single vuln; omit to evaluate every patch found.")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    agent_dir = args.runs / args.agent
    if not agent_dir.exists():
        sys.exit(f"no runs for agent: {agent_dir}")

    if args.vuln_id:
        targets = [args.vuln_id]
    else:
        targets = sorted(p.name for p in agent_dir.iterdir() if (p / "patch.diff").exists())
        if args.limit:
            targets = targets[: args.limit]

    n_plaus = 0
    for vid in targets:
        v = evaluate_one(args.workspaces, args.runs, args.agent, vid)
        flag = "PLAUSIBLE" if v["plausible"] else "FAIL"
        print(
            f"  {args.agent}/{vid}: {flag} "
            f"apply={v['apply_ok']} func_rc={v['functional_rc']} expl_rc={v['exploit_rc']} "
            f"({v['elapsed_s']}s)"
        )
        if v["plausible"]:
            n_plaus += 1
    print(f"[done] {args.agent}: plausible {n_plaus}/{len(targets)}")


if __name__ == "__main__":
    main()
