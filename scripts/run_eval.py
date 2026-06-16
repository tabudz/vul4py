#!/usr/bin/env python3
"""run_eval.py

Evaluate per-agent candidate patches under the junit-based pipeline.

For every (agent, vuln_id) with a `runs/<agent>/<vuln_id>/patch.diff`:

  1. _restore_target(vulnerable/) for a clean tree.
  2. `git apply` the patch against vulnerable/.
  3. run_functional(vulnerable/) -> junit; require all baseline tests pass.
  4. run_exploit_for_target("vulnerable") -> overlays new_test_files from
     fixed/ and runs them; require all new tests pass.
  5. Write `runs/<agent>/<vuln_id>/eval.json` and a CSV summary.

The vulnerable/.venv is reused, so per-vuln eval cost is essentially the
pytest run time. Workers process distinct vuln_ids in parallel; agents
on the same vuln are processed serially to avoid racing on vulnerable/.
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import shutil  # noqa: E402
import vul4py  # type: ignore


def _overlay_fixture_additions(fixed_dir: Path, target_dir: Path):
    """Copy any file the fix commit ADDED under tests/ or test/ that the
    candidate is missing. These are typically fixtures (e.g. malformed JSON,
    YAML payloads) referenced by the new tests. Existing files are NOT
    overwritten -- the new_test_files overlay handles those."""
    for tdir in ("tests", "test"):
        src_root = fixed_dir / tdir
        if not src_root.is_dir():
            continue
        for src in src_root.rglob("*"):
            if not src.is_file():
                continue
            rel = src.relative_to(fixed_dir)
            dst = target_dir / rel
            if dst.exists():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(src, dst)


def _agent_for(case_dir: Path, runs_root: Path, agent: str) -> Path:
    return runs_root / agent / case_dir.name


def _evaluate_one(case_dir: Path, runs_root: Path, agents: List[str], tools_root: Path) -> List[Dict]:
    """Process one vuln_id across all agents that have a patch for it."""
    out: List[Dict] = []
    meta = vul4py.load_meta(case_dir)
    vuln_dir = case_dir / "vulnerable"
    fixed_dir = case_dir / "fixed"
    logs_dir = case_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    for agent in agents:
        run_dir = _agent_for(case_dir, runs_root, agent)
        patch_path = run_dir / "patch.diff"
        eval_path = run_dir / "eval.json"
        verdict = {
            "agent": agent,
            "vuln_id": case_dir.name,
            "apply_ok": False,
            "func_ok": False,
            "exploit_ok": False,
            "plausible": False,
            "func_pfes": None,
            "exploit_pfes": None,
            "notes": "",
            "elapsed_s": None,
        }
        t0 = time.time()
        if not patch_path.exists():
            verdict["notes"] = "no patch"
            run_dir.mkdir(parents=True, exist_ok=True)
            eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
            out.append(verdict)
            continue

        # Clean tree for this agent.
        vul4py._restore_target(vuln_dir)

        # Try to apply the patch with several -p strip levels.
        applied = False
        for strip in (1, 0, 2, 3):
            cp = subprocess.run(
                ["git", "apply", f"-p{strip}", str(patch_path)],
                cwd=str(vuln_dir),
                capture_output=True,
                text=True,
            )
            if cp.returncode == 0:
                applied = True
                break
        if not applied:
            # Fallback: patch -p<N>
            for strip in (1, 0, 2, 3):
                cp = subprocess.run(
                    ["patch", f"-p{strip}", "-i", str(patch_path), "--no-backup-if-mismatch", "-f"],
                    cwd=str(vuln_dir),
                    capture_output=True,
                    text=True,
                )
                if cp.returncode == 0:
                    applied = True
                    break

        if not applied:
            verdict["notes"] = "patch did not apply"
            verdict["elapsed_s"] = round(time.time() - t0, 1)
            eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
            out.append(verdict)
            vul4py._restore_target(vuln_dir)
            continue
        verdict["apply_ok"] = True

        # Functional baseline on patched vulnerable.
        # We reuse the same logfile name pattern but suffix with the agent so
        # parallel agents on the same vuln don't clobber each other.
        func_log = logs_dir / f"functional_{agent}_candidate.log"
        # Temporarily rename to feed run_functional which derives the path
        try:
            func_rc = vul4py.run_functional(tools_root, vuln_dir, meta, logs_dir)
            # vul4py.run_functional writes functional_vulnerable.{log,junit.xml}
            # Move them to agent-suffixed names.
            for ext in ("log", "junit.xml"):
                src = logs_dir / f"functional_vulnerable.{ext}"
                dst = logs_dir / f"functional_{agent}_candidate.{ext}"
                if src.exists():
                    src.replace(dst)
            junit = vul4py._parse_junit(logs_dir / f"functional_{agent}_candidate.junit.xml")
            if junit is not None:
                verdict["func_pfes"] = (
                    f"{junit['passed']}/{junit['failed']}/{junit['errored']}/{junit['skipped']}"
                )
                verdict["func_ok"] = junit["failed"] == 0 and junit["errored"] == 0
            else:
                verdict["func_ok"] = func_rc == 0
        except Exception as e:
            verdict["notes"] = f"functional crash: {e!r}"

        # Bring over any fixture files the fix added (e.g. tests/yaml/x.yaml)
        # that the new tests reference. Without this, a correct patch still
        # fails the exploit oracle because pytest can't open a referenced
        # data file that was added alongside the fix commit.
        _overlay_fixture_additions(fixed_dir, vuln_dir)

        # Exploit on patched vulnerable: harness will overlay fixed tests.
        try:
            exp_rc = vul4py.run_exploit_for_target(
                tools_root, fixed_dir, vuln_dir, "vulnerable", meta, logs_dir
            )
            for ext in ("log", "junit.xml"):
                src = logs_dir / f"exploit_vulnerable.{ext}"
                dst = logs_dir / f"exploit_{agent}_candidate.{ext}"
                if src.exists():
                    src.replace(dst)
            junit = vul4py._parse_junit(logs_dir / f"exploit_{agent}_candidate.junit.xml")
            if junit is not None:
                verdict["exploit_pfes"] = (
                    f"{junit['passed']}/{junit['failed']}/{junit['errored']}/{junit['skipped']}"
                )
                verdict["exploit_ok"] = (
                    junit["passed"] > 0
                    and junit["failed"] == 0
                    and junit["errored"] == 0
                )
            else:
                verdict["exploit_ok"] = exp_rc == 0
        except Exception as e:
            verdict["notes"] = (verdict["notes"] + "; " if verdict["notes"] else "") + f"exploit crash: {e!r}"

        verdict["plausible"] = bool(verdict["apply_ok"] and verdict["func_ok"] and verdict["exploit_ok"])
        verdict["elapsed_s"] = round(time.time() - t0, 1)
        eval_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
        out.append(verdict)

        # Revert for the next agent.
        vul4py._restore_target(vuln_dir)

    return out


def _worker(args):
    case_dir, runs_root, agents, tools_root = args
    case_dir = Path(case_dir)
    runs_root = Path(runs_root)
    tools_root = Path(tools_root)
    try:
        return _evaluate_one(case_dir, runs_root, agents, tools_root)
    except Exception as e:
        return [{"agent": "?", "vuln_id": case_dir.name, "notes": f"worker crash: {e!r}"}]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspaces", type=Path, default=HERE.parent / "workspaces")
    ap.add_argument("--runs", type=Path, default=HERE.parent / "runs")
    ap.add_argument("--tools-root", type=Path, default=None)
    ap.add_argument("--agents", default="claude,gpt,openhands,swe,trae")
    ap.add_argument("--only", default="")
    ap.add_argument("--jobs", type=int, default=max(cpu_count() - 1, 1))
    args = ap.parse_args()

    tools_root = args.tools_root or (args.workspaces / ".vul4py_tools")
    agents = [a.strip() for a in args.agents.split(",") if a.strip()]
    only = set(s.strip() for s in args.only.split(",") if s.strip())

    cases = []
    for d in sorted(args.workspaces.iterdir()):
        if not d.is_dir() or not (d / "meta.json").exists():
            continue
        if only and d.name not in only:
            continue
        cases.append(d)

    print(f"[+] Evaluating {len(agents)} agents x {len(cases)} cases (jobs={args.jobs})")

    work = [(str(c), str(args.runs), agents, str(tools_root)) for c in cases]
    all_results: List[Dict] = []
    with Pool(processes=args.jobs) as pool:
        for batch in pool.imap_unordered(_worker, work):
            all_results.extend(batch)
            for v in batch:
                flag = "PLAUSIBLE" if v.get("plausible") else "FAIL"
                print(
                    f"  {v.get('agent'):<10} {v.get('vuln_id'):<25} {flag:<10} "
                    f"apply={v.get('apply_ok')} func={v.get('func_pfes')} "
                    f"expl={v.get('exploit_pfes')}"
                )

    out_csv = args.runs / "eval_summary.csv"
    cols = ["agent", "vuln_id", "apply_ok", "func_ok", "exploit_ok", "plausible",
            "func_pfes", "exploit_pfes", "elapsed_s", "notes"]
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for v in all_results:
            w.writerow({k: v.get(k, "") for k in cols})

    print(f"\n[+] wrote {out_csv}")
    # quick rollup
    by_agent: Dict[str, Dict[str, int]] = {}
    for v in all_results:
        a = v.get("agent", "?")
        d = by_agent.setdefault(a, {"plausible": 0, "applied": 0, "total": 0})
        d["total"] += 1
        if v.get("apply_ok"):
            d["applied"] += 1
        if v.get("plausible"):
            d["plausible"] += 1
    for a, d in by_agent.items():
        print(f"  {a:<10}: plausible {d['plausible']}/{d['total']} (applied {d['applied']})")


if __name__ == "__main__":
    main()
