#!/usr/bin/env python3
"""
label.py

Aggregate per-vuln eval.json files into results/correct_<agent>.jsonl, recording
which patches are plausible. Also writes results/summary.tsv with one row per
(agent, vuln_id) for easy cross-agent comparison.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
RUNS = HERE / "runs"
RESULTS = HERE / "results"


def label_agent(agent: str, runs_root: Path, results_root: Path) -> dict:
    agent_dir = runs_root / agent
    out_path = results_root / f"correct_{agent}.jsonl"
    n_total = n_apply = n_plaus = 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    with open(out_path, "w", encoding="utf-8") as out:
        for vuln_dir in sorted(agent_dir.iterdir()):
            if not vuln_dir.is_dir():
                continue
            eval_path = vuln_dir / "eval.json"
            if not eval_path.exists():
                continue
            v = json.loads(eval_path.read_text(encoding="utf-8"))
            n_total += 1
            if v.get("apply_ok"):
                n_apply += 1
            if v.get("plausible"):
                n_plaus += 1
                out.write(json.dumps(v) + "\n")
            rows.append(v)
    return {
        "agent": agent,
        "total": n_total,
        "apply_ok": n_apply,
        "plausible": n_plaus,
        "out_path": str(out_path),
        "rows": rows,
    }


def write_summary(stats: list, results_root: Path):
    rows = []
    for s in stats:
        for v in s["rows"]:
            rows.append((
                s["agent"],
                v.get("vuln_id"),
                "1" if v.get("apply_ok") else "0",
                str(v.get("functional_rc")),
                str(v.get("exploit_rc")),
                "1" if v.get("plausible") else "0",
            ))
    path = results_root / "summary.tsv"
    with open(path, "w", encoding="utf-8") as f:
        f.write("agent\tvuln_id\tapply_ok\tfunctional_rc\texploit_rc\tplausible\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    return path


def main():
    ap = argparse.ArgumentParser(description="Aggregate per-vuln eval.json files into per-agent jsonls.")
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--results", type=Path, default=RESULTS)
    ap.add_argument("--agent", action="append", help="Only label these agents (repeatable). Default: all under runs/")
    args = ap.parse_args()

    args.results.mkdir(parents=True, exist_ok=True)
    if args.agent:
        agents = args.agent
    else:
        agents = [p.name for p in args.runs.iterdir() if p.is_dir()]

    stats = []
    for a in agents:
        s = label_agent(a, args.runs, args.results)
        print(f"  {a:10s}  total={s['total']:>3}  apply_ok={s['apply_ok']:>3}  plausible={s['plausible']:>3}  -> {s['out_path']}")
        stats.append(s)

    p = write_summary(stats, args.results)
    print(f"[+] wrote {p}")


if __name__ == "__main__":
    main()
