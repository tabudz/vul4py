#!/usr/bin/env python3
"""aggregate_results.py

Rebuild a complete eval summary from every runs/<agent>/<vuln_id>/eval.json.

run_eval.py rewrites eval_summary.csv using only the cases processed in that
invocation, so a `--only` resume clobbers the full rollup. The per-case
eval.json files are the durable source of truth; this script reassembles them
into a complete CSV + prints a per-agent rollup and a list of any (agent,case)
pairs still missing an eval.json.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
COLS = ["agent", "vuln_id", "apply_ok", "func_ok", "exploit_ok", "plausible",
        "func_pfes", "exploit_pfes", "elapsed_s", "notes"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspaces", type=Path, default=HERE.parent / "workspaces")
    ap.add_argument("--runs", type=Path, default=HERE.parent / "runs")
    ap.add_argument("--agents", default="claude,gpt,openhands,swe,trae")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    agents = [a.strip() for a in args.agents.split(",") if a.strip()]
    cases = sorted(
        d.name for d in args.workspaces.iterdir()
        if d.is_dir() and (d / "meta.json").exists()
    )
    out_csv = args.out or (args.runs / "eval_summary_full.csv")

    rows = []
    missing = []
    for vid in cases:
        for agent in agents:
            ej = args.runs / agent / vid / "eval.json"
            if ej.exists():
                try:
                    rows.append(json.loads(ej.read_text()))
                except Exception as e:
                    missing.append(f"{agent}/{vid} (corrupt: {e})")
            else:
                missing.append(f"{agent}/{vid}")

    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in COLS})

    # per-agent rollup
    roll = {}
    for r in rows:
        d = roll.setdefault(r.get("agent", "?"), {"plausible": 0, "applied": 0, "total": 0})
        d["total"] += 1
        if r.get("apply_ok"):
            d["applied"] += 1
        if r.get("plausible"):
            d["plausible"] += 1

    print(f"[+] {len(cases)} cases x {len(agents)} agents = {len(cases)*len(agents)} pairs; "
          f"{len(rows)} evaluated, {len(missing)} missing")
    print(f"[+] wrote {out_csv}\n")
    print(f"  {'agent':<10} {'plausible':>10} {'applied':>9} {'total':>7}  plausible%")
    for a in agents:
        d = roll.get(a, {"plausible": 0, "applied": 0, "total": 0})
        pct = (100.0 * d["plausible"] / d["total"]) if d["total"] else 0.0
        print(f"  {a:<10} {d['plausible']:>10} {d['applied']:>9} {d['total']:>7}  {pct:8.1f}%")

    if missing:
        print(f"\n[!] missing eval.json ({len(missing)}):")
        for m in missing:
            print(f"      {m}")


if __name__ == "__main__":
    main()
