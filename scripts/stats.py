#!/usr/bin/env python3
"""
stats.py

Quick cross-agent comparison from results/correct_<agent>.jsonl.

Prints a Markdown table to stdout.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
RESULTS = HERE / "results"
DATASET = HERE / "dataset" / "vul4py.csv"


def count_dataset_size(csv_path: Path) -> int:
    if not csv_path.exists():
        return 0
    return sum(1 for _ in csv_path.open(encoding="utf-8")) - 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=RESULTS)
    ap.add_argument("--dataset", type=Path, default=DATASET)
    args = ap.parse_args()

    n_dataset = count_dataset_size(args.dataset)
    by_agent = {}
    plausible_per_vuln = defaultdict(set)

    for p in sorted(args.results.glob("correct_*.jsonl")):
        agent = p.stem.replace("correct_", "")
        n = 0
        for line in p.open(encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                v = json.loads(line)
            except json.JSONDecodeError:
                continue
            n += 1
            vid = v.get("vuln_id")
            if vid:
                plausible_per_vuln[vid].add(agent)
        by_agent[agent] = n

    print(f"Dataset size: {n_dataset}")
    print()
    print("| Agent | Plausible | % of dataset |")
    print("|---|---:|---:|")
    for agent, n in sorted(by_agent.items()):
        pct = (n / n_dataset * 100) if n_dataset else 0
        print(f"| {agent} | {n} | {pct:.1f}% |")
    print()

    n_solved_by_any = len(plausible_per_vuln)
    n_solved_by_all = sum(1 for vids in plausible_per_vuln.values() if len(vids) == len(by_agent))
    print(f"Vulns plausibly fixed by at least one agent: {n_solved_by_any}")
    print(f"Vulns plausibly fixed by all agents:         {n_solved_by_all}")


if __name__ == "__main__":
    main()
