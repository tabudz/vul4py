#!/usr/bin/env python3
"""
apply_overrides.py

Apply per-vuln meta.json overrides to a prepared workspace.

Source of truth: dataset/meta_overrides/<vuln_id>.json
Each override file supports three operations:

    {
      "set":         { "<field>": <value>, ... },        # replace
      "drop":        { "<field>": [<item>, ...], ... },  # remove exact items from a list field
      "drop_prefix": { "<field>": [<prefix>, ...], ... } # remove list items whose value starts with prefix
    }

The override file may also contain "_note" (free-form audit reason) which is ignored.

Idempotent: re-running with the same overrides is a no-op.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
OVERRIDES_DIR = HERE / "dataset" / "meta_overrides"
WORKSPACES = HERE / "workspaces"


def apply(meta: dict, override: dict) -> dict:
    for k, v in override.get("set", {}).items():
        meta[k] = v
    for k, drops in override.get("drop", {}).items():
        if not isinstance(meta.get(k), list):
            continue
        drop_set = set(drops)
        meta[k] = [x for x in meta[k] if x not in drop_set]
    for k, prefixes in override.get("drop_prefix", {}).items():
        if not isinstance(meta.get(k), list):
            continue
        meta[k] = [x for x in meta[k] if not any(x.startswith(p) for p in prefixes)]
    return meta


def main():
    ap = argparse.ArgumentParser(description="Apply per-vuln meta.json overrides.")
    ap.add_argument("--overrides", type=Path, default=OVERRIDES_DIR)
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--vuln-id", help="Apply only this one (default: all)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not args.overrides.exists():
        sys.exit(f"no overrides dir: {args.overrides}")

    override_files = sorted(args.overrides.glob("*.json"))
    if args.vuln_id:
        override_files = [p for p in override_files if p.stem == args.vuln_id]

    n_applied = n_skipped = 0
    for op in override_files:
        vid = op.stem
        meta_path = args.workspaces / vid / "meta.json"
        if not meta_path.exists():
            print(f"[skip] {vid}: no meta at {meta_path}")
            n_skipped += 1
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        ov = json.loads(op.read_text(encoding="utf-8"))
        before = json.dumps(meta, sort_keys=True)
        meta = apply(meta, ov)
        after = json.dumps(meta, sort_keys=True)
        if before == after:
            print(f"[noop] {vid}: already matches override")
            n_skipped += 1
            continue
        if args.dry_run:
            print(f"[dry ] {vid}: would update {meta_path}")
        else:
            meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
            print(f"[ok  ] {vid}: applied -> {meta_path}")
            n_applied += 1
    print(f"[done] applied={n_applied}  skipped={n_skipped}  total={len(override_files)}")


if __name__ == "__main__":
    main()
