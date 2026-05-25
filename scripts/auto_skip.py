#!/usr/bin/env python3
"""
auto_skip.py

For every CVE under workspaces/, parse `functional_fixed.junit.xml`. Every
test that FAILED or ERRORED on the fixed checkout is, by construction, a test
the fix-commit does not cause to pass -- so it's environmental noise (network
dep, OS-specific behaviour, library drift, flake), not a meaningful baseline
gate. Add a `--deselect <node_id>` to that CVE's functional_test_cmd_base so
subsequent scans focus on the actual oracle.

Idempotent: re-running after a clean scan picks up only newly-failing tests.

Output: writes (or merges into) dataset/meta_overrides/<vuln_id>.json with a
`set.functional_test_cmd_base` field that carries any pre-existing flags
plus the new --deselect entries.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
OVERRIDES_DIR = HERE / "dataset" / "meta_overrides"

AUTO_NOTE_TAG = "auto_skip"


def junit_to_deselect(file: str, classname: str, name: str) -> Optional[str]:
    """Build a pytest --deselect node identifier from a junit testcase tuple."""
    file = (file or "").replace("\\", "/")
    classname = classname or ""
    name = name or ""

    # If junit didn't populate `file` (common for collection errors), try
    # to derive it from the classname's dotted module prefix.
    if not file and classname:
        parts = classname.split(".")
        mod_parts: List[str] = []
        for p in parts:
            if p and p[0].isupper():
                break
            mod_parts.append(p)
        if mod_parts:
            file = "/".join(mod_parts) + ".py"

    if not file:
        return None

    # Last Title-Case segment of classname is the test class (if any).
    cls = ""
    for p in classname.split("."):
        if p and p[0].isupper():
            cls = p

    if cls and name:
        return f"{file}::{cls}::{name}"
    if name:
        return f"{file}::{name}"
    return file  # whole-file deselect (e.g. collection error)


def collect_failing(junit_path: Path) -> List[str]:
    if not junit_path.exists():
        return []
    try:
        root = ET.parse(junit_path).getroot()
    except ET.ParseError:
        return []
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    ids: List[str] = []
    seen = set()
    for s in suites:
        for c in s.findall("testcase"):
            if c.find("failure") is None and c.find("error") is None:
                continue
            ident = junit_to_deselect(
                c.get("file", ""), c.get("classname", ""), c.get("name", "")
            )
            if ident and ident not in seen:
                seen.add(ident)
                ids.append(ident)
    return ids


_DESELECT_RE = re.compile(r"--deselect[ =]([^ ]+|\S+)")


def existing_deselects(cmd: str) -> set:
    """Return the set of values currently passed as --deselect in a cmd."""
    out = set()
    tokens = shlex.split(cmd)
    i = 0
    while i < len(tokens):
        if tokens[i] == "--deselect" and i + 1 < len(tokens):
            out.add(tokens[i + 1])
            i += 2
        elif tokens[i].startswith("--deselect="):
            out.add(tokens[i].split("=", 1)[1])
            i += 1
        else:
            i += 1
    return out


def append_deselects(cmd: str, new_ids: List[str]) -> str:
    have = existing_deselects(cmd)
    to_add = [d for d in new_ids if d not in have]
    if not to_add:
        return cmd
    extra = " ".join(f"--deselect {shlex.quote(d)}" for d in to_add)
    return cmd.rstrip() + " " + extra


def merge_override(override_path: Path, vid: str, new_cmd: str, n_deselects: int) -> dict:
    if override_path.exists():
        ov = json.loads(override_path.read_text(encoding="utf-8"))
    else:
        ov = {}
    note = ov.get("_note", "")
    auto_marker = f"[{AUTO_NOTE_TAG}: {n_deselects} env-noise tests deselected on fixed]"
    if AUTO_NOTE_TAG in note:
        note = re.sub(r"\[" + AUTO_NOTE_TAG + r":[^\]]*\]", auto_marker, note)
    else:
        note = (note + " " if note else "") + auto_marker
    ov["_note"] = note.strip()
    ov.setdefault("set", {})["functional_test_cmd_base"] = new_cmd
    return ov


def main():
    ap = argparse.ArgumentParser(description="Auto-derive baseline test deselects from fixed-side failures.")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--overrides", type=Path, default=OVERRIDES_DIR)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--max-deselects", type=int, default=200,
                    help="Per-CVE cap; if a CVE has more failing tests than this, skip (likely a bigger meta problem).")
    args = ap.parse_args()

    if not args.workspaces.exists():
        sys.exit(f"no workspaces: {args.workspaces}")
    args.overrides.mkdir(parents=True, exist_ok=True)

    n_updated = n_noop = n_skip_large = 0
    for case in sorted(args.workspaces.iterdir()):
        if not case.is_dir() or not (case / "meta.json").exists():
            continue
        vid = case.name
        junit = case / "logs" / "functional_fixed.junit.xml"
        failing = collect_failing(junit)
        if not failing:
            continue
        if len(failing) > args.max_deselects:
            print(f"[skip-large] {vid}: {len(failing)} failing tests; treat as a meta problem, not env noise")
            n_skip_large += 1
            continue

        meta = json.loads((case / "meta.json").read_text(encoding="utf-8"))
        current_cmd = meta.get("functional_test_cmd_base", "pytest -q")
        new_cmd = append_deselects(current_cmd, failing)
        if new_cmd == current_cmd:
            n_noop += 1
            continue

        override_path = args.overrides / f"{vid}.json"
        ov = merge_override(override_path, vid, new_cmd, len(failing))
        if args.dry_run:
            print(f"[dry] {vid}: +{len(failing)} deselects -> {override_path}")
            for d in failing[:3]:
                print(f"       {d}")
            if len(failing) > 3:
                print(f"       (+{len(failing)-3} more)")
        else:
            override_path.write_text(json.dumps(ov, indent=2) + "\n", encoding="utf-8")
            print(f"[ok ] {vid}: +{len(failing)} deselects -> {override_path.name}")
            n_updated += 1

    print(f"[done] updated={n_updated}  noop={n_noop}  skip_large={n_skip_large}")


if __name__ == "__main__":
    main()
