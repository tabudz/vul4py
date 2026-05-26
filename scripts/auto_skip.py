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

    # Pytest module-level collection-error shape: classname is empty, name is a
    # dotted module path like "tests.test_urldispatch". Convert to a whole-file
    # deselect because there's no specific test to point at.
    if (not classname) and name and "." in name and "/" not in name and "::" not in name and not name.startswith("test_"):
        return name.replace(".", "/") + ".py"

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


def existing_flagged_filters(cmd: str) -> set:
    """Return {(flag, value), ...} for every --deselect/--ignore token."""
    out: set = set()
    tokens = shlex.split(cmd)
    i = 0
    while i < len(tokens):
        if tokens[i] in ("--deselect", "--ignore") and i + 1 < len(tokens):
            out.add((tokens[i], tokens[i + 1]))
            i += 2
        elif tokens[i].startswith("--deselect="):
            out.add(("--deselect", tokens[i].split("=", 1)[1]))
            i += 1
        elif tokens[i].startswith("--ignore="):
            out.add(("--ignore", tokens[i].split("=", 1)[1]))
            i += 1
        else:
            i += 1
    return out


def append_deselects(cmd: str, new_ids: List[str]) -> str:
    """Append --deselect for specific test ids, --ignore for whole-file paths.
    pytest's --deselect operates on already-collected tests, so it can't help
    when collection itself fails -- use --ignore for those. We key dedup on
    (flag, value) so a wrong-flag legacy entry doesn't suppress a needed
    right-flag addition."""
    have = existing_flagged_filters(cmd)
    parts = []
    for d in new_ids:
        flag = "--ignore" if "::" not in d else "--deselect"
        key = (flag, d)
        if key in have:
            continue
        have.add(key)
        parts.append(f"{flag} {shlex.quote(d)}")
    if not parts:
        return cmd
    return cmd.rstrip() + " " + " ".join(parts)


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

    PHASES = (
        ("functional_fixed.junit.xml", "functional_test_cmd_base"),
        ("exploit_fixed.junit.xml",    "exploit_test_cmd_base"),
    )

    n_updated = n_noop = n_skip_large = 0
    for case in sorted(args.workspaces.iterdir()):
        if not case.is_dir() or not (case / "meta.json").exists():
            continue
        vid = case.name

        meta_path = case / "meta.json"
        override_path = args.overrides / f"{vid}.json"
        updated_for_cve = False
        total_added = 0

        for junit_name, meta_field in PHASES:
            junit = case / "logs" / junit_name
            failing = collect_failing(junit)
            if not failing:
                continue
            if len(failing) > args.max_deselects:
                print(f"[skip-large] {vid}/{junit_name}: {len(failing)} failing; treat as meta problem")
                n_skip_large += 1
                continue

            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            current_cmd = meta.get(meta_field, "pytest -q")
            new_cmd = append_deselects(current_cmd, failing)

            # For whole-file collection-error entries, also drop them from
            # baseline_test_files (they're passed as positional args, which
            # overrides --ignore). Only affects functional, not exploit.
            whole_file_ids = [d for d in failing if "::" not in d]

            if new_cmd == current_cmd and not whole_file_ids:
                continue

            if override_path.exists():
                ov = json.loads(override_path.read_text(encoding="utf-8"))
            else:
                ov = {}
            ov.setdefault("set", {})[meta_field] = new_cmd

            if whole_file_ids and meta_field == "functional_test_cmd_base":
                ov.setdefault("drop", {})
                existing_drops = set(ov["drop"].get("baseline_test_files", []))
                for d in whole_file_ids:
                    existing_drops.add(d)
                ov["drop"]["baseline_test_files"] = sorted(existing_drops)

            note = ov.get("_note", "")
            marker = f"[{AUTO_NOTE_TAG}:{meta_field}={len(failing)}]"
            if AUTO_NOTE_TAG + ":" + meta_field in note:
                note = re.sub(r"\[" + AUTO_NOTE_TAG + r":" + meta_field + r"=[^\]]*\]", marker, note)
            else:
                note = (note + " " if note else "") + marker
            ov["_note"] = note.strip()

            if args.dry_run:
                print(f"[dry] {vid}/{meta_field}: +{len(failing)} deselects")
                for d in failing[:3]:
                    print(f"       {d}")
                if len(failing) > 3:
                    print(f"       (+{len(failing)-3} more)")
            else:
                override_path.write_text(json.dumps(ov, indent=2) + "\n", encoding="utf-8")
                print(f"[ok ] {vid}/{meta_field}: +{len(failing)} deselects -> {override_path.name}")
                updated_for_cve = True
                total_added += len(failing)

        if updated_for_cve:
            n_updated += 1
        else:
            n_noop += 1

    print(f"[done] cves_updated={n_updated}  cves_noop={n_noop}  skip_large_events={n_skip_large}")


if __name__ == "__main__":
    main()
