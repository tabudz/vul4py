# Vul4Py v2

Clean rebuild of the Vul4Py benchmark and agent-evaluation harness.

The benchmark is **100 Python vulnerabilities** (92 CVE + 8 GHSA). Each one ships a `vulnerable/` and `fixed/` checkout, a baseline test set (must keep passing after a patch), and an exploit test set (must fail before, pass after). The harness measures how well an LLM or agentic harness can produce a unified-diff patch that makes both verdicts flip correctly.

## Directory layout

```
vul4py_v2/
├── dataset/
│   ├── ok.txt              # canonical 100 vuln IDs, one per line
│   └── vul4py.csv          # vuln_id, repo_url, fix_commit (built deterministically)
├── scripts/
│   ├── build_dataset.py    # ok.txt + ../matches.jsonl -> dataset/vul4py.csv
│   ├── prepare.py          # CSV -> per-vuln workspaces/<id>/{vulnerable,fixed,meta.json}
│   ├── vul4py.py           # runner: setup, functional, exploit, fork+patch, scan
│   ├── run_agent.py        # patch generation: claude/gpt built-in; openhands/trae/swe external
│   ├── evaluate.py         # apply each patch, run baseline+exploit, emit eval.json
│   ├── label.py            # roll eval.json files into results/correct_<agent>.jsonl
│   └── stats.py            # cross-agent summary table
├── runs/                   # per-agent per-vuln outputs (gitignored)
│   └── <agent>/<vuln_id>/{prompt.txt,patch.diff,generation.json,eval.json,eval.log}
├── results/                # aggregated verdicts (committed)
│   ├── correct_<agent>.jsonl
│   └── summary.tsv
└── workspaces/             # cloned source trees (gitignored)
    └── <vuln_id>/{vulnerable,fixed,logs,meta.json}
```

## Phases

### 1. Build the dataset CSV

```bash
python3 scripts/build_dataset.py
```

Looks up `(repo_url, fix_commit)` for each ID in `dataset/ok.txt` against `../matches.jsonl`. Already done; output is `dataset/vul4py.csv`, 100 rows.

### 2. Prepare per-vuln workspaces (fresh clones)

```bash
python3 scripts/prepare.py --jobs 8
```

Clones each repo twice (vulnerable parent + fixed commit), computes baseline and new test files, writes `meta.json`. Expect this to take ~30-60 minutes and several GB of disk; resumable.

### 3. Verify the harness on `fixed/` (sanity check)

For every vuln, baseline tests should pass on `fixed/` and exploit tests should pass on `fixed/` & fail on `vulnerable/`. This is the gating step that decides whether the meta.json oracle is trustworthy.

```bash
python3 scripts/vul4py.py --workspace-root workspaces scan --jobs 8
```

Inspect `workspaces/scan_report.tsv`. Drop or fix any vuln whose row is not `OK` before treating its results as benchmark-quality.

### 4. Generate patches

Built-in (direct LLM):

```bash
export ANTHROPIC_API_KEY=...
python3 scripts/run_agent.py --agent claude               # default: claude-opus-4-7
python3 scripts/run_agent.py --agent claude --model claude-sonnet-4-6

export OPENAI_API_KEY=...
python3 scripts/run_agent.py --agent gpt --model gpt-4.1
python3 scripts/run_agent.py --agent gpt --model gpt-4o
```

External (agentic harnesses): run the harness externally and drop its unified-diff into `runs/<agent>/<vuln_id>/patch.diff`. Then mark them registered:

```bash
python3 scripts/run_agent.py --agent openhands
python3 scripts/run_agent.py --agent trae
python3 scripts/run_agent.py --agent swe
```

### 5. Evaluate

```bash
python3 scripts/evaluate.py --agent claude
python3 scripts/evaluate.py --agent gpt
python3 scripts/evaluate.py --agent openhands
python3 scripts/evaluate.py --agent trae
python3 scripts/evaluate.py --agent swe
```

For each `(agent, vuln_id)`, this forks `vulnerable/` into `<vuln_id>/<agent>_candidate/`, applies `patch.diff`, runs the baseline + exploit tests, and writes `runs/<agent>/<vuln_id>/eval.json`. A patch is `plausible` when `apply_ok && functional_rc in (0,999) && exploit_rc == 0`.

### 6. Label & summarise

```bash
python3 scripts/label.py
python3 scripts/stats.py
```

`label.py` writes one `results/correct_<agent>.jsonl` (plausibly-fixed only) and a `results/summary.tsv` (every row). `stats.py` prints the cross-agent table.

## Conventions

- All scripts assume `python3` ≥ 3.10 on the host. Per-vuln Python is provisioned automatically by `vul4py.py` via micromamba (no global install required).
- Vulnerability IDs preserve case (`CVE-…`, `GHSA-…`).
- Patches are unified diffs against the vulnerable repo root, prefixed `a/` and `b/`.
- `meta.json` keeps the `cve_id` field name for compatibility with `vul4py.py`; treat it as `vuln_id`.

## What's not in scope here

- The OSV ingestion pipeline lives at `../osv.py` and `../prepare.py`. The output it produces (`../matches.jsonl`) is the input to step 1.
- The agentic harness runners (OpenHands, Trae, SWE-agent) are not re-implemented; only their output contract (`runs/<agent>/<vuln_id>/patch.diff`) is.
