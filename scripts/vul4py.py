#!/usr/bin/env python3
"""
vul4py.py (portable)

Portable CLI for operating on Vul4Py workspaces created by prepare_vul4py.py.

Key portability changes vs the original:
- No hard-coded /mnt/sun-data/... paths.
- Uses a per-workspace tools directory (default: <workspace-root>/.vul4py_tools).
- Auto-provisions required Python versions from meta.json via:
    - micromamba (auto-downloaded if missing), or
    - conda/mamba if already present on PATH (or provided via env vars).
- Uses system gcc/g++ if available; otherwise provisions a conda/mamba toolchain.
- tqdm is optional.
- Patch apply prefers `git apply`, falls back to `patch`.

Environment variables (optional):
- VUL4PY_TOOLS_ROOT: override tools root directory
- VUL4PY_CONDA_EXE: path to conda executable (if you want to force it)
- VUL4PY_MAMBA_EXE: path to micromamba/mamba executable (force)
- VUL4PY_DISABLE_TOOLCHAIN=1: disable compiler env provisioning
- VUL4PY_DISABLE_MICROMAMBA_BOOTSTRAP=1: don't auto-download micromamba
"""

from __future__ import annotations

import os
import sys
import json
import shlex
import shutil
import argparse
import subprocess
import signal
import platform
import tarfile
import urllib.request
import contextlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from multiprocessing import Pool, cpu_count

# tqdm is OPTIONAL
try:
    from tqdm import tqdm  # type: ignore
except Exception:
    def tqdm(it, total=None, desc=None):
        return it


# ---------- basic helpers ----------

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def _require_cmd(cmd: str, hint: str = "") -> str:
    p = shutil.which(cmd)
    if p:
        return p
    msg = f"Required command not found on PATH: {cmd}"
    if hint:
        msg += f"\nHint: {hint}"
    raise RuntimeError(msg)


def load_meta(case_dir: Path) -> Dict:
    meta_path = case_dir / "meta.json"
    if not meta_path.exists():
        raise RuntimeError(f"Missing {meta_path}")
    with open(meta_path, "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_version_dir(case_dir: Path, version_name: str) -> Path:
    d = case_dir / version_name
    if not d.exists():
        raise RuntimeError(f"Version dir {d} not found.")
    return d


# ---------- file lock (avoid concurrent env creation in multiprocessing) ----------

@contextlib.contextmanager
def _file_lock(lock_path: Path):
    """
    Cross-process lock using fcntl on Unix. No-op on platforms without fcntl.
    """
    ensure_dir(lock_path.parent)
    with open(lock_path, "w", encoding="utf-8") as f:
        try:
            import fcntl  # Unix only
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        except Exception:
            # Best-effort fallback (no lock)
            yield


# ---------- tool roots (portable) ----------

def get_tools_root(workspace_root: Optional[Path] = None) -> Path:
    """
    Determine tools root:
      1) VUL4PY_TOOLS_ROOT if set
      2) <workspace_root>/.vul4py_tools if workspace_root provided
      3) ~/.cache/vul4py
    """
    env = os.environ.get("VUL4PY_TOOLS_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    if workspace_root is not None:
        return (workspace_root.resolve() / ".vul4py_tools").resolve()
    return (Path.home() / ".cache" / "vul4py").resolve()


def py_env_root(tools_root: Path) -> Path:
    return tools_root / "pyenvs"


def compiler_env_root(tools_root: Path) -> Path:
    return tools_root / "compiler_envs" / "gcc"


def bin_root(tools_root: Path) -> Path:
    return tools_root / "bin"


def lock_root(tools_root: Path) -> Path:
    return tools_root / "locks"


# ---------- micromamba bootstrap + env manager detection ----------

def _platform_tag_for_micromamba() -> str:
    sysname = platform.system().lower()
    machine = platform.machine().lower()

    if sysname.startswith("linux"):
        if machine in ("x86_64", "amd64"):
            return "linux-64"
        if machine in ("aarch64", "arm64"):
            return "linux-aarch64"
    if sysname.startswith("darwin"):
        if machine in ("x86_64", "amd64"):
            return "osx-64"
        if machine in ("arm64", "aarch64"):
            return "osx-arm64"

    raise RuntimeError(f"Unsupported platform for micromamba bootstrap: {sysname} / {machine}")


def _download(url: str, dst: Path):
    ensure_dir(dst.parent)
    with urllib.request.urlopen(url) as r, open(dst, "wb") as f:
        shutil.copyfileobj(r, f)


def _bootstrap_micromamba(tools_root: Path) -> Path:
    """
    Download micromamba into <tools_root>/bin/micromamba if missing.
    Requires internet access.
    """
    if os.environ.get("VUL4PY_DISABLE_MICROMAMBA_BOOTSTRAP") == "1":
        raise RuntimeError("micromamba not found and bootstrap disabled (VUL4PY_DISABLE_MICROMAMBA_BOOTSTRAP=1).")

    exe = bin_root(tools_root) / "micromamba"
    if exe.exists():
        return exe

    tag = _platform_tag_for_micromamba()
    # This endpoint returns a tar.bz2 containing bin/micromamba
    url = f"https://micro.mamba.pm/api/micromamba/{tag}/latest"
    dl = tools_root / "downloads" / f"micromamba-{tag}.tar.bz2"
    tmp = tools_root / "downloads" / f"micromamba-{tag}-extract"

    print(f"[vul4py] Downloading micromamba from {url}")
    _download(url, dl)

    if tmp.exists():
        shutil.rmtree(tmp)
    ensure_dir(tmp)

    with tarfile.open(dl, mode="r:bz2") as tf:
        tf.extractall(path=tmp)

    cand = tmp / "bin" / "micromamba"
    if not cand.exists():
        raise RuntimeError(f"micromamba bootstrap failed: expected {cand} after extract.")

    ensure_dir(exe.parent)
    shutil.copy2(cand, exe)
    try:
        exe.chmod(0o755)
    except Exception:
        pass

    return exe


def _find_env_manager(tools_root: Path) -> Tuple[str, Path]:
    """
    Return (kind, exe_path) where kind in {"micromamba","mamba","conda"}.

    Priority:
      1) VUL4PY_MAMBA_EXE (micromamba/mamba)
      2) VUL4PY_CONDA_EXE
      3) micromamba/mamba/conda on PATH
      4) auto-download micromamba
    """
    forced_mamba = os.environ.get("VUL4PY_MAMBA_EXE")
    if forced_mamba:
        p = Path(forced_mamba).expanduser().resolve()
        if not p.exists():
            raise RuntimeError(f"VUL4PY_MAMBA_EXE set but not found: {p}")
        name = p.name.lower()
        if "micro" in name:
            return ("micromamba", p)
        return ("mamba", p)

    forced_conda = os.environ.get("VUL4PY_CONDA_EXE")
    if forced_conda:
        p = Path(forced_conda).expanduser().resolve()
        if not p.exists():
            raise RuntimeError(f"VUL4PY_CONDA_EXE set but not found: {p}")
        return ("conda", p)

    for cmd in ("micromamba", "mamba", "conda"):
        w = shutil.which(cmd)
        if w:
            kind = "micromamba" if cmd == "micromamba" else ("mamba" if cmd == "mamba" else "conda")
            return (kind, Path(w).resolve())

    # nothing found -> bootstrap micromamba
    mm = _bootstrap_micromamba(tools_root)
    return ("micromamba", mm)


def _env_create_or_update(
    tools_root: Path,
    prefix: Path,
    packages: List[str],
    channels: Optional[List[str]] = None,
):
    """
    Create env at prefix if missing. No-op if exists.
    Uses micromamba/mamba/conda.

    For micromamba we set MAMBA_ROOT_PREFIX so it can operate without global install.
    """
    if prefix.exists():
        return

    kind, exe = _find_env_manager(tools_root)
    channels = channels or ["conda-forge"]

    env = os.environ.copy()

    if kind == "micromamba":
        # micromamba needs a root prefix (where it stores pkgs/metadata)
        mroot = tools_root / "mamba_root"
        ensure_dir(mroot)
        env["MAMBA_ROOT_PREFIX"] = str(mroot)
        cmd = [str(exe), "create", "-y", "-p", str(prefix)]
        for c in channels:
            cmd += ["-c", c]
        cmd += packages
    else:
        # conda/mamba
        cmd = [str(exe), "create", "-y", "-p", str(prefix)]
        for c in channels:
            cmd += ["-c", c]
        cmd += packages

    ensure_dir(prefix.parent)
    print(f"[vul4py] Creating env: {prefix} ({' '.join(packages)}) via {kind}")
    subprocess.run(cmd, text=True, check=True, env=env)


# ---------- interpreter provisioning (strict) ----------

def _get_requested_python_version(meta: dict) -> str:
    ver = meta.get("python_version")
    if not ver:
        raise RuntimeError(
            "meta.json has no 'python_version'. Please set it explicitly "
            '(e.g. "python_version": "3.8").'
        )
    return str(ver).strip()


def ensure_python_interpreter(tools_root: Path, python_version: str) -> Path:
    """
    Ensure a dedicated env exists for this python_version, and return its python.
    Example: python_version="3.8" -> <tools_root>/pyenvs/py38/bin/python
    """
    short = python_version.replace(".", "")
    prefix = py_env_root(tools_root) / f"py{short}"
    lock = lock_root(tools_root) / f"py{short}.lock"

    with _file_lock(lock):
        _env_create_or_update(
            tools_root=tools_root,
            prefix=prefix,
            packages=[f"python={python_version}", "pip"],
            channels=["conda-forge"],
        )

    py = prefix / "bin" / "python"
    if not py.exists():
        raise RuntimeError(f"Python not found after env creation: {py}")
    return py


# ---------- compiler toolchain provisioning ----------

def ensure_compiler_paths(tools_root: Path) -> Dict[str, str]:
    """
    Prefer system gcc/g++ if available.
    Otherwise create a toolchain env (conda-forge) under tools_root.

    Returns:
      {
        "bin_dir": "<...>" or "",
        "lib_dir": "<...>" or "",
        "enabled": "1" or "0"
      }
    """
    if os.environ.get("VUL4PY_DISABLE_TOOLCHAIN") == "1":
        return {"bin_dir": "", "lib_dir": "", "enabled": "0"}

    # System toolchain available? Great, nothing to do.
    if shutil.which("gcc") and shutil.which("g++"):
        return {"bin_dir": "", "lib_dir": "", "enabled": "1"}

    prefix = compiler_env_root(tools_root)
    lock = lock_root(tools_root) / "compiler.lock"

    with _file_lock(lock):
        _env_create_or_update(
            tools_root=tools_root,
            prefix=prefix,
            packages=[
                # conda-forge toolchain packages
                "gcc_linux-64",
                "gxx_linux-64",
                "binutils_linux-64",
            ],
            channels=["conda-forge"],
        )

    bin_dir = prefix / "bin"
    lib_dir = prefix / "lib"
    ensure_dir(bin_dir)
    ensure_dir(lib_dir)
    return {"bin_dir": str(bin_dir), "lib_dir": str(lib_dir), "enabled": "1"}


def link_compiler_into_venv(tools_root: Path, venv_dir: Path):
    """
    Symlink gcc/g++ into venv/bin if we're using a provisioned toolchain.
    If using system gcc, no-op.
    """
    info = ensure_compiler_paths(tools_root)
    bin_dir = Path(info["bin_dir"]) if info["bin_dir"] else None
    if not bin_dir or not bin_dir.exists():
        return

    venv_bin = venv_dir / "bin"
    ensure_dir(venv_bin)

    # Find a reasonable candidate in conda toolchain env
    wanted = {
        "gcc": ["gcc", "cc"],
        "g++": ["g++", "c++"],
        "cc": ["cc", "gcc"],
        "c++": ["c++", "g++"],
    }

    def find_candidate(suffix_list: List[str]) -> Optional[Path]:
        for suffix in suffix_list:
            direct = bin_dir / suffix
            if direct.exists() and direct.is_file():
                return direct
        for f in bin_dir.iterdir():
            if not f.is_file():
                continue
            for suffix in suffix_list:
                if f.name.endswith(suffix):
                    return f
        return None

    for canonical, suffixes in wanted.items():
        src = find_candidate(suffixes)
        if not src:
            continue
        dst = venv_bin / canonical
        if dst.exists():
            continue
        try:
            dst.symlink_to(src)
        except Exception as e:
            sys.stderr.write(f"[WARN] Failed to symlink {canonical} -> {src}: {e}\n")


# ---------- venv / test helpers ----------

def _venv_stamp_path(venv_dir: Path) -> Path:
    return venv_dir / ".vul4py_python_version"


def _read_existing_venv_version(venv_dir: Path) -> Optional[str]:
    stamp = _venv_stamp_path(venv_dir)
    if not venv_dir.exists() or not stamp.exists():
        return None
    return (stamp.read_text(encoding="utf-8", errors="replace").strip() or None)


def run_in_venv(
    tools_root: Path,
    cmd: str,
    proj_dir: Path,
    logfile: Path,
    check: bool,
    extra_pythonpath: Optional[List[str]] = None,
) -> subprocess.CompletedProcess:
    """
    Run `cmd` inside proj_dir's .venv, capturing stdout/stderr into logfile.
    Also wires compiler env (if any) into PATH/LD_LIBRARY_PATH.
    """
    proj_dir = proj_dir.resolve()
    logfile = logfile.resolve()

    venv_dir = proj_dir / ".venv"
    bin_dir = venv_dir / "bin"
    ensure_dir(logfile.parent)

    compiler = ensure_compiler_paths(tools_root)
    compiler_bin = compiler["bin_dir"]
    compiler_lib = compiler["lib_dir"]

    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(venv_dir)
    env.pop("PYTHONHOME", None)
    env["PYTHONNOUSERSITE"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

    # PATH = <venv>/bin : <compiler_env>/bin : old PATH
    orig_path = env.get("PATH", "")
    parts = [str(bin_dir)]
    if compiler_bin:
        parts.append(compiler_bin)
    parts.append(orig_path)
    env["PATH"] = os.pathsep.join([p for p in parts if p])

    # LD_LIBRARY_PATH add compiler libs if we provisioned toolchain
    if compiler_lib:
        orig_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = compiler_lib + (os.pathsep + orig_ld if orig_ld else "")

    # Encourage using gcc/g++ if present
    env.setdefault("CC", "gcc")
    env.setdefault("CXX", "g++")

    if extra_pythonpath:
        joined = os.pathsep.join(extra_pythonpath)
        env["PYTHONPATH"] = joined + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    debug_prefix = (
        "echo VENV_PY=$(which python); "
        "echo VENV_PYTEST=$(which pytest || true); "
        "echo GCC_BIN=$(which gcc || true); "
    )

    cp = subprocess.run(
        debug_prefix + cmd,
        shell=True,
        cwd=str(proj_dir),
        env=env,
        text=True,
        capture_output=True,
    )

    with open(logfile, "w", encoding="utf-8") as f:
        f.write(f"$ {cmd}\n")
        f.write(f"[exit {cp.returncode}]\n\n")
        f.write("STDOUT:\n")
        f.write(cp.stdout or "")
        f.write("\nSTDERR:\n")
        f.write(cp.stderr or "")
        f.write("\n")

    if check and cp.returncode != 0:
        raise RuntimeError(f"Command failed (rc={cp.returncode}): {cmd}\nSee {logfile}")

    return cp


def create_and_install(tools_root: Path, proj_dir: Path, meta: Dict, logs_dir: Path):
    """
    Ensure proj_dir/.venv exists and matches meta['python_version'].

    Steps:
    - ensure correct python interpreter exists (auto-provision)
    - recreate venv if version mismatch
    - stamp venv
    - symlink compiler tools into venv/bin if needed
    - bootstrap pip tooling + pytest
    - run meta['install_cmds']
    """
    requested_ver = _get_requested_python_version(meta)
    python_bin = ensure_python_interpreter(tools_root, requested_ver)

    venv_dir = proj_dir / ".venv"
    existing_ver = _read_existing_venv_version(venv_dir)

    if venv_dir.exists() and (existing_ver is None or existing_ver != requested_ver):
        shutil.rmtree(venv_dir, ignore_errors=True)

    if not venv_dir.exists():
        subprocess.run(
            [str(python_bin), "-m", "venv", str(venv_dir)],
            cwd=str(proj_dir),
            text=True,
            check=True,
        )
        _venv_stamp_path(venv_dir).write_text(requested_ver + "\n", encoding="utf-8")

    # Make compiler available (if provisioned)
    link_compiler_into_venv(tools_root, venv_dir)

    # Bootstrap pip tooling (best-effort ensurepip)
    bootstrap_logs = logs_dir / f"bootstrap_{proj_dir.name}.log"
    run_in_venv(
        tools_root,
        "python -m ensurepip --upgrade || true; "
        "python -m pip install -U pip setuptools wheel; "
        "python -m pip install -U pytest",
        proj_dir,
        bootstrap_logs,
        check=True,
    )

    # Run install_cmds under that venv
    for idx, cmd in enumerate(meta.get("install_cmds", [])):
        logfile = logs_dir / f"setup_{proj_dir.name}_{idx}.log"
        run_in_venv(tools_root, cmd, proj_dir, logfile, check=True)


def _junit_path_for(logfile: Path) -> Path:
    return logfile.with_suffix(".junit.xml")


def run_functional(tools_root: Path, proj_dir: Path, meta: Dict, logs_dir: Path) -> int:
    logfile = logs_dir / f"functional_{proj_dir.name}.log"
    junit = _junit_path_for(logfile)
    if junit.exists():
        junit.unlink()

    baseline_files = meta.get("baseline_test_files", [])
    existing = [p for p in baseline_files if (proj_dir / p).exists()]
    if not existing:
        ensure_dir(logfile.parent)
        with open(logfile, "w", encoding="utf-8") as f:
            f.write("[!] No baseline_test_files found in this version; skipping functional tests.\n")
        return 999

    base_cmd = meta.get("functional_test_cmd_base", "pytest -q").strip()
    cmd = f"{base_cmd} --junitxml={shlex.quote(str(junit))} " + " ".join(existing)
    cp = run_in_venv(tools_root, cmd, proj_dir, logfile, check=False)
    return cp.returncode


def backport_artifacts(
    fixed_dir: Path,
    target_dir: Path,
    new_test_files: List[str],
    new_code_files: List[str],
):
    """
    Overlay test files from fixed_dir directly into target_dir at their
    original relative paths. target_dir's existing package layout
    (__init__.py chain, conftest.py, data/fixture directories, etc.) is
    reused as-is, so package-relative imports and listdir() of adjacent
    fixture dirs all resolve naturally.

    This mutates target_dir's source tree. `_restore_target` reverts via
    `git checkout HEAD` at the start of each worker so re-runs are clean.

    new_code_files are mirrored into target_dir/backported_support/ for
    inspection/debug but NOT placed on PYTHONPATH -- adding the fixed
    helper code to the import path would un-fix the vulnerability for
    classes of fixes where the patch is delivered via a modified helper.
    """
    ensure_dir(target_dir)

    # Overlay test files into target_dir at their canonical paths.
    for relpath in new_test_files:
        src = fixed_dir / relpath
        if not src.exists():
            continue
        dst = target_dir / relpath
        ensure_dir(dst.parent)
        if src.is_dir():
            # tolerate test "files" that are directories (rare)
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            # `copy` (not copy2) deliberately resets mtime so any stale .pyc
            # alongside the original gets invalidated.
            shutil.copy(src, dst)

    # Keep a reference copy of new_code_files; NOT on PYTHONPATH.
    back_support_root = target_dir / "backported_support"
    ensure_dir(back_support_root)
    for relpath in new_code_files:
        src = fixed_dir / relpath
        if not src.exists():
            continue
        dst = back_support_root / relpath
        ensure_dir(dst.parent)
        shutil.copy(src, dst)


def _restore_target(target_dir: Path):
    """Revert any prior overlay so the next scan iteration sees a clean tree."""
    if not target_dir.exists() or not (target_dir / ".git").exists():
        return
    subprocess.run(
        ["git", "-C", str(target_dir), "checkout", "HEAD", "--", "."],
        capture_output=True, text=True, check=False,
    )
    subprocess.run(
        ["git", "-C", str(target_dir), "clean", "-fdx",
         "-e", ".venv", "-e", "backported_support", "-e", "backported_tests"],
        capture_output=True, text=True, check=False,
    )
    bs = target_dir / "backported_support"
    if bs.exists():
        shutil.rmtree(bs, ignore_errors=True)


def run_exploit_for_target(
    tools_root: Path,
    fixed_dir: Path,
    target_dir: Path,
    version_name: str,
    meta: Dict,
    logs_dir: Path,
) -> int:
    logfile = logs_dir / f"exploit_{version_name}.log"
    junit = _junit_path_for(logfile)
    ensure_dir(logfile.parent)
    if junit.exists():
        junit.unlink()

    new_test_files = meta.get("new_test_files", [])
    new_code_files = meta.get("new_code_files", [])

    if not new_test_files:
        with open(logfile, "w", encoding="utf-8") as f:
            f.write("[!] No new_test_files in meta.json; cannot run exploit oracle.\n")
        return 999

    base_cmd = meta.get("exploit_test_cmd_base", "pytest -q").strip()
    if base_cmd.startswith("pytest"):
        tail = base_cmd[len("pytest"):].strip()
    else:
        tail = base_cmd

    junit_arg = f"--junitxml={shlex.quote(str(junit))}"

    if version_name == "fixed":
        existing = [p for p in new_test_files if (fixed_dir / p).exists()]
        if not existing:
            with open(logfile, "w", encoding="utf-8") as f:
                f.write("[!] No regression tests exist in fixed dir.\n")
            return 999
        cmd = f"python -m pytest {tail} {junit_arg} " + " ".join(existing)
        cp = run_in_venv(tools_root, cmd, fixed_dir, logfile, check=False)
        return cp.returncode

    backport_artifacts(fixed_dir, target_dir, new_test_files, new_code_files)

    overlaid = [rel for rel in new_test_files if (target_dir / rel).exists()]
    if not overlaid:
        with open(logfile, "w", encoding="utf-8") as f:
            f.write("[!] Overlay failed: none of new_test_files were copied into target.\n")
        return 999

    # Run the overlaid tests from target_dir using target_dir's natural Python
    # path (cwd + venv site-packages). No extra PYTHONPATH: backported_support
    # is reference-only.
    cmd = f"python -m pytest {tail} {junit_arg} " + " ".join(overlaid)
    cp = run_in_venv(tools_root, cmd, target_dir, logfile, check=False)
    return cp.returncode


def copy_version_dir(src_dir: Path, dst_dir: Path):
    src_dir = src_dir.resolve()
    dst_dir = dst_dir.resolve()
    if dst_dir.exists():
        raise RuntimeError(f"Destination {dst_dir} already exists.")

    def _ignore(_dirpath, names):
        skip = {".venv", "__pycache__", ".pytest_cache", "backported_tests", "backported_support"}
        return [n for n in names if n in skip]

    shutil.copytree(src_dir, dst_dir, ignore=_ignore)
    ensure_dir(dst_dir / "backported_tests")
    ensure_dir(dst_dir / "backported_support")


def fork_from_ref(case_dir: Path, dst_name: str, repo_url: str, git_ref: str) -> Path:
    _require_cmd("git", hint="Install git (e.g., apt/yum/brew) before running vul4py fork.")
    case_dir = case_dir.resolve()
    dst_dir = case_dir / dst_name
    if dst_dir.exists():
        raise RuntimeError(f"{dst_dir} already exists.")

    subprocess.run(["git", "clone", repo_url, str(dst_dir)], cwd=str(case_dir), text=True, check=True)
    subprocess.run(["git", "-C", str(dst_dir), "checkout", git_ref], text=True, check=True)
    ensure_dir(dst_dir / "backported_tests")
    ensure_dir(dst_dir / "backported_support")
    return dst_dir


def apply_unidiff_patch(dst_dir: Path, patch_file: Path, logs_dir: Path):
    """
    Apply unified diff patch to dst_dir.
    Prefer `git apply` (more reliable), fallback to `patch`.
    """
    _require_cmd("git", hint="Install git to apply patches via `git apply`.")
    dst_dir = dst_dir.resolve()
    logs_dir = logs_dir.resolve()
    logfile = logs_dir / f"patch_{dst_dir.name}.log"
    ensure_dir(logfile.parent)

    patch_abs = str(Path(patch_file).resolve())

    # Try git apply first
    cp = subprocess.run(
        ["git", "apply", "--whitespace=nowarn", patch_abs],
        cwd=str(dst_dir),
        text=True,
        capture_output=True,
    )

    # Fallback to patch if git apply fails
    if cp.returncode != 0:
        patch_cmd = shutil.which("patch")
        if patch_cmd:
            cp2 = subprocess.run(
                [patch_cmd, "-p1", "-i", patch_abs],
                cwd=str(dst_dir),
                text=True,
                capture_output=True,
            )
            # keep the fallback result as final
            cp = cp2

    with open(logfile, "w", encoding="utf-8") as f:
        f.write(f"$ (git apply || patch) {patch_abs}\n")
        f.write(f"[exit {cp.returncode}]\n\n")
        f.write("STDOUT:\n")
        f.write(cp.stdout or "")
        f.write("\nSTDERR:\n")
        f.write(cp.stderr or "")
        f.write("\n")

    if cp.returncode != 0:
        raise RuntimeError(f"Failed to apply patch {patch_file} to {dst_dir}. See {logfile}")


# ---------- orchestration helpers ----------

def wipe_all_venvs(case_dir: Path):
    case_dir = case_dir.resolve()
    for sub in case_dir.iterdir():
        if not sub.is_dir():
            continue
        venv_path = sub / ".venv"
        if venv_path.exists() and venv_path.is_dir():
            shutil.rmtree(venv_path, ignore_errors=True)


def run_full_pipeline_for_cve(tools_root: Path, case_dir: Path) -> Tuple[int, int, int, int]:
    case_dir = case_dir.resolve()
    meta = load_meta(case_dir)
    logs_dir = case_dir / "logs"
    ensure_dir(logs_dir)

    vuln_dir = resolve_version_dir(case_dir, "vulnerable").resolve()
    fixed_dir = resolve_version_dir(case_dir, "fixed").resolve()

    create_and_install(tools_root, vuln_dir, meta, logs_dir)
    create_and_install(tools_root, fixed_dir, meta, logs_dir)

    func_vuln_rc = run_functional(tools_root, vuln_dir, meta, logs_dir)
    func_fixed_rc = run_functional(tools_root, fixed_dir, meta, logs_dir)

    exploit_vuln_rc = run_exploit_for_target(
        tools_root=tools_root,
        fixed_dir=fixed_dir,
        target_dir=vuln_dir,
        version_name="vulnerable",
        meta=meta,
        logs_dir=logs_dir,
    )
    exploit_fixed_rc = run_exploit_for_target(
        tools_root=tools_root,
        fixed_dir=fixed_dir,
        target_dir=fixed_dir,
        version_name="fixed",
        meta=meta,
        logs_dir=logs_dir,
    )

    return func_vuln_rc, func_fixed_rc, exploit_vuln_rc, exploit_fixed_rc


def _run_full_pipeline_for_cve_with_timeout(tools_root: Path, case_dir: Path, timeout_sec: int):
    class TimeoutExc(Exception):
        pass

    def _handler(signum, frame):
        raise TimeoutExc("TIMEOUT")

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(timeout_sec)

    try:
        a, b, c, d = run_full_pipeline_for_cve(tools_root, case_dir)
        err_msg = ""
    except TimeoutExc as te:
        a = b = c = d = -2
        err_msg = str(te)
    except Exception as e:
        a = b = c = d = -1
        err_msg = str(e)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    return a, b, c, d, err_msg


def _rc_is_timeout(rc: int) -> bool:
    return rc == -2


# --- rc-based verdicts (FALLBACK; used only when junit XML is unavailable) ---

def _functional_ok(rc: int) -> bool:
    return rc in (0, 999)


def _exploit_expected_vulnerable(rc: int) -> bool:
    if rc in (0, 999, -1, -2):
        return False
    return True


def _exploit_expected_fixed(rc: int) -> bool:
    return rc == 0


# --- junit-based verdicts (PRIMARY; structured pass/fail/error counts) ---

def _parse_junit(path: Path) -> Optional[Dict[str, Any]]:
    """
    Parse a pytest --junitxml file. Returns:
        {"tests","passed","failed","errored","skipped","failed_cases": [...]}
    or None if the file does not exist or is malformed (treated as
    "infrastructure-broken" by callers).
    """
    if not path.exists():
        return None
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return None
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    tests = failures = errors = skipped = 0
    failed_cases: List[Dict[str, str]] = []
    for s in suites:
        tests += int(s.get("tests", 0) or 0)
        failures += int(s.get("failures", 0) or 0)
        errors += int(s.get("errors", 0) or 0)
        skipped += int(s.get("skipped", 0) or 0)
        for c in s.findall("testcase"):
            if c.find("failure") is not None or c.find("error") is not None:
                failed_cases.append(
                    {
                        "classname": c.get("classname", "") or "",
                        "name": c.get("name", "") or "",
                        "file": c.get("file", "") or "",
                    }
                )
    return {
        "tests": tests,
        "passed": max(0, tests - failures - errors - skipped),
        "failed": failures,
        "errored": errors,
        "skipped": skipped,
        "failed_cases": failed_cases,
    }


def _functional_ok_struct(res: Optional[Dict[str, Any]]) -> Optional[bool]:
    if res is None:
        return None
    return res["failed"] == 0 and res["errored"] == 0


def _exploit_caught_vuln_struct(res: Optional[Dict[str, Any]], new_test_files: List[str]) -> Optional[bool]:
    """
    True iff at least one failed test case came from a file listed in
    new_test_files (matched by basename in c['file'] or by stem in c['classname']).
    """
    if res is None:
        return None
    if not res["failed_cases"]:
        return False
    new_files_norm = [p.replace("\\", "/") for p in new_test_files]
    new_stems = {os.path.basename(p).rsplit(".", 1)[0] for p in new_files_norm if p}
    for c in res["failed_cases"]:
        f = (c.get("file") or "").replace("\\", "/")
        if f and any(f.endswith(n) for n in new_files_norm):
            return True
        cls = c.get("classname") or ""
        if any(stem and stem in cls for stem in new_stems):
            return True
    return False


def _exploit_passes_fixed_struct(res: Optional[Dict[str, Any]]) -> Optional[bool]:
    if res is None:
        return None
    return res["failed"] == 0 and res["errored"] == 0 and res["passed"] >= 1


def _infra_broken(rc: int, res: Optional[Dict[str, Any]]) -> bool:
    """A run is 'infra broken' if pytest didn't produce a junit AND rc isn't a
    sentinel we already understand (0=clean pass, 999=no tests, -1=exception,
    -2=timeout). That covers collection errors, plugin failures, usage errors."""
    if res is not None:
        return False
    return rc not in (0, 999, -1, -2)


def _scan_one_cve(args_for_worker) -> Dict[str, object]:
    case_dir_str, timeout_sec, tools_root_str = args_for_worker
    tools_root = Path(tools_root_str).resolve()
    case_dir = Path(case_dir_str).resolve()
    cve_id = case_dir.name

    wipe_all_venvs(case_dir)
    # Revert any prior overlay before re-running. Safe even on a fresh tree.
    for sub in ("vulnerable", "fixed"):
        _restore_target(case_dir / sub)

    a, b, c, d, err_msg = _run_full_pipeline_for_cve_with_timeout(tools_root, case_dir, timeout_sec)

    logs_dir = case_dir / "logs"
    fv = _parse_junit(logs_dir / "functional_vulnerable.junit.xml")
    ff = _parse_junit(logs_dir / "functional_fixed.junit.xml")
    ev = _parse_junit(logs_dir / "exploit_vulnerable.junit.xml")
    ef = _parse_junit(logs_dir / "exploit_fixed.junit.xml")

    new_test_files: List[str] = []
    try:
        new_test_files = load_meta(case_dir).get("new_test_files", [])
    except Exception:
        pass

    # Per-run verdicts: prefer junit struct, fall back to rc.
    def _per_run(struct_v: Optional[bool], rc_v: bool) -> Tuple[bool, str]:
        if struct_v is None:
            return rc_v, "rc"
        return struct_v, "struct"

    fv_ok, fv_src = _per_run(_functional_ok_struct(fv), _functional_ok(a))
    ff_ok, ff_src = _per_run(_functional_ok_struct(ff), _functional_ok(b))
    ev_caught, ev_src = _per_run(_exploit_caught_vuln_struct(ev, new_test_files), _exploit_expected_vulnerable(c))
    ef_ok, ef_src = _per_run(_exploit_passes_fixed_struct(ef), _exploit_expected_fixed(d))

    infra = [
        _infra_broken(a, fv),
        _infra_broken(b, ff),
        _infra_broken(c, ev),
        _infra_broken(d, ef),
    ]

    if any(_rc_is_timeout(x) for x in (a, b, c, d)):
        status = "TIMEOUT"
    elif any(infra):
        status = "INFRA_BROKEN"
    elif fv_ok and ff_ok and ev_caught and ef_ok:
        status = "OK"
    elif fv_ok and ff_ok and (not ev_caught) and ef_ok:
        # Baseline clean on both sides; exploit cleanly passes on fixed; but the
        # exact same exploit test also passes on vulnerable (no failure tied to
        # a new_test_file). The upstream regression test does not differentiate
        # vulnerable from fixed -- meta is fine, fix is fine, but this CVE
        # needs a hand-written PoC to be a real oracle.
        status = "NON_ORACLE"
    else:
        status = "UNEXPECTED"

    verdict_src = "+".join([fv_src, ff_src, ev_src, ef_src])  # e.g. "struct+struct+rc+struct"

    def _pf(res: Optional[Dict[str, Any]]) -> str:
        if res is None:
            return "-"
        return f"{res['passed']}/{res['failed']}/{res['errored']}/{res['skipped']}"

    return {
        "cve_id": cve_id,
        "status": status,
        "verdict_src": verdict_src,
        "func_vuln_rc": a,
        "func_fixed_rc": b,
        "exploit_vuln_rc": c,
        "exploit_fixed_rc": d,
        "fv_pfes": _pf(fv),
        "ff_pfes": _pf(ff),
        "ev_pfes": _pf(ev),
        "ef_pfes": _pf(ef),
        "error": err_msg,
    }


# ---------- subcommands ----------

def subcmd_setup(args):
    if not args.cve_id:
        raise RuntimeError("--cve-id is required for setup")

    case_dir = (args.workspace_root / args.cve_id).resolve()
    meta = load_meta(case_dir)
    logs_dir = case_dir / "logs"
    ensure_dir(logs_dir)

    version_dir = resolve_version_dir(case_dir, args.target).resolve()

    print(f"[+] Setup {args.cve_id}::{args.target}")
    create_and_install(args.tools_root, version_dir, meta, logs_dir)
    print("[+] Setup done.")


def subcmd_functional(args):
    if not args.cve_id:
        raise RuntimeError("--cve-id is required for functional")

    case_dir = (args.workspace_root / args.cve_id).resolve()
    meta = load_meta(case_dir)
    logs_dir = case_dir / "logs"
    ensure_dir(logs_dir)

    version_dir = resolve_version_dir(case_dir, args.target).resolve()
    create_and_install(args.tools_root, version_dir, meta, logs_dir)

    print(f"[+] Functional {args.cve_id}::{args.target}")
    rc = run_functional(args.tools_root, version_dir, meta, logs_dir)
    print(f"  rc={rc}")


def subcmd_exploit(args):
    if not args.cve_id:
        raise RuntimeError("--cve-id is required for exploit")

    case_dir = (args.workspace_root / args.cve_id).resolve()
    meta = load_meta(case_dir)
    logs_dir = case_dir / "logs"
    ensure_dir(logs_dir)

    fixed_dir = resolve_version_dir(case_dir, "fixed").resolve()
    create_and_install(args.tools_root, fixed_dir, meta, logs_dir)

    print(f"[+] Exploit tests for {args.cve_id}")
    for tgt in args.targets:
        target_dir = resolve_version_dir(case_dir, tgt).resolve()
        create_and_install(args.tools_root, target_dir, meta, logs_dir)

        rc = run_exploit_for_target(
            tools_root=args.tools_root,
            fixed_dir=fixed_dir,
            target_dir=target_dir,
            version_name=tgt,
            meta=meta,
            logs_dir=logs_dir,
        )
        print(f"  {tgt}: rc={rc}")


def subcmd_fork(args):
    if not args.cve_id:
        raise RuntimeError("--cve-id is required for fork")

    case_dir = (args.workspace_root / args.cve_id).resolve()
    meta = load_meta(case_dir)
    logs_dir = case_dir / "logs"
    ensure_dir(logs_dir)

    if args.src and args.ref:
        raise RuntimeError("Provide either --src OR --ref, not both.")
    if not args.src and not args.ref:
        raise RuntimeError("Must provide --src <ver> OR --ref <git_ref>.")

    dst_dir = (case_dir / args.dst).resolve()
    if dst_dir.exists():
        raise RuntimeError(f"{dst_dir} already exists.")

    if args.src:
        src_dir = resolve_version_dir(case_dir, args.src).resolve()
        print(f"[+] Fork {args.cve_id}: copy {args.src} -> {args.dst}")
        copy_version_dir(src_dir, dst_dir)

        if args.patch:
            patch_path = Path(args.patch).resolve()
            print(f"[+] Applying patch {patch_path} to {args.dst}")
            apply_unidiff_patch(dst_dir, patch_path, logs_dir)

        print("[+] Fork (copy) done.")
    else:
        print(f"[+] Fork {args.cve_id}: clone {meta['repo_url']} @ {args.ref} -> {args.dst}")
        fork_from_ref(case_dir, args.dst, meta["repo_url"], args.ref)
        print("[+] Fork (ref) done.")


def subcmd_all(args):
    if not args.cve_id:
        raise RuntimeError("--cve-id is required for all")

    case_dir = (args.workspace_root / args.cve_id).resolve()
    print(f"[+] ALL pipeline for {args.cve_id}")
    a, b, c, d = run_full_pipeline_for_cve(args.tools_root, case_dir)

    print(f"  vulnerable functional rc={a}")
    print(f"  fixed      functional rc={b}")
    print(f"  vulnerable exploit    rc={c}")
    print(f"  fixed      exploit    rc={d}")
    print("[+] ALL done.")


def subcmd_scan(args):
    ws_root = args.workspace_root.resolve()

    jobs = args.jobs if args.jobs is not None else max(cpu_count() - 1, 1)
    timeout_sec = 1800  # 30 min per CVE

    print(f"[+] Scanning all CVEs under {ws_root} with {jobs} workers (timeout {timeout_sec}s/CVE)")
    print(f"[+] Tools root: {args.tools_root}")

    cve_dirs = []
    for item in sorted(ws_root.iterdir()):
        if item.is_dir() and (item / "meta.json").exists():
            cve_dirs.append(str(item.resolve()))

    results = []
    # Ensure tools root exists early
    ensure_dir(args.tools_root)

    # Prewarm: serially provision every Python version + the compiler env BEFORE
    # spawning workers. Without this, multiple workers race on the same
    # conda/micromamba env directory; on this host the file lock occasionally
    # fails and a worker raises mid-create, returning rc=-1 for that CVE.
    py_versions = set()
    for c in cve_dirs:
        try:
            v = str(load_meta(Path(c)).get("python_version", "")).strip()
            if v:
                py_versions.add(v)
        except Exception:
            pass
    print(f"[+] Prewarming compiler env + python interpreters: {sorted(py_versions)}")
    ensure_compiler_paths(args.tools_root)
    for v in sorted(py_versions):
        ensure_python_interpreter(args.tools_root, v)

    # Workers need to see the same tools root; pass as string
    worker_args = [(c, timeout_sec, str(args.tools_root)) for c in cve_dirs]

    with Pool(processes=jobs) as pool:
        async_results = [pool.apply_async(_scan_one_cve, (wa,)) for wa in worker_args]
        pool.close()

        for ar in tqdm(async_results, total=len(async_results), desc="Scanning CVEs"):
            results.append(ar.get())

        pool.join()

    out_path = ws_root / "scan_report.tsv"
    cols = [
        "cve_id", "status", "verdict_src",
        "func_vuln_rc", "func_fixed_rc", "exploit_vuln_rc", "exploit_fixed_rc",
        "fv_pfes", "ff_pfes", "ev_pfes", "ef_pfes",
    ]
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\t".join(cols) + "\n")
        for r in results:
            f.write("\t".join(str(r.get(c, "")) for c in cols) + "\n")

    print(f"[+] Scan complete. Report written to {out_path}")
    print("    pfes columns are passed/failed/errored/skipped per run; '-' means junit was not produced (rc-based fallback in effect).")


# ---------- main ----------

def main():
    _require_cmd("git", hint="Install git first; vul4py needs it for cloning and patching.")

    parser = argparse.ArgumentParser(
        description="vul4py: reproduce, build, test, exploit-check, batch scan Python CVE workspaces (portable)"
    )

    parser.add_argument(
        "--workspace-root",
        default="workspace",
        type=Path,
        help="Root created by prepare_vul4py.py (default: workspace)",
    )
    parser.add_argument(
        "--tools-root",
        type=Path,
        default=None,
        help="Where vul4py stores provisioned interpreters/toolchains (default: <workspace-root>/.vul4py_tools)",
    )
    parser.add_argument(
        "--cve-id",
        help="CVE folder name, e.g. CVE-2022-21797 (required for most commands except scan)",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_setup = sub.add_parser("setup", help="create/refresh venv & install deps for one version in one CVE")
    p_setup.add_argument("--target", required=True, help="version dir (vulnerable, fixed, candidate_llm, ...)")
    p_setup.set_defaults(func=subcmd_setup)

    p_func = sub.add_parser("functional", help="run baseline (pre-fix) tests for a version in one CVE")
    p_func.add_argument("--target", required=True, help="version dir to test")
    p_func.set_defaults(func=subcmd_functional)

    p_expl = sub.add_parser("exploit", help="run regression/security tests for version(s) in one CVE")
    p_expl.add_argument("--targets", nargs="+", required=True, help="version dirs (e.g. vulnerable fixed candidate_llm)")
    p_expl.set_defaults(func=subcmd_exploit)

    p_fork = sub.add_parser("fork", help="create new version dir; optional --patch unified diff")
    p_fork.add_argument("--dst", required=True, help="new version dir name (e.g. candidate_llm)")
    p_fork.add_argument("--src", help="existing version dir to copy (e.g. vulnerable)")
    p_fork.add_argument("--ref", help="git ref/commit for fresh clone (mutually exclusive with --src)")
    p_fork.add_argument("--patch", help="unified diff file to apply (only valid with --src)")
    p_fork.set_defaults(func=subcmd_fork)

    p_all = sub.add_parser("all", help="full pipeline for one CVE: setup+functional+exploit on vuln+fixed")
    p_all.set_defaults(func=subcmd_all)

    p_scan = sub.add_parser("scan", help="run all CVEs in parallel and summarize timeout/unexpected")
    p_scan.add_argument("--jobs", type=int, help="number of parallel workers (default: cpu_count()-1)")
    p_scan.set_defaults(func=subcmd_scan)

    args = parser.parse_args()

    # Resolve tools root now that we know workspace root
    if args.tools_root is None:
        args.tools_root = get_tools_root(args.workspace_root)
    else:
        args.tools_root = args.tools_root.expanduser().resolve()

    # Export so child processes inherit same location
    os.environ["VUL4PY_TOOLS_ROOT"] = str(args.tools_root)

    args.func(args)


if __name__ == "__main__":
    main()
