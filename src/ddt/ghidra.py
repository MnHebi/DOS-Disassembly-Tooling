"""Read-only export of one analyzed function from an existing Ghidra project.

This module only builds and runs an analyzeHeadless command line. It never
imports Ghidra, opens the project itself, or modifies the saved analysis: the
-process/-readOnly/-noanalysis invocation hands a bundled GhidraScript to
Ghidra, which writes a small versioned JSON record.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .errors import DDTError

SCHEMA = "ddt.ghidra-function.v1"
DEFAULT_TIMEOUT = 600
# Ghidra ships both an extensionless script and a .bat wrapper; prefer the one
# native to the host and fall back to the other if only one is present.
_LAUNCHERS = ("analyzeHeadless.bat", "analyzeHeadless") if os.name == "nt" \
    else ("analyzeHeadless", "analyzeHeadless.bat")


def bundled_script_dir() -> Path:
    return Path(__file__).resolve().parent / "ghidra_scripts"


def locate_headless(ghidra: str | Path | None = None) -> Path:
    """Return the analyzeHeadless launcher for a Ghidra install, or raise.

    ``ghidra`` may be the Ghidra install directory or the launcher itself. When
    omitted, the ``GHIDRA_HOME`` (or legacy ``GHIDRA_INSTALL_DIR``) environment
    variable is used. Nothing is added to PATH and no shell configuration is
    read or written.
    """
    roots: list[Path] = []
    if ghidra is not None:
        roots.append(Path(ghidra))
    else:
        for key in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR"):
            value = os.environ.get(key)
            if value:
                roots.append(Path(value))
    for root in roots:
        launcher = _headless_in(root)
        if launcher is not None:
            return launcher
    raise DDTError("Ghidra analyzeHeadless not found; pass --ghidra <dir> or set GHIDRA_HOME")


def _headless_in(root: Path) -> Path | None:
    if root.is_file():
        return root if root.name.lower().startswith("analyzeheadless") else None
    for name in _LAUNCHERS:
        candidate = root / "support" / name
        if candidate.is_file():
            return candidate
    return None


def resolve_project(project: str | Path) -> tuple[Path, str]:
    """Resolve a project location and name from a ``.gpr`` file or its directory."""
    path = Path(project)
    if path.is_file() and path.suffix.lower() == ".gpr":
        return path.parent, path.stem
    if path.is_dir():
        projects = sorted(path.glob("*.gpr"))
        if len(projects) == 1:
            return path, projects[0].stem
        if not projects:
            raise DDTError(f"no Ghidra project (*.gpr) found in {path}")
        raise DDTError(f"multiple Ghidra projects in {path}; pass the .gpr file explicitly")
    raise DDTError(f"not a Ghidra project file or directory: {path}")


def build_command(headless: Path, location: Path, name: str, program: str,
                  address: str, out_path: Path, script_dir: Path) -> list[str]:
    """Build the read-only analyzeHeadless argument list for one function export."""
    launcher = ["cmd", "/c", str(headless)] if headless.suffix.lower() == ".bat" else [str(headless)]
    return [*launcher, str(location), name, "-process", program,
            "-readOnly", "-noanalysis",
            "-scriptPath", str(script_dir),
            "-postScript", "ExportFunction.java", address, str(out_path)]


def export_function(project: str | Path, program: str, address: str, out_path: str | Path, *,
                    ghidra: str | Path | None = None, java_home: str | Path | None = None,
                    script_dir: str | Path | None = None,
                    timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Export one analyzed function, returning the validated JSON record."""
    if not program:
        raise DDTError("program name must be provided")
    headless = locate_headless(ghidra)
    location, name = resolve_project(project)
    scripts = Path(script_dir) if script_dir is not None else bundled_script_dir()
    destination = Path(out_path)
    if destination.is_dir():
        raise DDTError(f"--out must be a file path, not a directory: {destination}")
    try:
        staging = Path(tempfile.mkdtemp(prefix=destination.name + ".", dir=destination.parent))
    except OSError as exc:
        raise DDTError(f"cannot stage an export next to {destination}: {exc}") from exc
    # Write to a private staging path so a failed run can never be mistaken for a
    # stale-but-valid file already sitting at the destination.
    staged = staging / "export.json"
    command = build_command(headless, location, name, program, address, staged, scripts)
    env = dict(os.environ)
    if java_home is not None:
        env["JAVA_HOME"] = str(java_home)
    try:
        try:
            proc = subprocess.run(command, capture_output=True, text=True, env=env, timeout=timeout)
        except FileNotFoundError as exc:
            raise DDTError(f"could not run Ghidra launcher {headless}: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise DDTError(f"Ghidra export exceeded {timeout}s") from exc
        if proc.returncode != 0:
            raise DDTError(
                f"Ghidra export failed with exit status {proc.returncode}; " + _output_tail(proc))
        if not staged.is_file():
            raise DDTError("Ghidra export produced no output file; " + _output_tail(proc))
        try:
            record = json.loads(staged.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DDTError(f"unreadable Ghidra export output: {exc}") from exc
        if "error" in record:
            raise DDTError(f"Ghidra export failed: {record['error']}")
        if record.get("schema") != SCHEMA:
            raise DDTError(f"unexpected Ghidra export schema: {record.get('schema')!r}")
        os.replace(staged, destination)
        return record
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _output_tail(proc: subprocess.CompletedProcess) -> str:
    text = (proc.stdout or "") + (proc.stderr or "")
    lines = [line for line in text.splitlines() if line.strip()]
    return "Ghidra output tail:\n" + "\n".join(lines[-20:])
