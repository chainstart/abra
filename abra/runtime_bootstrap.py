"""Repo-local Python runtime bootstrap for ABRA entrypoints."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ABRA_RUNTIME_BOOTSTRAPPED_ENV = "ABRA_RUNTIME_BOOTSTRAPPED"
ABRA_DISABLE_RUNTIME_BOOTSTRAP_ENV = "ABRA_DISABLE_RUNTIME_BOOTSTRAP"
DEFAULT_REQUIREMENTS_RELPATH = "tools/requirements.txt"
DEFAULT_VENV_RELPATH = ".venv"


def current_missing_modules(module_names: Iterable[str]) -> list[str]:
    """Return required module names missing from the current interpreter."""

    importlib.invalidate_caches()
    missing: list[str] = []
    for module_name in module_names:
        name = str(module_name).strip()
        if not name:
            continue
        if importlib.util.find_spec(name) is None:
            missing.append(name)
    return missing


def runtime_has_modules(python_bin: Path, module_names: Iterable[str]) -> bool:
    """Check whether a Python executable can import all required modules."""

    modules = [str(name).strip() for name in module_names if str(name).strip()]
    if not modules:
        return True
    probe = (
        "import importlib.util, sys; "
        f"mods={modules!r}; "
        "missing=[m for m in mods if importlib.util.find_spec(m) is None]; "
        "raise SystemExit(0 if not missing else 1)"
    )
    result = subprocess.run(
        [str(python_bin), "-c", probe],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def create_local_venv(repo_root: Path, venv_dir: Path) -> None:
    """Create a repo-local virtualenv."""

    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        cwd=str(repo_root),
    )


def install_requirements(python_bin: Path, requirements_path: Path, repo_root: Path) -> None:
    """Install ABRA tool requirements into the target runtime."""

    subprocess.run(
        [str(python_bin), "-m", "pip", "install", "--quiet", "-r", str(requirements_path)],
        check=True,
        cwd=str(repo_root),
    )


def reexec_into_python(python_bin: Path) -> None:
    """Replace the current process with the repo-local runtime."""

    env = dict(os.environ)
    env[ABRA_RUNTIME_BOOTSTRAPPED_ENV] = "1"
    os.execvpe(str(python_bin), [str(python_bin), *sys.argv], env)


def repo_venv_python(repo_root: Path, venv_relpath: str = DEFAULT_VENV_RELPATH) -> Path:
    """Return the repo-local virtualenv Python path."""

    if os.name == "nt":
        return repo_root / venv_relpath / "Scripts" / "python.exe"
    return repo_root / venv_relpath / "bin" / "python"


def same_python(left: str | Path, right: str | Path) -> bool:
    """Return whether two Python executables resolve to the same path."""

    return Path(left).expanduser().absolute() == Path(right).expanduser().absolute()


def ensure_repo_runtime(
    repo_root: Path,
    *,
    required_modules: Iterable[str],
    requirements_relpath: str = DEFAULT_REQUIREMENTS_RELPATH,
    venv_relpath: str = DEFAULT_VENV_RELPATH,
) -> None:
    """Ensure ABRA entrypoints run inside a repo-local runtime with required modules."""

    if os.environ.get(ABRA_DISABLE_RUNTIME_BOOTSTRAP_ENV):
        return

    missing_now = current_missing_modules(required_modules)
    if not missing_now:
        return

    requirements_path = repo_root / requirements_relpath
    if not requirements_path.exists():
        raise FileNotFoundError(f"ABRA runtime requirements file not found: {requirements_path}")

    venv_dir = repo_root / venv_relpath
    python_bin = repo_venv_python(repo_root, venv_relpath=venv_relpath)
    if not python_bin.exists():
        create_local_venv(repo_root, venv_dir)

    if not runtime_has_modules(python_bin, required_modules):
        install_requirements(python_bin, requirements_path, repo_root)

    if same_python(sys.executable, python_bin):
        remaining = current_missing_modules(required_modules)
        if remaining:
            raise RuntimeError(
                "ABRA runtime bootstrap did not make required modules available in the repo-local runtime: "
                + ", ".join(sorted(remaining))
            )
        return

    if os.environ.get(ABRA_RUNTIME_BOOTSTRAPPED_ENV):
        raise RuntimeError(
            "ABRA runtime bootstrap loop detected while required modules are still missing: "
            + ", ".join(sorted(missing_now))
        )
    reexec_into_python(python_bin)
