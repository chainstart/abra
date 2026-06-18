from __future__ import annotations

import sys
from pathlib import Path

import pytest

from abra import runtime_bootstrap


def test_ensure_repo_runtime_returns_immediately_when_modules_exist(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_bootstrap, "current_missing_modules", lambda modules: [])
    monkeypatch.setattr(runtime_bootstrap, "create_local_venv", lambda repo_root, venv_dir: pytest.fail("no venv"))
    monkeypatch.setattr(
        runtime_bootstrap,
        "install_requirements",
        lambda python_bin, requirements_path, repo_root: pytest.fail("no install"),
    )
    monkeypatch.setattr(runtime_bootstrap, "reexec_into_python", lambda python_bin: pytest.fail("no reexec"))

    runtime_bootstrap.ensure_repo_runtime(tmp_path, required_modules=("requests", "bs4"))


def test_ensure_repo_runtime_bootstraps_repo_venv_and_reexecs_when_modules_missing(tmp_path, monkeypatch):
    requirements = tmp_path / "tools" / "requirements.txt"
    requirements.parent.mkdir(parents=True, exist_ok=True)
    requirements.write_text("requests\nbeautifulsoup4\n", encoding="utf-8")

    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(runtime_bootstrap, "current_missing_modules", lambda modules: ["bs4"])
    monkeypatch.setattr(runtime_bootstrap, "runtime_has_modules", lambda python_bin, modules: False)

    def fake_create_local_venv(repo_root: Path, venv_dir: Path) -> None:
        calls.append(("create", str(venv_dir)))
        python_bin = runtime_bootstrap.repo_venv_python(repo_root)
        python_bin.parent.mkdir(parents=True, exist_ok=True)
        python_bin.write_text("", encoding="utf-8")

    def fake_install_requirements(python_bin: Path, requirements_path: Path, repo_root: Path) -> None:
        calls.append(("install", f"{python_bin}|{requirements_path}"))

    def fake_reexec(python_bin: Path) -> None:
        calls.append(("reexec", str(python_bin)))
        raise RuntimeError("reexec")

    monkeypatch.setattr(runtime_bootstrap, "create_local_venv", fake_create_local_venv)
    monkeypatch.setattr(runtime_bootstrap, "install_requirements", fake_install_requirements)
    monkeypatch.setattr(runtime_bootstrap, "same_python", lambda left, right: False)
    monkeypatch.setattr(runtime_bootstrap, "reexec_into_python", fake_reexec)

    with pytest.raises(RuntimeError, match="reexec"):
        runtime_bootstrap.ensure_repo_runtime(tmp_path, required_modules=("requests", "bs4"))

    venv_python = runtime_bootstrap.repo_venv_python(tmp_path)
    assert calls == [
        ("create", str(tmp_path / ".venv")),
        ("install", f"{venv_python}|{requirements}"),
        ("reexec", str(venv_python)),
    ]


def test_ensure_repo_runtime_installs_into_current_repo_venv_without_reexec(tmp_path, monkeypatch):
    requirements = tmp_path / "tools" / "requirements.txt"
    requirements.parent.mkdir(parents=True, exist_ok=True)
    requirements.write_text("pyyaml\n", encoding="utf-8")
    venv_python = runtime_bootstrap.repo_venv_python(tmp_path)
    venv_python.parent.mkdir(parents=True, exist_ok=True)
    venv_python.write_text("", encoding="utf-8")

    seen_installs: list[tuple[str, str]] = []
    missing_states = [["yaml"], []]

    monkeypatch.setattr(runtime_bootstrap, "current_missing_modules", lambda modules: missing_states.pop(0))
    monkeypatch.setattr(runtime_bootstrap, "runtime_has_modules", lambda python_bin, modules: False)
    monkeypatch.setattr(runtime_bootstrap, "same_python", lambda left, right: True)
    monkeypatch.setattr(
        runtime_bootstrap,
        "install_requirements",
        lambda python_bin, requirements_path, repo_root: seen_installs.append(
            (str(python_bin), str(requirements_path))
        ),
    )
    monkeypatch.setattr(runtime_bootstrap, "reexec_into_python", lambda python_bin: pytest.fail("no reexec"))
    monkeypatch.setattr(runtime_bootstrap, "create_local_venv", lambda repo_root, venv_dir: pytest.fail("no create"))
    monkeypatch.setattr(sys, "executable", str(venv_python))

    runtime_bootstrap.ensure_repo_runtime(tmp_path, required_modules=("yaml",))

    assert seen_installs == [(str(venv_python), str(requirements))]


def test_same_python_distinguishes_repo_venv_symlink_from_system_python(tmp_path):
    system_python = tmp_path / "python3.12"
    system_python.write_text("", encoding="utf-8")
    venv_python = tmp_path / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True, exist_ok=True)
    venv_python.symlink_to(system_python)

    assert runtime_bootstrap.same_python(system_python, venv_python) is False
    assert runtime_bootstrap.same_python(venv_python, venv_python) is True
