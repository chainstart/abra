"""ABRA research lab manifest loading and validation."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


LAB_MANIFEST_SCHEMA_VERSION = "abra.research_lab_manifest.v1"
REQUIRED_EVIDENCE_LEVELS = ("L0", "L1", "L2", "L3", "L4", "L5", "L6")


@dataclass(frozen=True)
class ManifestValidation:
    """Validation result for ``research_lab.yaml``."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class ResearchLabManifest:
    """Normalized ABRA view of the ARA lab manifest contract."""

    path: Path
    raw: dict[str, Any]
    validation: ManifestValidation

    @property
    def lab_id(self) -> str:
        return str(self.raw.get("lab_id") or "")

    @property
    def system_name(self) -> str:
        return str(self.raw.get("system_name") or "")

    @property
    def full_name(self) -> str:
        return str(self.raw.get("full_name") or "")

    @property
    def domain(self) -> str:
        return str(self.raw.get("domain") or "")

    @property
    def legacy(self) -> dict[str, list[str]]:
        legacy = _mapping(self.raw.get("legacy"))
        return {
            "lab_ids": _string_list(legacy.get("lab_ids")),
            "repo_names": _string_list(legacy.get("repo_names")),
        }

    @property
    def entrypoints(self) -> dict[str, list[str]]:
        entrypoints = _mapping(self.raw.get("entrypoints"))
        return {
            "agent_cli": _string_list(entrypoints.get("agent_cli")),
            "direct_tools": _string_list(entrypoints.get("direct_tools")),
        }

    @property
    def command_policy(self) -> dict[str, list[str]]:
        commands = _mapping(self.raw.get("commands"))
        return {
            "allow_prefixes": _string_list(commands.get("allow_prefixes")),
            "deny_patterns": _string_list(commands.get("deny_patterns")),
        }

    @property
    def dispatch_commands(self) -> dict[str, Any]:
        dispatch = _mapping(self.raw.get("dispatch"))
        commands = dispatch.get("commands", {})
        return dict(commands) if isinstance(commands, dict) else {}

    @property
    def environment(self) -> dict[str, list[str]]:
        environment = _mapping(self.raw.get("environment"))
        return {
            "required": _string_list(environment.get("required")),
            "optional": _string_list(environment.get("optional")),
        }

    @property
    def artifact_globs(self) -> dict[str, list[str]]:
        artifacts = _mapping(self.raw.get("artifacts"))
        return {
            "include": _string_list(artifacts.get("include")),
            "exclude": _string_list(artifacts.get("exclude")),
        }

    @property
    def produced_bundles(self) -> list[str]:
        bundles = _mapping(self.raw.get("bundles"))
        return _string_list(bundles.get("produced"))

    @property
    def evidence_levels(self) -> dict[str, str]:
        evidence = self.raw.get("evidence_levels", {})
        if not isinstance(evidence, dict):
            return {}
        return {str(key): str(value) for key, value in evidence.items()}

    @property
    def safety(self) -> dict[str, Any]:
        safety = self.raw.get("safety", {})
        return dict(safety) if isinstance(safety, dict) else {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": LAB_MANIFEST_SCHEMA_VERSION,
            "lab_id": self.lab_id,
            "system_name": self.system_name,
            "full_name": self.full_name,
            "domain": self.domain,
            "path": str(self.path),
            "legacy": self.legacy,
            "entrypoints": self.entrypoints,
            "commands": self.command_policy,
            "dispatch_commands": self.dispatch_commands,
            "environment": self.environment,
            "artifact_globs": self.artifact_globs,
            "produced_bundles": self.produced_bundles,
            "bundle_types": self.produced_bundles,
            "evidence_levels": self.evidence_levels,
            "safety": self.safety,
            "valid": self.validation.valid,
            "errors": list(self.validation.errors),
            "warnings": list(self.validation.warnings),
        }


def repo_root() -> Path:
    """Return the blockchain-security repository root."""

    return Path(__file__).resolve().parents[1]


def default_manifest_path() -> Path:
    """Return the default ABRA lab manifest path."""

    return repo_root() / "research_lab.yaml"


def load_manifest(path: str | Path | None = None) -> ResearchLabManifest:
    """Load and validate an ABRA ``research_lab.yaml`` manifest."""

    manifest_path = Path(path).expanduser().resolve() if path else default_manifest_path()
    if not manifest_path.exists():
        raise FileNotFoundError(f"Lab manifest not found: {manifest_path}")
    raw_obj = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    raw = raw_obj if isinstance(raw_obj, dict) else {}
    validation = validate_manifest(raw)
    if not isinstance(raw_obj, dict):
        validation = ManifestValidation(
            valid=False,
            errors=["Manifest root must be a mapping."],
            warnings=validation.warnings,
        )
    return ResearchLabManifest(path=manifest_path, raw=raw, validation=validation)


def validate_manifest(raw: dict[str, Any]) -> ManifestValidation:
    """Validate the schema-light ARA lab contract used by ABRA."""

    errors: list[str] = []
    warnings: list[str] = []

    for key in ("lab_id", "system_name", "full_name", "domain"):
        if not _non_empty_string(raw.get(key)):
            errors.append(f"`{key}` is required and must be a non-empty string.")

    if raw.get("lab_id") != "abra":
        errors.append("`lab_id` must be `abra` for the ABRA domain lab.")
    if raw.get("system_name") != "ABRA":
        errors.append("`system_name` must be `ABRA`.")
    if raw.get("domain") != "blockchain_security":
        errors.append("`domain` must be `blockchain_security`.")

    legacy = _typed_mapping(raw.get("legacy"), "legacy", errors)
    _validate_string_list(legacy.get("lab_ids"), "legacy.lab_ids", errors)
    _validate_string_list(legacy.get("repo_names"), "legacy.repo_names", errors)
    if "blockchain-security" not in _string_list(legacy.get("repo_names")):
        errors.append("`legacy.repo_names` must include `blockchain-security`.")

    entrypoints = _typed_mapping(raw.get("entrypoints"), "entrypoints", errors)
    agent_cli = _validate_string_list(entrypoints.get("agent_cli"), "entrypoints.agent_cli", errors)
    _validate_string_list(entrypoints.get("direct_tools"), "entrypoints.direct_tools", errors)
    if "python3 -m abra" not in agent_cli:
        errors.append("`entrypoints.agent_cli` must include `python3 -m abra`.")

    commands = _typed_mapping(raw.get("commands"), "commands", errors)
    allow_prefixes = _validate_string_list(commands.get("allow_prefixes"), "commands.allow_prefixes", errors)
    deny_patterns = _validate_string_list(commands.get("deny_patterns"), "commands.deny_patterns", errors)
    if "python3 -m abra" not in allow_prefixes:
        errors.append("`commands.allow_prefixes` must include `python3 -m abra`.")
    for denied in ("rm -rf", "cast send", "--broadcast", "PRIVATE_KEY"):
        if denied not in deny_patterns:
            errors.append(f"`commands.deny_patterns` must include `{denied}`.")

    environment = _typed_mapping(raw.get("environment"), "environment", errors)
    required_env = _validate_string_list(environment.get("required"), "environment.required", errors)
    _validate_string_list(environment.get("optional"), "environment.optional", errors)
    if any("PRIVATE_KEY" in item for item in required_env):
        errors.append("Private keys must not be required by the ABRA lab manifest.")

    artifacts = _typed_mapping(raw.get("artifacts"), "artifacts", errors)
    include_globs = _validate_string_list(artifacts.get("include"), "artifacts.include", errors)
    _validate_string_list(artifacts.get("exclude"), "artifacts.exclude", errors)
    for required_glob in ("reports/*.md", "reports/events/*.md", "findings/*.md"):
        if required_glob not in include_globs:
            errors.append(f"`artifacts.include` must preserve `{required_glob}`.")

    bundles = _typed_mapping(raw.get("bundles"), "bundles", errors)
    produced = _validate_string_list(bundles.get("produced"), "bundles.produced", errors)
    if "abra_result_bundle" not in produced:
        errors.append("`bundles.produced` must include `abra_result_bundle`.")

    evidence_levels = raw.get("evidence_levels", {})
    if not isinstance(evidence_levels, dict):
        errors.append("`evidence_levels` must be a mapping.")
    else:
        for level in REQUIRED_EVIDENCE_LEVELS:
            if not _non_empty_string(evidence_levels.get(level)):
                errors.append(f"`evidence_levels.{level}` is required and must be a non-empty string.")

    safety = _typed_mapping(raw.get("safety"), "safety", errors)
    if safety.get("destructive_commands") is not False:
        errors.append("`safety.destructive_commands` must be false.")
    if "max_wall_time_minutes" in safety and not isinstance(safety["max_wall_time_minutes"], int):
        errors.append("`safety.max_wall_time_minutes` must be an integer.")
    if "network_policy" in safety and not _non_empty_string(safety.get("network_policy")):
        errors.append("`safety.network_policy` must be a non-empty string.")

    dispatch = raw.get("dispatch")
    if dispatch is not None:
        dispatch_map = _typed_mapping(dispatch, "dispatch", errors)
        dispatch_commands = dispatch_map.get("commands", {})
        if not isinstance(dispatch_commands, dict):
            errors.append("`dispatch.commands` must be a mapping when present.")
        else:
            _validate_dispatch_commands(dispatch_commands, allow_prefixes, deny_patterns, errors)
    else:
        warnings.append("`dispatch.commands` is not declared; ARA will fall back to CLI help smoke.")

    return ManifestValidation(valid=not errors, errors=errors, warnings=warnings)


def _validate_dispatch_commands(
    commands: dict[str, Any],
    allow_prefixes: list[str],
    deny_patterns: list[str],
    errors: list[str],
) -> None:
    for name, value in commands.items():
        argv = _coerce_argv(value)
        if not argv:
            errors.append(f"`dispatch.commands.{name}` must define a non-empty argv or command.")
            continue
        command_text = shlex.join(argv)
        if any(pattern and pattern in command_text for pattern in deny_patterns):
            errors.append(f"`dispatch.commands.{name}` matches a denied command pattern.")
        if allow_prefixes and not any(_matches_prefix(argv, prefix) for prefix in allow_prefixes):
            errors.append(f"`dispatch.commands.{name}` is not covered by commands.allow_prefixes.")
        if name in {"smoke", "tools-list", "manifest-inspect"} and not _side_effect_free(value):
            errors.append(f"`dispatch.commands.{name}` must be marked side_effect_free: true.")


def _coerce_argv(value: Any) -> list[str]:
    if isinstance(value, str):
        return shlex.split(value)
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, dict):
        if isinstance(value.get("argv"), list):
            return [str(item) for item in value["argv"] if str(item).strip()]
        for key in ("command", "run", "exec"):
            if isinstance(value.get(key), str):
                return shlex.split(value[key])
    return []


def _side_effect_free(value: Any) -> bool:
    if isinstance(value, dict):
        return value.get("side_effect_free") is True
    return False


def _matches_prefix(argv: list[str], prefix: str) -> bool:
    prefix_argv = shlex.split(prefix)
    return bool(prefix_argv and argv[: len(prefix_argv)] == prefix_argv)


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _typed_mapping(value: Any, field_name: str, errors: list[str]) -> dict[str, Any]:
    if value is None:
        errors.append(f"`{field_name}` is required and must be a mapping.")
        return {}
    if not isinstance(value, dict):
        errors.append(f"`{field_name}` must be a mapping.")
        return {}
    return value


def _validate_string_list(value: Any, field_name: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"`{field_name}` is required and must be a list.")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not _non_empty_string(item):
            errors.append(f"`{field_name}[{index}]` must be a non-empty string.")
            continue
        result.append(str(item).strip())
    return result


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
