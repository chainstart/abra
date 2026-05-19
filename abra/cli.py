"""Command-line interface for the ABRA domain lab."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from abra import __version__
from abra.agent import run_research_agent
from abra.bundle import build_result_bundle, validate_result_bundle
from abra.manifest import load_manifest
from abra.replay_agent import assess_replay_fixture, validate_evidence_bundle
from abra.smoke import build_smoke_report
from abra.tools import list_tools


INSPECT_SCHEMA_VERSION = "abra.lab_manifest.inspect.v1"
TOOLS_SCHEMA_VERSION = "abra.tool_inventory.v1"


def main(argv: list[str] | None = None) -> int:
    """Run the ABRA CLI."""

    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    try:
        if args.command == "labs":
            return _handle_labs(args)
        if args.command == "tools":
            return _handle_tools(args)
        if args.command == "bundle":
            return _handle_bundle(args)
        if args.command == "replay":
            return _handle_replay(args)
        if args.command == "evidence":
            return _handle_evidence(args)
        if args.command == "agent":
            return _handle_agent(args)
    except ValueError as exc:
        payload = {"status": "failed", "error": str(exc)}
        _emit(payload, getattr(args, "json", False))
        return 2
    except FileNotFoundError as exc:
        payload = {"status": "failed", "error": str(exc)}
        _emit(payload, getattr(args, "json", False))
        return 2

    parser.error(f"Unsupported command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="abra",
        description="ABRA: Automated Blockchain Research Agents domain lab CLI.",
    )
    parser.add_argument("--version", action="version", version=f"abra {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    labs = subparsers.add_parser("labs", help="Inspect the ABRA lab manifest and smoke status.")
    labs_sub = labs.add_subparsers(dest="labs_command", required=True)

    labs_inspect = labs_sub.add_parser("inspect", help="Inspect research_lab.yaml.")
    labs_inspect.add_argument("--manifest", help="Path to research_lab.yaml. Defaults to repository root.")
    labs_inspect.add_argument("--json", action="store_true", help="Print JSON output.")

    labs_smoke = labs_sub.add_parser("smoke", help="Run side-effect-free ABRA smoke checks.")
    labs_smoke.add_argument("--manifest", help="Path to research_lab.yaml. Defaults to repository root.")
    labs_smoke.add_argument("--json", action="store_true", help="Print JSON output.")

    tools = subparsers.add_parser("tools", help="Inspect ABRA tool inventory.")
    tools_sub = tools.add_subparsers(dest="tools_command", required=True)

    tools_list = tools_sub.add_parser("list", help="List ABRA tools.")
    tools_list.add_argument("--json", action="store_true", help="Print JSON output.")

    bundle = subparsers.add_parser("bundle", help="Build and validate ABRA result bundles.")
    bundle_sub = bundle.add_subparsers(dest="bundle_command", required=True)

    bundle_build = bundle_sub.add_parser("build", help="Build an abra_result_bundle from reports and artifacts.")
    bundle_build.add_argument("--source", required=True, help="Source reports directory.")
    bundle_build.add_argument("--out", required=True, help="Output bundle directory.")
    bundle_build.add_argument("--json", action="store_true", help="Print JSON output.")

    bundle_validate = bundle_sub.add_parser("validate", help="Validate an ABRA result bundle directory.")
    bundle_validate.add_argument("bundle_path", help="Path to an abra_result_bundle directory.")
    bundle_validate.add_argument("--json", action="store_true", help="Print JSON output.")

    replay = subparsers.add_parser("replay", help="Assess bounded ABRA replay feasibility.")
    replay_sub = replay.add_subparsers(dest="replay_command", required=True)

    replay_assess = replay_sub.add_parser("assess", help="Build a replay feasibility evidence bundle.")
    replay_assess.add_argument("--case-fixture", required=True, help="Local replay case fixture JSON.")
    replay_assess.add_argument("--out", required=True, help="Output replay evidence bundle directory.")
    replay_assess.add_argument("--json", action="store_true", help="Print JSON output.")

    evidence = subparsers.add_parser("evidence", help="Validate ABRA evidence bundles.")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)

    evidence_validate = evidence_sub.add_parser("validate", help="Validate an ABRA evidence bundle directory.")
    evidence_validate.add_argument("bundle_path", help="Path to a bundle containing evidence_bundle.json.")
    evidence_validate.add_argument("--min-level", default="L0", help="Minimum required evidence level, e.g. L1.")
    evidence_validate.add_argument("--json", action="store_true", help="Print JSON output.")

    agent = subparsers.add_parser("agent", help="Run bounded ABRA research agent loops.")
    agent_sub = agent.add_subparsers(dest="agent_command", required=True)

    agent_run = agent_sub.add_parser("run", help="Run a local plan-act-observe-reflect research agent loop.")
    agent_run.add_argument("--case-fixture", required=True, help="Local replay case fixture JSON.")
    agent_run.add_argument("--out", required=True, help="Output agent evidence bundle directory.")
    agent_run.add_argument("--rounds", type=int, default=3, help="Maximum local rounds to run, capped at 5.")
    agent_run.add_argument("--min-level", default="L1", help="Minimum evidence level required for validation.")
    agent_run.add_argument("--json", action="store_true", help="Print JSON output.")

    return parser


def _handle_labs(args: argparse.Namespace) -> int:
    if args.labs_command == "inspect":
        manifest = load_manifest(args.manifest)
        payload = {
            "schema_version": INSPECT_SCHEMA_VERSION,
            "status": "passed" if manifest.validation.valid else "failed",
            "lab_id": manifest.lab_id,
            "manifest_path": str(manifest.path),
            "manifest": manifest.to_dict(),
            "valid": manifest.validation.valid,
            "errors": list(manifest.validation.errors),
            "warnings": list(manifest.validation.warnings),
        }
        _emit(payload, args.json)
        return 0 if manifest.validation.valid else 1

    if args.labs_command == "smoke":
        payload = build_smoke_report(args.manifest)
        _emit(payload, args.json)
        return 0 if payload["status"] == "passed" else 1

    raise ValueError(f"Unsupported labs command: {args.labs_command}")


def _handle_tools(args: argparse.Namespace) -> int:
    if args.tools_command == "list":
        tools = list_tools()
        payload = {
            "schema_version": TOOLS_SCHEMA_VERSION,
            "status": "passed" if all(tool["exists"] for tool in tools) else "failed",
            "tools": tools,
        }
        _emit(payload, args.json)
        return 0 if payload["status"] == "passed" else 1

    raise ValueError(f"Unsupported tools command: {args.tools_command}")


def _handle_bundle(args: argparse.Namespace) -> int:
    if args.bundle_command == "build":
        result = build_result_bundle(args.source, args.out)
        _emit(result.payload, args.json)
        return 0 if result.payload["status"] == "passed" else 1

    if args.bundle_command == "validate":
        payload = validate_result_bundle(args.bundle_path)
        _emit(payload, args.json)
        return 0 if payload["status"] == "passed" else 1

    raise ValueError(f"Unsupported bundle command: {args.bundle_command}")


def _handle_replay(args: argparse.Namespace) -> int:
    if args.replay_command == "assess":
        payload = assess_replay_fixture(args.case_fixture, args.out)
        _emit(payload, args.json)
        return 0 if payload["status"] == "passed" else 1

    raise ValueError(f"Unsupported replay command: {args.replay_command}")


def _handle_evidence(args: argparse.Namespace) -> int:
    if args.evidence_command == "validate":
        payload = validate_evidence_bundle(args.bundle_path, args.min_level)
        _emit(payload, args.json)
        return 0 if payload["status"] == "passed" else 1

    raise ValueError(f"Unsupported evidence command: {args.evidence_command}")


def _handle_agent(args: argparse.Namespace) -> int:
    if args.agent_command == "run":
        payload = run_research_agent(
            case_fixture=args.case_fixture,
            out=args.out,
            rounds=args.rounds,
            min_level=args.min_level,
        )
        _emit(payload, args.json)
        return 0 if payload["status"] == "passed" else 1

    raise ValueError(f"Unsupported agent command: {args.agent_command}")


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    status = payload.get("status", "unknown")
    schema = payload.get("schema_version", "abra")
    print(f"{schema}: {status}")
    if "manifest_path" in payload:
        print(f"manifest: {Path(str(payload['manifest_path']))}")
    if "tools" in payload:
        for tool in payload["tools"]:
            marker = "ok" if tool.get("exists") else "missing"
            print(f"{marker} {tool['name']} {tool['relative_path']}")
    if "bundle_path" in payload:
        print(f"bundle: {Path(str(payload['bundle_path']))}")
    if "claim_count" in payload:
        print(f"claims: {payload['claim_count']}")
    if "artifact_count" in payload:
        print(f"artifacts: {payload['artifact_count']}")
    if "case_count" in payload:
        print(f"cases: {payload['case_count']}")
    if "round_count" in payload:
        print(f"rounds: {payload['round_count']}")
    if "evidence_levels" in payload:
        print(f"evidence: {payload['evidence_levels']}")
    if payload.get("errors"):
        for error in payload["errors"]:
            print(f"error: {error}")
