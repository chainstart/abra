from __future__ import annotations

import json
import subprocess
import sys

from abra import cli


def test_labs_inspect_cli_emits_manifest_contract(capsys):
    exit_code = cli.main(["labs", "inspect", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "abra.lab_manifest.inspect.v1"
    assert payload["status"] == "passed"
    assert payload["lab_id"] == "abra"
    assert payload["valid"] is True
    assert payload["manifest"]["entrypoints"]["agent_cli"] == ["python3 -m abra"]
    assert "abra_result_bundle" in payload["manifest"]["bundle_types"]
    assert "abra_research_agent_bundle" in payload["manifest"]["bundle_types"]
    assert "agent-run-fixture" in payload["manifest"]["dispatch_commands"]


def test_python_module_labs_inspect_smoke_matches_harness_command():
    result = subprocess.run(
        [sys.executable, "-m", "abra", "labs", "inspect", "--json"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "passed"
    assert payload["manifest"]["lab_id"] == "abra"


def test_labs_smoke_cli_reports_side_effect_free_checks(capsys):
    exit_code = cli.main(["labs", "smoke", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "abra.lab_smoke.v1"
    assert payload["status"] == "passed"
    checks = {check["name"]: check["status"] for check in payload["checks"]}
    assert checks["manifest"] == "passed"
    assert checks["command_policy"] == "passed"
    assert checks["tools"] == "passed"
    assert checks["reports"] == "passed"
    assert checks["findings"] == "passed"
    assert checks["agent_bundle"] == "passed"


def test_tools_list_cli_preserves_existing_tool_inventory(capsys):
    exit_code = cli.main(["tools", "list", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "abra.tool_inventory.v1"
    assert payload["status"] == "passed"
    tools = {tool["name"]: tool for tool in payload["tools"]}
    assert tools["scanner"]["relative_path"] == "tools/scanner.py"
    assert tools["replay_runner"]["relative_path"] == "tools/replay_runner.py"
    assert tools["phase1_pipeline"]["relative_path"] == "tools/pipeline/run_phase1.py"
    assert tools["security_evidence_enrichment"]["relative_path"] == "abra/evidence_pipeline.py"
    assert tools["alchemy_onchain_backfill"]["relative_path"] == "abra/evidence_pipeline.py"
    assert all(tool["exists"] for tool in tools.values())
