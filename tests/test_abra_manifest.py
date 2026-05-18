from __future__ import annotations

import shlex

from abra.manifest import REQUIRED_EVIDENCE_LEVELS, load_manifest, repo_root


def test_manifest_matches_abra_identity_and_legacy_contract():
    manifest = load_manifest()

    assert manifest.validation.valid, manifest.validation.errors
    assert manifest.lab_id == "abra"
    assert manifest.system_name == "ABRA"
    assert manifest.domain == "blockchain_security"
    assert manifest.legacy["repo_names"] == ["blockchain-security"]
    assert {"blockchain-security", "blockchain_security"} <= set(manifest.legacy["lab_ids"])


def test_manifest_declares_ara_entrypoints_and_result_bundle():
    manifest = load_manifest()

    assert "python3 -m abra" in manifest.entrypoints["agent_cli"]
    assert "python3 tools/scanner.py" in manifest.entrypoints["direct_tools"]
    assert "python3 tools/replay_runner.py" in manifest.entrypoints["direct_tools"]
    assert "abra_result_bundle" in manifest.produced_bundles


def test_manifest_command_policy_is_hardened_for_local_smoke():
    manifest = load_manifest()
    policy = manifest.command_policy

    assert "python3 -m abra" in policy["allow_prefixes"]
    assert "python3 tools/" in policy["allow_prefixes"]
    assert "forge test --match-path test/replay/" in policy["allow_prefixes"]
    assert {"rm -rf", "git reset --hard", "cast send", "--broadcast", "PRIVATE_KEY"} <= set(
        policy["deny_patterns"]
    )
    assert manifest.environment["required"] == []
    assert not any("PRIVATE_KEY" in value for value in manifest.environment["required"])
    assert manifest.safety["destructive_commands"] is False
    assert manifest.safety["network_policy"] == "read_only_rpc"


def test_manifest_dispatch_commands_are_side_effect_free_and_allowed():
    manifest = load_manifest()
    allow_prefixes = manifest.command_policy["allow_prefixes"]
    commands = manifest.dispatch_commands

    assert {"manifest-inspect", "smoke", "tools-list"} <= set(commands)
    for name in ("manifest-inspect", "smoke", "tools-list"):
        command = commands[name]
        argv = [str(part) for part in command["argv"]]
        assert command["side_effect_free"] is True
        assert any(argv[: len(shlex.split(prefix))] == shlex.split(prefix) for prefix in allow_prefixes)


def test_manifest_preserves_existing_artifact_surfaces():
    manifest = load_manifest()
    include_globs = set(manifest.artifact_globs["include"])

    assert "reports/*.md" in include_globs
    assert "reports/events/*.md" in include_globs
    assert "findings/*.md" in include_globs
    assert "data/processed/*.csv" in include_globs
    assert "runs/*/abra_result_bundle/**" in include_globs
    assert (repo_root() / "reports" / "events" / "INDEX.md").exists()
    assert (repo_root() / "findings" / "summary.md").exists()


def test_manifest_declares_abra_evidence_ladder():
    manifest = load_manifest()

    assert tuple(manifest.evidence_levels) == REQUIRED_EVIDENCE_LEVELS
    assert manifest.evidence_levels["L1"] == "static_alert"
    assert manifest.evidence_levels["L4"] == "fork_replayed"
    assert manifest.evidence_levels["L6"] == "audit_ready"
