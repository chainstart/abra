"""Inventory for existing blockchain security tools exposed through ABRA."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from abra.manifest import repo_root


TOOL_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "name": "scanner",
        "description": "Run Solidity static analyzers and emit console, JSON, or Markdown findings.",
        "path": "tools/scanner.py",
        "command": ["python3", "tools/scanner.py"],
        "category": "static_analysis",
        "side_effect_free": True,
    },
    {
        "name": "replay_runner",
        "description": "Run bounded Foundry fork-replay checks and summarize replay blockers.",
        "path": "tools/replay_runner.py",
        "command": ["python3", "tools/replay_runner.py"],
        "category": "replay",
        "side_effect_free": False,
    },
    {
        "name": "report_generator",
        "description": "Render scanner JSON output into Markdown audit reports.",
        "path": "tools/report_generator.py",
        "command": ["python3", "tools/report_generator.py"],
        "category": "reporting",
        "side_effect_free": False,
    },
    {
        "name": "phase1_pipeline",
        "description": "Collect public candidate events, normalize incidents, enrich security evidence, and emit Alchemy backfill ledgers.",
        "path": "tools/pipeline/run_phase1.py",
        "command": ["python3", "tools/pipeline/run_phase1.py"],
        "category": "data_pipeline",
        "side_effect_free": False,
    },
    {
        "name": "direct_evidence_collector",
        "description": "Collect direct tx / replay-oriented candidates from public sources such as DeFiHackLabs fixtures.",
        "path": "tools/pipeline/direct_evidence_collector.py",
        "command": ["python3", "tools/pipeline/direct_evidence_collector.py"],
        "category": "data_pipeline",
        "side_effect_free": False,
    },
    {
        "name": "security_evidence_enrichment",
        "description": "Materialize provenance, security-source, and reference evidence for candidate incidents.",
        "path": "abra/evidence_pipeline.py",
        "command": ["python3", "-m", "abra", "evidence", "produce"],
        "category": "data_pipeline",
        "side_effect_free": False,
    },
    {
        "name": "alchemy_onchain_backfill",
        "description": "Discover transaction anchors for candidate incidents and verify fork blocks with Alchemy read-only receipts.",
        "path": "abra/evidence_pipeline.py",
        "command": ["python3", "-m", "abra", "evidence", "produce"],
        "category": "data_pipeline",
        "side_effect_free": False,
    },
    {
        "name": "event_card_generator",
        "description": "Generate incident event cards from processed pipeline data.",
        "path": "tools/pipeline/generate_event_cards.py",
        "command": ["python3", "tools/pipeline/generate_event_cards.py"],
        "category": "reporting",
        "side_effect_free": False,
    },
    {
        "name": "phase2_incident_selector",
        "description": "Select high-value incidents for replay implementation.",
        "path": "tools/pipeline/select_phase2_incidents.py",
        "command": ["python3", "tools/pipeline/select_phase2_incidents.py"],
        "category": "data_pipeline",
        "side_effect_free": False,
    },
    {
        "name": "replay_cohort_builder",
        "description": "Build validated incident cohorts for replay evidence production.",
        "path": "abra/replay_cohort.py",
        "command": ["python3", "-m", "abra", "replay", "cohort"],
        "category": "data_pipeline",
        "side_effect_free": False,
    },
)


def list_tools(root: Path | None = None) -> list[dict[str, Any]]:
    """Return ABRA's local tool inventory with existence metadata."""

    base = root or repo_root()
    tools: list[dict[str, Any]] = []
    for definition in TOOL_DEFINITIONS:
        path = base / str(definition["path"])
        tools.append(
            {
                **definition,
                "path": str(path),
                "relative_path": str(definition["path"]),
                "exists": path.exists(),
            }
        )
    return tools
