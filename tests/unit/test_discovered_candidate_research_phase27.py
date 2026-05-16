"""外部发现候选事件研究测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.discovered_incident_repository import save_discovered_incidents  # noqa: E402
from services.research.incident_research_workflow_service import run_discovered_candidate_research_workflow  # noqa: E402
from services.research.models import DiscoveredIncidentCandidate  # noqa: E402


class DiscoveredCandidateResearchPhase27Test(unittest.TestCase):
    """验证外部候选事件可直接进入研究流程。"""

    def test_candidate_research_workflow_returns_gate_result(self) -> None:
        """即使候选事件证据不完整，也应能进入研究流程并给出门禁结果。"""

        save_discovered_incidents(
            [
                DiscoveredIncidentCandidate(
                    candidate_id="candidate_demo",
                    source="slowmist_hacked",
                    title="Moonwell",
                    discovered_at="2026-03-26",
                    summary="Moonwell is facing a governance attack where an attacker seeks to control markets and oracle contracts.",
                    attack_method="Governance Attack",
                    loss_text="$1,080,000",
                    protocol_name_guess="Moonwell",
                    protocol_type_guess="lending",
                    relevance_score=0.82,
                    suggested_categories=["SC-09: Governance", "SC-02: Access Control"],
                    tags=["governance", "lending"],
                    reference_url="https://example.com/moonwell",
                )
            ]
        )

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_discovered_candidate_research_workflow(candidate_id="candidate_demo")

        self.assertIsNotNone(result.selected_idea)
        self.assertGreater(len(result.research_ideas), 0)
        self.assertIsNotNone(result.evidence_assessment)
        self.assertIn(result.evidence_assessment.status, {"conditional", "insufficient", "sufficient"})


if __name__ == "__main__":
    unittest.main()
