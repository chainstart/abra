"""外部攻击事件发现测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.external_incident_discovery import discover_external_incidents  # noqa: E402


SLOWMIST_SAMPLE = """
<ul>
  <li>
    <span class="time">2026-03-27</span>
    <h3><em>Hacked target: </em>Moonwell</h3>
    <p><em>Description of the event: </em>Moonwell is facing a governance attack on its Moonriver deployment, where an attacker seeks to transfer administrative control of lending markets and the oracle.</p>
    <p><span><em>Amount of loss: </em>$ 1,080,000</span><span><em>Attack method: </em>Governance Attack</span></p>
    <p class="link-reference"><a href="https://example.com/moonwell">View Reference Sources</a></p>
  </li>
  <li>
    <span class="time">2026-03-26</span>
    <h3><em>Hacked target: </em>unknown contract (Stake) on BSC</h3>
    <p><em>Description of the event: </em>The attacker exploited a spot price dependency vulnerability and manipulated reward calculations.</p>
    <p><span><em>Amount of loss: </em>$ 133,000</span><span><em>Attack method: </em>Oracle Manipulation</span></p>
    <p class="link-reference"><a href="https://example.com/stake">View Reference Sources</a></p>
  </li>
</ul>
"""


class ExternalIncidentDiscoveryPhase26Test(unittest.TestCase):
    """验证外部事件发现器。"""

    def test_discover_external_incidents_parses_slowmist_entries(self) -> None:
        """应能从 SlowMist 页面抽取候选事件。"""

        with patch(
            "services.research.external_incident_discovery._fetch_slowmist_home",
            return_value=SLOWMIST_SAMPLE,
        ):
            candidates = discover_external_incidents(limit=10, min_relevance=0.1)

        self.assertGreaterEqual(len(candidates), 2)
        self.assertEqual(candidates[0].source, "slowmist_hacked")
        self.assertTrue(candidates[0].candidate_id)
        self.assertTrue(candidates[0].suggested_categories)
        self.assertGreater(candidates[0].relevance_score, 0.1)


if __name__ == "__main__":
    unittest.main()
