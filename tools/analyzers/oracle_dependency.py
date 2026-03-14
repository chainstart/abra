"""Static analyzer for oracle-related risks in Solidity contracts.

Detects:
- Chainlink latestRoundData() usage without staleness checks
- Missing price feed validation (zero price, negative price)
- Single oracle dependency (no fallback)
- TWAP oracle manipulation surface (short observation window)
- Price update frequency mismatches
- Hardcoded oracle addresses
"""

import re
from pathlib import Path

from .base import BaseAnalyzer, Finding, Severity


# Chainlink patterns
_LATEST_ROUND_DATA = re.compile(r"\.latestRoundData\s*\(\s*\)")
_LATEST_ANSWER = re.compile(r"\.latestAnswer\s*\(\s*\)")

# Price validation patterns
_PRICE_GT_ZERO = re.compile(
    r"require\s*\([^)]*(?:price|answer)\s*>\s*0|"
    r"if\s*\([^)]*(?:price|answer)\s*(?:<=|==)\s*0[^)]*\)\s*revert|"
    r"assert\s*\([^)]*(?:price|answer)\s*>\s*0",
    re.IGNORECASE,
)

# Staleness check patterns
_STALENESS_CHECK = re.compile(
    r"updatedAt|timestamp|roundId|answeredInRound|"
    r"block\.timestamp\s*-\s*\w*[Tt]ime|"
    r"stale|heartbeat|maxDelay|MAX_DELAY",
    re.IGNORECASE,
)

# Round completeness check
_ROUND_COMPLETENESS = re.compile(
    r"answeredInRound\s*>=?\s*roundId|"
    r"roundId\s*<=?\s*answeredInRound"
)

# Oracle address patterns
_HARDCODED_ADDRESS = re.compile(
    r"(?:address|AggregatorV[23]Interface|AggregatorInterface)\s*"
    r"(?:public|private|internal|immutable|\s)*\s*\w+\s*=\s*"
    r"(?:address\s*\()?\s*0x[0-9a-fA-F]{40}"
)

# TWAP patterns
_TWAP_OBSERVE = re.compile(
    r"\.observe\s*\(|\.consult\s*\(|twap|TWAP|"
    r"OracleLibrary\.getQuoteAtTick"
)

# Oracle interface imports
_ORACLE_IMPORT = re.compile(
    r"import\s+.*(?:AggregatorV[23]|Chainlink|Oracle|PriceFeed)",
    re.IGNORECASE,
)

# Feed registry
_FEED_REGISTRY = re.compile(r"FeedRegistryInterface|feedRegistry")

# Multiple oracle / fallback patterns
_FALLBACK_ORACLE = re.compile(
    r"fallback[Oo]racle|secondary[Oo]racle|backup[Oo]racle|"
    r"oracle[AB12]|primaryOracle.*secondaryOracle|"
    r"try\s+\w+\.latestRoundData",
    re.IGNORECASE,
)

# Sequencer uptime feed (for L2s)
_SEQUENCER_CHECK = re.compile(
    r"sequencerUptimeFeed|sequencer|isSequencerUp|"
    r"GRACE_PERIOD_TIME|gracePeriod",
    re.IGNORECASE,
)

# Price deviation check
_DEVIATION_CHECK = re.compile(
    r"deviation|maxDeviation|priceDeviation|"
    r"abs\s*\([^)]*price|circuit[Bb]reaker|"
    r"MIN_PRICE|MAX_PRICE|minPrice|maxPrice",
    re.IGNORECASE,
)


class OracleDependencyAnalyzer(BaseAnalyzer):
    """Analyzes Solidity contracts for oracle-related vulnerabilities."""

    name = "oracle-dependency"
    description = "Detects oracle-related risks and price feed vulnerabilities"

    def analyze(self, file_path: str) -> list[Finding]:
        """Run all oracle checks on a Solidity file.

        Args:
            file_path: Path to the .sol file.

        Returns:
            List of findings related to oracle issues.
        """
        content, lines = self._read_source(file_path)
        if not content:
            return []

        # Only analyze files that appear to use oracles
        has_oracle = bool(
            _LATEST_ROUND_DATA.search(content)
            or _LATEST_ANSWER.search(content)
            or _ORACLE_IMPORT.search(content)
            or _TWAP_OBSERVE.search(content)
            or re.search(r"\b[Oo]racle\b|\b[Pp]riceFeed\b", content)
        )
        if not has_oracle:
            return []

        findings: list[Finding] = []
        findings.extend(self._check_staleness_validation(file_path, content, lines))
        findings.extend(self._check_price_validation(file_path, content, lines))
        findings.extend(self._check_deprecated_api(file_path, content, lines))
        findings.extend(self._check_single_oracle(file_path, content, lines))
        findings.extend(self._check_hardcoded_oracle_address(file_path, content, lines))
        findings.extend(self._check_twap_manipulation(file_path, content, lines))
        findings.extend(self._check_l2_sequencer(file_path, content, lines))
        findings.extend(self._check_round_completeness(file_path, content, lines))
        findings.extend(self._check_price_deviation_bounds(file_path, content, lines))
        findings.extend(self._check_decimal_handling(file_path, content, lines))
        return findings

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _check_staleness_validation(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect latestRoundData() calls without staleness checks."""
        findings: list[Finding] = []

        for match in _LATEST_ROUND_DATA.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Look for staleness check in surrounding context (within ~30 lines)
            context_start = max(0, match.start() - 200)
            context_end = min(len(content), match.end() + 1000)
            context = content[context_start:context_end]

            has_staleness = bool(_STALENESS_CHECK.search(context))

            if not has_staleness:
                findings.append(Finding(
                    analyzer=self.name,
                    title="Missing staleness check on `latestRoundData()`",
                    severity=Severity.HIGH,
                    file=file_path,
                    line=line_num,
                    description=(
                        "The call to `latestRoundData()` does not appear to validate "
                        "the `updatedAt` timestamp for staleness. If the Chainlink "
                        "oracle stops updating (e.g., during network congestion or "
                        "oracle failure), the contract will use stale prices, which "
                        "can be exploited for arbitrage or liquidation manipulation."
                    ),
                    recommendation=(
                        "Add a staleness check: "
                        "`require(block.timestamp - updatedAt < MAX_STALENESS, "
                        "\"Stale price\");` where MAX_STALENESS is set to the oracle's "
                        "heartbeat interval (e.g., 3600 for 1-hour heartbeats)."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-09: Oracle Dependency",
                ))

        return findings

    def _check_price_validation(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect missing price validation (zero or negative price)."""
        findings: list[Finding] = []

        for match in _LATEST_ROUND_DATA.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            context_end = min(len(content), match.end() + 1000)
            context = content[match.start():context_end]

            has_price_check = bool(_PRICE_GT_ZERO.search(context))

            if not has_price_check:
                findings.append(Finding(
                    analyzer=self.name,
                    title="Missing price validation on oracle response",
                    severity=Severity.HIGH,
                    file=file_path,
                    line=line_num,
                    description=(
                        "The oracle response is not validated for zero or negative "
                        "prices. Chainlink can return 0 during outages or negative "
                        "values for certain feeds. Using an invalid price can lead "
                        "to incorrect valuations, allowing attackers to borrow "
                        "against worthless collateral or liquidate healthy positions."
                    ),
                    recommendation=(
                        "Add `require(answer > 0, \"Invalid price\");` after the "
                        "call to `latestRoundData()`. For int256 answers, also check "
                        "that the price is not negative."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-09: Oracle Dependency",
                ))

        return findings

    def _check_deprecated_api(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect usage of deprecated Chainlink API (latestAnswer)."""
        findings: list[Finding] = []

        for match in _LATEST_ANSWER.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            findings.append(Finding(
                analyzer=self.name,
                title="Deprecated Chainlink API `latestAnswer()` used",
                severity=Severity.MEDIUM,
                file=file_path,
                line=line_num,
                description=(
                    "`latestAnswer()` is a deprecated Chainlink API that does not "
                    "return round data needed for staleness and completeness checks. "
                    "It provides no way to verify if the price is current."
                ),
                recommendation=(
                    "Replace `latestAnswer()` with `latestRoundData()` which returns "
                    "roundId, answer, startedAt, updatedAt, and answeredInRound for "
                    "proper validation."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-09: Oracle Dependency",
            ))

        return findings

    def _check_single_oracle(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect single oracle dependency without fallback."""
        findings: list[Finding] = []

        has_oracle_usage = bool(
            _LATEST_ROUND_DATA.search(content) or _LATEST_ANSWER.search(content)
        )
        has_fallback = bool(_FALLBACK_ORACLE.search(content))

        if has_oracle_usage and not has_fallback:
            # Find the first oracle usage for line reference
            first_match = _LATEST_ROUND_DATA.search(content) or _LATEST_ANSWER.search(content)
            if first_match:
                line_num = content[: first_match.start()].count("\n") + 1

                findings.append(Finding(
                    analyzer=self.name,
                    title="Single oracle dependency without fallback",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=line_num,
                    description=(
                        "The contract relies on a single oracle source without a "
                        "fallback mechanism. If the primary oracle fails, becomes "
                        "stale, or is manipulated, the contract has no alternative "
                        "price source."
                    ),
                    recommendation=(
                        "Implement a fallback oracle pattern: try the primary oracle "
                        "first, and if it fails or returns stale data, fall back to "
                        "a secondary source (e.g., Chainlink + Uniswap TWAP, or "
                        "Chainlink + Pyth)."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-09: Oracle Dependency",
                ))

        return findings

    def _check_hardcoded_oracle_address(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect hardcoded oracle addresses that cannot be updated."""
        findings: list[Finding] = []

        for match in _HARDCODED_ADDRESS.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Check if it's immutable (which is acceptable but worth noting)
            is_immutable = "immutable" in match.group(0)

            findings.append(Finding(
                analyzer=self.name,
                title="Hardcoded oracle address",
                severity=Severity.LOW if is_immutable else Severity.MEDIUM,
                file=file_path,
                line=line_num,
                description=(
                    "An oracle address is hardcoded in the contract. "
                    + (
                        "It is marked as immutable, which is gas-efficient but "
                        "cannot be changed if the oracle is deprecated."
                        if is_immutable
                        else "If the oracle feed is deprecated or migrated, the "
                        "contract cannot be updated to use the new address."
                    )
                ),
                recommendation=(
                    "Consider using a configurable oracle address that can be "
                    "updated by governance (with a timelock). At minimum, set "
                    "the address in the constructor rather than as a literal."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-09: Oracle Dependency",
            ))

        return findings

    def _check_twap_manipulation(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect TWAP oracle usage with potentially short observation windows."""
        findings: list[Finding] = []

        for match in _TWAP_OBSERVE.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Look for the observation window / period parameter
            context = content[max(0, match.start() - 500): match.end() + 500]

            # Check for short periods (common values: 10 minutes = 600, 30 min = 1800)
            short_period = re.search(r"(?:period|window|secondsAgo)\s*=?\s*(\d+)", context)
            period_value = int(short_period.group(1)) if short_period else None

            is_short = period_value is not None and period_value < 1800  # < 30 min

            findings.append(Finding(
                analyzer=self.name,
                title="TWAP oracle usage" + (" with short observation window" if is_short else ""),
                severity=Severity.HIGH if is_short else Severity.MEDIUM,
                file=file_path,
                line=line_num,
                description=(
                    "The contract uses a TWAP (Time-Weighted Average Price) oracle. "
                    + (
                        f"The observation window appears to be {period_value} seconds "
                        f"({period_value // 60} minutes), which may be too short to "
                        f"resist manipulation via flash loans or large swaps."
                        if is_short
                        else "Ensure the observation window is long enough to resist "
                        "price manipulation (recommended: at least 30 minutes)."
                    )
                ),
                recommendation=(
                    "Use a TWAP period of at least 30 minutes (1800 seconds) for "
                    "high-value operations. For critical operations like liquidations, "
                    "consider using Chainlink as the primary oracle with TWAP as "
                    "fallback."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-09: Oracle Dependency",
            ))

        return findings

    def _check_l2_sequencer(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect missing L2 sequencer uptime checks for L2 deployments."""
        findings: list[Finding] = []

        # Heuristic: if the contract uses Chainlink and mentions L2-related terms
        has_chainlink = bool(_LATEST_ROUND_DATA.search(content))
        has_l2_hints = bool(re.search(
            r"Arbitrum|Optimism|L2|arbitrum|optimism|sequencer",
            content,
            re.IGNORECASE,
        ))
        has_sequencer_check = bool(_SEQUENCER_CHECK.search(content))

        if has_chainlink and has_l2_hints and not has_sequencer_check:
            first_oracle = _LATEST_ROUND_DATA.search(content)
            if first_oracle:
                line_num = content[: first_oracle.start()].count("\n") + 1
                findings.append(Finding(
                    analyzer=self.name,
                    title="Missing L2 sequencer uptime check",
                    severity=Severity.HIGH,
                    file=file_path,
                    line=line_num,
                    description=(
                        "The contract appears to be deployed on an L2 (references to "
                        "Arbitrum/Optimism detected) and uses Chainlink oracles, but "
                        "does not check the sequencer uptime feed. When the L2 "
                        "sequencer goes down, oracle prices become stale but "
                        "latestRoundData() still returns the last known price."
                    ),
                    recommendation=(
                        "Add a Chainlink sequencer uptime feed check before using "
                        "oracle prices. Also implement a grace period after the "
                        "sequencer comes back online to prevent front-running."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-09: Oracle Dependency",
                ))

        return findings

    def _check_round_completeness(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect missing round completeness checks on latestRoundData."""
        findings: list[Finding] = []

        for match in _LATEST_ROUND_DATA.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            context = content[match.start(): min(len(content), match.end() + 1000)]
            has_round_check = bool(_ROUND_COMPLETENESS.search(context))

            if not has_round_check:
                findings.append(Finding(
                    analyzer=self.name,
                    title="Missing round completeness check",
                    severity=Severity.LOW,
                    file=file_path,
                    line=line_num,
                    description=(
                        "The `latestRoundData()` return values do not include a "
                        "round completeness check (`answeredInRound >= roundId`). "
                        "An incomplete round may return a price from a previous round. "
                        "Note: this check is less critical with newer Chainlink "
                        "aggregator versions but is still recommended."
                    ),
                    recommendation=(
                        "Add `require(answeredInRound >= roundId, \"Stale price\");` "
                        "after calling `latestRoundData()`."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-09: Oracle Dependency",
                ))

        return findings

    def _check_price_deviation_bounds(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect missing price deviation/sanity bounds."""
        findings: list[Finding] = []

        has_oracle = bool(
            _LATEST_ROUND_DATA.search(content) or _LATEST_ANSWER.search(content)
        )
        has_deviation = bool(_DEVIATION_CHECK.search(content))

        if has_oracle and not has_deviation:
            first_match = (
                _LATEST_ROUND_DATA.search(content) or _LATEST_ANSWER.search(content)
            )
            if first_match:
                line_num = content[: first_match.start()].count("\n") + 1
                findings.append(Finding(
                    analyzer=self.name,
                    title="No price deviation bounds or circuit breaker",
                    severity=Severity.LOW,
                    file=file_path,
                    line=line_num,
                    description=(
                        "The contract uses oracle prices without any deviation bounds "
                        "or circuit breaker mechanism. A sudden extreme price movement "
                        "(e.g., during an oracle manipulation or market crash) could "
                        "cause the protocol to process transactions at unreasonable "
                        "prices."
                    ),
                    recommendation=(
                        "Implement price deviation bounds (e.g., reject prices that "
                        "deviate more than X% from the last known good price). "
                        "Consider a circuit breaker that pauses operations during "
                        "extreme volatility."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-09: Oracle Dependency",
                ))

        return findings

    def _check_decimal_handling(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect potential issues with oracle decimal handling."""
        findings: list[Finding] = []

        # Look for hardcoded decimal assumptions
        for match in re.finditer(r"(?:1e(\d+)|10\s*\*\*\s*(\d+))\s*(?:;|[*/)])", content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            exponent = match.group(1) or match.group(2)
            if exponent in ("8", "18"):  # Common oracle decimals
                # Check if there is a dynamic decimals() call nearby
                context = content[max(0, match.start() - 500): match.end() + 200]
                has_dynamic_decimals = bool(re.search(r"\.decimals\s*\(\s*\)", context))

                if not has_dynamic_decimals:
                    findings.append(Finding(
                        analyzer=self.name,
                        title=f"Hardcoded decimal assumption (10^{exponent})",
                        severity=Severity.LOW,
                        file=file_path,
                        line=line_num,
                        description=(
                            f"The contract uses a hardcoded decimal value of 10^{exponent} "
                            f"near oracle-related code. Not all Chainlink feeds use 8 "
                            f"decimals (e.g., ETH/USD uses 8, but some feeds use 18). "
                            f"Hardcoding decimals can cause incorrect price scaling."
                        ),
                        recommendation=(
                            "Query the oracle's `decimals()` function dynamically, or "
                            "document the assumption clearly and validate it in the "
                            "constructor."
                        ),
                        code_snippet=self._extract_snippet(lines, line_num),
                        category="SC-09: Oracle Dependency",
                    ))

        return findings
