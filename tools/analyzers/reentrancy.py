"""Static analyzer for reentrancy vulnerabilities in Solidity contracts.

Detects:
- External calls followed by state changes (CEI pattern violations)
- Missing nonReentrant modifier on functions with external calls
- ReentrancyGuard usage patterns
- Cross-function reentrancy via shared state
- Read-only reentrancy risks (view functions reading stale state)
"""

import re
from pathlib import Path

from .base import BaseAnalyzer, Finding, Severity


# External call patterns
_EXTERNAL_CALL = re.compile(
    r"\.call\s*\{|"
    r"\.call\s*\(|"
    r"\.delegatecall\s*\(|"
    r"\.staticcall\s*\(|"
    r"\.transfer\s*\(|"
    r"\.send\s*\("
)

# Higher-level external calls (interface/contract calls)
_INTERFACE_CALL = re.compile(
    r"(?:IERC20|IERC721|IERC1155|IUniswap\w*|IAave\w*|ICompound\w*|"
    r"I[A-Z]\w+)\s*\([^)]*\)\s*\.\w+\s*\(|"
    r"\w+\s*\.\w+\s*\{[^}]*\}\s*\("
)

# State modification patterns
_STATE_CHANGE = re.compile(
    r"(?:^|\s)(\w+)\s*(?:\[.*?\])?\s*=[^=]|"  # Assignment (not ==)
    r"(?:^|\s)(\w+)\s*(?:\[.*?\])?\s*\+=|"
    r"(?:^|\s)(\w+)\s*(?:\[.*?\])?\s*-=|"
    r"(?:^|\s)(\w+)\s*(?:\[.*?\])?\s*\+\+|"
    r"(?:^|\s)(\w+)\s*(?:\[.*?\])?\s*--|"
    r"\bdelete\s+\w+|"
    r"\.push\s*\(|"
    r"\.pop\s*\("
)

# State variables typically involved in reentrancy
_BALANCE_PATTERN = re.compile(
    r"\b(balance|balances|shares|totalSupply|totalShares|"
    r"reserves|liquidity|debt|supplied|borrowed)\b",
    re.IGNORECASE,
)

# Reentrancy guard
_NONREENTRANT = re.compile(r"\bnonReentrant\b")
_REENTRANCY_GUARD = re.compile(r"\bReentrancyGuard\b")

# Function definition
_FUNC_DEF = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s+(external|public|internal|private)"
    r"([^{]*)\{",
)

# View/pure functions
_VIEW_PURE = re.compile(r"\b(view|pure)\b")

# Event emission (effects that are safe after external calls)
_EVENT_EMIT = re.compile(r"\bemit\s+\w+")


class ReentrancyAnalyzer(BaseAnalyzer):
    """Analyzes Solidity contracts for reentrancy vulnerabilities."""

    name = "reentrancy"
    description = "Detects reentrancy vulnerabilities and CEI pattern violations"

    def analyze(self, file_path: str) -> list[Finding]:
        """Run all reentrancy checks on a Solidity file.

        Args:
            file_path: Path to the .sol file.

        Returns:
            List of findings related to reentrancy issues.
        """
        content, lines = self._read_source(file_path)
        if not content:
            return []

        findings: list[Finding] = []
        findings.extend(self._check_cei_violations(file_path, content, lines))
        findings.extend(self._check_missing_reentrancy_guard(file_path, content, lines))
        findings.extend(self._check_transfer_send_return(file_path, content, lines))
        findings.extend(self._check_cross_function_reentrancy(file_path, content, lines))
        findings.extend(self._check_read_only_reentrancy(file_path, content, lines))
        findings.extend(self._check_raw_call_value(file_path, content, lines))
        findings.extend(self._check_callback_patterns(file_path, content, lines))
        return findings

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _check_cei_violations(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect Checks-Effects-Interactions pattern violations.

        Looks for state changes that occur AFTER external calls within
        the same function body.
        """
        findings: list[Finding] = []
        functions = self._extract_functions(content)

        for func_name, func_start, func_body, func_line in functions:
            # Skip view/pure functions
            sig_end = content.find("{", func_start)
            if sig_end != -1:
                signature = content[func_start:sig_end]
                if _VIEW_PURE.search(signature):
                    continue

            # Find all external calls and state changes in the function body
            external_calls = list(_EXTERNAL_CALL.finditer(func_body))
            interface_calls = list(_INTERFACE_CALL.finditer(func_body))
            all_calls = external_calls + interface_calls

            if not all_calls:
                continue

            for call_match in all_calls:
                call_pos = call_match.start()
                # Look for state changes AFTER this external call
                after_call = func_body[call_pos + len(call_match.group()):]

                state_changes = _STATE_CHANGE.finditer(after_call)
                for sc_match in state_changes:
                    # Calculate actual line number
                    sc_pos_in_body = call_pos + len(call_match.group()) + sc_match.start()
                    sc_line = func_line + func_body[:sc_pos_in_body].count("\n")

                    # Check if the state change is on a balance-related variable
                    sc_text = sc_match.group(0).strip()
                    is_balance_related = bool(_BALANCE_PATTERN.search(sc_text))

                    # Skip event emissions (emit Foo(...))
                    context_before = after_call[max(0, sc_match.start() - 20):sc_match.start()]
                    if "emit " in context_before:
                        continue

                    severity = Severity.HIGH if is_balance_related else Severity.MEDIUM

                    findings.append(Finding(
                        analyzer=self.name,
                        title=f"CEI violation in `{func_name}`: state change after external call",
                        severity=severity,
                        file=file_path,
                        line=sc_line,
                        description=(
                            f"In function `{func_name}`, a state variable is modified "
                            f"after an external call. This violates the Checks-Effects-"
                            f"Interactions pattern and can allow an attacker to re-enter "
                            f"the function before the state update completes."
                        ),
                        recommendation=(
                            "Move all state changes before external calls (follow the "
                            "CEI pattern). Alternatively, add a `nonReentrant` modifier "
                            "from OpenZeppelin's ReentrancyGuard."
                        ),
                        code_snippet=self._extract_snippet(lines, sc_line),
                        category="SC-01: Reentrancy",
                    ))
                    break  # One finding per call is enough

        return findings

    def _check_missing_reentrancy_guard(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect functions with external calls but no nonReentrant modifier."""
        findings: list[Finding] = []
        has_guard_import = bool(_REENTRANCY_GUARD.search(content))

        functions = self._extract_functions(content)
        for func_name, func_start, func_body, func_line in functions:
            sig_end = content.find("{", func_start)
            if sig_end == -1:
                continue
            signature = content[func_start:sig_end]

            # Skip view/pure, internal/private
            if _VIEW_PURE.search(signature):
                continue
            if not re.search(r"\b(external|public)\b", signature):
                continue

            has_external_call = bool(
                _EXTERNAL_CALL.search(func_body) or _INTERFACE_CALL.search(func_body)
            )
            has_nonreentrant = bool(_NONREENTRANT.search(signature))

            if has_external_call and not has_nonreentrant:
                findings.append(Finding(
                    analyzer=self.name,
                    title=f"Missing `nonReentrant` on `{func_name}` with external calls",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=func_line,
                    description=(
                        f"Function `{func_name}` makes external calls but does not "
                        f"use the `nonReentrant` modifier. "
                        + (
                            "The contract imports ReentrancyGuard but this function "
                            "does not use it."
                            if has_guard_import
                            else "Consider adding ReentrancyGuard to the contract."
                        )
                    ),
                    recommendation=(
                        "Add the `nonReentrant` modifier to prevent reentrancy. "
                        "Import and inherit from OpenZeppelin's ReentrancyGuard."
                    ),
                    code_snippet=self._extract_snippet(lines, func_line),
                    category="SC-01: Reentrancy",
                ))

        return findings

    def _check_transfer_send_return(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect unchecked return values from .send() and low-level .call()."""
        findings: list[Finding] = []

        # Check for .send() without checking return value
        for match in re.finditer(r"\.send\s*\(", content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            line_text = lines[line_num - 1] if line_num <= len(lines) else ""
            # Check if return value is captured
            if not re.search(r"(bool\s+\w+|require)\s*.*\.send\s*\(", line_text):
                findings.append(Finding(
                    analyzer=self.name,
                    title="Unchecked return value of `.send()`",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=line_num,
                    description=(
                        "The return value of `.send()` is not checked. `.send()` "
                        "returns false on failure instead of reverting, so the "
                        "contract will continue execution even if the transfer fails."
                    ),
                    recommendation=(
                        "Use `.call{value: ...}(\"\")` with a success check, or use "
                        "OpenZeppelin's `Address.sendValue()`. Alternatively, wrap "
                        "in `require()`."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-01: Reentrancy",
                ))

        return findings

    def _check_cross_function_reentrancy(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect potential cross-function reentrancy via shared state variables.

        If function A makes an external call and function B reads/writes
        the same state variable, cross-function reentrancy may be possible.
        """
        findings: list[Finding] = []
        functions = self._extract_functions(content)

        # Build a map: func_name -> (has_external_call, state_vars_modified, line)
        func_info: dict[str, tuple[bool, set[str], int]] = {}
        for func_name, func_start, func_body, func_line in functions:
            has_call = bool(
                _EXTERNAL_CALL.search(func_body) or _INTERFACE_CALL.search(func_body)
            )
            modified_vars: set[str] = set()
            for m in _STATE_CHANGE.finditer(func_body):
                for g in m.groups():
                    if g and not g.startswith(("uint", "int", "bool", "address", "bytes", "string")):
                        modified_vars.add(g)
            func_info[func_name] = (has_call, modified_vars, func_line)

        # Look for pairs where func A has external call + state change,
        # and func B touches the same state variable
        reported: set[tuple[str, str]] = set()
        for func_a, (has_call_a, vars_a, line_a) in func_info.items():
            if not has_call_a or not vars_a:
                continue
            for func_b, (_, vars_b, line_b) in func_info.items():
                if func_a == func_b:
                    continue
                shared = vars_a & vars_b
                pair_key = (min(func_a, func_b), max(func_a, func_b))
                if shared and pair_key not in reported:
                    reported.add(pair_key)
                    # Filter out common non-state false positives
                    shared_filtered = {
                        v for v in shared
                        if v not in ("i", "j", "k", "success", "result", "amount", "value", "data")
                    }
                    if not shared_filtered:
                        continue

                    findings.append(Finding(
                        analyzer=self.name,
                        title=f"Potential cross-function reentrancy: `{func_a}` and `{func_b}`",
                        severity=Severity.MEDIUM,
                        file=file_path,
                        line=line_a,
                        description=(
                            f"Functions `{func_a}` (has external call) and `{func_b}` "
                            f"both modify shared state variables: "
                            f"{', '.join(sorted(shared_filtered))}. An attacker could "
                            f"re-enter `{func_b}` during `{func_a}`'s external call "
                            f"to manipulate shared state."
                        ),
                        recommendation=(
                            "Apply `nonReentrant` to both functions, or ensure the CEI "
                            "pattern is followed with state updates before external calls "
                            "in both functions."
                        ),
                        code_snippet=self._extract_snippet(lines, line_a),
                        category="SC-01: Reentrancy",
                    ))

        return findings

    def _check_read_only_reentrancy(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect read-only reentrancy where view functions read stale state.

        If a non-view function makes an external call before updating state,
        and a view function reads that same state, an attacker can get stale
        reads during the callback.
        """
        findings: list[Finding] = []
        functions = self._extract_functions(content)

        # Identify view functions that read balance-like state
        view_funcs_with_state: list[tuple[str, int]] = []
        state_modifying_with_calls: list[tuple[str, int]] = []

        for func_name, func_start, func_body, func_line in functions:
            sig_end = content.find("{", func_start)
            if sig_end == -1:
                continue
            signature = content[func_start:sig_end]

            if _VIEW_PURE.search(signature) and _BALANCE_PATTERN.search(func_body):
                view_funcs_with_state.append((func_name, func_line))
            elif not _VIEW_PURE.search(signature):
                has_call = bool(
                    _EXTERNAL_CALL.search(func_body) or _INTERFACE_CALL.search(func_body)
                )
                has_balance_mod = bool(_BALANCE_PATTERN.search(func_body))
                if has_call and has_balance_mod:
                    state_modifying_with_calls.append((func_name, func_line))

        if view_funcs_with_state and state_modifying_with_calls:
            for mod_func, mod_line in state_modifying_with_calls:
                for view_func, view_line in view_funcs_with_state:
                    findings.append(Finding(
                        analyzer=self.name,
                        title=f"Read-only reentrancy risk: `{view_func}` may return stale data",
                        severity=Severity.LOW,
                        file=file_path,
                        line=view_line,
                        description=(
                            f"View function `{view_func}` reads balance/share state that "
                            f"is also modified by `{mod_func}` (which has external calls). "
                            f"If `{mod_func}` makes an external call before updating state, "
                            f"a callback could invoke `{view_func}` and get stale values. "
                            f"This is exploitable if other protocols rely on this view function."
                        ),
                        recommendation=(
                            "Ensure state is updated before external calls in "
                            f"`{mod_func}`. If this view function is used by external "
                            "protocols for pricing, consider adding reentrancy protection."
                        ),
                        code_snippet=self._extract_snippet(lines, view_line),
                        category="SC-01: Reentrancy",
                    ))

        return findings

    def _check_raw_call_value(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect raw .call{value:} patterns that may be vulnerable."""
        findings: list[Finding] = []

        for match in re.finditer(r"\.call\s*\{[^}]*value\s*:", content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Check if success is validated
            before_context = content[max(0, match.start() - 100): match.start()]
            after_context = content[match.end(): match.end() + 200]

            success_checked = bool(re.search(
                r"\(bool\s+(\w+)\s*,|require\s*\(\s*success",
                before_context + after_context,
            ))

            if not success_checked:
                findings.append(Finding(
                    analyzer=self.name,
                    title="Unchecked low-level call with value",
                    severity=Severity.HIGH,
                    file=file_path,
                    line=line_num,
                    description=(
                        "A low-level `.call{value: ...}` is used without checking "
                        "the return value. If the call fails (e.g., the recipient "
                        "reverts or runs out of gas), the transaction will silently "
                        "continue, potentially losing funds."
                    ),
                    recommendation=(
                        "Always check the boolean return value: "
                        "`(bool success, ) = addr.call{value: amount}(\"\"); "
                        "require(success);`"
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-01: Reentrancy",
                ))

        return findings

    def _check_callback_patterns(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect callback function patterns that might be reentrancy entry points."""
        findings: list[Finding] = []

        callback_patterns = [
            (r"function\s+onERC721Received\s*\(", "ERC721 callback"),
            (r"function\s+onERC1155Received\s*\(", "ERC1155 callback"),
            (r"function\s+onERC1155BatchReceived\s*\(", "ERC1155 batch callback"),
            (r"function\s+tokensReceived\s*\(", "ERC777 tokensReceived callback"),
            (r"function\s+onFlashLoan\s*\(", "Flash loan callback"),
            (r"function\s+uniswapV[23]", "Uniswap callback"),
            (r"receive\s*\(\s*\)\s*external\s+payable", "receive() fallback"),
            (r"fallback\s*\(\s*\)\s*external", "fallback() function"),
        ]

        for pattern, callback_type in callback_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[: match.start()].count("\n") + 1
                if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                    continue

                # Check if the callback has state modifications
                brace_start = content.find("{", match.end())
                if brace_start == -1:
                    continue
                brace_end = self._find_matching_brace(content, brace_start)
                body = content[brace_start:brace_end]

                has_state_change = bool(_STATE_CHANGE.search(body))

                if has_state_change:
                    findings.append(Finding(
                        analyzer=self.name,
                        title=f"State-modifying {callback_type} detected",
                        severity=Severity.MEDIUM,
                        file=file_path,
                        line=line_num,
                        description=(
                            f"The {callback_type} modifies contract state. This "
                            f"function is called by external contracts during token "
                            f"transfers/operations and can be used as a reentrancy "
                            f"entry point."
                        ),
                        recommendation=(
                            "Ensure that all callers of this callback are protected "
                            "with `nonReentrant`. Review the callback logic carefully "
                            "for state consistency."
                        ),
                        code_snippet=self._extract_snippet(lines, line_num),
                        category="SC-01: Reentrancy",
                    ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_functions(
        self, content: str
    ) -> list[tuple[str, int, str, int]]:
        """Extract all function bodies from Solidity source.

        Returns:
            List of (func_name, start_index, body_text, line_number) tuples.
        """
        results: list[tuple[str, int, str, int]] = []
        for match in _FUNC_DEF.finditer(content):
            func_name = match.group(1)
            func_start = match.start()
            line_num = content[:func_start].count("\n") + 1

            # Find the function body
            brace_start = match.end() - 1  # The '{' is the last char in the match
            brace_end = self._find_matching_brace(content, brace_start)
            body = content[brace_start:brace_end]
            results.append((func_name, func_start, body, line_num))
        return results

    def _find_matching_brace(self, content: str, start: int) -> int:
        """Find the index past the closing brace matching the opening brace at `start`."""
        depth = 0
        i = start
        while i < len(content):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return len(content)
