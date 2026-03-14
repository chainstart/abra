"""Static analyzer for access control vulnerabilities in Solidity contracts.

Detects:
- Public/external functions missing access modifiers
- Unprotected selfdestruct and delegatecall
- Missing zero-address checks in constructors and setters
- tx.origin usage (phishing vulnerability)
- Unprotected initialization functions
- Admin/owner privilege and centralization risks
- OpenZeppelin AccessControl pattern issues
"""

import re
from pathlib import Path

from .base import BaseAnalyzer, Finding, Severity


# Patterns that indicate an access control modifier or guard is present
_ACCESS_MODIFIERS = re.compile(
    r"\b(onlyOwner|onlyRole|onlyAdmin|onlyGovernance|onlyMinter|"
    r"onlyOperator|onlyController|onlyAuthorized|onlyGuardian|"
    r"whenNotPaused|initializer|reinitializer|nonReentrant)\b"
)

_REQUIRE_SENDER_CHECK = re.compile(
    r"require\s*\(\s*msg\.sender\s*==|"
    r"require\s*\(\s*_msgSender\(\)\s*==|"
    r"if\s*\(\s*msg\.sender\s*!=.*revert|"
    r"_checkOwner\(\)|"
    r"_checkRole\("
)

# Sensitive operations that must always be protected
_SELFDESTRUCT_PATTERN = re.compile(r"\bselfdestruct\s*\(")
_DELEGATECALL_PATTERN = re.compile(r"\.delegatecall\s*\(")
_TX_ORIGIN_PATTERN = re.compile(r"\btx\.origin\b")

# Function definition patterns
_FUNC_DEF = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s+(external|public)([^{]*)\{"
)

# Functions that are commonly sensitive and should be protected
_SENSITIVE_FUNC_NAMES = re.compile(
    r"^(set|update|change|modify|configure|add|remove|delete|grant|revoke|"
    r"pause|unpause|withdraw|transfer|mint|burn|upgrade|migrate|emergency|"
    r"rescue|recover|sweep|kill|destroy|toggle|enable|disable|whitelist|"
    r"blacklist|freeze|unfreeze)\w*$",
    re.IGNORECASE,
)

# Initializer patterns
_INIT_FUNC = re.compile(
    r"function\s+(initialize|init|setup|configure)\s*\(",
    re.IGNORECASE,
)

# Zero address literal
_ZERO_ADDR_CHECK = re.compile(
    r"require\s*\([^)]*!=\s*address\s*\(\s*0\s*\)|"
    r"if\s*\([^)]*==\s*address\s*\(\s*0\s*\)\s*\)\s*revert|"
    r"require\s*\([^)]*!=\s*address\s*\(0x0+\)|"
    r"_require\([^)]*!=\s*address\s*\(\s*0\s*\)"
)

# Constructor
_CONSTRUCTOR = re.compile(r"\bconstructor\s*\(([^)]*)\)")

# Address parameter
_ADDR_PARAM = re.compile(r"address\s+(?:payable\s+)?(\w+)")

# Ownership renounce / transfer
_OWNERSHIP_TRANSFER = re.compile(
    r"\b(renounceOwnership|transferOwnership)\s*\("
)

# OpenZeppelin AccessControl role management
_ROLE_MANAGEMENT = re.compile(
    r"\b(grantRole|revokeRole|renounceRole|_setupRole|_grantRole)\s*\("
)


class AccessControlAnalyzer(BaseAnalyzer):
    """Analyzes Solidity contracts for access control vulnerabilities."""

    name = "access-control"
    description = "Detects access control vulnerabilities and centralization risks"

    def analyze(self, file_path: str) -> list[Finding]:
        """Run all access control checks on a Solidity file.

        Args:
            file_path: Path to the .sol file.

        Returns:
            List of findings related to access control issues.
        """
        content, lines = self._read_source(file_path)
        if not content:
            return []

        findings: list[Finding] = []
        findings.extend(self._check_unprotected_functions(file_path, content, lines))
        findings.extend(self._check_selfdestruct(file_path, content, lines))
        findings.extend(self._check_delegatecall(file_path, content, lines))
        findings.extend(self._check_tx_origin(file_path, content, lines))
        findings.extend(self._check_missing_zero_address(file_path, content, lines))
        findings.extend(self._check_unprotected_initializer(file_path, content, lines))
        findings.extend(self._check_centralization_risks(file_path, content, lines))
        findings.extend(self._check_role_management(file_path, content, lines))
        findings.extend(self._check_missing_two_step_ownership(file_path, content, lines))
        findings.extend(self._check_unrestricted_setter(file_path, content, lines))
        return findings

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _check_unprotected_functions(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect public/external functions with sensitive names lacking access control."""
        findings: list[Finding] = []
        for match in _FUNC_DEF.finditer(content):
            func_name = match.group(1)
            visibility = match.group(3)
            modifiers_section = match.group(4)
            line_num = content[: match.start()].count("\n") + 1

            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Skip view/pure functions -- they don't modify state
            if re.search(r"\b(view|pure)\b", modifiers_section):
                continue

            if not _SENSITIVE_FUNC_NAMES.match(func_name):
                continue

            # Check if modifiers section contains access control
            has_modifier = bool(_ACCESS_MODIFIERS.search(modifiers_section))

            # Also check the first few lines of the function body for require checks
            body_start = match.end()
            body_preview = content[body_start: body_start + 500]
            has_require = bool(_REQUIRE_SENDER_CHECK.search(body_preview))

            if not has_modifier and not has_require:
                findings.append(Finding(
                    analyzer=self.name,
                    title=f"Unprotected sensitive function `{func_name}`",
                    severity=Severity.HIGH,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"The {visibility} function `{func_name}` performs a sensitive "
                        f"operation but lacks access control modifiers or require-based "
                        f"sender checks. Any external account can call this function."
                    ),
                    recommendation=(
                        "Add an access control modifier such as `onlyOwner`, `onlyRole(...)`, "
                        "or a `require(msg.sender == ...)` check to restrict who can call "
                        "this function."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-02: Access Control",
                ))
        return findings

    def _check_selfdestruct(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect unprotected selfdestruct calls."""
        findings: list[Finding] = []
        for match in _SELFDESTRUCT_PATTERN.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Walk backwards to find the enclosing function and check its modifiers
            func_context = content[max(0, match.start() - 1000): match.start()]
            has_protection = bool(
                _ACCESS_MODIFIERS.search(func_context)
                or _REQUIRE_SENDER_CHECK.search(func_context)
            )

            severity = Severity.MEDIUM if has_protection else Severity.CRITICAL
            title = (
                "Selfdestruct usage detected"
                if has_protection
                else "Unprotected selfdestruct"
            )

            findings.append(Finding(
                analyzer=self.name,
                title=title,
                severity=severity,
                file=file_path,
                line=line_num,
                description=(
                    "The contract contains a `selfdestruct` call. "
                    + ("" if has_protection else "No access control was found protecting this call. ")
                    + "After EIP-6780, selfdestruct only sends ETH unless called in the "
                    "same transaction as contract creation. It can still be dangerous in "
                    "proxy patterns."
                ),
                recommendation=(
                    "Remove selfdestruct if possible. If needed, ensure it is behind "
                    "strict access control (multi-sig or timelock). Consider the "
                    "implications for proxies and EIP-6780."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-02: Access Control",
            ))
        return findings

    def _check_delegatecall(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect potentially unsafe delegatecall usage."""
        findings: list[Finding] = []
        for match in _DELEGATECALL_PATTERN.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            func_context = content[max(0, match.start() - 1000): match.start()]
            has_protection = bool(
                _ACCESS_MODIFIERS.search(func_context)
                or _REQUIRE_SENDER_CHECK.search(func_context)
            )

            findings.append(Finding(
                analyzer=self.name,
                title="Delegatecall usage" + ("" if has_protection else " without access control"),
                severity=Severity.HIGH if not has_protection else Severity.MEDIUM,
                file=file_path,
                line=line_num,
                description=(
                    "The contract uses `delegatecall` which executes external code in "
                    "the context of this contract's storage. "
                    + ("No access control was detected around this call." if not has_protection else "")
                ),
                recommendation=(
                    "Ensure delegatecall targets are trusted, immutable, or controlled "
                    "by strict access control. Validate the target address is not "
                    "user-controlled."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-02: Access Control",
            ))
        return findings

    def _check_tx_origin(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect tx.origin usage which is vulnerable to phishing attacks."""
        findings: list[Finding] = []
        for match in _TX_ORIGIN_PATTERN.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Check if used for authentication (== comparison)
            line_text = lines[line_num - 1] if line_num <= len(lines) else ""
            is_auth_use = "==" in line_text or "require" in line_text

            findings.append(Finding(
                analyzer=self.name,
                title="Usage of `tx.origin`" + (" for authentication" if is_auth_use else ""),
                severity=Severity.HIGH if is_auth_use else Severity.LOW,
                file=file_path,
                line=line_num,
                description=(
                    "`tx.origin` returns the original sender of the transaction, not the "
                    "immediate caller. Using it for authentication is vulnerable to "
                    "phishing attacks where a malicious contract tricks a user into "
                    "calling it, then forwards the call to the victim contract."
                ),
                recommendation=(
                    "Replace `tx.origin` with `msg.sender` for authentication. "
                    "`tx.origin` is only safe for checking that a call was initiated "
                    "by an EOA (not a contract), but even that has edge cases."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-02: Access Control",
            ))
        return findings

    def _check_missing_zero_address(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect address parameters in constructors/setters without zero-address checks."""
        findings: list[Finding] = []

        # Check constructors
        for match in _CONSTRUCTOR.finditer(content):
            params = match.group(1)
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            addr_params = _ADDR_PARAM.findall(params)
            if not addr_params:
                continue

            # Check constructor body for zero-address validation
            body_start = content.find("{", match.end())
            if body_start == -1:
                continue
            body_end = self._find_matching_brace(content, body_start)
            body = content[body_start:body_end]

            for param_name in addr_params:
                # Check if there's a zero-address check for this parameter
                param_check = re.search(
                    rf"{re.escape(param_name)}\s*!=\s*address\s*\(\s*0\s*\)|"
                    rf"address\s*\(\s*0\s*\)\s*!=\s*{re.escape(param_name)}",
                    body,
                )
                if not param_check and not _ZERO_ADDR_CHECK.search(body):
                    findings.append(Finding(
                        analyzer=self.name,
                        title=f"Missing zero-address check for `{param_name}` in constructor",
                        severity=Severity.LOW,
                        file=file_path,
                        line=line_num,
                        description=(
                            f"The constructor accepts address parameter `{param_name}` "
                            f"but does not validate that it is not the zero address. "
                            f"Accidentally passing address(0) could brick the contract."
                        ),
                        recommendation=(
                            f"Add `require({param_name} != address(0), \"zero address\");` "
                            f"or use a custom error for gas efficiency."
                        ),
                        code_snippet=self._extract_snippet(lines, line_num),
                        category="SC-07: Input Validation",
                    ))
        return findings

    def _check_unprotected_initializer(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect initialize functions without the initializer modifier."""
        findings: list[Finding] = []
        for match in _INIT_FUNC.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Get the full function signature line(s)
            sig_end = content.find("{", match.start())
            if sig_end == -1:
                continue
            signature = content[match.start(): sig_end]

            has_initializer = bool(re.search(r"\binitializer\b", signature))
            has_reinitializer = bool(re.search(r"\breinitializer\b", signature))

            if not has_initializer and not has_reinitializer:
                findings.append(Finding(
                    analyzer=self.name,
                    title="Initialization function without `initializer` modifier",
                    severity=Severity.CRITICAL,
                    file=file_path,
                    line=line_num,
                    description=(
                        "The function appears to be an initialization function but "
                        "does not use the `initializer` or `reinitializer` modifier. "
                        "This means it can be called multiple times, potentially allowing "
                        "an attacker to re-initialize the contract and take ownership."
                    ),
                    recommendation=(
                        "Add the `initializer` modifier from OpenZeppelin's "
                        "`Initializable` contract to ensure it can only be called once."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-02: Access Control",
                ))
        return findings

    def _check_centralization_risks(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect admin functions that pose centralization risks."""
        findings: list[Finding] = []

        # Detect single-owner patterns with powerful capabilities
        dangerous_owner_funcs = re.finditer(
            r"function\s+(\w+)\s*\([^)]*\)\s+external[^{]*\bonlyOwner\b[^{]*\{",
            content,
        )
        owner_func_names: list[str] = []
        for match in dangerous_owner_funcs:
            func_name = match.group(1)
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue
            owner_func_names.append(func_name)

            # Check if the function body has particularly risky operations
            body_start = match.end() - 1
            body_end = self._find_matching_brace(content, body_start)
            body = content[body_start:body_end]

            risky_ops = []
            if re.search(r"\.transfer\(|\.call\{value:", body):
                risky_ops.append("ETH transfer")
            if re.search(r"\.transferFrom\(|\.safeTransferFrom\(|\.safeTransfer\(", body):
                risky_ops.append("token transfer")
            if re.search(r"selfdestruct\(", body):
                risky_ops.append("selfdestruct")

            if risky_ops:
                findings.append(Finding(
                    analyzer=self.name,
                    title=f"Centralization risk: `{func_name}` allows owner to {', '.join(risky_ops)}",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"The onlyOwner function `{func_name}` can perform: "
                        f"{', '.join(risky_ops)}. A compromised or malicious owner "
                        f"could exploit this to drain funds or destroy the contract."
                    ),
                    recommendation=(
                        "Consider using a multi-sig wallet or timelock for the owner "
                        "address. Add event emissions for transparency. Consider "
                        "decentralizing control via a DAO or role-based access."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-13: Centralization Risk",
                ))

        return findings

    def _check_role_management(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Check for issues in OpenZeppelin AccessControl usage."""
        findings: list[Finding] = []

        # Detect DEFAULT_ADMIN_ROLE granted to deployer without rotation
        if "DEFAULT_ADMIN_ROLE" in content:
            for match in re.finditer(r"_grantRole\s*\(\s*DEFAULT_ADMIN_ROLE", content):
                line_num = content[: match.start()].count("\n") + 1
                if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                    continue

                findings.append(Finding(
                    analyzer=self.name,
                    title="DEFAULT_ADMIN_ROLE granted -- review admin rotation",
                    severity=Severity.INFO,
                    file=file_path,
                    line=line_num,
                    description=(
                        "The DEFAULT_ADMIN_ROLE is being granted. This role can grant "
                        "and revoke any other role. Ensure proper admin rotation and "
                        "consider revoking the deployer's admin role after setup."
                    ),
                    recommendation=(
                        "Implement admin role rotation. Consider using "
                        "AccessControlDefaultAdminRules for a two-step admin transfer "
                        "with a delay."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-02: Access Control",
                ))

        return findings

    def _check_missing_two_step_ownership(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect single-step ownership transfer without confirmation."""
        findings: list[Finding] = []

        for match in _OWNERSHIP_TRANSFER.finditer(content):
            func_name = match.group(1)
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Check if the contract uses Ownable2Step
            uses_two_step = "Ownable2Step" in content or "acceptOwnership" in content

            if func_name == "transferOwnership" and not uses_two_step:
                findings.append(Finding(
                    analyzer=self.name,
                    title="Single-step ownership transfer",
                    severity=Severity.LOW,
                    file=file_path,
                    line=line_num,
                    description=(
                        "Ownership is transferred in a single step via `transferOwnership`. "
                        "If the new owner address is incorrect, ownership is permanently "
                        "lost with no recovery mechanism."
                    ),
                    recommendation=(
                        "Use OpenZeppelin's `Ownable2Step` which requires the new owner "
                        "to call `acceptOwnership()`, preventing accidental transfers "
                        "to wrong addresses."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-02: Access Control",
                ))
            elif func_name == "renounceOwnership":
                findings.append(Finding(
                    analyzer=self.name,
                    title="Ownership renunciation detected",
                    severity=Severity.INFO,
                    file=file_path,
                    line=line_num,
                    description=(
                        "`renounceOwnership` is called, which permanently removes the "
                        "owner. Ensure all owner-only configurations are finalized "
                        "before renouncing."
                    ),
                    recommendation=(
                        "Verify that all necessary setup is complete before calling "
                        "renounceOwnership. Consider if future upgrades or parameter "
                        "changes might be needed."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-02: Access Control",
                ))

        return findings

    def _check_unrestricted_setter(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect setter functions that allow setting critical parameters without bounds."""
        findings: list[Finding] = []

        # Look for functions that set fee/rate/limit parameters
        fee_setters = re.finditer(
            r"function\s+(set\w*(?:Fee|Rate|Limit|Max|Min|Threshold|Delay)\w*)\s*\("
            r"([^)]*)\)\s+(external|public)([^{]*)\{",
            content,
            re.IGNORECASE,
        )

        for match in fee_setters:
            func_name = match.group(1)
            line_num = content[: match.start()].count("\n") + 1
            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Check body for bounds checking
            body_start = match.end() - 1
            body_end = self._find_matching_brace(content, body_start)
            body = content[body_start:body_end]

            has_bounds = bool(re.search(
                r"require\s*\([^)]*[<>]=?|"
                r"if\s*\([^)]*[<>]=?[^)]*\)\s*revert",
                body,
            ))

            if not has_bounds:
                findings.append(Finding(
                    analyzer=self.name,
                    title=f"Setter `{func_name}` lacks bounds validation",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"The function `{func_name}` sets a critical parameter but "
                        f"does not validate input bounds. An owner could set the value "
                        f"to an extreme (e.g., 100% fee) to extract user funds."
                    ),
                    recommendation=(
                        "Add upper/lower bound checks. For fees, enforce a maximum "
                        "(e.g., `require(fee <= MAX_FEE)`). Emit events on changes "
                        "for off-chain monitoring."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-07: Input Validation",
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _find_matching_brace(self, content: str, start: int) -> int:
        """Find the index of the closing brace matching the opening brace at `start`.

        Args:
            content: Full source code string.
            start: Index of the opening '{'.

        Returns:
            Index just past the matching '}', or end of content if not found.
        """
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
