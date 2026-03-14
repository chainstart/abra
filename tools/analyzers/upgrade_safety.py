"""Static analyzer for proxy/upgrade safety issues in Solidity contracts.

Detects:
- delegatecall usage patterns
- Uninitialized proxy contracts (missing initializer modifier)
- Storage collision risks in upgradeable contracts
- Missing _disableInitializers() in implementation constructors
- selfdestruct in implementation contracts
- State variable ordering issues (storage gap patterns)
- Function selector clashes between proxy and implementation
"""

import re
import hashlib
from pathlib import Path

from .base import BaseAnalyzer, Finding, Severity


# Upgradeable contract patterns
_UPGRADEABLE_IMPORT = re.compile(
    r"import\s+.*(?:Upgradeable|UUPSUpgradeable|TransparentUpgradeable|"
    r"BeaconProxy|ERC1967|Initializable|Proxy)",
    re.IGNORECASE,
)

_IS_UPGRADEABLE = re.compile(
    r"\bis\s+[^{]*(?:Upgradeable|UUPSUpgradeable|Initializable|OwnableUpgradeable|"
    r"PausableUpgradeable|ReentrancyGuardUpgradeable|ERC\d+Upgradeable)",
)

# Proxy patterns
_PROXY_CONTRACT = re.compile(
    r"contract\s+\w+\s+is\s+[^{]*(?:Proxy|ERC1967Proxy|TransparentUpgradeableProxy|"
    r"BeaconProxy|UUPSUpgradeable)"
)

# Constructor patterns
_CONSTRUCTOR = re.compile(r"\bconstructor\s*\([^)]*\)\s*([^{]*)\{")
_EMPTY_CONSTRUCTOR = re.compile(r"\bconstructor\s*\(\s*\)\s*\{")

# Disable initializers pattern
_DISABLE_INITIALIZERS = re.compile(
    r"_disableInitializers\s*\(\s*\)"
)

# Storage gap pattern
_STORAGE_GAP = re.compile(
    r"uint256\s*\[\s*(\d+)\s*\]\s+(?:private\s+)?__gap\s*;"
)

# State variable declarations (for ordering analysis)
_STATE_VAR = re.compile(
    r"^\s*(mapping|address|uint\d*|int\d*|bool|bytes\d*|string|"
    r"struct\s+\w+|enum\s+\w+|\w+\[\])\s+"
    r"(?:public\s+|private\s+|internal\s+|immutable\s+|constant\s+)*"
    r"(\w+)\s*(?:=|;)",
    re.MULTILINE,
)

# Initializer modifier
_INITIALIZER_MOD = re.compile(r"\binitializer\b")
_REINITIALIZER_MOD = re.compile(r"\breinitializer\b")

# Initialize function
_INIT_FUNC = re.compile(
    r"function\s+(initialize\w*|__\w+_init(?:_unchained)?)\s*\(",
)

# selfdestruct
_SELFDESTRUCT = re.compile(r"\bselfdestruct\s*\(")

# delegatecall
_DELEGATECALL = re.compile(r"\.delegatecall\s*\(")

# Storage slot constants (EIP-1967)
_STORAGE_SLOT = re.compile(
    r"bytes32\s+(?:private\s+|internal\s+|public\s+)?(?:constant\s+)?"
    r"(\w+)\s*=\s*(0x[0-9a-fA-F]+|keccak256\([^)]+\))"
)

# Implementation slot pattern
_IMPLEMENTATION_SLOT = re.compile(
    r"(?:IMPLEMENTATION_SLOT|_IMPLEMENTATION_SLOT|"
    r"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)"
)

# Function definitions (for selector clash detection)
_FUNC_DEF = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)"
)

# Admin slot
_ADMIN_SLOT = re.compile(
    r"(?:ADMIN_SLOT|_ADMIN_SLOT|"
    r"0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103)"
)

# Immutable variables in upgradeable contracts
_IMMUTABLE_VAR = re.compile(
    r"\b(address|uint\d*|int\d*|bool|bytes\d*)\s+(?:public\s+|private\s+|internal\s+)?"
    r"immutable\s+(\w+)"
)


class UpgradeSafetyAnalyzer(BaseAnalyzer):
    """Analyzes Solidity contracts for proxy/upgrade safety issues."""

    name = "upgrade-safety"
    description = "Detects proxy/upgrade risks: storage collisions, initialization, selfdestruct"

    def analyze(self, file_path: str) -> list[Finding]:
        """Run all upgrade safety checks on a Solidity file.

        Args:
            file_path: Path to the .sol file.

        Returns:
            List of findings related to upgrade safety issues.
        """
        content, lines = self._read_source(file_path)
        if not content:
            return []

        findings: list[Finding] = []

        # Always check these regardless of upgradeable status
        findings.extend(self._check_delegatecall_safety(file_path, content, lines))

        # Check if this contract is part of an upgradeable system
        is_upgradeable = bool(
            _UPGRADEABLE_IMPORT.search(content)
            or _IS_UPGRADEABLE.search(content)
            or _PROXY_CONTRACT.search(content)
        )

        if is_upgradeable:
            findings.extend(self._check_missing_disable_initializers(file_path, content, lines))
            findings.extend(self._check_missing_storage_gap(file_path, content, lines))
            findings.extend(self._check_selfdestruct_in_implementation(file_path, content, lines))
            findings.extend(self._check_initializer_modifier(file_path, content, lines))
            findings.extend(self._check_constructor_in_upgradeable(file_path, content, lines))
            findings.extend(self._check_immutable_in_upgradeable(file_path, content, lines))
            findings.extend(self._check_init_chain(file_path, content, lines))
            findings.extend(self._check_function_selector_clash(file_path, content, lines))
            findings.extend(self._check_storage_slot_collisions(file_path, content, lines))
        else:
            # For non-upgradeable contracts, still check for potential upgrade patterns
            findings.extend(self._check_accidental_upgradeability(file_path, content, lines))

        return findings

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _check_delegatecall_safety(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect potentially unsafe delegatecall patterns."""
        findings: list[Finding] = []

        for match in _DELEGATECALL.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            # Check if the target address is hardcoded / immutable
            context_before = content[max(0, match.start() - 200): match.start()]
            line_text = lines[line_num - 1] if line_num <= len(lines) else ""

            # Check if target is a variable that could be user-controlled
            target_match = re.search(r"(\w+)\.delegatecall", line_text)
            if target_match:
                target_var = target_match.group(1)
                # Check if target is a function parameter
                func_context = content[max(0, match.start() - 1000): match.start()]
                is_param = bool(re.search(
                    rf"function\s+\w+\s*\([^)]*\b{re.escape(target_var)}\b",
                    func_context,
                ))

                if is_param:
                    findings.append(Finding(
                        analyzer=self.name,
                        title="Delegatecall with user-controlled target",
                        severity=Severity.CRITICAL,
                        file=file_path,
                        line=line_num,
                        description=(
                            f"The `delegatecall` target `{target_var}` appears to be "
                            f"a function parameter, meaning a caller could execute "
                            f"arbitrary code in this contract's storage context. This "
                            f"allows an attacker to overwrite any storage slot."
                        ),
                        recommendation=(
                            "Never allow user-controlled addresses as delegatecall "
                            "targets. Use a whitelist of approved implementation "
                            "addresses or restrict to owner-set immutable addresses."
                        ),
                        code_snippet=self._extract_snippet(lines, line_num),
                        category="SC-10: Proxy/Upgrade",
                    ))

        return findings

    def _check_missing_disable_initializers(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect implementation contracts missing _disableInitializers() in constructor."""
        findings: list[Finding] = []

        has_initializable = bool(re.search(r"\bInitializable\b", content))
        if not has_initializable:
            return findings

        # Check if there is a constructor
        constructor_match = _CONSTRUCTOR.search(content)
        if constructor_match:
            # Check if _disableInitializers is called in the constructor
            brace_start = content.find("{", constructor_match.start())
            if brace_start != -1:
                brace_end = self._find_matching_brace(content, brace_start)
                constructor_body = content[brace_start:brace_end]

                if not _DISABLE_INITIALIZERS.search(constructor_body):
                    line_num = content[: constructor_match.start()].count("\n") + 1
                    findings.append(Finding(
                        analyzer=self.name,
                        title="Missing `_disableInitializers()` in constructor",
                        severity=Severity.HIGH,
                        file=file_path,
                        line=line_num,
                        description=(
                            "The upgradeable implementation contract has a constructor "
                            "that does not call `_disableInitializers()`. Without this, "
                            "an attacker can call the `initialize` function directly on "
                            "the implementation contract (not the proxy), potentially "
                            "taking control of it and using it for selfdestruct attacks."
                        ),
                        recommendation=(
                            "Add `_disableInitializers()` to the constructor:\n"
                            "```\n"
                            "constructor() {\n"
                            "    _disableInitializers();\n"
                            "}\n"
                            "```"
                        ),
                        code_snippet=self._extract_snippet(lines, line_num),
                        category="SC-10: Proxy/Upgrade",
                    ))
        else:
            # No constructor at all -- should add one with _disableInitializers
            contract_match = re.search(r"\bcontract\s+(\w+)", content)
            if contract_match:
                line_num = content[: contract_match.start()].count("\n") + 1
                findings.append(Finding(
                    analyzer=self.name,
                    title="Upgradeable contract missing constructor with `_disableInitializers()`",
                    severity=Severity.HIGH,
                    file=file_path,
                    line=line_num,
                    description=(
                        "This upgradeable contract does not have a constructor. "
                        "Implementation contracts should have a constructor that "
                        "calls `_disableInitializers()` to prevent direct "
                        "initialization of the implementation."
                    ),
                    recommendation=(
                        "Add a constructor:\n"
                        "```\n"
                        "/// @custom:oz-upgrades-unsafe-allow constructor\n"
                        "constructor() {\n"
                        "    _disableInitializers();\n"
                        "}\n"
                        "```"
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-10: Proxy/Upgrade",
                ))

        return findings

    def _check_missing_storage_gap(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect missing storage gaps in upgradeable base contracts."""
        findings: list[Finding] = []

        # Check if this is a base contract (likely to be inherited)
        is_abstract = "abstract" in content.split("contract")[0] if "contract" in content else False
        has_state_vars = bool(_STATE_VAR.search(content))

        if not has_state_vars:
            return findings

        has_gap = bool(_STORAGE_GAP.search(content))
        gap_match = _STORAGE_GAP.search(content)

        if not has_gap and is_abstract:
            contract_match = re.search(r"\bcontract\s+(\w+)", content)
            if contract_match:
                line_num = content[: contract_match.start()].count("\n") + 1
                findings.append(Finding(
                    analyzer=self.name,
                    title="Missing storage gap in upgradeable base contract",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=line_num,
                    description=(
                        "This abstract/base upgradeable contract declares state "
                        "variables but does not include a `__gap` storage array. "
                        "Without a gap, adding new state variables in a future "
                        "version will shift the storage layout of derived contracts, "
                        "causing storage collisions."
                    ),
                    recommendation=(
                        "Add a storage gap at the end of the contract:\n"
                        "```\n"
                        "uint256[50] private __gap;\n"
                        "```\n"
                        "The gap size should be chosen so that the total number of "
                        "slots used by the contract equals a round number (e.g., 50)."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-10: Proxy/Upgrade",
                ))

        # Check if gap is too small
        if gap_match:
            gap_size = int(gap_match.group(1))
            if gap_size < 10:
                line_num = content[: gap_match.start()].count("\n") + 1
                findings.append(Finding(
                    analyzer=self.name,
                    title=f"Storage gap may be too small ({gap_size} slots)",
                    severity=Severity.LOW,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"The storage gap `__gap` has only {gap_size} slots. This "
                        f"limits the number of new state variables that can be added "
                        f"in future upgrades. The standard recommendation is 50 slots."
                    ),
                    recommendation=(
                        "Increase the gap size to allow more room for future "
                        "upgrades. A common pattern is to use 50 slots minus "
                        "the number of existing state variables."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-10: Proxy/Upgrade",
                ))

        return findings

    def _check_selfdestruct_in_implementation(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect selfdestruct in upgradeable implementation contracts."""
        findings: list[Finding] = []

        for match in _SELFDESTRUCT.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            findings.append(Finding(
                analyzer=self.name,
                title="Selfdestruct in upgradeable implementation contract",
                severity=Severity.CRITICAL,
                file=file_path,
                line=line_num,
                description=(
                    "The upgradeable implementation contract contains `selfdestruct`. "
                    "If an attacker gains control of the implementation (e.g., by "
                    "initializing it directly), they could destroy it. While "
                    "EIP-6780 limits selfdestruct behavior, this is still dangerous "
                    "in proxy patterns where the implementation holds the logic."
                ),
                recommendation=(
                    "Remove `selfdestruct` from upgradeable contracts entirely. "
                    "Use the upgrade mechanism to replace logic instead."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-10: Proxy/Upgrade",
            ))

        return findings

    def _check_initializer_modifier(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect initialize functions missing the initializer modifier."""
        findings: list[Finding] = []

        for match in _INIT_FUNC.finditer(content):
            func_name = match.group(1)
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            # Get the full function signature
            sig_end = content.find("{", match.start())
            if sig_end == -1:
                continue
            signature = content[match.start():sig_end]

            has_initializer = bool(_INITIALIZER_MOD.search(signature))
            has_reinitializer = bool(_REINITIALIZER_MOD.search(signature))

            # __init_unchained functions don't need the modifier (called by parent init)
            is_unchained = "unchained" in func_name

            if not has_initializer and not has_reinitializer and not is_unchained:
                findings.append(Finding(
                    analyzer=self.name,
                    title=f"Initializer `{func_name}` missing `initializer` modifier",
                    severity=Severity.HIGH,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"The function `{func_name}` appears to be an initialization "
                        f"function in an upgradeable contract but lacks the "
                        f"`initializer` or `reinitializer` modifier. This means it "
                        f"can be called multiple times."
                    ),
                    recommendation=(
                        f"Add the `initializer` modifier to `{func_name}` to ensure "
                        f"it can only be called once. For re-initialization during "
                        f"upgrades, use `reinitializer(version)`."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-10: Proxy/Upgrade",
                ))

        return findings

    def _check_constructor_in_upgradeable(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect state changes in constructors of upgradeable contracts."""
        findings: list[Finding] = []

        constructor_match = _CONSTRUCTOR.search(content)
        if not constructor_match:
            return findings

        brace_start = content.find("{", constructor_match.start())
        if brace_start == -1:
            return findings
        brace_end = self._find_matching_brace(content, brace_start)
        body = content[brace_start:brace_end]

        # Check for state variable assignments in constructor (these won't persist in proxy)
        state_writes = re.findall(
            r"(?<!immutable\s)(\w+)\s*=\s*(?!.*immutable)",
            body,
        )

        # Filter out _disableInitializers and common safe patterns
        unsafe_writes = [
            w for w in state_writes
            if w not in ("_disableInitializers", "")
            and not w.startswith("_")
        ]

        if unsafe_writes:
            line_num = content[: constructor_match.start()].count("\n") + 1
            findings.append(Finding(
                analyzer=self.name,
                title="State variable set in constructor of upgradeable contract",
                severity=Severity.HIGH,
                file=file_path,
                line=line_num,
                description=(
                    "The constructor of this upgradeable contract sets state "
                    "variables. In a proxy pattern, the constructor runs in the "
                    "context of the implementation contract, not the proxy. "
                    "These values will NOT be available when the proxy delegates "
                    "calls to this implementation."
                ),
                recommendation=(
                    "Move state initialization to the `initialize()` function. "
                    "The constructor should only call `_disableInitializers()`. "
                    "Use `immutable` for values that truly need to be set at "
                    "deploy time (they are stored in bytecode, not storage)."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-10: Proxy/Upgrade",
            ))

        return findings

    def _check_immutable_in_upgradeable(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect immutable variables in upgradeable contracts (informational)."""
        findings: list[Finding] = []

        for match in _IMMUTABLE_VAR.finditer(content):
            var_name = match.group(2)
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            findings.append(Finding(
                analyzer=self.name,
                title=f"Immutable variable `{var_name}` in upgradeable contract",
                severity=Severity.INFO,
                file=file_path,
                line=line_num,
                description=(
                    f"The immutable variable `{var_name}` is stored in the "
                    f"implementation contract's bytecode. This is safe and "
                    f"gas-efficient, but the value will be determined when the "
                    f"implementation is deployed and cannot be changed through "
                    f"proxy upgrades."
                ),
                recommendation=(
                    "Ensure the immutable value is correct for all proxies that "
                    "will use this implementation. If different proxies need "
                    "different values, use a regular state variable set in "
                    "`initialize()` instead."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-10: Proxy/Upgrade",
            ))

        return findings

    def _check_init_chain(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect incomplete initialization chains (missing parent init calls)."""
        findings: list[Finding] = []

        # Find the inheritance list
        inherit_match = re.search(r"contract\s+\w+\s+is\s+([^{]+)\{", content)
        if not inherit_match:
            return findings

        parents = [p.strip() for p in inherit_match.group(1).split(",")]
        upgradeable_parents = [
            p for p in parents
            if "Upgradeable" in p or "Initializable" in p
        ]

        if not upgradeable_parents:
            return findings

        # Find the initialize function body
        init_match = re.search(r"function\s+initialize\w*\s*\([^)]*\)[^{]*\{", content)
        if not init_match:
            return findings

        brace_start = init_match.end() - 1
        brace_end = self._find_matching_brace(content, brace_start)
        init_body = content[brace_start:brace_end]

        # Check that each upgradeable parent's init is called
        for parent in upgradeable_parents:
            parent_base = parent.replace("Upgradeable", "")
            init_patterns = [
                f"__{parent_base}_init",
                f"__{parent}_init",
                f"{parent}.__init",
            ]
            called = any(p in init_body for p in init_patterns)
            if not called and parent != "Initializable":
                line_num = content[: init_match.start()].count("\n") + 1
                findings.append(Finding(
                    analyzer=self.name,
                    title=f"Missing initialization of parent `{parent}`",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"The `initialize` function does not appear to call the "
                        f"initialization function for parent contract `{parent}`. "
                        f"Uninitialized parent contracts may have unset state, "
                        f"potentially causing security issues."
                    ),
                    recommendation=(
                        f"Call `__{parent_base}_init(...)` or "
                        f"`__{parent_base}_init_unchained(...)` in the initialize "
                        f"function. Follow OpenZeppelin's initialization pattern."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-10: Proxy/Upgrade",
                ))

        return findings

    def _check_function_selector_clash(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect potential function selector clashes in proxy contracts."""
        findings: list[Finding] = []

        if not _PROXY_CONTRACT.search(content):
            return findings

        # Extract all function selectors
        selectors: dict[str, list[tuple[str, int]]] = {}
        for match in _FUNC_DEF.finditer(content):
            func_name = match.group(1)
            params = match.group(2)
            line_num = content[: match.start()].count("\n") + 1

            if self._is_in_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                continue

            # Compute selector (first 4 bytes of keccak256)
            param_types = self._extract_param_types(params)
            sig = f"{func_name}({','.join(param_types)})"
            selector = hashlib.sha3_256(sig.encode()).hexdigest()[:8]

            if selector not in selectors:
                selectors[selector] = []
            selectors[selector].append((func_name, line_num))

        # Check for clashes
        for selector, funcs in selectors.items():
            if len(funcs) > 1:
                names = ", ".join(f"`{f[0]}`" for f in funcs)
                findings.append(Finding(
                    analyzer=self.name,
                    title=f"Function selector clash: {names}",
                    severity=Severity.HIGH,
                    file=file_path,
                    line=funcs[0][1],
                    description=(
                        f"Functions {names} have the same 4-byte selector (0x{selector}). "
                        f"In a proxy contract, this can cause the proxy to intercept "
                        f"calls intended for the implementation, or vice versa."
                    ),
                    recommendation=(
                        "Rename one of the clashing functions. Use the "
                        "`@custom:oz-upgrades-unsafe-allow` annotation if the "
                        "clash is intentional."
                    ),
                    code_snippet=self._extract_snippet(lines, funcs[0][1]),
                    category="SC-10: Proxy/Upgrade",
                ))

        return findings

    def _check_storage_slot_collisions(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect custom storage slots that might collide with EIP-1967 slots."""
        findings: list[Finding] = []

        # Known EIP-1967 slots
        eip1967_slots = {
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": "implementation",
            "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": "admin",
            "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50": "beacon",
        }

        for match in _STORAGE_SLOT.finditer(content):
            slot_name = match.group(1)
            slot_value = match.group(2)
            line_num = content[: match.start()].count("\n") + 1

            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            # Check if it's a keccak256 computation that might collide
            if slot_value.startswith("0x"):
                slot_hex = slot_value.lower()
                if slot_hex in eip1967_slots:
                    collision_with = eip1967_slots[slot_hex]
                    findings.append(Finding(
                        analyzer=self.name,
                        title=f"Custom slot `{slot_name}` uses EIP-1967 {collision_with} slot",
                        severity=Severity.INFO,
                        file=file_path,
                        line=line_num,
                        description=(
                            f"The storage slot `{slot_name}` uses the EIP-1967 "
                            f"{collision_with} slot value. This is expected if this "
                            f"is a proxy contract, but should be verified."
                        ),
                        recommendation=(
                            "Verify this is intentional EIP-1967 compliance. If this "
                            "is a custom storage slot, use a different value to avoid "
                            "collision."
                        ),
                        code_snippet=self._extract_snippet(lines, line_num),
                        category="SC-10: Proxy/Upgrade",
                    ))

        return findings

    def _check_accidental_upgradeability(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect contracts that use delegatecall but don't appear to be proper proxies."""
        findings: list[Finding] = []

        has_delegatecall = bool(_DELEGATECALL.search(content))
        is_proxy = bool(_PROXY_CONTRACT.search(content))

        if has_delegatecall and not is_proxy:
            match = _DELEGATECALL.search(content)
            if match:
                line_num = content[: match.start()].count("\n") + 1
                findings.append(Finding(
                    analyzer=self.name,
                    title="Non-proxy contract uses delegatecall",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=line_num,
                    description=(
                        "This contract uses `delegatecall` but does not appear to be "
                        "a formal proxy contract. If the delegatecall target can be "
                        "changed, this effectively makes the contract upgradeable "
                        "without the standard safety guarantees."
                    ),
                    recommendation=(
                        "If upgradeability is intended, use a standard proxy pattern "
                        "(UUPS or Transparent) with proper access control. If not, "
                        "ensure the delegatecall target is immutable."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-10: Proxy/Upgrade",
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_param_types(self, params_str: str) -> list[str]:
        """Extract parameter types from a function parameter list string.

        Args:
            params_str: Raw parameter string, e.g., "address _to, uint256 _amount".

        Returns:
            List of type strings, e.g., ["address", "uint256"].
        """
        if not params_str.strip():
            return []
        types: list[str] = []
        for param in params_str.split(","):
            param = param.strip()
            if not param:
                continue
            # Take the first word as the type
            parts = param.split()
            if parts:
                type_name = parts[0]
                # Handle memory/calldata/storage qualifiers
                if len(parts) > 1 and parts[1] in ("memory", "calldata", "storage"):
                    type_name = parts[0]
                types.append(type_name)
        return types

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
