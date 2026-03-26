"""Static analyzer for arithmetic issues in Solidity contracts.

Detects:
- Division before multiplication (precision loss)
- Unchecked arithmetic in unchecked { } blocks
- Hardcoded decimals assumptions
- Missing zero-denominator checks
- Rounding direction issues in share/token calculations
- Large number multiplication overflow potential
- Unsafe casting (uint256 to uint128, etc.)
"""

import re
from pathlib import Path

from .base import BaseAnalyzer, Finding, Severity


# Division before multiplication: a / b * c  or  (a / b) * c
_DIV_BEFORE_MUL = re.compile(
    r"(?:\w+\s*/\s*\w+)\s*\*\s*\w+|"
    r"\([^)]*\/[^)]*\)\s*\*\s*\w+"
)

# Unchecked blocks
_UNCHECKED_BLOCK = re.compile(r"\bunchecked\s*\{")

# Division operations (for zero-denominator check)
_DIVISION = re.compile(r"(\w[\w\[\].()]*)\s*/\s*(\w[\w\[\].()]*)")

# Zero denominator check patterns
_ZERO_DENOM_CHECK = re.compile(
    r"require\s*\([^)]*!=\s*0|"
    r"require\s*\([^)]*>\s*0|"
    r"if\s*\([^)]*==\s*0[^)]*\)\s*revert|"
    r"assert\s*\([^)]*!=\s*0"
)

# Unsafe casting patterns
_UNSAFE_CAST = re.compile(
    r"\b(uint8|uint16|uint32|uint64|uint96|uint128|uint160|"
    r"int8|int16|int32|int64|int96|int128)\s*\(\s*(\w+)"
)

# Safe casting patterns (OpenZeppelin SafeCast)
_SAFE_CAST = re.compile(
    r"\.toUint\d+\(\)|\.toInt\d+\(\)|SafeCast\."
)

# Hardcoded decimal multipliers
_HARDCODED_DECIMALS = re.compile(
    r"\b(1e\d+|10\s*\*\*\s*\d+)\b"
)

# Rounding-sensitive operations (minting/burning shares, exchange rates)
_SHARE_CALCULATION = re.compile(
    r"\b(shares?|amount|assets?|tokens?|supply)\s*=\s*[^;]*[*/][^;]*"
    r"(?:shares?|amount|assets?|tokens?|supply|totalSupply|totalShares|"
    r"totalAssets|exchangeRate|rate)",
    re.IGNORECASE,
)

# mulDiv or FullMath usage (safe patterns)
_MULDIV = re.compile(r"\b(?:mulDiv|FullMath\.|Math\.mulDiv|PRBMath)\b")

# Solidity version pragma
_PRAGMA = re.compile(r"pragma\s+solidity\s+([^;]+);")

# Function definitions for context
_FUNC_DEF = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)\s+(?:external|public|internal|private)"
    r"([^{]*)\{",
)

# Large multiplication patterns (variables * variables * variables)
_LARGE_MUL = re.compile(
    r"(\w+)\s*\*\s*(\w+)\s*\*\s*(\w+)"
)

# Type narrowing in assembly
_ASSEMBLY_TRUNC = re.compile(
    r"assembly\s*\{[^}]*(?:and|shr|shl)\s*\([^)]*\)[^}]*\}"
)

# Signed arithmetic
_SIGNED_ARITH = re.compile(
    r"\bint(?:8|16|32|64|128|256)?\b[^u]"
)


class ArithmeticAnalyzer(BaseAnalyzer):
    """Analyzes Solidity contracts for arithmetic vulnerabilities."""

    name = "arithmetic"
    description = "Detects arithmetic issues: precision loss, overflow, unsafe casting"

    def analyze(self, file_path: str) -> list[Finding]:
        """Run all arithmetic checks on a Solidity file.

        Args:
            file_path: Path to the .sol file.

        Returns:
            List of findings related to arithmetic issues.
        """
        content, lines = self._read_source(file_path)
        if not content:
            return []

        findings: list[Finding] = []
        findings.extend(self._check_div_before_mul(file_path, content, lines))
        findings.extend(self._check_unchecked_blocks(file_path, content, lines))
        findings.extend(self._check_zero_denominator(file_path, content, lines))
        findings.extend(self._check_unsafe_casting(file_path, content, lines))
        findings.extend(self._check_rounding_direction(file_path, content, lines))
        findings.extend(self._check_large_multiplication(file_path, content, lines))
        findings.extend(self._check_hardcoded_decimals(file_path, content, lines))
        findings.extend(self._check_signed_unsigned_conversion(file_path, content, lines))
        findings.extend(self._check_phantom_overflow(file_path, content, lines))
        findings.extend(self._check_ether_unit_math(file_path, content, lines))
        return findings

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _check_div_before_mul(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect division before multiplication causing precision loss."""
        findings: list[Finding] = []

        for match in _DIV_BEFORE_MUL.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            # Check if mulDiv is used nearby (safe pattern)
            context = content[max(0, match.start() - 200): match.end() + 200]
            if _MULDIV.search(context):
                continue

            findings.append(Finding(
                analyzer=self.name,
                title="Division before multiplication (precision loss)",
                severity=Severity.MEDIUM,
                file=file_path,
                line=line_num,
                description=(
                    f"The expression `{match.group(0).strip()}` performs division "
                    f"before multiplication, which truncates the intermediate result "
                    f"and can cause significant precision loss in Solidity's integer "
                    f"arithmetic. For example, `(a / b) * c` loses the remainder "
                    f"of `a / b` before multiplying."
                ),
                recommendation=(
                    "Reorder to multiply before dividing: `a * c / b`. For cases "
                    "where overflow is a concern, use a `mulDiv` function (e.g., "
                    "OpenZeppelin's Math.mulDiv or Uniswap's FullMath.mulDiv)."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-06: Arithmetic",
            ))

        return findings

    def _check_unchecked_blocks(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect potentially dangerous operations inside unchecked blocks."""
        findings: list[Finding] = []

        for match in _UNCHECKED_BLOCK.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            # Extract the unchecked block body
            brace_start = match.end() - 1
            brace_end = self._find_matching_brace(content, brace_start)
            block_body = content[brace_start:brace_end]

            # Check for dangerous operations inside unchecked
            has_sub = bool(re.search(r"\w+\s*-\s*\w+|--", block_body))
            has_mul = bool(re.search(r"\w+\s*\*\s*\w+", block_body))
            has_add = bool(re.search(r"\w+\s*\+\s*\w+|\+\+", block_body))
            has_division = bool(re.search(r"\w+\s*/\s*\w+", block_body))

            # Simple loop counter increments are fine
            is_loop_increment = bool(re.search(
                r"^\s*(?:\+\+\w+|\w+\+\+|i\s*\+=\s*1)\s*;?\s*$",
                block_body.strip(),
            ))
            if is_loop_increment:
                continue

            dangerous_ops = []
            if has_sub:
                dangerous_ops.append("subtraction (underflow risk)")
            if has_mul:
                dangerous_ops.append("multiplication (overflow risk)")

            if dangerous_ops:
                findings.append(Finding(
                    analyzer=self.name,
                    title="Potentially dangerous unchecked arithmetic",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"An `unchecked` block contains: {', '.join(dangerous_ops)}. "
                        f"In Solidity 0.8+, the unchecked block disables overflow/"
                        f"underflow checks. This is safe for loop counters but "
                        f"dangerous for business logic calculations."
                    ),
                    recommendation=(
                        "Verify that the values in this unchecked block cannot "
                        "overflow or underflow. Add comments explaining why unchecked "
                        "is safe here. Consider adding explicit bounds checks before "
                        "the unchecked block."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num, context=2),
                    category="SC-06: Arithmetic",
                ))

        return findings

    def _check_zero_denominator(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect division operations without zero-denominator protection."""
        findings: list[Finding] = []
        reported_lines: set[int] = set()

        for match in _DIVISION.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if line_num in reported_lines:
                continue
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            denominator = match.group(2).strip()

            # Skip literal non-zero denominators
            if re.match(r"^\d+$", denominator) and denominator != "0":
                continue
            # Skip common safe denominators
            if denominator in ("1e18", "1e8", "1e6", "1 ether", "1e27"):
                continue

            # Check surrounding context for zero checks on the denominator
            context_before = content[max(0, match.start() - 500): match.start()]
            has_zero_check = bool(re.search(
                rf"require\s*\([^)]*{re.escape(denominator)}\s*(?:!=\s*0|>\s*0)|"
                rf"if\s*\([^)]*{re.escape(denominator)}\s*==\s*0[^)]*\)\s*revert|"
                rf"{re.escape(denominator)}\s*!=\s*0",
                context_before,
            ))

            if not has_zero_check:
                reported_lines.add(line_num)
                findings.append(Finding(
                    analyzer=self.name,
                    title=f"Potential division by zero: `/ {denominator}`",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"Division by `{denominator}` without a preceding zero check. "
                        f"If `{denominator}` can be zero, this will cause a revert "
                        f"(Solidity 0.8+) or return zero (Solidity <0.8), both of "
                        f"which may be unintended."
                    ),
                    recommendation=(
                        f"Add `require({denominator} != 0, \"Division by zero\");` "
                        f"before this operation, or handle the zero case explicitly."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-06: Arithmetic",
                ))

        return findings

    def _check_unsafe_casting(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect unsafe type casting that can truncate values."""
        findings: list[Finding] = []

        for match in _UNSAFE_CAST.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            target_type = match.group(1)
            source_var = match.group(2)

            # Check if SafeCast is used nearby
            context = content[max(0, match.start() - 100): match.end() + 100]
            if _SAFE_CAST.search(context):
                continue

            # Determine target bit width
            bit_match = re.search(r"\d+", target_type)
            target_bits = int(bit_match.group()) if bit_match else 256

            findings.append(Finding(
                analyzer=self.name,
                title=f"Unsafe downcast to `{target_type}`",
                severity=Severity.MEDIUM if target_bits <= 64 else Severity.LOW,
                file=file_path,
                line=line_num,
                description=(
                    f"The value `{source_var}` is cast to `{target_type}` without "
                    f"bounds checking. If the value exceeds the maximum for "
                    f"`{target_type}` (2^{target_bits} - 1), it will silently "
                    f"truncate, leading to incorrect values."
                ),
                recommendation=(
                    f"Use OpenZeppelin's SafeCast library: "
                    f"`value.to{target_type.capitalize()}()` which reverts on "
                    f"overflow. Alternatively, add an explicit bounds check."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-06: Arithmetic",
            ))

        return findings

    def _check_rounding_direction(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect share/asset calculations where rounding direction matters."""
        findings: list[Finding] = []

        # Look for ERC4626-style share calculations
        share_patterns = [
            (r"assets?\s*\*\s*(?:totalSupply|supply)", "assets to shares"),
            (r"shares?\s*\*\s*(?:totalAssets|assets)", "shares to assets"),
            (r"(?:convertToShares|previewDeposit|previewMint)", "share conversion"),
            (r"(?:convertToAssets|previewWithdraw|previewRedeem)", "asset conversion"),
        ]

        for pattern, operation in share_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[: match.start()].count("\n") + 1
                if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                    continue

                # Check if rounding is explicitly handled
                context = content[max(0, match.start() - 200): match.end() + 200]
                has_rounding = bool(re.search(
                    r"[Rr]ound(?:Up|Down|ing)|[Cc]eil|[Ff]loor|mulDivUp|mulDivDown|"
                    r"\+\s*1\b|[Mm]ath\.\w+[Rr]ound",
                    context,
                ))

                if not has_rounding:
                    findings.append(Finding(
                        analyzer=self.name,
                        title=f"Rounding direction not explicit in {operation}",
                        severity=Severity.LOW,
                        file=file_path,
                        line=line_num,
                        description=(
                            f"The {operation} calculation does not explicitly handle "
                            f"rounding direction. In vault/share systems, rounding "
                            f"should favor the protocol (round down for deposits/mints, "
                            f"round up for withdrawals/redeems) to prevent value "
                            f"extraction through rounding."
                        ),
                        recommendation=(
                            "Use explicit rounding: `Math.mulDiv(a, b, c)` for round-down "
                            "and `Math.mulDiv(a, b, c) + (a * b % c > 0 ? 1 : 0)` for "
                            "round-up, or use a library with mulDivUp/mulDivDown."
                        ),
                        code_snippet=self._extract_snippet(lines, line_num),
                        category="SC-06: Arithmetic",
                    ))

        return findings

    def _check_large_multiplication(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect large multiplications that could overflow even in 0.8+."""
        findings: list[Finding] = []

        for match in _LARGE_MUL.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            # Skip if mulDiv is used
            context = content[max(0, match.start() - 100): match.end() + 100]
            if _MULDIV.search(context):
                continue

            # Skip if all operands are small constants
            operands = [match.group(1), match.group(2), match.group(3)]
            all_small_constants = all(
                re.match(r"^\d+$", op) and int(op) < 1e18
                for op in operands
            )
            if all_small_constants:
                continue

            findings.append(Finding(
                analyzer=self.name,
                title="Triple multiplication may overflow",
                severity=Severity.LOW,
                file=file_path,
                line=line_num,
                description=(
                    f"The expression `{match.group(0)}` multiplies three values. "
                    f"Even in Solidity 0.8+ (with overflow checks), the intermediate "
                    f"result of the first multiplication could exceed uint256 max "
                    f"(~1.15e77), causing a revert. This is especially risky with "
                    f"token amounts (1e18 scale) or price values."
                ),
                recommendation=(
                    "Use `Math.mulDiv(a, b, c)` to compute `a * b / c` without "
                    "intermediate overflow. If all three must be multiplied, consider "
                    "reordering to divide by the largest value first."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-06: Arithmetic",
            ))

        return findings

    def _check_hardcoded_decimals(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect hardcoded decimal constants that may not be correct for all tokens."""
        findings: list[Finding] = []

        # Look for magic numbers related to decimals
        magic_patterns = [
            (r"\b1e18\b", "18 decimals", "ETH/ERC20"),
            (r"\b1e6\b", "6 decimals", "USDC/USDT"),
            (r"\b1e8\b", "8 decimals", "WBTC/Chainlink"),
        ]

        for pattern, decimal_desc, token_hint in magic_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[: match.start()].count("\n") + 1
                if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                    continue

                # Check if decimals() is called dynamically nearby
                context = content[max(0, match.start() - 500): match.end() + 500]
                has_dynamic = bool(re.search(r"\.decimals\s*\(\s*\)", context))
                is_constant_def = bool(re.search(
                    r"(?:constant|immutable)\s+\w+\s*=",
                    lines[line_num - 1] if line_num <= len(lines) else "",
                ))

                if not has_dynamic and not is_constant_def:
                    findings.append(Finding(
                        analyzer=self.name,
                        title=f"Hardcoded {decimal_desc} assumption ({token_hint})",
                        severity=Severity.LOW,
                        file=file_path,
                        line=line_num,
                        description=(
                            f"The value `{match.group(0)}` assumes {decimal_desc}, "
                            f"typical for {token_hint}. Not all tokens use this "
                            f"decimal precision. Using a hardcoded value can cause "
                            f"incorrect calculations with tokens of different decimals."
                        ),
                        recommendation=(
                            "Use `IERC20Metadata(token).decimals()` to dynamically "
                            "determine token decimals. If the decimal value must be "
                            "hardcoded for gas efficiency, document it clearly and "
                            "validate in the constructor."
                        ),
                        code_snippet=self._extract_snippet(lines, line_num),
                        category="SC-06: Arithmetic",
                    ))

        return findings

    def _check_signed_unsigned_conversion(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect unsafe signed/unsigned integer conversions."""
        findings: list[Finding] = []

        # uint -> int conversion
        for match in re.finditer(r"\bint(?:256|128|64|32|16|8)?\s*\(\s*(uint\w*\s+)?\w+\s*\)", content):
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            findings.append(Finding(
                analyzer=self.name,
                title="Unsigned to signed integer conversion",
                severity=Severity.LOW,
                file=file_path,
                line=line_num,
                description=(
                    "Converting an unsigned integer to a signed type can produce "
                    "a negative value if the unsigned value exceeds the signed "
                    "type's maximum (e.g., uint256 > type(int256).max). In "
                    "Solidity 0.8+, this reverts; in earlier versions, it wraps."
                ),
                recommendation=(
                    "Validate that the value fits in the target signed type before "
                    "casting. Use SafeCast for safe conversions."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-06: Arithmetic",
            ))

        return findings

    def _check_phantom_overflow(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect expressions where Solidity 0.8+ overflow protection may cause unexpected reverts."""
        findings: list[Finding] = []

        # a * b where both could be large (e.g., token amount * price)
        mul_pattern = re.compile(
            r"(\w+(?:\.\w+)?)\s*\*\s*(\w+(?:\.\w+)?)\s*/\s*(\w+(?:\.\w+)?)"
        )

        for match in mul_pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            context = content[max(0, match.start() - 100): match.end() + 100]
            if _MULDIV.search(context):
                continue

            a, b, c = match.group(1), match.group(2), match.group(3)

            # Heuristic: if variable names suggest large values
            large_hints = re.compile(
                r"amount|balance|supply|price|value|total|reserve",
                re.IGNORECASE,
            )
            hint_count = sum(1 for v in [a, b] if large_hints.search(v))

            if hint_count >= 1:
                findings.append(Finding(
                    analyzer=self.name,
                    title="Multiplication before division may revert on overflow",
                    severity=Severity.LOW,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"The expression `{a} * {b} / {c}` computes the multiplication "
                        f"first. If `{a} * {b}` exceeds uint256 max, the transaction "
                        f"reverts even though the final result (after division) would "
                        f"fit. This is a \"phantom overflow\" issue."
                    ),
                    recommendation=(
                        f"Use `Math.mulDiv({a}, {b}, {c})` which handles the "
                        f"intermediate overflow safely using 512-bit math."
                    ),
                    code_snippet=self._extract_snippet(lines, line_num),
                    category="SC-06: Arithmetic",
                ))

        return findings

    def _check_ether_unit_math(
        self, file_path: str, content: str, lines: list[str]
    ) -> list[Finding]:
        """Detect mixing of ether units and raw wei values in arithmetic."""
        findings: list[Finding] = []

        # Detect mixing ether keywords with raw numbers
        ether_units = re.finditer(
            r"(\d+)\s*(ether|gwei|wei)\s*(?:[+\-*/])\s*(\d+)\s*(?!ether|gwei|wei|e\d)",
            content,
        )

        for match in ether_units:
            line_num = content[: match.start()].count("\n") + 1
            if line_num <= len(lines) and self._is_in_comment(lines[line_num - 1]):
                continue

            findings.append(Finding(
                analyzer=self.name,
                title="Mixed ether unit arithmetic",
                severity=Severity.LOW,
                file=file_path,
                line=line_num,
                description=(
                    f"Arithmetic operation mixes ether unit keywords (e.g., "
                    f"`{match.group(0).strip()}`) with raw numeric values. This "
                    f"can lead to unit mismatches where one operand is in wei "
                    f"and another is a raw number."
                ),
                recommendation=(
                    "Ensure all operands in arithmetic expressions use consistent "
                    "units. Prefer explicit ether unit keywords for clarity."
                ),
                code_snippet=self._extract_snippet(lines, line_num),
                category="SC-06: Arithmetic",
            ))

        return findings


    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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

        
def print_audit_status():
    """这是我为项目增加的审计状态追踪功能"""
    print("\n" + "="*50)
    print(">>> [审计日志] 算术逻辑分析器正在运行...")
    print(">>> [状态] 正在扫描：硬编码、溢出及精度损失风险")
    print("="*50 + "\n")

# 在这里直接调用它，确保每次加载这个分析器都会显示
print_audit_status()