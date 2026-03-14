"""Base classes for smart contract analyzers."""
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class Finding:
    analyzer: str
    title: str
    severity: Severity
    file: str
    line: int
    description: str
    recommendation: str
    code_snippet: str = ""
    category: str = ""  # OWASP SC category

    def to_dict(self) -> dict:
        return {
            "analyzer": self.analyzer,
            "title": self.title,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "recommendation": self.recommendation,
            "code_snippet": self.code_snippet,
            "category": self.category,
        }


class BaseAnalyzer:
    """Base class for all smart contract analyzers.

    Subclasses must set `name` and `description` and implement `analyze()`.
    """

    name: str = "base"
    description: str = ""

    def analyze(self, file_path: str) -> list[Finding]:
        """Analyze a Solidity source file and return a list of findings.

        Args:
            file_path: Path to a .sol file.

        Returns:
            List of Finding objects discovered during analysis.
        """
        raise NotImplementedError

    def _read_source(self, file_path: str) -> tuple[str, list[str]]:
        """Read a Solidity source file and return (content, lines).

        Args:
            file_path: Path to the Solidity file.

        Returns:
            Tuple of (full file content, list of individual lines).
            Returns ("", []) if the file does not exist or is not a .sol file.
        """
        path = Path(file_path)
        if not path.exists() or path.suffix != ".sol":
            return "", []
        content = path.read_text(encoding="utf-8")
        lines = content.splitlines()
        return content, lines

    def _is_in_comment(self, line: str, col: int = 0) -> bool:
        """Check if a position in a line is inside a comment.

        This is a heuristic check -- it handles single-line comments (//)
        and common multi-line comment patterns (* prefix lines, /* openers).

        Args:
            line: The source line to inspect.
            col: Column offset (currently unused, reserved for future use).

        Returns:
            True if the line appears to be a comment.
        """
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            return True
        return False

    def _extract_snippet(self, lines: list[str], line_num: int, context: int = 1) -> str:
        """Extract a code snippet around a given line number.

        Args:
            lines: All lines from the source file.
            line_num: 1-based line number to centre the snippet on.
            context: Number of lines of context above and below.

        Returns:
            A string with the snippet, each line prefixed with its line number.
        """
        start = max(0, line_num - 1 - context)
        end = min(len(lines), line_num + context)
        snippet_lines: list[str] = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{prefix}{i + 1}: {lines[i]}")
        return "\n".join(snippet_lines)
