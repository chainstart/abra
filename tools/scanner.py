from __future__ import annotations
#!/usr/bin/env python3
"""Unified smart contract security scanner.

Discovers Solidity files, runs all configured analyzers, aggregates
findings, and outputs results to console, JSON, or Markdown.

Usage examples::

    # Scan a directory with all analyzers, output to console
    python scanner.py --target ../contracts/lido/

    # Scan with specific analyzers and minimum severity
    python scanner.py --target ./MyContract.sol --analyzers reentrancy,arithmetic --severity Medium

    # Output to markdown file
    python scanner.py --target ../contracts/ --output markdown --output-file findings.md

    # Output to JSON
    python scanner.py --target ../contracts/ --output json --output-file findings.json
"""

import argparse
import json
import sys
import time
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from analyzers.base import Finding, Severity
from analyzers.access_control import AccessControlAnalyzer
from analyzers.reentrancy import ReentrancyAnalyzer
from analyzers.oracle_dependency import OracleDependencyAnalyzer
from analyzers.arithmetic import ArithmeticAnalyzer
from analyzers.upgrade_safety import UpgradeSafetyAnalyzer

# Registry of all available analyzers
ANALYZER_REGISTRY = {
    "access-control": AccessControlAnalyzer,
    "reentrancy": ReentrancyAnalyzer,
    "oracle-dependency": OracleDependencyAnalyzer,
    "arithmetic": ArithmeticAnalyzer,
    "upgrade-safety": UpgradeSafetyAnalyzer,
}

# Severity ordering for comparison and sorting
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def discover_sol_files(target: str) -> list[str]:
    """Discover all .sol files at the given target path.

    Args:
        target: Path to a directory or a single .sol file.

    Returns:
        Sorted list of absolute paths to .sol files.
    """
    target_path = Path(target).resolve()

    if target_path.is_file():
        if target_path.suffix == ".sol":
            return [str(target_path)]
        return []

    if target_path.is_dir():
        sol_files = sorted(str(p) for p in target_path.rglob("*.sol"))
        return sol_files

    return []


def run_scan(
    target: str,
    analyzer_names: list[str] | None = None,
    min_severity: Severity = Severity.INFO,
) -> tuple[list[Finding], dict]:
    """Run the security scan on a target.

    Args:
        target: Directory or file path to scan.
        analyzer_names: List of analyzer names to run (None = all).
        min_severity: Minimum severity to include in results.

    Returns:
        Tuple of (list of findings, statistics dict).
    """
    sol_files = discover_sol_files(target)
    if not sol_files:
        print(f"No .sol files found at: {target}", file=sys.stderr)
        return [], {}

    # Determine which analyzers to run
    if analyzer_names:
        analyzers = []
        for name in analyzer_names:
            name = name.strip()
            if name in ANALYZER_REGISTRY:
                analyzers.append(ANALYZER_REGISTRY[name]())
            else:
                print(f"Warning: Unknown analyzer '{name}', skipping.", file=sys.stderr)
    else:
        analyzers = [cls() for cls in ANALYZER_REGISTRY.values()]

    if not analyzers:
        print("No valid analyzers selected.", file=sys.stderr)
        return [], {}

    # Run all analyzers on all files
    all_findings: list[Finding] = []
    start_time = time.time()

    for sol_file in sol_files:
        for analyzer in analyzers:
            try:
                findings = analyzer.analyze(sol_file)
                all_findings.extend(findings)
            except Exception as e:
                print(
                    f"Error running {analyzer.name} on {sol_file}: {e}",
                    file=sys.stderr,
                )

    elapsed = time.time() - start_time

    # Filter by minimum severity
    severity_threshold = SEVERITY_ORDER[min_severity]
    filtered = [
        f for f in all_findings
        if SEVERITY_ORDER[f.severity] <= severity_threshold
    ]

    # Sort by severity (most severe first), then by file and line
    filtered.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))

    # Compute statistics
    stats = {
        "files_scanned": len(sol_files),
        "analyzers_run": len(analyzers),
        "total_findings": len(filtered),
        "elapsed_seconds": round(elapsed, 2),
        "by_severity": {},
        "by_analyzer": {},
    }
    for sev in Severity:
        count = sum(1 for f in filtered if f.severity == sev)
        if count > 0:
            stats["by_severity"][sev.value] = count
    for analyzer in analyzers:
        count = sum(1 for f in filtered if f.analyzer == analyzer.name)
        if count > 0:
            stats["by_analyzer"][analyzer.name] = count

    return filtered, stats


def output_console(findings: list[Finding], stats: dict) -> None:
    """Print findings to the console using rich formatting (or plain text fallback).

    Args:
        findings: List of findings to display.
        stats: Scan statistics dict.
    """
    if RICH_AVAILABLE:
        _output_console_rich(findings, stats)
    else:
        _output_console_plain(findings, stats)


def _output_console_rich(findings: list[Finding], stats: dict) -> None:
    """Rich-formatted console output."""
    console = Console()

    # Header
    console.print()
    console.print(
        Panel(
            "[bold]Smart Contract Security Scanner[/bold]\n"
            f"Files scanned: {stats.get('files_scanned', 0)} | "
            f"Analyzers: {stats.get('analyzers_run', 0)} | "
            f"Time: {stats.get('elapsed_seconds', 0)}s",
            title="Scan Results",
            border_style="blue",
        )
    )

    if not findings:
        console.print("[green]No findings detected.[/green]")
        return

    # Summary table
    summary_table = Table(title="Severity Distribution")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")

    for sev in Severity:
        count = stats.get("by_severity", {}).get(sev.value, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "white")
            summary_table.add_row(f"[{color}]{sev.value}[/{color}]", str(count))

    console.print(summary_table)
    console.print()

    # Detailed findings
    for i, finding in enumerate(findings, start=1):
        color = SEVERITY_COLORS.get(finding.severity, "white")
        severity_text = f"[{color}]{finding.severity.value}[/{color}]"

        console.print(
            Panel(
                f"[bold]{finding.title}[/bold]\n\n"
                f"Severity: {severity_text}\n"
                f"File: {finding.file}:{finding.line}\n"
                f"Analyzer: {finding.analyzer}\n"
                f"Category: {finding.category}\n\n"
                f"[bold]Description:[/bold]\n{finding.description}\n\n"
                f"[bold]Recommendation:[/bold]\n{finding.recommendation}"
                + (
                    f"\n\n[bold]Code:[/bold]\n[dim]{finding.code_snippet}[/dim]"
                    if finding.code_snippet else ""
                ),
                title=f"Finding #{i}",
                border_style=color.split()[-1] if " " in color else color,
            )
        )

    console.print(
        f"\n[bold]Total: {len(findings)} findings[/bold] "
        f"({stats.get('elapsed_seconds', 0)}s)\n"
    )


def _output_console_plain(findings: list[Finding], stats: dict) -> None:
    """Plain-text console output fallback."""
    print("\n" + "=" * 60)
    print("Smart Contract Security Scanner - Results")
    print(
        f"Files: {stats.get('files_scanned', 0)} | "
        f"Analyzers: {stats.get('analyzers_run', 0)} | "
        f"Time: {stats.get('elapsed_seconds', 0)}s"
    )
    print("=" * 60)

    if not findings:
        print("No findings detected.")
        return

    # Severity summary
    print("\nSeverity Distribution:")
    for sev in Severity:
        count = stats.get("by_severity", {}).get(sev.value, 0)
        if count > 0:
            print(f"  {sev.value}: {count}")

    # Detailed findings
    for i, finding in enumerate(findings, start=1):
        print(f"\n--- Finding #{i} ---")
        print(f"  [{finding.severity.value}] {finding.title}")
        print(f"  File: {finding.file}:{finding.line}")
        print(f"  Analyzer: {finding.analyzer}")
        print(f"  Category: {finding.category}")
        print(f"  Description: {finding.description}")
        print(f"  Recommendation: {finding.recommendation}")
        if finding.code_snippet:
            print(f"  Code:\n{finding.code_snippet}")

    print(f"\nTotal: {len(findings)} findings")


def output_json(findings: list[Finding], stats: dict, output_file: str | None = None) -> str:
    """Serialize findings and stats to JSON.

    Args:
        findings: List of findings.
        stats: Scan statistics dict.
        output_file: Optional path to write JSON output.

    Returns:
        JSON string.
    """
    data = {
        "stats": stats,
        "findings": [f.to_dict() for f in findings],
    }
    json_str = json.dumps(data, indent=2, ensure_ascii=False)

    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        Path(output_file).write_text(json_str, encoding="utf-8")
        print(f"JSON output written to: {output_file}")

    return json_str


def output_markdown(findings: list[Finding], stats: dict, output_file: str | None = None) -> str:
    """Generate a Markdown report of findings.

    Args:
        findings: List of findings.
        stats: Scan statistics dict.
        output_file: Optional path to write Markdown output.

    Returns:
        Markdown string.
    """
    lines: list[str] = []
    lines.append("# Smart Contract Security Scan Report\n")
    lines.append(f"- **Files scanned**: {stats.get('files_scanned', 0)}")
    lines.append(f"- **Analyzers run**: {stats.get('analyzers_run', 0)}")
    lines.append(f"- **Total findings**: {stats.get('total_findings', 0)}")
    lines.append(f"- **Scan time**: {stats.get('elapsed_seconds', 0)}s\n")

    # Severity distribution
    lines.append("## Severity Distribution\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in Severity:
        count = stats.get("by_severity", {}).get(sev.value, 0)
        if count > 0:
            lines.append(f"| {sev.value} | {count} |")
    lines.append("")

    # Findings by analyzer
    if stats.get("by_analyzer"):
        lines.append("## Findings by Analyzer\n")
        lines.append("| Analyzer | Count |")
        lines.append("|----------|-------|")
        for name, count in stats["by_analyzer"].items():
            lines.append(f"| {name} | {count} |")
        lines.append("")

    # Detailed findings
    lines.append("## Detailed Findings\n")

    if not findings:
        lines.append("No findings detected.\n")
    else:
        for i, finding in enumerate(findings, start=1):
            lines.append(f"### {i}. [{finding.severity.value}] {finding.title}\n")
            lines.append(f"- **File**: `{finding.file}:{finding.line}`")
            lines.append(f"- **Analyzer**: {finding.analyzer}")
            lines.append(f"- **Category**: {finding.category}\n")
            lines.append(f"**Description**: {finding.description}\n")
            lines.append(f"**Recommendation**: {finding.recommendation}\n")
            if finding.code_snippet:
                lines.append("**Code**:")
                lines.append(f"```solidity\n{finding.code_snippet}\n```\n")
            lines.append("---\n")

    md_str = "\n".join(lines)

    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        Path(output_file).write_text(md_str, encoding="utf-8")
        print(f"Markdown output written to: {output_file}")

    return md_str


def parse_severity(value: str) -> Severity:
    """Parse a severity string into a Severity enum value.

    Args:
        value: Case-insensitive severity name.

    Returns:
        Matching Severity enum value.

    Raises:
        argparse.ArgumentTypeError: If the severity string is invalid.
    """
    mapping = {s.value.lower(): s for s in Severity}
    key = value.strip().lower()
    if key in mapping:
        return mapping[key]
    valid = ", ".join(s.value for s in Severity)
    raise argparse.ArgumentTypeError(f"Invalid severity '{value}'. Choose from: {valid}")


def main() -> None:
    """CLI entry point for the scanner."""
    parser = argparse.ArgumentParser(
        description="Smart Contract Security Scanner -- static analysis for Solidity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scanner.py --target ./contracts/\n"
            "  python scanner.py --target ./Token.sol --analyzers reentrancy,arithmetic\n"
            "  python scanner.py --target ./contracts/ --output markdown --output-file report.md\n"
            "  python scanner.py --target ./contracts/ --severity High --output json\n"
        ),
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Directory or .sol file to scan",
    )
    parser.add_argument(
        "--analyzers",
        default=None,
        help=(
            "Comma-separated list of analyzers to run. "
            f"Available: {', '.join(ANALYZER_REGISTRY.keys())}. "
            "Default: all."
        ),
    )
    parser.add_argument(
        "--severity",
        type=parse_severity,
        default=Severity.INFO,
        help="Minimum severity to report (Critical, High, Medium, Low, Informational). Default: Informational.",
    )
    parser.add_argument(
        "--output",
        choices=["console", "json", "markdown"],
        default="console",
        help="Output format. Default: console.",
    )
    parser.add_argument(
        "--output-file",
        default=None,
        help="Write results to this file (for json/markdown output).",
    )

    args = parser.parse_args()

    # Parse analyzer list
    analyzer_names = None
    if args.analyzers:
        analyzer_names = [a.strip() for a in args.analyzers.split(",")]

    # Run scan
    findings, stats = run_scan(
        target=args.target,
        analyzer_names=analyzer_names,
        min_severity=args.severity,
    )

    # Output results
    if args.output == "console":
        output_console(findings, stats)
    elif args.output == "json":
        json_str = output_json(findings, stats, args.output_file)
        if not args.output_file:
            print(json_str)
    elif args.output == "markdown":
        md_str = output_markdown(findings, stats, args.output_file)
        if not args.output_file:
            print(md_str)

    # Exit code: non-zero if Critical/High findings exist
    critical_high = sum(
        1 for f in findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()
