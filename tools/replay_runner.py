#!/usr/bin/env python3
"""Run and summarize Foundry fork-replay experiments.

The replay tests in this repository intentionally need archive-capable RPC
endpoints. This runner makes that precondition explicit so an unset RPC
environment variable is recorded as `no_rpc` instead of being confused with a
verified replay.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ReplayCase:
    incident: str
    slug: str
    chain: str
    rpc_env: str
    attack_family: str
    loss_usd: int
    fork_block: int | None
    test_path: str | None
    metadata_test: str | None
    replay_test: str | None
    status_if_no_test: str = "no_test"


@dataclass
class ReplayResult:
    incident: str
    slug: str
    chain: str
    rpc_env: str
    attack_family: str
    loss_usd: int
    fork_block: int | None
    test_path: str | None
    replay_test: str | None
    status: str
    metadata_status: str
    command: str
    returncode: int | None
    duration_seconds: float
    log_path: str
    blocker: str
    verified: bool


REPLAY_CASES: tuple[ReplayCase, ...] = (
    ReplayCase(
        incident="Euler Finance",
        slug="euler-finance",
        chain="ethereum",
        rpc_env="ETH_RPC_URL",
        attack_family="flash_loan",
        loss_usd=197_000_000,
        fork_block=16_817_995,
        test_path="test/replay/EulerFinanceReplay.t.sol",
        metadata_test="test_EulerReplayMetadata",
        replay_test="test_EulerReplay",
    ),
    ReplayCase(
        incident="BonqDAO & AllianceBlock",
        slug="bonqdao-allianceblock",
        chain="polygon",
        rpc_env="POLYGON_RPC_URL",
        attack_family="oracle_manipulation",
        loss_usd=120_000_000,
        fork_block=38_792_977,
        test_path="test/replay/BonqDAOReplay.t.sol",
        metadata_test="test_BonqReplayMetadata",
        replay_test="test_BonqReplayTx1",
    ),
    ReplayCase(
        incident="Lendf.Me",
        slug="lendf-me",
        chain="ethereum",
        rpc_env="ETH_RPC_URL",
        attack_family="reentrancy",
        loss_usd=24_696_616,
        fork_block=9_899_725,
        test_path="test/replay/LendfMeReplay.t.sol",
        metadata_test="test_LendfMeReplayMetadata",
        replay_test="test_LendfMeReplay",
    ),
    ReplayCase(
        incident="Fei Protocol & Rari Capital",
        slug="fei-rari",
        chain="ethereum",
        rpc_env="ETH_RPC_URL",
        attack_family="reentrancy",
        loss_usd=80_000_000,
        fork_block=None,
        test_path=None,
        metadata_test=None,
        replay_test=None,
    ),
    ReplayCase(
        incident="Beanstalk",
        slug="beanstalk",
        chain="ethereum",
        rpc_env="ETH_RPC_URL",
        attack_family="flash_loan_governance",
        loss_usd=182_000_000,
        fork_block=None,
        test_path=None,
        metadata_test=None,
        replay_test=None,
    ),
    ReplayCase(
        incident="UwU Lend",
        slug="uwu-lend",
        chain="ethereum",
        rpc_env="ETH_RPC_URL",
        attack_family="oracle_manipulation",
        loss_usd=19_300_000,
        fork_block=None,
        test_path=None,
        metadata_test=None,
        replay_test=None,
    ),
    ReplayCase(
        incident="Cream Finance",
        slug="cream-finance",
        chain="ethereum",
        rpc_env="ETH_RPC_URL",
        attack_family="flash_loan",
        loss_usd=130_000_000,
        fork_block=None,
        test_path=None,
        metadata_test=None,
        replay_test=None,
    ),
    ReplayCase(
        incident="xToken",
        slug="xtoken",
        chain="ethereum",
        rpc_env="ETH_RPC_URL",
        attack_family="oracle_manipulation",
        loss_usd=25_000_000,
        fork_block=None,
        test_path=None,
        metadata_test=None,
        replay_test=None,
    ),
    ReplayCase(
        incident="flash.sx",
        slug="flash-sx",
        chain="eos",
        rpc_env="EOS_RPC_URL",
        attack_family="reentrancy",
        loss_usd=11_742_000,
        fork_block=None,
        test_path=None,
        metadata_test=None,
        replay_test=None,
    ),
    ReplayCase(
        incident="Mirror Protocol",
        slug="mirror-protocol",
        chain="terra",
        rpc_env="TERRA_RPC_URL",
        attack_family="contract_bug",
        loss_usd=90_000_000,
        fork_block=None,
        test_path=None,
        metadata_test=None,
        replay_test=None,
    ),
    ReplayCase(
        incident="Cetus",
        slug="cetus",
        chain="sui",
        rpc_env="SUI_RPC_URL",
        attack_family="contract_bug",
        loss_usd=230_000_000,
        fork_block=None,
        test_path=None,
        metadata_test=None,
        replay_test=None,
    ),
    ReplayCase(
        incident="Balancer V2",
        slug="balancer-v2",
        chain="multi_evm",
        rpc_env="ETH_RPC_URL",
        attack_family="logic_bug",
        loss_usd=121_100_000,
        fork_block=None,
        test_path=None,
        metadata_test=None,
        replay_test=None,
    ),
)


def _run(cmd: list[str], timeout: int, log_file: Path) -> tuple[int, float]:
    started = datetime.now(timezone.utc)
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    duration = (datetime.now(timezone.utc) - started).total_seconds()
    log_file.write_text(proc.stdout, encoding="utf-8")
    return proc.returncode, duration


def _forge_cmd(test_path: str, test_name: str, verbosity: str) -> list[str]:
    return [
        "forge",
        "test",
        "--match-path",
        test_path,
        "--match-test",
        test_name,
        verbosity,
    ]


def classify_failure(log_text: str) -> str:
    """Classify a replay failure log without running a replay command."""

    return _classify_failure(log_text)


def _classify_failure(log_text: str) -> str:
    lowered = log_text.lower()
    if "historical state" in lowered and "not available" in lowered:
        return "archive_state_unavailable"
    if "missing trie node" in lowered or "header not found" in lowered:
        return "archive_state_unavailable"
    if "rate limit" in lowered or "too many requests" in lowered:
        return "rpc_rate_limited"
    if "connection refused" in lowered or "connection reset" in lowered or "timed out" in lowered:
        return "rpc_transport_failure"
    if "execution reverted" in lowered or "[fail:" in lowered:
        return "replay_assertion_or_execution_failure"
    return "forge_test_failed"


def run_case(case: ReplayCase, logs_dir: Path, timeout: int, verbosity: str) -> ReplayResult:
    if not case.test_path or not case.replay_test:
        return ReplayResult(
            incident=case.incident,
            slug=case.slug,
            chain=case.chain,
            rpc_env=case.rpc_env,
            attack_family=case.attack_family,
            loss_usd=case.loss_usd,
            fork_block=case.fork_block,
            test_path=case.test_path,
            replay_test=case.replay_test,
            status=case.status_if_no_test,
            metadata_status="not_applicable",
            command="",
            returncode=None,
            duration_seconds=0.0,
            log_path="",
            blocker="replay_test_not_implemented",
            verified=False,
        )

    metadata_status = "not_run"
    if case.metadata_test:
        metadata_log = logs_dir / f"{case.slug}.metadata.log"
        metadata_cmd = _forge_cmd(case.test_path, case.metadata_test, "-vv")
        metadata_rc, _ = _run(metadata_cmd, timeout, metadata_log)
        metadata_status = "passed" if metadata_rc == 0 else "failed"
        if metadata_rc != 0:
            return ReplayResult(
                incident=case.incident,
                slug=case.slug,
                chain=case.chain,
                rpc_env=case.rpc_env,
                attack_family=case.attack_family,
                loss_usd=case.loss_usd,
                fork_block=case.fork_block,
                test_path=case.test_path,
                replay_test=case.replay_test,
                status="metadata_failed",
                metadata_status=metadata_status,
                command=" ".join(metadata_cmd),
                returncode=metadata_rc,
                duration_seconds=0.0,
                log_path=str(metadata_log.relative_to(REPO_ROOT)),
                blocker="metadata_or_compile_failure",
                verified=False,
            )

    if not os.environ.get(case.rpc_env):
        return ReplayResult(
            incident=case.incident,
            slug=case.slug,
            chain=case.chain,
            rpc_env=case.rpc_env,
            attack_family=case.attack_family,
            loss_usd=case.loss_usd,
            fork_block=case.fork_block,
            test_path=case.test_path,
            replay_test=case.replay_test,
            status="no_rpc",
            metadata_status=metadata_status,
            command="",
            returncode=None,
            duration_seconds=0.0,
            log_path="",
            blocker=f"{case.rpc_env} not configured",
            verified=False,
        )

    replay_log = logs_dir / f"{case.slug}.replay.log"
    replay_cmd = _forge_cmd(case.test_path, case.replay_test, verbosity)
    try:
        rc, duration = _run(replay_cmd, timeout, replay_log)
    except subprocess.TimeoutExpired as exc:
        replay_log.write_text(exc.stdout or "", encoding="utf-8")
        return ReplayResult(
            incident=case.incident,
            slug=case.slug,
            chain=case.chain,
            rpc_env=case.rpc_env,
            attack_family=case.attack_family,
            loss_usd=case.loss_usd,
            fork_block=case.fork_block,
            test_path=case.test_path,
            replay_test=case.replay_test,
            status="timeout",
            metadata_status=metadata_status,
            command=" ".join(replay_cmd),
            returncode=None,
            duration_seconds=float(timeout),
            log_path=str(replay_log.relative_to(REPO_ROOT)),
            blocker="forge_test_timeout",
            verified=False,
        )

    log_text = replay_log.read_text(encoding="utf-8", errors="ignore")
    blocker = "" if rc == 0 else _classify_failure(log_text)

    return ReplayResult(
        incident=case.incident,
        slug=case.slug,
        chain=case.chain,
        rpc_env=case.rpc_env,
        attack_family=case.attack_family,
        loss_usd=case.loss_usd,
        fork_block=case.fork_block,
        test_path=case.test_path,
        replay_test=case.replay_test,
        status="verified" if rc == 0 else "failed",
        metadata_status=metadata_status,
        command=" ".join(replay_cmd),
        returncode=rc,
        duration_seconds=duration,
        log_path=str(replay_log.relative_to(REPO_ROOT)),
        blocker=blocker,
        verified=rc == 0,
    )


def write_csv(path: Path, rows: Iterable[ReplayResult]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def write_blocker_matrix(path: Path, rows: Iterable[ReplayResult]) -> None:
    fieldnames = [
        "incident",
        "slug",
        "chain",
        "status",
        "has_replay_test",
        "rpc_configured",
        "metadata_passed",
        "needs_archive_rpc",
        "needs_replay_logic",
        "needs_non_evm_harness",
        "verified",
        "blocker",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            non_evm = row.chain in {"eos", "terra", "sui"}
            archive_blocked = row.blocker == "archive_state_unavailable"
            writer.writerow(
                {
                    "incident": row.incident,
                    "slug": row.slug,
                    "chain": row.chain,
                    "status": row.status,
                    "has_replay_test": bool(row.test_path),
                    "rpc_configured": row.status not in {"no_rpc", "no_test"} and not row.blocker.endswith(
                        "not configured"
                    ),
                    "metadata_passed": row.metadata_status == "passed",
                    "needs_archive_rpc": row.status == "no_rpc" or archive_blocked,
                    "needs_replay_logic": row.status == "no_test" and not non_evm,
                    "needs_non_evm_harness": row.status == "no_test" and non_evm,
                    "verified": row.verified,
                    "blocker": row.blocker,
                }
            )


def write_report(path: Path, rows: list[ReplayResult], logs_dir: Path) -> None:
    verified = sum(1 for row in rows if row.verified)
    no_rpc = sum(1 for row in rows if row.status == "no_rpc")
    no_test = sum(1 for row in rows if row.status == "no_test")
    failed = sum(1 for row in rows if row.status in {"failed", "metadata_failed", "timeout"})
    archive_blocked = sum(1 for row in rows if row.blocker == "archive_state_unavailable")
    replay_logic_blocked = sum(
        1 for row in rows if row.blocker == "replay_assertion_or_execution_failure"
    )
    implemented = sum(1 for row in rows if row.test_path)
    verified_names = ", ".join(row.incident for row in rows if row.verified) or "none"
    archive_names = ", ".join(
        row.incident for row in rows if row.blocker == "archive_state_unavailable"
    )
    replay_logic_names = ", ".join(
        row.incident for row in rows if row.blocker == "replay_assertion_or_execution_failure"
    )
    missing_test_names = ", ".join(row.incident for row in rows if row.status == "no_test")

    interpretation = [
        "A case is counted as replay-verified only when the concrete Foundry replay test runs",
        "against a configured RPC endpoint and exits successfully. Metadata-only tests, missing",
        "RPC configuration, and unimplemented replay scaffolds are not replay evidence.",
        "",
    ]
    if verified:
        interpretation.extend(
            [
                f"This run provides replay evidence for: {verified_names}. These cases can be",
                "used as concrete empirical support in the paper, subject to adding negative",
                "controls and documenting the fork block, chain, and replay command.",
                "",
            ]
        )
    else:
        interpretation.extend(
            [
                "This run did not produce a replay-verified exploit, so the paper should treat",
                "the current replay work as a blocker analysis rather than empirical replay evidence.",
                "",
            ]
        )
    if archive_blocked:
        interpretation.extend(
            [
                f"Archive-state access remains a chain-specific blocker for: {archive_names}.",
                "Those cases need archive-capable RPC on the affected chain before the replay",
                "logic can be evaluated.",
                "",
            ]
        )
    if replay_logic_blocked:
        interpretation.extend(
            [
                f"Replay logic or anchoring must be repaired for: {replay_logic_names}.",
                "These failures indicate that archive state was reachable but the current PoC",
                "does not yet reproduce the intended exploit path.",
                "",
            ]
        )
    if no_test:
        interpretation.extend(
            [
                f"Replay tests are still missing for: {missing_test_names}.",
                "These should be treated as implementation backlog, not failed replay evidence.",
            ]
        )

    targets = []
    if archive_blocked:
        targets.append("Configure archive-capable RPC for the blocked chains and rerun those cases.")
    if replay_logic_blocked:
        targets.append("Repair replay anchors and exploit steps for assertion/execution failures.")
    if no_test:
        targets.append("Implement high-value missing replay tests, prioritizing Fei/Rari, Beanstalk, and UwU Lend.")
    if verified:
        targets.append("Add negative controls for each verified replay and report pass/fail separation.")
    if not targets:
        targets.append("Expand the replay corpus and add negative controls.")

    lines = [
        "# Report 27: Replay Verification Results",
        "",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Summary",
        "",
        f"- Replay cases tracked: {len(rows)}",
        f"- Implemented Foundry replay tests: {implemented}",
        f"- Verified fork replays: {verified}",
        f"- Missing RPC configuration: {no_rpc}",
        f"- Archive-state unavailable on configured/public RPC: {archive_blocked}",
        f"- Replay logic/assertion failures: {replay_logic_blocked}",
        f"- Missing replay test implementation: {no_test}",
        f"- Failed or timed out replay attempts: {failed}",
        f"- Log directory: `{logs_dir.relative_to(REPO_ROOT)}`",
        "",
        "## Case Matrix",
        "",
        "| Incident | Chain | Family | Fork block | Test | Status | Blocker |",
        "|---|---|---|---:|---|---|---|",
    ]
    for row in rows:
        test = row.replay_test or ""
        block = row.fork_block if row.fork_block is not None else ""
        lines.append(
            f"| {row.incident} | {row.chain} | {row.attack_family} | {block} | "
            f"`{test}` | `{row.status}` | {row.blocker} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            *interpretation,
            "",
            "## Next Implementation Targets",
            "",
        ]
    )
    for index, target in enumerate(targets, start=1):
        lines.append(f"{index}. {target}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=900, help="Per-test timeout in seconds")
    parser.add_argument("--verbosity", default="-vvv", choices=["-v", "-vv", "-vvv", "-vvvv"])
    parser.add_argument(
        "--only",
        nargs="*",
        default=[],
        help="Optional slugs to run, e.g. euler-finance lendf-me",
    )
    args = parser.parse_args(argv)

    selected = [case for case in REPLAY_CASES if not args.only or case.slug in set(args.only)]
    if not selected:
        print("No replay cases selected", file=sys.stderr)
        return 2

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    logs_dir = REPO_ROOT / "reports" / "replay_runs" / run_id
    logs_dir.mkdir(parents=True, exist_ok=True)

    rows = [run_case(case, logs_dir, args.timeout, args.verbosity) for case in selected]

    processed_dir = REPO_ROOT / "data" / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)
    write_csv(processed_dir / "replay_results.csv", rows)
    write_blocker_matrix(processed_dir / "replay_blocker_matrix.csv", rows)
    (processed_dir / "replay_results.json").write_text(
        json.dumps([asdict(row) for row in rows], indent=2),
        encoding="utf-8",
    )
    write_report(REPO_ROOT / "reports" / "27_replay_verification_results.md", rows, logs_dir)

    print(json.dumps({"run_id": run_id, "results": [asdict(row) for row in rows]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
