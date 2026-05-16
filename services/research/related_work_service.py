"""本地 related work 检索。

当前仍然以本地资料为主，但这层不再只是“捞点相关文本”，
而是为研究问题构建带理由的引用链。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re

from services.analysis.models import AuditRunResult
from services.research.incident_evidence_service import build_incident_evidence_package
from services.research.models import CitationRecord, ResearchIdea


def _tokenize(text: str) -> set[str]:
    """做稳定的关键词拆分。"""

    return {
        token
        for token in re.split(r"[^a-zA-Z0-9_\-\u4e00-\u9fff]+", text.lower())
        if token
    }


def _citation_id(prefix: str, source_ref: str, title: str) -> str:
    """生成稳定引用 ID。"""

    digest = hashlib.sha1(f"{prefix}::{source_ref}::{title}".encode("utf-8")).hexdigest()[:16]
    return f"citation_{digest}"


def _snippet(text: str, keyword: str, window: int = 160) -> str:
    """截取带关键词的摘要片段。"""

    lower_text = text.lower()
    index = lower_text.find(keyword.lower())
    if index == -1:
        return text[:window].strip()
    start = max(index - window // 2, 0)
    end = min(index + window // 2, len(text))
    return text[start:end].strip()


def _clean_report_excerpt(text: str, max_length: int = 180) -> str:
    """把报告片段清洗成更像正文摘录的短句。"""

    cleaned_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("|") or line.startswith("```"):
            continue
        if set(line) <= {"-", "=", "#", "|", "*", "`", " "}:
            continue
        cleaned_lines.append(line)

    merged = " ".join(cleaned_lines)
    merged = re.sub(r"\s+", " ", merged).strip()
    if not merged:
        return ""
    if len(merged) <= max_length:
        return merged
    cut = merged[:max_length].rstrip(" ,;:")
    return f"{cut}..."


def _is_good_report_citation(citation: CitationRecord) -> bool:
    """过滤明显过脏的报告引用。"""

    noisy = sum(marker in (citation.key_takeaway or citation.snippet) for marker in ["|", "```", "###"])
    if noisy >= 1 and citation.support_level == "reference":
        return False
    return True


def _support_level(score: int) -> str:
    """把相关性分数映射成文字等级。"""

    if score >= 8:
        return "high"
    if score >= 5:
        return "medium"
    return "reference"


def _claim_for_index(research_idea: ResearchIdea, index: int) -> str:
    """为引用匹配一条研究主张。"""

    questions = research_idea.research_questions or []
    if questions:
        return questions[index % len(questions)]
    return research_idea.problem_statement or research_idea.hypothesis


def retrieve_related_work(
    research_idea: ResearchIdea,
    audit_result: AuditRunResult,
    *,
    report_dir: Path | None = None,
    limit: int = 10,
) -> list[CitationRecord]:
    """从本地历史案例和报告中抽取 related work。"""

    root = Path(report_dir or Path("reports")).resolve()
    query_tokens = set()
    query_tokens.update(_tokenize(research_idea.title))
    query_tokens.update(_tokenize(research_idea.focus_category))
    query_tokens.update(_tokenize(research_idea.hypothesis))
    query_tokens.update(_tokenize(research_idea.problem_statement))
    for question in research_idea.research_questions or []:
        query_tokens.update(_tokenize(question))
    query_tokens.update(_tokenize(audit_result.classification.protocol_type))
    for incident_match in audit_result.related_incidents:
        query_tokens.update(_tokenize(incident_match.incident.title))
        query_tokens.update(_tokenize(incident_match.incident.root_cause))

    citations: list[CitationRecord] = []

    for index, incident_match in enumerate(audit_result.related_incidents):
        incident = incident_match.incident
        evidence_package = build_incident_evidence_package(incident)
        claim_supported = _claim_for_index(research_idea, index)
        key_takeaway = (
            evidence_package.evidence_summary[-1]
            if evidence_package.evidence_summary
            else incident.root_cause or incident.summary
        )
        citation_reason = "；".join(incident_match.reasons) or "该历史案例与当前研究方向在攻击模式或根因上相近。"
        citations.append(
            CitationRecord(
                citation_id=_citation_id("incident", incident.incident_id, incident.title),
                title=incident.title,
                source_type="incident",
                source_ref=incident.incident_id,
                snippet="；".join(evidence_package.evidence_summary[:3]) or incident.summary,
                relevance_score=incident_match.score,
                claim_supported=claim_supported,
                citation_reason=citation_reason,
                support_level=_support_level(incident_match.score),
                key_takeaway=key_takeaway,
            )
        )

    if root.exists():
        for path in sorted(root.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            report_tokens = _tokenize(path.name) | _tokenize(text[:5000])
            overlap = query_tokens.intersection(report_tokens)
            if not overlap:
                continue

            best_keyword = sorted(overlap, key=len, reverse=True)[0]
            overlap_score = min(len(overlap), 10)
            claim_supported = _claim_for_index(research_idea, overlap_score)
            citations.append(
                CitationRecord(
                    citation_id=_citation_id("report", str(path), path.stem),
                    title=path.stem,
                    source_type="report",
                    source_ref=str(path),
                    snippet=_clean_report_excerpt(_snippet(text, best_keyword)) or _snippet(text, best_keyword),
                    relevance_score=overlap_score,
                    claim_supported=claim_supported,
                    citation_reason=(
                        f"报告内容与研究问题在关键词 `{best_keyword}` 上重合，"
                        "适合用作本地相关工作或方法对照。"
                    ),
                    support_level=_support_level(overlap_score),
                    key_takeaway=_clean_report_excerpt(_snippet(text, best_keyword, window=90)) or _snippet(text, best_keyword, window=90),
                )
            )

    citations.sort(
        key=lambda item: (
            -item.relevance_score,
            0 if item.source_type == "incident" else 1,
            item.title,
        )
    )

    deduped: list[CitationRecord] = []
    seen_ids: set[str] = set()
    for citation in citations:
        if citation.citation_id in seen_ids:
            continue
        if citation.source_type == "report" and not _is_good_report_citation(citation):
            continue
        seen_ids.add(citation.citation_id)
        deduped.append(citation)
    return deduped[:limit]
