"""导出 manuscript package。"""

from __future__ import annotations

from services.research.models import ManuscriptPackage


def render_manuscript_package_markdown(package: ManuscriptPackage | dict) -> str:
    if isinstance(package, dict):
        title = package.get("title", "")
        keywords = package.get("keywords", [])
        claims = package.get("claims", [])
        references = package.get("references", [])
        figures = package.get("figures", [])
        tables = package.get("tables", [])
    else:
        title = package.title
        keywords = package.keywords
        claims = [item.to_dict() for item in package.claims]
        references = [item.to_dict() for item in package.references]
        figures = [item.to_dict() for item in package.figures]
        tables = [item.to_dict() for item in package.tables]

    sections = [
        "# Manuscript Package",
        "",
        f"- Title: {title}",
        f"- Keywords: {'；'.join(keywords) or '暂无'}",
        "",
        "## Claims",
        "",
    ]
    if claims:
        for item in claims:
            sections.extend(
                [
                    f"### {item.get('claim', '')}",
                    "",
                    f"- Evidence: {item.get('evidence_summary', '')}",
                    f"- Validation: {item.get('validation_summary', '')}",
                    f"- Boundary: {item.get('boundary', '')}",
                    "",
                ]
            )
    else:
        sections.extend(["- 暂无", ""])

    sections.extend(["## Figures", ""])
    if figures:
        for item in figures:
            sections.extend(
                [
                    f"- {item.get('title', '')}: {item.get('caption', '')}",
                ]
            )
        sections.append("")
    else:
        sections.extend(["- 暂无", ""])

    sections.extend(["## Tables", ""])
    if tables:
        for item in tables:
            sections.extend(
                [
                    f"- {item.get('title', '')}: {item.get('caption', '')}",
                ]
            )
        sections.append("")
    else:
        sections.extend(["- 暂无", ""])

    sections.extend(["## References", ""])
    if references:
        for item in references:
            sections.append(f"- {item.get('title', '')}: {item.get('takeaway', '')}")
    else:
        sections.append("- 暂无")
    sections.append("")
    return "\n".join(sections)
