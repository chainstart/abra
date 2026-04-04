"""论文与报告 PDF 渲染。"""

from __future__ import annotations

import io
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Iterable

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer


_REGISTERED_FONT_NAME: str | None = None


def _font_name() -> str:
    """返回可用的中文字体名称。"""

    global _REGISTERED_FONT_NAME
    if _REGISTERED_FONT_NAME:
        return _REGISTERED_FONT_NAME

    candidates = [
        "/usr/share/fonts/truetype/arphic-gbsn00lp/gbsn00lp.ttf",
        "/usr/share/fonts/truetype/arphic/uming.ttc",
        "/usr/share/fonts/truetype/arphic-gkai00mp/gkai00mp.ttf",
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            font_name = f"pdf_font_{Path(path).stem}"
            try:
                pdfmetrics.getFont(font_name)
            except Exception:
                pdfmetrics.registerFont(TTFont(font_name, path))
            _REGISTERED_FONT_NAME = font_name
            return font_name

    _REGISTERED_FONT_NAME = "Helvetica"
    return _REGISTERED_FONT_NAME


def _styles():
    styles = getSampleStyleSheet()
    font_name = _font_name()
    title = ParagraphStyle(
        "PaperTitle",
        parent=styles["Title"],
        fontName=font_name,
        fontSize=17,
        leading=23,
        alignment=TA_CENTER,
        spaceAfter=10,
        textColor=colors.HexColor("#1b2430"),
        wordWrap="CJK",
    )
    section = ParagraphStyle(
        "PaperSection",
        parent=styles["Heading2"],
        fontName=font_name,
        fontSize=13,
        leading=18,
        spaceBefore=12,
        spaceAfter=8,
        textColor=colors.HexColor("#1b2430"),
        alignment=TA_LEFT,
        wordWrap="CJK",
    )
    subsection = ParagraphStyle(
        "PaperSubsection",
        parent=styles["Heading3"],
        fontName=font_name,
        fontSize=11,
        leading=15,
        spaceBefore=8,
        spaceAfter=6,
        textColor=colors.HexColor("#2f4156"),
        alignment=TA_LEFT,
        wordWrap="CJK",
    )
    body = ParagraphStyle(
        "PaperBody",
        parent=styles["BodyText"],
        fontName=font_name,
        fontSize=10,
        leading=15,
        alignment=TA_LEFT,
        spaceAfter=7,
        textColor=colors.HexColor("#1f2933"),
        wordWrap="CJK",
    )
    meta = ParagraphStyle(
        "PaperMeta",
        parent=body,
        fontName=font_name,
        fontSize=9,
        leading=13,
        alignment=TA_LEFT,
        spaceAfter=8,
        textColor=colors.HexColor("#52606d"),
        wordWrap="CJK",
    )
    return title, section, subsection, body, meta


def _escape(text: str) -> str:
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _paragraphs_from_lines(lines: Iterable[str]) -> list[str]:
    paragraphs: list[str] = []
    current: list[str] = []
    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            if current:
                paragraphs.append(" ".join(item.strip() for item in current))
                current = []
            continue
        current.append(line)
    if current:
        paragraphs.append(" ".join(item.strip() for item in current))
    return paragraphs


def _page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont(_font_name(), 8)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    canvas.drawRightString(doc.pagesize[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _escape_latex(text: str) -> str:
    """转义 LaTeX 特殊字符。"""

    escaped = str(text or "")
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
    }
    for old, new in replacements.items():
        escaped = escaped.replace(old, new)
    escaped = escaped.replace("~", r"\textasciitilde{}")
    escaped = escaped.replace("^", r"\textasciicircum{}")
    escaped = escaped.replace("’", "'")
    escaped = escaped.replace("“", "``").replace("”", "''")
    return escaped


def _strip_section_number(title: str) -> str:
    """移除 Markdown heading 中已写死的章节号。"""

    cleaned = str(title or "").strip()
    cleaned = re.sub(r"^\d+(?:\.\d+)*\.?\s+", "", cleaned)
    return cleaned.strip()


def _extract_title(markdown: str) -> str:
    for line in markdown.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return "Research Manuscript"


def _extract_section_body(markdown: str, heading: str) -> str:
    marker = f"## {heading}"
    if marker not in markdown:
        return ""
    start = markdown.index(marker) + len(marker)
    next_idx = markdown.find("\n## ", start)
    if next_idx == -1:
        next_idx = len(markdown)
    return markdown[start:next_idx].strip()


def _extract_abstract_text(markdown: str) -> str:
    body = _extract_section_body(markdown, "摘要")
    if not body:
        return ""
    lines = [
        line
        for line in body.splitlines()
        if not line.strip().startswith("**关键词：**")
        and not line.strip().startswith("**Keywords:**")
    ]
    return "\n".join(lines).strip()


def _extract_keywords(markdown: str) -> str:
    for line in markdown.splitlines():
        stripped = line.strip()
        if stripped.startswith("**关键词：**") or stripped.startswith("**Keywords:**"):
            return re.sub(r"\*\*", "", stripped).strip()
    return ""


def _extract_reference_items(markdown: str) -> list[str]:
    refs_body = _extract_section_body(markdown, "References")
    if not refs_body:
        return []
    items: list[str] = []
    for line in refs_body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^\[\d+\]\s+", stripped):
            items.append(re.sub(r"^\[\d+\]\s+", "", stripped))
    return items


def _markdown_body_to_latex(markdown: str) -> str:
    """将当前简化 Markdown 转成 LaTeX 正文。"""

    lines = markdown.splitlines()
    body: list[str] = []
    i = 0
    while i < len(lines):
        raw = lines[i].rstrip("\n")
        stripped = raw.strip()

        if not stripped:
            i += 1
            continue

        if stripped.startswith("# "):
            i += 1
            continue

        if stripped.startswith("## "):
            heading = stripped[3:].strip()
            if heading in {"摘要", "References"}:
                i += 1
                continue
            body.append(r"\section{" + _escape_latex(_strip_section_number(heading)) + "}")
            body.append("")
            i += 1
            continue

        if stripped.startswith("### "):
            body.append(r"\subsection{" + _escape_latex(stripped[4:].strip()) + "}")
            body.append("")
            i += 1
            continue

        if stripped.startswith("**关键词：**") or stripped.startswith("**Keywords:**"):
            i += 1
            continue

        if stripped.startswith("- "):
            bullet_lines = []
            while i < len(lines) and lines[i].strip().startswith("- "):
                bullet_lines.append(lines[i].strip()[2:].strip())
                i += 1
            body.append(r"\begin{itemize}[leftmargin=1.8em,itemsep=0.35em,topsep=0.35em]")
            for item in bullet_lines:
                body.append(r"\item " + _escape_latex(item))
            body.append(r"\end{itemize}")
            body.append("")
            continue

        if stripped[0].isdigit() and ". " in stripped[:5]:
            numbered_lines = []
            while i < len(lines):
                current = lines[i].strip()
                if not current or not current[0].isdigit() or ". " not in current[:5]:
                    break
                numbered_lines.append(current.split(". ", 1)[1].strip())
                i += 1
            body.append(r"\begin{enumerate}[leftmargin=1.8em,itemsep=0.35em,topsep=0.35em]")
            for item in numbered_lines:
                body.append(r"\item " + _escape_latex(item))
            body.append(r"\end{enumerate}")
            body.append("")
            continue

        para_lines = []
        while i < len(lines):
            current = lines[i].rstrip()
            current_stripped = current.strip()
            if not current_stripped:
                break
            if current_stripped.startswith(("# ", "## ", "### ", "- ")):
                break
            if current_stripped[0].isdigit() and ". " in current_stripped[:5]:
                break
            para_lines.append(current_stripped)
            i += 1
        paragraph = " ".join(para_lines).strip()
        if paragraph:
            body.append(_escape_latex(paragraph))
            body.append("")
        if i < len(lines) and not lines[i].strip():
            i += 1

    return "\n".join(body).strip() + "\n"


def _build_latex_document(markdown: str) -> str:
    title = _escape_latex(_extract_title(markdown))
    abstract_text = _escape_latex(_extract_abstract_text(markdown))
    raw_keywords_text = _extract_keywords(markdown)
    if "：" in raw_keywords_text:
        keyword_label_raw, keyword_value_raw = raw_keywords_text.split("：", 1)
    else:
        keyword_label_raw, keyword_value_raw = "关键词", raw_keywords_text
    keyword_label = _escape_latex(keyword_label_raw.strip())
    keyword_value = _escape_latex(keyword_value_raw.strip())
    body = _markdown_body_to_latex(markdown)
    references = _extract_reference_items(markdown)
    bibliography = "\n".join(
        [
            r"\begin{thebibliography}{99}",
            *[
                r"\bibitem{ref" + str(index) + "} " + _escape_latex(item)
                for index, item in enumerate(references, start=1)
            ],
            r"\end{thebibliography}",
        ]
    ) if references else r"\section*{References}" + "\n" + r"\noindent No references provided."
    return (
        r"\documentclass[10pt,twocolumn,a4paper]{ctexart}" "\n"
        r"\usepackage{geometry}" "\n"
        r"\usepackage{enumitem}" "\n"
        r"\usepackage{abstract}" "\n"
        r"\usepackage{newtxtext,newtxmath}" "\n"
        r"\usepackage{titlesec}" "\n"
        r"\usepackage{fancyhdr}" "\n"
        r"\usepackage{microtype}" "\n"
        r"\usepackage[hidelinks]{hyperref}" "\n"
        r"\geometry{top=1.7cm,bottom=2.0cm,left=1.45cm,right=1.45cm,columnsep=0.62cm}" "\n"
        r"\setlength{\parindent}{1.2em}" "\n"
        r"\setlength{\parskip}{0.15em}" "\n"
        r"\renewcommand{\abstractname}{摘要}" "\n"
        r"\renewcommand{\abstracttextfont}{\normalfont\small}" "\n"
        r"\renewcommand{\absnamepos}{center}" "\n"
        r"\titleformat{\section}{\large\bfseries}{\thesection.}{0.5em}{}" "\n"
        r"\titleformat{\subsection}{\normalsize\bfseries}{\thesubsection}{0.5em}{}" "\n"
        r"\titlespacing*{\section}{0pt}{1.0ex plus 0.2ex minus 0.2ex}{0.5ex}" "\n"
        r"\titlespacing*{\subsection}{0pt}{0.8ex plus 0.2ex minus 0.2ex}{0.35ex}" "\n"
        r"\pagestyle{fancy}" "\n"
        r"\fancyhf{}" "\n"
        r"\fancyfoot[C]{\thepage}" "\n"
        r"\renewcommand{\headrulewidth}{0pt}" "\n"
        r"\setlist[itemize]{leftmargin=1.4em,itemsep=0.2em,topsep=0.25em}" "\n"
        r"\setlist[enumerate]{leftmargin=1.5em,itemsep=0.2em,topsep=0.25em}" "\n"
        r"\makeatletter" "\n"
        r"\begin{document}" "\n\n"
        r"\twocolumn[" "\n"
        r"\begin{@twocolumnfalse}" "\n"
        r"\begin{center}" "\n"
        r"{\LARGE\bfseries " + title + r"\par}" "\n"
        r"\vspace{0.8em}" "\n"
        r"\end{center}" "\n"
        r"\begin{abstract}" "\n"
        + abstract_text + "\n"
        r"\end{abstract}" "\n"
        + (
            r"\noindent{\small\textbf{" + keyword_label + r"：" + r"} " + keyword_value + r"\par}" "\n"
            if keyword_value
            else ""
        )
        + r"\vspace{1.0em}" "\n"
        r"\end{@twocolumnfalse}" "\n"
        r"]" "\n\n"
        + body
        + "\n"
        + bibliography
        + "\n"
        r"\makeatother" "\n"
        r"\end{document}" "\n"
    )


def _render_with_xelatex(markdown: str) -> bytes | None:
    """优先用 XeLaTeX 生成正式 PDF。"""

    if not shutil.which("xelatex"):
        return None

    latex = _build_latex_document(markdown)
    with tempfile.TemporaryDirectory(prefix="paper_xelatex_") as tmpdir:
        tmp = Path(tmpdir)
        tex_path = tmp / "paper.tex"
        pdf_path = tmp / "paper.pdf"
        tex_path.write_text(latex, encoding="utf-8")
        for _ in range(2):
            run = subprocess.run(
                [
                    "xelatex",
                    "-interaction=nonstopmode",
                    "-halt-on-error",
                    "-output-directory",
                    str(tmp),
                    str(tex_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            if run.returncode != 0:
                return None
        if not pdf_path.exists():
            return None
        return pdf_path.read_bytes()


def _render_with_reportlab(markdown: str) -> bytes:
    """ReportLab 兜底渲染。"""

    title_style, section_style, subsection_style, body_style, meta_style = _styles()
    story = []
    lines = markdown.splitlines()

    title_rendered = False
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped.startswith("# ") and not title_rendered:
            story.append(Paragraph(_escape(stripped[2:]), title_style))
            story.append(Spacer(1, 3 * mm))
            title_rendered = True
            i += 1
            continue

        if stripped.startswith("## "):
            story.append(Paragraph(_escape(stripped[3:]), section_style))
            i += 1
            continue

        if stripped.startswith("### "):
            story.append(Paragraph(_escape(stripped[4:]), subsection_style))
            i += 1
            continue

        if stripped.startswith("**关键词：**") or stripped.startswith("**Keywords:**"):
            story.append(Paragraph(_escape(stripped.replace("**", "")), meta_style))
            i += 1
            continue

        if stripped.startswith("- "):
            bullet_lines = []
            while i < len(lines) and lines[i].strip().startswith("- "):
                bullet_lines.append(lines[i].strip()[2:])
                i += 1
            story.append(
                ListFlowable(
                    [
                        ListItem(Paragraph(_escape(item), body_style), leftIndent=8)
                        for item in bullet_lines
                    ],
                    bulletType="bullet",
                    start="circle",
                    leftIndent=12,
                    spaceAfter=4,
                )
            )
            continue

        if stripped[0].isdigit() and ". " in stripped[:5]:
            numbered = []
            while i < len(lines):
                current = lines[i].strip()
                if not current or not current[0].isdigit() or ". " not in current[:5]:
                    break
                numbered.append(current.split(". ", 1)[1])
                i += 1
            story.append(
                ListFlowable(
                    [
                        ListItem(Paragraph(_escape(item), body_style), value=index + 1)
                        for index, item in enumerate(numbered)
                    ],
                    bulletType="1",
                    leftIndent=12,
                    spaceAfter=4,
                )
            )
            continue

        para_lines = []
        while i < len(lines):
            current = lines[i].rstrip()
            stripped_current = current.strip()
            if not stripped_current:
                break
            if stripped_current.startswith(("# ", "## ", "### ", "- ")):
                break
            if stripped_current[0].isdigit() and ". " in stripped_current[:5]:
                break
            para_lines.append(current)
            i += 1
        for paragraph in _paragraphs_from_lines(para_lines):
            story.append(Paragraph(_escape(paragraph), body_style))
        if i < len(lines) and not lines[i].strip():
            i += 1

    if not story:
        story.append(Paragraph("Empty document.", body_style))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title="Research Paper",
    )
    doc.build(story, onFirstPage=_page_number, onLaterPages=_page_number)
    return buffer.getvalue()


def render_markdown_to_pdf_bytes(markdown: str) -> bytes:
    """把当前论文/报告 markdown 渲染为 PDF。"""

    rendered = _render_with_xelatex(markdown)
    if rendered:
        return rendered
    return _render_with_reportlab(markdown)
