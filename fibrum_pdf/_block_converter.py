"""Block to Markdown conversion."""

from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger(__name__)

BULLETS = frozenset("•‣⁃⁌⁍∙▪▫●○◦■□▶▸◆◇♦➤\uf0b7\ufffd")
FMT_MARKERS = ("**", "*", "`", "~~")
PUNCT = " \n\t.,;:)]/\\-?!"
STYLES = [("bold", "**"), ("italic", "*"), ("strikeout", "~~"), ("subscript", "~")]


def _normalize_bullets(text: str) -> str:
    out: list[str] = []
    i: int = 0
    while i < len(text):
        if text[i] in BULLETS:
            out.append("- ")
            i += 1
            while i < len(text) and text[i] in " \t":
                i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _style_span(span: dict[str, Any]) -> str:
    if not (text := span.get("text", "")):
        return ""
    link = (
        next((span.get(k) for k in ["link", "uri"] if isinstance(span.get(k), str)), "")
        or ""
    )
    if span.get("superscript"):
        s = text.strip()
        return f"[{s}]" if s.isdigit() or re.match(r"^\d+[,\s\d]*$", s) else f"^{text}^"
    for key, fmt in STYLES:
        if span.get(key):
            text = f"{fmt}{text}{fmt}"
    return f"[{text}]({link})" if link else text


def _join_spans(spans: list[dict[str, Any]]) -> str:
    parts = []
    for i, span in enumerate(spans):
        if not (styled := _style_span(span)):
            continue
        if (
            parts
            and any(styled.startswith(m) for m in FMT_MARKERS)
            and parts[-1][-1:] not in " \n\t([/"
        ):
            parts.append(" ")
        parts.append(styled)
        if (
            i + 1 < len(spans)
            and (nxt := spans[i + 1].get("text", ""))
            and any(styled.endswith(m) for m in FMT_MARKERS)
            and nxt[0] not in PUNCT
        ):
            parts.append(" ")
    return "".join(parts)


def _cell_text(cell: dict[str, Any]) -> str:
    text = (
        " ".join(s.get("text", "") for s in (cell.get("spans") or [])).strip()
        if cell.get("spans")
        else cell.get("text", "").strip()
    )
    return text.replace("|", "\\|").replace("\n", "<br>")


def _table(rows: list[dict[str, Any]]) -> str:
    if (
        not rows
        or not (
            matrix := [[_cell_text(c) for c in row.get("cells", [])] for row in rows]
        )
        or not any(matrix[0])
    ):
        return ""
    hdr = matrix[0]
    lines = [
        "| " + " | ".join(hdr) + " |",
        "| " + " | ".join("---" for _ in hdr) + " |",
    ]
    for row in matrix[1:]:
        row = (row + [""] * len(hdr))[: len(hdr)]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def _list(block: dict[str, Any], text: str) -> str:
    if items := block.get("items"):
        lines = [
            f"{'  ' * item.get('indent', 0)}{item.get('prefix', '-') + ' ' if item.get('prefix') else '- '}{t.strip()}"
            for item in items
            if (t := _join_spans(item.get("spans", [])))
        ]
        return "\n".join(lines) + "\n" if lines else ""
    return (
        "\n".join(f"- {ln.strip()}" for ln in text.split("\n") if ln.strip()) + "\n"
        if text
        else ""
    )


def block_to_markdown(block: dict[str, Any]) -> str:
    type = block.get("type", "")
    text = block.get("text", "").strip() or _join_spans(block.get("spans", []))
    if not text and typ not in ("table", "list"):
        return ""

    if typ == "heading":
        level = max(1, min(int(block.get("level") or 1), 6))
        if level >= 4:
            plain = (block.get("text") or "").strip() or "".join(
                str(span.get("text", "")) for span in block.get("spans", [])
            ).strip()
            return f"**{plain or text}**\n"
        return f"{'#' * level} **{text}**\n"
    elif typ in ("paragraph", "text"):
        return f"{text}\n"
    elif typ == "code":
        return f"{text}\n"
    elif typ == "table":
        return _table(block.get("rows", []))
    elif typ == "list":
        return _list(block, text)
    elif typ == "figure":
        return f"![Figure]({block.get('text', 'figure')})\n"
    log.debug("skipping block type=%s", typ)
    return ""
