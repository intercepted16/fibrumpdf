"""Block to Markdown conversion."""

from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger(__name__)

BULLETS = frozenset("•‣⁃⁌⁍∙▪▫●○◦■□▶▸◆◇♦➤\uf0b7\ufffd")
FMT_MARKERS = ("**", "*", "`", "~~")
PUNCT = " \n\t.,;:)]/\\-?!"
STYLES = [
    ("monospace", "`"),
    ("bold", "**"),
    ("italic", "*"),
    ("strikeout", "~~"),
    ("subscript", "~"),
]


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
    text = span.get("text", "")
    if not text:
        return ""
    if span.get("superscript"):
        s = text.strip()
        return f"[{s}]" if s.isdigit() or re.match(r"^\d+[,\s\d]*$", s) else f"^{text}^"
    for key, fmt in STYLES:
        if span.get(key):
            text = f"{fmt}{text}{fmt}"
    return text


def _join_spans(spans: list[dict[str, Any]]) -> str:
    if not spans:
        return ""
    parts: list[str] = []
    for i, span in enumerate(spans):
        styled = _style_span(span)
        if not styled:
            continue
        if (
            parts
            and any(styled.startswith(m) for m in FMT_MARKERS)
            and parts[-1][-1:] not in " \n\t([/"
        ):
            parts.append(" ")
        parts.append(styled)
        if i + 1 < len(spans):
            nxt = spans[i + 1].get("text", "")
            if (
                any(styled.endswith(m) for m in FMT_MARKERS)
                and nxt
                and nxt[0] not in PUNCT
            ):
                parts.append(" ")
    return "".join(parts)


def _cell_text(cell: dict[str, Any]) -> str:
    if spans := cell.get("spans"):
        return " ".join(s.get("text", "") for s in spans).strip().replace("|", "\\|")
    return cell.get("text", "").strip().replace("|", "\\|")


def _table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return ""
    hdr = [_cell_text(c) for c in rows[0].get("cells", [])]
    lines: list[str] = []
    if any(hdr):
        lines += [
            "| " + " | ".join(hdr) + " |",
            "| " + " | ".join("---" for _ in hdr) + " |",
        ]
    for row in rows[1:]:
        lines.append(
            "| " + " | ".join(_cell_text(c) for c in row.get("cells", [])) + " |"
        )
    return "\n".join(lines) + "\n" if lines else ""


def _list(block: dict[str, Any], text: str) -> str:
    if items := block.get("items"):
        lines: list[str] = []
        for item in items:
            if t := _join_spans(item.get("spans", [])):
                ind = "  " * item.get("indent", 0)
                mark = f"{item.get('prefix')} " if item.get("prefix") else "- "
                lines.append(f"{ind}{mark}{t.strip()}")
        return "\n".join(lines) + "\n" if lines else ""
    return (
        "\n".join(f"- {ln.strip()}" for ln in text.split("\n") if ln.strip()) + "\n"
        if text
        else ""
    )


def block_to_markdown(block: dict[str, Any]) -> str:
    type = block.get("type", "")
    text = block.get("text", "").strip() or _join_spans(block.get("spans", []))
    if text:
        text = _normalize_bullets(text)

    match type:
        case "heading" if text:
            return f"{'#' * block.get('level', 1)} {text}\n"
        case "paragraph" | "text" if text:
            return f"{text}\n"
        case "table":
            return _table(block.get("rows", []))
        case "list":
            return _list(block, text)
        case "figure":
            return f"![Figure]({block.get('text', 'figure')})\n"
        case _:
            log.debug("skipping block type=%s", type)
            return ""
