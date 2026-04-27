"""Normalize Markdown and ground-truth HTML into comparable document content."""

import json
import re
import unicodedata
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Iterable, cast

import mistune
from lxml import html

FEATURE_KEYS = (
    "headings",
    "links",
    "tables",
    "images",
    "bold",
    "italic",
    "code_blocks",
)
FEATURE_MAP = {
    "heading": "headings",
    "link": "links",
    "table": "tables",
    "image": "images",
    "strong": "bold",
    "emphasis": "italic",
    "codespan": "code_blocks",
    "block_code": "code_blocks",
}
PAGE_SPLIT_RE = re.compile(r"\n\s*---\s*\n")
MARKDOWN_AST = mistune.create_markdown(renderer=None, plugins=["table"])
MARKDOWN_HTML = mistune.create_markdown(renderer="html", plugins=["table"])


@dataclass(frozen=True)
class NormalizedDoc:
    text: list[str]
    tables: list[str]
    features: dict[str, int] | None = None

    def feature_counts(self) -> dict[str, int]:
        return {key: int((self.features or {}).get(key, 0)) for key in FEATURE_KEYS}


def from_text(text: str) -> NormalizedDoc:
    pages = re.split(PAGE_SPLIT_RE, text)
    blocks: list[str] = []
    tables: list[str] = []
    features = Counter(dict.fromkeys(FEATURE_KEYS, 0))
    for page in pages:
        features.update(_feature_counts(MARKDOWN_AST(page) or []))
        page_blocks, page_tables = _html_content(str(MARKDOWN_HTML(page) or ""))
        blocks.extend(page_blocks)
        tables.extend(page_tables)
    return NormalizedDoc(blocks, tables, dict(features))


def from_gt(gt_json: str) -> NormalizedDoc:
    blocks: list[str] = []
    tables: list[str] = []
    for item in json.loads(gt_json or "[]"):
        page_blocks, page_tables = _html_content(str(item.get("html") or ""))
        blocks.extend(page_blocks)
        tables.extend(page_tables)
    return NormalizedDoc(blocks, tables)


def reconcile_pages(
    pages: list[str], fallback_text: str, expected_pages: int
) -> list[str]:
    content = [page.strip() for page in pages] or [fallback_text.strip()]
    if expected_pages <= 1:
        return ["\n\n".join(content).strip()]
    if len(content) > expected_pages:
        tail = "\n\n".join(content[expected_pages - 1 :]).strip()
        return [*content[: expected_pages - 1], tail]
    return [*content, *([""] * (expected_pages - len(content)))]


def distribute_pages(pages: list[str], counts: list[int]) -> list[str]:
    chunks = []
    start = 0
    for count in counts:
        end = start + count
        chunks.append("\n---\n\n".join(pages[start:end]).strip())
        start = end
    return chunks


def _feature_counts(tokens: Iterable[Mapping[str, object]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    stack = list(tokens)
    while stack:
        token = stack.pop()
        if token.get("type") in FEATURE_MAP:
            counts[FEATURE_MAP[cast(str, token["type"])]] += 1
        stack.extend(cast(Iterable[Mapping[str, object]], token.get("children") or []))
    return counts


def _clean_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).replace("\u00a0", " ")
    return re.sub(r"\s+", " ", text).strip()


def _html_content(fragment: str) -> tuple[list[str], list[str]]:
    root = html.fragment_fromstring(
        fragment.strip() or "<div></div>", create_parent=True
    )
    blocks = list(
        filter(
            None,
            (
                _clean_text(element.text_content())
                for element in root.iter("h1", "h2", "h3", "h4", "h5", "h6", "p", "li")
            ),
        )
    )
    blocks.extend(row for table in root.iter("table") for row in _table_rows(table))
    tables = [html.tostring(table, encoding="unicode") for table in root.iter("table")]
    return blocks, tables


def _table_rows(table: html.HtmlElement) -> list[str]:
    rows = []
    for tr in table.xpath(".//tr"):
        row = [_clean_text(cell.text_content()) for cell in tr.xpath("./th|./td")]
        if row:
            rows.append(_clean_text(" | ".join(row)))
    return rows
