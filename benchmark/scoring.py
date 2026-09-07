"""Turn Markdown and ground-truth HTML into comparable content, and score it."""

import json
import re
import unicodedata
from math import isfinite
from collections import Counter

import Levenshtein
import mistune
from apted import APTED, Config
from apted.helpers import Tree
from lxml import html
from rapidfuzz import fuzz
from scipy.optimize import linear_sum_assignment
from scipy.stats import kendalltau

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
FEATURE_KEYS = tuple(dict.fromkeys(FEATURE_MAP.values()))
BLOCK_TAGS = ("h1", "h2", "h3", "h4", "h5", "h6", "p", "li")
PAGE_SPLIT_RE = re.compile(r"\n\s*---\s*\n")
MARKDOWN_AST = mistune.create_markdown(renderer=None, plugins=["table"])
MARKDOWN_HTML = mistune.create_markdown(renderer="html", plugins=["table"])


def score_text(text, gt_json, native_features=None):
    gt_blocks, gt_tables = _parse(
        str(item.get("html") or "") for item in json.loads(gt_json or "[]")
    )
    pages = PAGE_SPLIT_RE.split(text)
    blocks, tables = _parse(str(MARKDOWN_HTML(page) or "") for page in pages)

    markdown = Counter()
    for page in pages:
        markdown.update(_features(MARKDOWN_AST(page) or []))
    # a tool reporting its own formatting counts overrides our Markdown parse
    native = native_features or {}
    counts = {key: int(native.get(key, markdown[key])) for key in FEATURE_KEYS}
    counts["tables"] = max(counts["tables"], len(tables))

    matched = _match_tables(gt_tables, tables)
    return {
        "marker_heuristic_score": _heuristic_score(gt_blocks, "\n".join(blocks)),
        "table_teds": sum(matched) / len(gt_tables) if gt_tables else 1.0,
        "gt_tables": len(gt_tables),
        "pred_tables": len(tables),
        "matched_tables": len(matched),
        **counts,
    }


def _parse(fragments):
    blocks, tables = [], []
    for fragment in fragments:
        root = html.fragment_fromstring(
            fragment.strip() or "<div></div>", create_parent=True
        )
        blocks += [
            text for el in root.iter(*BLOCK_TAGS) if (text := _norm(el.text_content()))
        ]
        found = list(root.iter("table"))
        blocks += [
            _norm(" | ".join(cells))
            for table in found
            for row in table.xpath(".//tr")
            if (cells := [_norm(c.text_content()) for c in row.xpath("./th|./td")])
        ]
        tables += [html.tostring(table, encoding="unicode") for table in found]
    return blocks, tables


def _features(tokens):
    counts = Counter()
    stack = list(tokens)
    while stack:
        token = stack.pop()
        if token.get("type") in FEATURE_MAP:
            counts[FEATURE_MAP[token["type"]]] += 1
        stack.extend(token.get("children") or [])
    return counts


def _norm(text):
    text = unicodedata.normalize("NFKC", text).replace("\u00a0", " ")
    return re.sub(r"\s+", " ", text).strip()


def _clean(text):
    text = re.sub(r"(?<!\\\$)\$(?:\$([^$]+)\$\$|\s*([^$\n]+?)\s*\$)", r"$\1\2$", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def _heuristic_score(gt_blocks, pred_md):
    if not pred_md:
        return 0.0
    blocks = [_clean(block)[:4000] for block in gt_blocks if block]
    if not blocks:
        return 100.0
    pred = _clean(pred_md)[:8000]
    aligned = [fuzz.partial_ratio_alignment(b, pred, score_cutoff=70) for b in blocks]
    scores = [align.score if align else 0.0 for align in aligned]
    if len(blocks) == 1:
        return scores[0] * 0.8 + 20.0
    starts = [align.dest_start if align else 0 for align in aligned]
    weights = [len(block) for block in blocks]
    tau = kendalltau(
        range(len(starts)), sorted(range(len(starts)), key=starts.__getitem__)
    ).statistic
    order = tau if tau is not None and isfinite(tau) else 0.0
    content = sum(s * w for s, w in zip(scores, weights, strict=True))
    return (content / max(1, sum(weights))) * 0.8 + ((order + 1.0) * 50.0) * 0.2


def _match_tables(gt_tables, pred_tables):
    if not gt_tables or not pred_tables:
        return []
    scores = [[_teds(pred, gt) for pred in pred_tables[:50]] for gt in gt_tables[:50]]
    pairs = zip(*linear_sum_assignment(scores, maximize=True), strict=True)
    return [score for r, c in pairs if (score := scores[r][c]) >= 0.1]


class _TableTree(Tree):
    def __init__(self, node):  # noqa: D107
        super().__init__(node.tag)
        self.tag = node.tag
        self.colspan = int(node.attrib.get("colspan", 1))
        self.rowspan = int(node.attrib.get("rowspan", 1))
        self.content = "".join(node.itertext()) if node.tag == "td" else ""
        self.children = [_TableTree(child) for child in node]


class _TableConfig(Config):
    def rename(self, node1, node2):
        shape1 = (node1.tag, node1.colspan, node1.rowspan)
        shape2 = (node2.tag, node2.colspan, node2.rowspan)
        if shape1 != shape2:
            return 1
        distance = Levenshtein.distance(node1.content, node2.content)
        return int(distance / max(len(node1.content), len(node2.content), 1))


def _teds(pred_html, true_html):
    tables = [_table(fragment) for fragment in (pred_html, true_html)]
    if any(table is None for table in tables):
        return 0.0
    nodes = max(len(table.xpath(".//*")) for table in tables)
    if not nodes:
        return 0.0
    distance = APTED(*map(_TableTree, tables), _TableConfig()).compute_edit_distance()
    return 1.0 - int(distance) / nodes


def _table(fragment):
    document = f"<html><body>{fragment.strip()}</body></html>"[:50000]
    return next(iter(html.fromstring(document).xpath("body/table")), None)
