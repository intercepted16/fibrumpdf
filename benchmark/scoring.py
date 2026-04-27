"""Extraction quality and table scoring."""

from math import isfinite
import re

from rapidfuzz import fuzz
from scipy.optimize import linear_sum_assignment
from scipy.stats import kendalltau

import benchmark.teds as teds
from benchmark.normalize import FEATURE_KEYS, from_gt, from_text

FeatureCounts = dict[str, int]


def score_text(
    text: str, gt_json: str, native_features: FeatureCounts | None = None
) -> dict[str, float | int]:
    gt_doc = from_gt(gt_json)
    pred_doc = from_text(text)
    table_data = _table_score(gt_doc.tables, pred_doc.tables)
    counts = pred_doc.feature_counts()
    if native_features:
        for key in FEATURE_KEYS:
            if key in native_features:
                counts[key] = int(native_features[key])
    counts["tables"] = max(counts["tables"], table_data["pred_tables"])
    heuristic = _heuristic_score(gt_doc.text, "\n".join(pred_doc.text))
    scores = {
        "marker_heuristic_score": heuristic,
        "marker_heuristic_score_median": heuristic,
        "marker_heuristic_score_stdev": 0.0,
    }
    scores.update(counts)
    scores.update(table_data)
    return scores


def _table_score(
    gt_tables: list[str], pred_tables: list[str]
) -> dict[str, float | int]:
    matched = _match_tables(gt_tables, pred_tables)
    return {
        "table_teds": sum(matched) / len(gt_tables) if gt_tables else 1.0,
        "table_precision": len(matched) / len(pred_tables) if pred_tables else 1.0,
        "table_recall": len(matched) / len(gt_tables) if gt_tables else 1.0,
        "gt_tables": len(gt_tables),
        "pred_tables": len(pred_tables),
        "matched_tables": len(matched),
    }


def _match_tables(gt_tables: list[str], pred_tables: list[str]) -> list[float]:
    if not gt_tables or not pred_tables:
        return []
    scores = [
        [
            teds.similarity_eval_html(
                teds.wrap_table_html(pred_html)[:50000],
                teds.wrap_table_html(gt_html)[:50000],
            )
            for pred_html in pred_tables[:50]
        ]
        for gt_html in gt_tables[:50]
    ]
    gt_indices, pred_indices = linear_sum_assignment(scores, maximize=True)
    matched = []
    for index, gt_index in enumerate(gt_indices):
        pred_index = pred_indices[index]
        matched.append(scores[gt_index][pred_index])
    return [score for score in matched if score >= 0.1]


def _heuristic_score(gt_blocks: list[str], pred_md: str) -> float:
    if not pred_md:
        return 0.0
    blocks = [_clean(block)[:4000] for block in gt_blocks if block]
    if not blocks:
        return 100.0
    pred = _clean(pred_md)[:8000]
    if len(blocks) == 1:
        align = fuzz.partial_ratio_alignment(blocks[0], pred, score_cutoff=70)
        return (align.score if align else 0.0) * 0.8 + 20.0
    scores = [
        fuzz.partial_ratio_alignment(block, pred, score_cutoff=70) for block in blocks
    ]
    starts = [align.dest_start if align else 0 for align in scores]
    weights = [len(block) for block in blocks]
    statistic = kendalltau(
        range(len(starts)), sorted(range(len(starts)), key=starts.__getitem__)
    ).statistic
    order = statistic if statistic is not None and isfinite(statistic) else 0.0
    content = 0.0
    for index, align in enumerate(scores):
        content += (align.score if align else 0.0) * weights[index]
    return (content / max(1, sum(weights))) * 0.8 + ((order + 1.0) * 50.0) * 0.2


def _clean(text: str) -> str:
    text = re.sub(r"(?<!\\\$)\$(?:\$([^$]+)\$\$|\s*([^$\n]+?)\s*\$)", r"$\1\2$", text)
    return re.sub(r"\s+", " ", text).strip().lower()
