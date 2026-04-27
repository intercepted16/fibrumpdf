"""Result frame normalization, aggregation, and CSV writing."""

from collections.abc import Mapping, Sequence
from pathlib import Path

import polars as pl

from benchmark.normalize import FEATURE_KEYS

SUMMARY_PDF = "ALL"
TYPE_PREFIX = "Type: "
TIMING_FIELDS = (
    "time_median_s",
    "time_mean_s",
    "time_stdev_s",
    "time_min_s",
    "time_max_s",
    "runs",
)
RESULT_COLUMNS = [
    "pdf",
    "description",
    "language",
    "tool",
    "time_median_s",
    "time_mean_s",
    "time_stdev_s",
    "time_min_s",
    "time_max_s",
    "runs",
    "pages",
    "pages_per_s",
    "pages_per_s_stdev",
    "marker_heuristic_score",
    "marker_heuristic_score_median",
    "marker_heuristic_score_stdev",
    "table_teds",
    "table_precision",
    "table_recall",
    "gt_tables",
    "pred_tables",
    "matched_tables",
]
RESULT_COLUMNS.extend(FEATURE_KEYS)
RESULT_COLUMNS.append("error")
TEXT_COLS = ["pdf", "description", "language", "tool", "error"]
INT_COLS = ["runs", "gt_tables", "pred_tables", "matched_tables"]
INT_COLS.extend(FEATURE_KEYS)
SUM_COLS = ["gt_tables", "pred_tables", "matched_tables"]
SUM_COLS.extend(FEATURE_KEYS)
MEAN_COLS = list(TIMING_FIELDS)
MEAN_COLS.extend(["pages", "marker_heuristic_score", "table_teds"])


def rows_frame(rows: Sequence[Mapping[str, object]]) -> pl.DataFrame:
    return normalize_frame(pl.from_dicts(rows) if rows else pl.DataFrame())


def normalize_frame(frame: pl.DataFrame) -> pl.DataFrame:
    if not frame.columns:
        frame = pl.DataFrame({column: [] for column in RESULT_COLUMNS})
    missing = []
    for column in RESULT_COLUMNS:
        if column not in frame.columns:
            missing.append(pl.lit(None).alias(column))
    if missing:
        frame = frame.with_columns(missing)

    expressions = []
    for column in RESULT_COLUMNS:
        dtype = (
            pl.Utf8
            if column in TEXT_COLS
            else pl.Int64
            if column in INT_COLS
            else pl.Float64
        )
        default = "" if column in TEXT_COLS else 0
        expressions.append(
            pl.col(column).cast(dtype, strict=False).fill_null(default).alias(column)
        )
    return frame.select(expressions)


def _ratio(num: str, den: str, default: float) -> pl.Expr:
    return pl.when(pl.col(den) > 0).then(pl.col(num) / pl.col(den)).otherwise(default)


def _aggregate(raw: pl.DataFrame, group_cols: list[str]) -> pl.DataFrame:
    expressions = []
    for column in MEAN_COLS:
        expressions.append(pl.col(column).mean().alias(column))
    expressions.extend(
        [
            pl.col("marker_heuristic_score")
            .median()
            .alias("marker_heuristic_score_median"),
            pl.col("marker_heuristic_score")
            .std()
            .fill_null(0)
            .alias("marker_heuristic_score_stdev"),
        ]
    )
    for column in SUM_COLS:
        expressions.append(pl.col(column).sum().alias(column))
    return raw.group_by(group_cols).agg(expressions)


def _finalize(frame: pl.DataFrame) -> pl.DataFrame:
    return normalize_frame(
        frame.with_columns(
            [
                pl.col("runs").round(0).cast(pl.Int64),
                _ratio("matched_tables", "pred_tables", 1.0).alias("table_precision"),
                _ratio("matched_tables", "gt_tables", 1.0).alias("table_recall"),
                _ratio("pages", "time_median_s", 0.0).alias("pages_per_s"),
                pl.when(pl.col("time_median_s") > 0)
                .then(
                    (pl.col("pages") / pl.col("time_median_s"))
                    * (pl.col("time_stdev_s") / pl.col("time_median_s"))
                )
                .otherwise(0.0)
                .alias("pages_per_s_stdev"),
            ]
        )
    )


def aggregate_rows(raw: pl.DataFrame) -> pl.DataFrame:
    summary = _aggregate(raw, ["tool"]).with_columns(
        [
            pl.lit(SUMMARY_PDF).alias("pdf"),
            pl.lit(SUMMARY_PDF).alias("description"),
            pl.lit("").alias("language"),
            pl.lit("").alias("error"),
        ]
    )
    by_type = _aggregate(raw, ["description", "tool"]).with_columns(
        [
            (pl.lit(TYPE_PREFIX) + pl.col("description")).alias("pdf"),
            pl.lit("").alias("language"),
            pl.lit("").alias("error"),
        ]
    )
    return _finalize(pl.concat([summary, by_type], how="diagonal_relaxed"))


def result_frame(rows: pl.DataFrame) -> pl.DataFrame:
    raw = normalize_frame(rows).unique(
        ["pdf", "tool"], keep="last", maintain_order=True
    )
    raw = raw.filter(
        (pl.col("pdf") != SUMMARY_PDF) & (~pl.col("pdf").str.starts_with(TYPE_PREFIX))
    )
    if raw.is_empty():
        return raw
    return _finalize(pl.concat([raw, aggregate_rows(raw)], how="diagonal_relaxed"))


def merge_results(
    existing_csv: Path, new_rows: pl.DataFrame, update_only: bool
) -> pl.DataFrame:
    if not update_only or not existing_csv.exists() or new_rows.is_empty():
        return new_rows
    existing = pl.read_csv(existing_csv, schema_overrides={"pdf": pl.Utf8})
    old_rows = existing.filter(~pl.col("tool").is_in(new_rows["tool"].unique()))
    return pl.concat([old_rows, new_rows], how="diagonal_relaxed")


def write_results(path: Path, rows: pl.DataFrame) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    result_frame(rows).write_csv(path)
