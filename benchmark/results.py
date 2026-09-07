"""Result frame schema, aggregation, and CSV writing."""

import polars as pl

from benchmark.scoring import FEATURE_KEYS

SUMMARY_PDF = "ALL"
TYPE_PREFIX = "Type: "
SCORE = "marker_heuristic_score"
TIMES = ("time_median_s", "time_mean_s", "time_stdev_s", "time_min_s", "time_max_s")
COUNTS = ("gt_tables", "pred_tables", "matched_tables", *FEATURE_KEYS)
MEANS = (*TIMES, "runs", "pages", SCORE, "table_teds")
SCHEMA = {
    **dict.fromkeys(("pdf", "description", "language", "tool"), pl.Utf8),
    **dict.fromkeys(TIMES, pl.Float64),
    "runs": pl.Int64,
    **dict.fromkeys(("pages", "pages_per_s", "pages_per_s_stdev"), pl.Float64),
    **dict.fromkeys((SCORE, f"{SCORE}_median", f"{SCORE}_stdev"), pl.Float64),
    **dict.fromkeys(("table_teds", "table_precision", "table_recall"), pl.Float64),
    **dict.fromkeys(COUNTS, pl.Int64),
    "error": pl.Utf8,
}


def conform(frame):
    if not frame.columns:
        frame = pl.DataFrame(schema=SCHEMA)
    frame = frame.with_columns(
        pl.lit(None).alias(column) for column in SCHEMA if column not in frame.columns
    )
    return frame.select(
        pl.col(column)
        .cast(dtype, strict=False)
        .fill_null("" if dtype == pl.Utf8 else 0)
        for column, dtype in SCHEMA.items()
    )


def result_frame(rows):
    raw = (
        conform(rows)
        .unique(["pdf", "tool"], keep="last", maintain_order=True)
        .filter(
            (pl.col("pdf") != SUMMARY_PDF) & ~pl.col("pdf").str.starts_with(TYPE_PREFIX)
        )
    )
    if raw.is_empty():
        return raw
    summary = _rollup(raw, "tool").with_columns(
        pl.lit(SUMMARY_PDF).alias("pdf"), pl.lit(SUMMARY_PDF).alias("description")
    )
    by_type = _rollup(raw, "description", "tool").with_columns(
        (pl.lit(TYPE_PREFIX) + pl.col("description")).alias("pdf")
    )
    raw = raw.with_columns(
        pl.col(SCORE).alias(f"{SCORE}_median"), pl.lit(0.0).alias(f"{SCORE}_stdev")
    )
    return _derive(pl.concat([raw, summary, by_type], how="diagonal_relaxed"))


def _rollup(raw, *group):
    return raw.group_by(*group, maintain_order=True).agg(
        *(pl.col(column).mean() for column in MEANS),
        pl.col(SCORE).median().alias(f"{SCORE}_median"),
        pl.col(SCORE).std().fill_null(0).alias(f"{SCORE}_stdev"),
        *(pl.col(column).sum() for column in COUNTS),
    )


def _derive(frame):
    speed = pl.col("pages") / pl.col("time_median_s")
    timed = pl.col("time_median_s") > 0
    matched = pl.col("matched_tables")
    return conform(
        frame.with_columns(
            pl.col("runs").round(0).cast(pl.Int64),
            _ratio(matched, pl.col("pred_tables")).alias("table_precision"),
            _ratio(matched, pl.col("gt_tables")).alias("table_recall"),
            pl.when(timed).then(speed).otherwise(0.0).alias("pages_per_s"),
            pl.when(timed)
            .then(speed * pl.col("time_stdev_s") / pl.col("time_median_s"))
            .otherwise(0.0)
            .alias("pages_per_s_stdev"),
        )
    )


def _ratio(numerator, denominator):
    return pl.when(denominator > 0).then(numerator / denominator).otherwise(1.0)


def write_results(path, rows, previous=None):
    if previous is not None and not rows.is_empty():
        kept = previous.filter(~pl.col("tool").is_in(rows["tool"].unique()))
        rows = pl.concat([kept, rows], how="diagonal_relaxed")
    path.parent.mkdir(parents=True, exist_ok=True)
    result_frame(rows).write_csv(path)


def read_results(path):
    return pl.read_csv(path, schema_overrides={"pdf": pl.Utf8})
