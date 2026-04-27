"""Altair dashboard generation."""

# pyright: reportUnknownVariableType=false

from pathlib import Path

import altair as alt
import polars as pl

COLORS = {"fibrum": "#10b981", "pymupdf4llm": "#3b82f6", "docling": "#ef4444"}
TABLE_METRICS = [
    ("time_mean_s", "Mean Time", ".3f", "s"),
    ("time_median_s", "Median Time", ".3f", "s"),
    ("pages_per_s", "Throughput", ".1f", " pg/s"),
    ("pages_per_s_stdev", "Throughput Std", ".3f", ""),
    ("marker_heuristic_score", "Mean Score", ".3f", ""),
    ("marker_heuristic_score_median", "Median Score", ".3f", ""),
    ("marker_heuristic_score_stdev", "Score Std", ".3f", ""),
    ("table_teds", "Table TEDS", ".3f", ""),
    ("table_precision", "Table Prec.", ".3f", ""),
    ("table_recall", "Table Rec.", ".3f", ""),
]


def _bar(df: pl.DataFrame, tools: list[str], field: str, title: str, width: int):
    return (
        alt.Chart(df)
        .mark_bar()
        .encode(
            x=alt.X("tool:N", sort=tools, title="Tool"),
            y=alt.Y(f"{field}:Q", title=title),
            color=alt.Color(
                "tool:N",
                scale=alt.Scale(
                    domain=tools, range=[COLORS.get(tool, "#6b7280") for tool in tools]
                ),
                legend=None,
            ),
            tooltip=["tool", field],
        )
        .properties(height=220, width=width)
    )


def _summary_table(df: pl.DataFrame, tools: list[str]):
    fields = []
    labels = {"tool": "Tool"}
    for field, label, _, _ in TABLE_METRICS:
        fields.append(field)
        labels[field] = label
    select_columns = ["tool"]
    select_columns.extend(fields)
    table = df.filter(pl.col("tool").is_in(tools)).select(select_columns).rename(labels)
    rows = []
    for row in table.iter_rows(named=True):
        formatted = {"Tool": row["Tool"]}
        for _, label, spec, suffix in TABLE_METRICS:
            value = row[label]
            formatted[label] = f"{value:{spec}}{suffix}" if value is not None else ""
        rows.append(formatted)
    melted = pl.DataFrame(rows).unpivot(
        index="Tool", variable_name="Metric", value_name="Value"
    )
    base = alt.Chart(melted).encode(
        x=alt.X(
            "Metric:N",
            sort=[label for _, label, *_ in TABLE_METRICS],
            title=None,
            axis=alt.Axis(orient="top"),
        ),
        y=alt.Y("Tool:N", sort=tools, title=None),
    )
    return (
        base.mark_rect().encode(
            color=alt.value("transparent"), stroke=alt.value("#eeeeee")
        )
        + base.mark_text(size=12, font="monospace").encode(text="Value:N")
    ).properties(title="Summary Metrics Table", width=800, height=40 * len(tools))


def dashboard(
    csv_path: Path, out_path: Path, tools_order: list[str]
) -> alt.TopLevelMixin | None:
    df = pl.read_csv(csv_path, schema_overrides={"pdf": pl.Utf8})
    summary = df.filter(pl.col("pdf") == "ALL")
    if summary.is_empty():
        return None
    summary_tools = set(summary["tool"].to_list())
    tools = [tool for tool in tools_order if tool in summary_tools]
    table_df = (
        summary.filter(pl.col("tool").is_in(tools))
        .select(["tool", "table_precision", "table_recall"])
        .unpivot(index="tool", variable_name="metric", value_name="value")
        .with_columns(
            pl.col("metric").replace(
                {"table_precision": "Precision", "table_recall": "Recall"}
            )
        )
    )
    table_metrics = (
        alt.Chart(table_df)
        .mark_bar()
        .encode(
            x=alt.X("tool:N", sort=tools, title="Tool"),
            y=alt.Y("value:Q", title="Score", scale=alt.Scale(domain=[0, 1])),
            color=alt.Color(
                "metric:N",
                scale=alt.Scale(
                    domain=["Precision", "Recall"], range=["#3b82f6", "#f59e0b"]
                ),
                title="Metric",
            ),
            xOffset="metric:N",
            tooltip=["tool", "metric", alt.Tooltip("value:Q", format=".3f")],
        )
        .properties(height=220, width=300, title="Table Precision & Recall")
    )
    by_type = (
        df.filter(pl.col("pdf").str.contains("Type:"))
        .group_by(["description", "tool"])
        .agg(pl.col("marker_heuristic_score").mean())
    )
    type_chart = (
        alt.Chart(by_type.filter(pl.col("tool").is_in(tools)))
        .mark_rect()
        .encode(
            x=alt.X("description:N", title="Document Type", sort=None),
            y=alt.Y("tool:N", title="Tool", sort=tools),
            color=alt.Color(
                "marker_heuristic_score:Q",
                title="Avg Quality",
                scale=alt.Scale(domain=[0, 100], scheme="greenblue"),
            ),
            tooltip=["tool", "description", "marker_heuristic_score"],
        )
        .properties(
            title="Quality by Document Type",
            width=50 * max(1, by_type["description"].n_unique()),
            height=220,
        )
    )
    chart = (
        alt.vconcat(
            _bar(summary, tools, "pages_per_s", "Throughput (pg/s)", 600).properties(
                title="Extraction Speed Comparison"
            ),
            alt.hconcat(
                _bar(summary, tools, "marker_heuristic_score", "Heuristic Score", 280),
                _bar(summary, tools, "table_teds", "Table TEDS", 280),
                table_metrics,
                spacing=40,
            ),
            type_chart,
            _summary_table(summary, tools),
            spacing=60,
        )
        .configure_view(strokeWidth=0)
        .configure_title(fontSize=18, anchor="start", color="#333333")
        .configure_axis(labelFontSize=11, titleFontSize=13)
    )
    chart.save(out_path if out_path.suffix else out_path / "dashboard.html")
    return chart
