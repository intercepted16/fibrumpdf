"""Generate benchmark comparison charts."""

from __future__ import annotations

from pathlib import Path

import altair as alt
import polars as pl

COLORS = {
    "fibrum": "#00a67e",  # benchmark subject: vivid green
    "pymupdf4llm": "#94a3b8",
    "docling": "#64748b",
}
FALLBACK_COLOR = "#9ca3af"

WIDTH = 680
ROW_HEIGHT = 36


def _load(csv_path: Path, tools_order: list[str]):
    df = pl.read_csv(csv_path, schema_overrides={"pdf": pl.Utf8})
    summary = df.filter(pl.col("pdf") == "ALL")
    if summary.is_empty():
        return None

    present = set(summary["tool"].to_list())
    tools = ["fibrum"] if "fibrum" in present else []
    tools += [t for t in tools_order if t in present and t not in tools]
    tools += [t for t in COLORS if t in present and t not in tools]
    tools += sorted(present - set(tools))
    return df, summary, tools


def _color_scale(tools: list[str]) -> alt.Scale:
    return alt.Scale(domain=tools, range=[COLORS.get(t, FALLBACK_COLOR) for t in tools])


def _style(chart: alt.Chart) -> alt.Chart:
    return (
        chart.configure_view(strokeWidth=0)
        .configure_title(fontSize=17, fontWeight=600, anchor="start", color="#111827")
        .configure_axis(
            labelFontSize=11,
            titleFontSize=11,
            grid=False,
            tickColor="#cbd5e1",
            domainColor="#94a3b8",
        )
    )


def _bar(
    summary: pl.DataFrame,
    tools: list[str],
    field: str,
    title: str,
    *,
    domain: list[float],
    log: bool = False,
    baseline: str | None = None,
) -> alt.Chart:
    scale = alt.Scale(domain=domain, type="log" if log else "linear")
    axis = alt.Axis(values=[0.5, 1, 10, 100]) if log else alt.Axis(tickCount=4)
    bars = (
        alt.Chart(summary)
        .mark_bar(size=24, cornerRadiusEnd=3)
        .encode(
            y=alt.Y("tool:N", sort=tools, title=None),
            x=alt.X(
                f"{field}:Q",
                title=None,
                axis=axis,
                scale=scale,
            ),
            x2=alt.X2(f"{baseline}:Q") if baseline else alt.value(0),
            color=alt.Color("tool:N", scale=_color_scale(tools), legend=None),
            tooltip=["tool", field],
        )
    )
    labels = (
        alt.Chart(summary)
        .mark_text(align="left", baseline="middle", dx=7, fontSize=11, color="#111827")
        .encode(
            y=alt.Y("tool:N", sort=tools, title=None),
            x=alt.X(f"{field}:Q", scale=scale),
            text=alt.Text(f"{field}:Q", format=".3~g"),
        )
    )
    return _style(
        (bars + labels).properties(
            title=title,
            width=WIDTH,
            height=ROW_HEIGHT * len(tools),
        )
    )


def speed_chart(summary: pl.DataFrame, tools: list[str]) -> alt.Chart:
    floor = max(float(summary["pages_per_s"].min()) / 2, 0.01)
    speed = summary.with_columns(pl.lit(floor).alias("speed_floor"))
    return _bar(
        speed,
        tools,
        "pages_per_s",
        "Speed (pages/s · log scale)",
        domain=[floor, max(float(summary["pages_per_s"].max()) * 1.5, 1)],
        log=True,
        baseline="speed_floor",
    )


def text_score_chart(summary: pl.DataFrame, tools: list[str]) -> alt.Chart:
    return _bar(
        summary,
        tools,
        "marker_heuristic_score",
        "Text quality",
        domain=[0, 100],
    )


def teds_chart(summary: pl.DataFrame, tools: list[str]) -> alt.Chart:
    return _bar(summary, tools, "table_teds", "Table fidelity (TEDS)", domain=[0, 1])


def precision_recall_chart(summary: pl.DataFrame, tools: list[str]) -> alt.Chart:
    long = summary.select(["tool", "table_precision", "table_recall"]).unpivot(
        index="tool", variable_name="metric", value_name="value"
    )
    long = long.with_columns(
        pl.col("metric").replace(
            {"table_precision": "Precision", "table_recall": "Recall"}
        )
    )
    bars = (
        alt.Chart(long)
        .mark_bar(size=24, cornerRadiusEnd=3)
        .encode(
            y=alt.Y("tool:N", sort=tools, title=None),
            x=alt.X(
                "value:Q",
                title=None,
                axis=alt.Axis(tickCount=4),
                scale=alt.Scale(domain=[0, 1]),
            ),
            color=alt.Color("tool:N", scale=_color_scale(tools), legend=None),
            tooltip=["tool", "metric", "value"],
        )
    )
    labels = (
        alt.Chart(long)
        .mark_text(align="left", baseline="middle", dx=7, fontSize=11, color="#111827")
        .encode(
            y=alt.Y("tool:N", sort=tools, title=None),
            x=alt.X("value:Q", scale=alt.Scale(domain=[0, 1])),
            text=alt.Text("value:Q", format=".0%"),
        )
    )
    return _style(
        alt.layer(bars, labels)
        .properties(width=(WIDTH - 28) // 2, height=ROW_HEIGHT * len(tools))
        .facet(
            column=alt.Column(
                "metric:N",
                sort=["Precision", "Recall"],
                title=None,
                header=alt.Header(labelFontSize=13, labelFontWeight=600),
            )
        )
        .properties(
            title="Table accuracy",
            columns=2,
        )
    )


def heatmap_chart(df: pl.DataFrame, tools: list[str]) -> alt.Chart:
    by_type = (
        df.filter(pl.col("pdf").str.contains("Type:"))
        .filter(pl.col("tool").is_in(tools))
        .group_by(["description", "tool"])
        .agg(pl.col("marker_heuristic_score").mean())
    )
    chart = (
        alt.Chart(by_type)
        .mark_rect()
        .encode(
            x=alt.X("description:N", title=None, sort=None),
            y=alt.Y("tool:N", title=None, sort=tools),
            color=alt.Color(
                "marker_heuristic_score:Q",
                title="Score",
                scale=alt.Scale(domain=[70, 100], range=["#e2e8f0", "#00a67e"]),
            ),
            tooltip=["tool", "description", "marker_heuristic_score"],
        )
        .properties(
            title="Quality by Document Type",
            width=max(WIDTH, 60 * by_type["description"].n_unique()),
            height=ROW_HEIGHT * len(tools) + 20,
        )
    )
    return _style(chart)


def save_charts(csv_path: Path, out_dir: Path, tools_order: list[str]) -> list[Path]:
    loaded = _load(csv_path, tools_order)
    if loaded is None:
        return []
    df, summary, tools = loaded

    charts = {
        "speed": speed_chart(summary, tools),
        "text_score": text_score_chart(summary, tools),
        "teds": teds_chart(summary, tools),
        "precision_recall": precision_recall_chart(summary, tools),
        "heatmap": heatmap_chart(df, tools),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    saved = []
    for name, chart in charts.items():
        path = out_dir / f"{name}.png"
        chart.save(path)
        saved.append(path)
    return saved
