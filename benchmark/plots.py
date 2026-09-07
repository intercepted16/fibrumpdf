"""Generate the benchmark comparison charts."""

import altair as alt
import polars as pl

from benchmark.results import SCORE, SUMMARY_PDF, TYPE_PREFIX, read_results

COLORS = {
    "fibrum": "#00a67e",  # benchmark subject: vivid green
    "pymupdf4llm": "#94a3b8",
    "docling": "#64748b",
}
INK = "#111827"
WIDTH = 680
ROW_HEIGHT = 36


def save_charts(csv_path, out_dir, tools_order):
    frame = read_results(csv_path)
    summary = frame.filter(pl.col("pdf") == SUMMARY_PDF)
    if summary.is_empty():
        return []
    tools = _order(set(summary["tool"].to_list()), tools_order)
    speeds = summary["pages_per_s"]
    floor = max(float(speeds.min()) / 2, 0.01)
    charts = {
        "speed": _bars(
            summary.with_columns(pl.lit(floor).alias("floor")),
            tools,
            "pages_per_s",
            "Speed (pages/s · log scale)",
            domain=[floor, max(float(speeds.max()) * 1.5, 1)],
            log=True,
            baseline="floor",
        ),
        "text_score": _bars(summary, tools, SCORE, "Text quality", domain=[0, 100]),
        "teds": _bars(
            summary, tools, "table_teds", "Table fidelity (TEDS)", domain=[0, 1]
        ),
        "precision_recall": _bars(
            _by_metric(summary),
            tools,
            "value",
            "Table accuracy",
            domain=[0, 1],
            fmt=".0%",
            facet="metric",
        ),
        "heatmap": _heatmap(frame, tools),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    saved = [out_dir / f"{name}.png" for name in charts]
    for path, chart in zip(saved, charts.values(), strict=True):
        chart.save(path)
    return saved


def _order(present, preferred):
    tools = ["fibrum"] if "fibrum" in present else []
    for tool in (*preferred, *COLORS):
        if tool in present and tool not in tools:
            tools.append(tool)
    return tools + sorted(present - set(tools))


def _by_metric(summary):
    return (
        summary.select(["tool", "table_precision", "table_recall"])
        .unpivot(index="tool", variable_name="metric", value_name="value")
        .with_columns(
            pl.col("metric").replace(
                {"table_precision": "Precision", "table_recall": "Recall"}
            )
        )
    )


def _bars(
    data,
    tools,
    field,
    title,
    *,
    domain,
    log=False,
    baseline=None,
    fmt=".3~g",
    facet=None,
):
    scale = alt.Scale(domain=domain, type="log" if log else "linear")
    base = alt.Chart(data).encode(
        y=alt.Y("tool:N", sort=tools, title=None),
        x=alt.X(
            f"{field}:Q",
            title=None,
            scale=scale,
            axis=alt.Axis(values=[0.5, 1, 10, 100]) if log else alt.Axis(tickCount=4),
        ),
    )
    layer = base.mark_bar(size=24, cornerRadiusEnd=3).encode(
        x2=alt.X2(f"{baseline}:Q")
        if baseline
        else (alt.Undefined if facet else alt.value(0)),
        color=alt.Color(
            "tool:N",
            scale=alt.Scale(
                domain=tools, range=[COLORS.get(t, "#9ca3af") for t in tools]
            ),
            legend=None,
        ),
        tooltip=["tool", *filter(None, [facet]), field],
    ) + base.mark_text(
        align="left", baseline="middle", dx=7, fontSize=11, color=INK
    ).encode(text=alt.Text(f"{field}:Q", format=fmt))

    height = ROW_HEIGHT * len(tools)
    if not facet:
        return _style(layer.properties(title=title, width=WIDTH, height=height))
    return _style(
        layer.properties(width=(WIDTH - 28) // 2, height=height)
        .facet(
            column=alt.Column(
                f"{facet}:N",
                title=None,
                header=alt.Header(labelFontSize=13, labelFontWeight=600),
            )
        )
        .properties(title=title, columns=2)
    )


def _heatmap(frame, tools):
    by_type = (
        frame.filter(pl.col("pdf").str.starts_with(TYPE_PREFIX))
        .filter(pl.col("tool").is_in(tools))
        .group_by(["description", "tool"], maintain_order=True)
        .agg(pl.col(SCORE).mean())
    )
    return _style(
        alt.Chart(by_type)
        .mark_rect()
        .encode(
            x=alt.X("description:N", title=None, sort=None),
            y=alt.Y("tool:N", title=None, sort=tools),
            color=alt.Color(
                f"{SCORE}:Q",
                title="Score",
                scale=alt.Scale(domain=[70, 100], range=["#e2e8f0", "#00a67e"]),
            ),
            tooltip=["tool", "description", SCORE],
        )
        .properties(
            title="Quality by Document Type",
            width=max(WIDTH, 60 * by_type["description"].n_unique()),
            height=ROW_HEIGHT * len(tools) + 20,
        )
    )


def _style(chart):
    return (
        chart.configure_view(strokeWidth=0)
        .configure_title(fontSize=17, fontWeight=600, anchor="start", color=INK)
        .configure_axis(
            labelFontSize=11,
            titleFontSize=11,
            grid=False,
            tickColor="#cbd5e1",
            domainColor="#94a3b8",
        )
    )
