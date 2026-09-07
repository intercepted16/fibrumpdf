"""Benchmark orchestration: sample, shard, execute, score, and chart."""

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import polars as pl
from rich.console import Console
from rich.progress import track

from benchmark.plots import save_charts
from benchmark.results import conform, read_results, write_results
from benchmark.runner import run_tool
from benchmark.scoring import score_text

SHARD_PAGE_TARGET = 300
console = Console()


class Doc(NamedTuple):
    uuid: str
    pages: int
    gt: str
    description: str
    language: str


class Shard(NamedTuple):
    pdf: Path
    docs: list[Doc]


@dataclass
class BenchmarkConfig:
    dataset_path: Path | None
    output: Path
    tools: list[str]
    runs: int = 1
    max_rows: int | None = None
    seed: int = 0
    graph_only: bool = False
    update_only: bool = False

    @property
    def csv_path(self):
        return self.output / "benchmark.csv"


def run_benchmark(config):
    if config.graph_only and not config.csv_path.exists():
        raise FileNotFoundError(
            "Cannot generate graphs: benchmark results were not found at "
            f"{config.csv_path}. Pass --output with the directory containing "
            "benchmark.csv."
        )
    config.output.mkdir(parents=True, exist_ok=True)
    if not config.graph_only:
        keep = config.update_only and config.csv_path.exists()
        write_results(
            config.csv_path,
            _run_tools(config),
            read_results(config.csv_path) if keep else None,
        )
    if saved := save_charts(config.csv_path, config.output, config.tools):
        console.print(
            f"[green]Generated {len(saved)} charts in {config.output}[/green]"
        )
    return config.csv_path


def _run_tools(config):
    shards = _shards(config)
    rows = []
    for tool in config.tools:
        with console.status(f"[bold green]Executing {tool}", spinner="dots"):
            for shard in shards:
                run = run_tool(tool, shard.pdf, runs=config.runs)
                rows += _score(config, tool, shard, run)
    return conform(pl.from_dicts(rows) if rows else pl.DataFrame())


def _score(config, tool, shard, run):
    counts = [doc.pages for doc in shard.docs]
    total = sum(counts)
    pages = _fit_pages(run.pages, run.text, total)
    texts = ["\n---\n\n".join(group).strip() for group in _regroup(pages, counts)]
    features = [
        dict(sum(map(Counter, group), Counter())) or None
        for group in _regroup(run.features or [], counts)
    ]
    rows = []
    for doc, text, doc_features in zip(shard.docs, texts, features, strict=True):
        path = config.output / "markdown" / tool / f"{doc.uuid}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        rows.append(
            {
                "pdf": doc.uuid,
                "description": doc.description,
                "language": doc.language,
                "tool": tool,
                "pages": float(doc.pages),
                "error": "",
                **run.timing(doc.pages / total),
                **score_text(text, doc.gt, doc_features),
            }
        )
    return rows


def _regroup(items, counts):
    start = 0
    for count in counts:
        yield items[start : start + count]
        start += count


def _fit_pages(pages, fallback, expected):
    # tools do not always return one entry per page; fold or pad to match.
    content = [page.strip() for page in pages] or [fallback.strip()]
    if expected <= 1:
        return ["\n\n".join(content).strip()]
    if len(content) > expected:
        tail = "\n\n".join(content[expected - 1 :]).strip()
        return [*content[: expected - 1], tail]
    return [*content, *([""] * (expected - len(content)))]


def _pymupdf():
    import pymupdf

    pymupdf.TOOLS.mupdf_display_warnings(False)
    pymupdf.TOOLS.reset_mupdf_warnings()
    return pymupdf


def _doc(row):
    gt = row.get("gt_blocks") or []
    with _pymupdf().open(stream=row["pdf"], filetype="pdf") as pdf:
        pages = max(1, pdf.page_count)
    return Doc(
        uuid="" if row["uuid"] is None else str(row["uuid"]),
        pages=pages,
        gt=gt if isinstance(gt, str) else json.dumps(gt, ensure_ascii=False),
        description=str(row.get("classification") or ""),
        language=str(row.get("language") or ""),
    )


def _merge(config, index, batch):
    pymupdf = _pymupdf()
    path = config.output / "_shards" / "merged" / f"shard_{index:05d}.pdf"
    path.parent.mkdir(parents=True, exist_ok=True)
    with pymupdf.open() as merged:
        for _, pdf in batch:
            with pymupdf.open(stream=pdf, filetype="pdf") as source:
                merged.insert_pdf(source)
        merged.save(path)
    return Shard(path, [doc for doc, _ in batch])


def _shards(config):
    import datasets

    data = datasets.load_from_disk(config.dataset_path).shuffle(seed=config.seed)
    data = data.select(range(min(config.max_rows or len(data), len(data))))
    shards, batch, pages = [], [], 0
    # PDF bytes live only until their shard is written, so peak memory is one
    # shard's worth of documents rather than the whole dataset's.
    for row in track(data, description="Loading samples..."):
        doc = _doc(row)
        batch.append((doc, row["pdf"]))
        pages += doc.pages
        if pages >= SHARD_PAGE_TARGET:
            shards.append(_merge(config, len(shards), batch))
            batch, pages = [], 0
    return shards + ([_merge(config, len(shards), batch)] if batch else [])
