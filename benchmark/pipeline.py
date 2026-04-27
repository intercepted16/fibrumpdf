"""Benchmark orchestration pipeline."""

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple, cast

from rich.console import Console
from rich.progress import track

from benchmark.normalize import distribute_pages, reconcile_pages
from benchmark.plots import dashboard
from benchmark.results import merge_results, rows_frame, write_results
from benchmark.runner import ToolRunResult, run_tool
from benchmark.scoring import score_text

SHARD_PAGE_TARGET = 300
console = Console()
FeatureCounts = dict[str, int]
ResultValue = str | int | float
ResultRow = dict[str, ResultValue]


class DocSample(NamedTuple):
    uuid: str
    pdf: bytes
    pages: int
    gt: str
    description: str = ""
    language: str = ""

    def result_row(self, tool: str) -> ResultRow:
        return {
            "pdf": self.uuid,
            "description": self.description,
            "language": self.language,
            "tool": tool,
            "pages": float(self.pages),
            "error": "",
        }


class Shard(NamedTuple):
    merged_pdf: Path
    pages: int
    docs: list[DocSample]


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


class ArtifactLayout(NamedTuple):
    output: Path

    @property
    def csv_path(self) -> Path:
        return self.output / "benchmark.csv"

    @property
    def markdown_dir(self) -> Path:
        return self.output / "markdown"

    @property
    def merged_dir(self) -> Path:
        return self.output / "_shards" / "merged"

    def prepare_output(self) -> None:
        self.output.mkdir(parents=True, exist_ok=True)

    def prepare_run(self) -> None:
        self.markdown_dir.mkdir(parents=True, exist_ok=True)
        self.merged_dir.mkdir(parents=True, exist_ok=True)

    def markdown_path(self, tool: str, uuid: str) -> Path:
        return self.markdown_dir / tool / f"{uuid}.md"


def _dataset(config: BenchmarkConfig):
    import datasets

    dataset = datasets.load_from_disk(config.dataset_path).shuffle(seed=config.seed)
    return dataset.select(range(min(config.max_rows or len(dataset), len(dataset))))


def _pymupdf():
    import pymupdf

    pymupdf.TOOLS.mupdf_display_warnings(False)
    pymupdf.TOOLS.reset_mupdf_warnings()
    return pymupdf


def _page_count(pdf: bytes) -> int:
    pymupdf = _pymupdf()

    with pymupdf.open(stream=pdf, filetype="pdf") as doc:
        return max(1, doc.page_count)


def _sample(row: Mapping[str, object]) -> DocSample:
    uuid = "" if row["uuid"] is None else str(row["uuid"])
    pdf = cast(bytes, row["pdf"])
    gt = row.get("gt_blocks") or []
    return DocSample(
        uuid=uuid,
        pdf=pdf,
        pages=_page_count(pdf),
        gt=gt if isinstance(gt, str) else json.dumps(gt, ensure_ascii=False),
        description=str(row.get("classification") or ""),
        language=str(row.get("language") or ""),
    )


def _samples(config: BenchmarkConfig) -> Iterable[DocSample]:
    rows = track(_dataset(config), description="Loading samples...")
    return (_sample(row) for row in rows)


def _merge_pdfs(output: Path, docs: Iterable[DocSample]) -> None:
    pymupdf = _pymupdf()

    with pymupdf.open() as merged:
        for sample in docs:
            with pymupdf.open(stream=sample.pdf, filetype="pdf") as src:
                merged.insert_pdf(src)
        merged.save(output)


def _shard(
    layout: ArtifactLayout, index: int, docs: list[DocSample], pages: int
) -> Shard:
    merged_pdf = layout.merged_dir / f"shard_{index:05d}.pdf"
    _merge_pdfs(merged_pdf, docs)
    return Shard(merged_pdf=merged_pdf, pages=pages, docs=docs)


def _shards(layout: ArtifactLayout, samples: Iterable[DocSample]) -> list[Shard]:
    shards, batch, pages = [], [], 0
    for sample in track(samples, description="Sharding..."):
        batch.append(sample)
        pages += sample.pages
        if pages >= SHARD_PAGE_TARGET:
            shards.append(_shard(layout, len(shards), batch, pages))
            batch, pages = [], 0
    return shards + ([_shard(layout, len(shards), batch, pages)] if batch else [])


def _feature_buckets(
    features: list[FeatureCounts] | None,
    page_counts: list[int],
) -> list[FeatureCounts | None]:
    if not features:
        return [None] * len(page_counts)
    buckets = []
    start = 0
    for count in page_counts:
        end = start + count
        bucket = Counter()
        for page_features in features[start:end]:
            bucket.update(page_features)
        buckets.append(dict(bucket) or None)
        start = end
    return buckets


def _write_markdown(layout: ArtifactLayout, tool: str, uuid: str, text: str) -> None:
    path = layout.markdown_path(tool, uuid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _score_run(
    layout: ArtifactLayout,
    tool: str,
    shard: Shard,
    run: ToolRunResult,
) -> list[ResultRow]:
    doc_pages = [doc.pages for doc in shard.docs]
    pages = reconcile_pages(run.pages, run.text, shard.pages)
    texts = distribute_pages(pages, doc_pages)
    rows: list[ResultRow] = []
    features_by_doc = _feature_buckets(run.native_features, doc_pages)
    for index, doc in enumerate(shard.docs):
        text = texts[index]
        features = features_by_doc[index]
        _write_markdown(layout, tool, doc.uuid, text)
        row = doc.result_row(tool)
        row.update(run.timing.scaled(doc.pages / shard.pages))
        row.update(score_text(text, doc.gt, features))
        rows.append(row)
    return rows


def _run_tools(config: BenchmarkConfig, layout: ArtifactLayout, shards: list[Shard]):
    rows: list[ResultRow] = []
    for tool in config.tools:
        with console.status(f"[bold green]Executing {tool}", spinner="dots"):
            for shard in shards:
                run = run_tool(tool, shard.merged_pdf, runs=config.runs)
                rows.extend(_score_run(layout, tool, shard, run))
    return rows_frame(rows)


def _finish(config: BenchmarkConfig, layout: ArtifactLayout) -> Path:
    if layout.csv_path.exists():
        dashboard(layout.csv_path, config.output, config.tools)
    return layout.csv_path


def run_benchmark(config: BenchmarkConfig) -> Path:
    layout = ArtifactLayout(config.output)
    layout.prepare_output()
    if config.graph_only:
        return _finish(config, layout)
    layout.prepare_run()
    rows = _run_tools(config, layout, _shards(layout, _samples(config)))
    write_results(
        layout.csv_path,
        merge_results(layout.csv_path, rows, config.update_only),
    )
    return _finish(config, layout)
