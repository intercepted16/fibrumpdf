"""Subprocess-isolated execution of benchmarked extraction tools."""

import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, NamedTuple, TypedDict, cast

FeatureCounts = dict[str, int]
Runner = Callable[[str], tuple[list[str], list[FeatureCounts] | None]]
TIMEOUT_S = 3600


class RunnerPayload(TypedDict):
    tool: str
    target: str
    runs: int


class TimingStats(NamedTuple):
    time_median_s: float = 0.0
    time_mean_s: float = 0.0
    time_stdev_s: float = 0.0
    time_min_s: float = 0.0
    time_max_s: float = 0.0
    runs: int = 0

    @classmethod
    def from_timings(cls, timings: list[float]) -> "TimingStats":
        return cls(
            statistics.median(timings),
            statistics.mean(timings),
            statistics.stdev(timings) if len(timings) > 1 else 0.0,
            min(timings),
            max(timings),
            len(timings),
        )

    def scaled(self, factor: float) -> dict[str, int | float]:
        values: dict[str, int | float] = {}
        for index, field in enumerate(self._fields):
            value = self[index]
            values[field] = value if field == "runs" else value * factor
        return values


class ToolRunResult(NamedTuple):
    text: str
    pages: list[str]
    timing: TimingStats
    native_features: list[FeatureCounts] | None


class ToolRunError(RuntimeError):
    """Raised when an isolated benchmark tool process fails."""


def _output_block(label: str, value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    value = (value or "").strip()
    return f"{label}:\n{value or '<empty>'}"


def _tool_error_message(
    tool: str,
    pdf: Path,
    reason: str,
    *,
    returncode: int | None = None,
    stdout: str | bytes | None = None,
    stderr: str | bytes | None = None,
) -> str:
    lines = [
        f"Benchmark tool failed: {tool}",
        f"PDF: {pdf}",
        f"Reason: {reason}",
    ]
    if returncode is not None:
        lines.append(f"Exit code: {returncode}")
    lines.extend(
        [
            _output_block("stdout", stdout),
            _output_block("stderr", stderr),
        ]
    )
    return "\n\n".join(lines)


def run_tool(tool: str, pdf: Path, *, runs: int = 1) -> ToolRunResult:
    payload = json.dumps({"tool": tool, "target": str(pdf.resolve()), "runs": runs})
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "benchmark.runner", payload],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolRunError(
            _tool_error_message(
                tool,
                pdf,
                f"timed out after {TIMEOUT_S} seconds",
                stdout=exc.stdout,
                stderr=exc.stderr,
            )
        ) from exc
    if proc.returncode:
        raise ToolRunError(
            _tool_error_message(
                tool,
                pdf,
                "subprocess exited with an error",
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        )
    try:
        data = cast(dict[str, object], json.loads(proc.stdout))
    except json.JSONDecodeError as exc:
        raise ToolRunError(
            _tool_error_message(
                tool,
                pdf,
                "subprocess did not return valid JSON",
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        ) from exc
    return ToolRunResult(
        text=cast(str, data["text"]),
        pages=cast(list[str], data["pages"]),
        timing=TimingStats.from_timings(cast(list[float], data["times"])),
        native_features=cast(list[FeatureCounts] | None, data.get("features")),
    )


def _run_pymupdf4llm(pdf_path: str) -> tuple[list[str], None]:
    import pymupdf4llm

    return [
        page.get("text", "")
        for page in pymupdf4llm.to_markdown(pdf_path, page_chunks=True)
    ], None


def _run_docling(pdf_path: str) -> tuple[list[str], list[FeatureCounts]]:
    from docling.document_converter import DocumentConverter
    from docling_core.types.doc.document import TextItem

    doc = DocumentConverter().convert(pdf_path).document
    pages = [doc.export_to_markdown(page_no=i) for i in range(1, doc.num_pages() + 1)]
    features = [{"bold": 0, "italic": 0} for _ in pages]
    for item, _ in doc.iterate_items():
        if isinstance(item, TextItem) and item.formatting and item.prov:
            page = features[item.prov[0].page_no - 1]
            page["bold"] += int(item.formatting.bold)
            page["italic"] += int(item.formatting.italic)
    return pages, features


def _run_fibrum(pdf_path: str) -> tuple[list[str], None]:
    import fibrum_pdf as fibrum

    return [page.markdown for page in fibrum.to_json(pdf_path)], None


TOOLS: dict[str, Runner] = {
    "pymupdf4llm": _run_pymupdf4llm,
    "docling": _run_docling,
    "fibrum": _run_fibrum,
}


def _execute(payload: RunnerPayload) -> dict[str, object]:
    times, pages, features = [], [], None
    for _ in range(int(payload["runs"])):
        start = time.perf_counter()
        pages, features = TOOLS[payload["tool"]](payload["target"])
        times.append(time.perf_counter() - start)
    pages = [page.strip() for page in pages]
    return {
        "text": "\n---\n\n".join(page for page in pages if page),
        "pages": pages,
        "times": times,
        "features": features,
    }


if __name__ == "__main__":
    payload = cast(RunnerPayload, json.loads(sys.argv[1]))
    sys.stdout.write(json.dumps(_execute(payload), ensure_ascii=False))
