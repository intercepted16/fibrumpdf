"""Subprocess-isolated execution of the benchmarked extraction tools."""

import json
import statistics
import subprocess
import sys
import time
from typing import NamedTuple

TIMEOUT_S = 3600


class ToolRunError(RuntimeError): ...


class ToolRunResult(NamedTuple):
    text: str
    pages: list[str]
    times: list[float]
    features: list[dict[str, int]] | None

    def timing(self, scale):
        spread = statistics.stdev(self.times) if len(self.times) > 1 else 0.0
        return {
            "time_median_s": statistics.median(self.times) * scale,
            "time_mean_s": statistics.mean(self.times) * scale,
            "time_stdev_s": spread * scale,
            "time_min_s": min(self.times) * scale,
            "time_max_s": max(self.times) * scale,
            "runs": len(self.times),
        }


def run_tool(tool, pdf, runs=1):
    payload = json.dumps({"tool": tool, "target": str(pdf.resolve()), "runs": runs})
    command = [sys.executable, "-m", "benchmark.runner", payload]
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=TIMEOUT_S
        )
    except subprocess.TimeoutExpired as exc:
        raise _failed(tool, pdf, f"timed out after {TIMEOUT_S}s", exc) from exc
    if proc.returncode:
        raise _failed(tool, pdf, f"exited with code {proc.returncode}", proc)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise _failed(tool, pdf, "did not return valid JSON", proc) from exc
    return ToolRunResult(
        data["text"], data["pages"], data["times"], data.get("features")
    )


def _block(label, value):
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    return f"{label}:\n{(value or '').strip() or '<empty>'}"


def _failed(tool, pdf, reason, proc):
    return ToolRunError(
        f"Benchmark tool failed: {tool}\nPDF: {pdf}\nReason: {reason}\n\n"
        f"{_block('stdout', proc.stdout)}\n\n{_block('stderr', proc.stderr)}"
    )


def _run_pymupdf4llm(pdf_path):
    import pymupdf4llm

    chunks = pymupdf4llm.to_markdown(pdf_path, page_chunks=True)
    return [page.get("text", "") for page in chunks], None


def _run_docling(pdf_path):
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


def _run_fibrum(pdf_path):
    import fibrum_pdf as fibrum

    return [page.markdown for page in fibrum.to_json(pdf_path)], None


TOOLS = {
    "pymupdf4llm": _run_pymupdf4llm,
    "docling": _run_docling,
    "fibrum": _run_fibrum,
}


def _execute(tool, target, runs):
    times, pages, features = [], [], None
    for _ in range(runs):
        start = time.perf_counter()
        pages, features = TOOLS[tool](target)
        times.append(time.perf_counter() - start)
    pages = [page.strip() for page in pages]
    return {
        "text": "\n---\n\n".join(page for page in pages if page),
        "pages": pages,
        "times": times,
        "features": features,
    }


if __name__ == "__main__":
    sys.stdout.write(
        json.dumps(_execute(**json.loads(sys.argv[1])), ensure_ascii=False)
    )
