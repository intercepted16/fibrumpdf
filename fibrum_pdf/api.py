"""public api for pdf to json extraction."""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import threading
from contextlib import contextmanager
from functools import cached_property, lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

if TYPE_CHECKING:
    from .models import Page, Pages

log = logging.getLogger(__name__)
_legacy_capture_lock = threading.Lock()


class ExtractionError(Exception):
    pass


@contextmanager
def _redirect_legacy_c_output() -> Iterator[int]:
    """Capture output from native libraries predating direct error returns."""
    with _legacy_capture_lock, tempfile.TemporaryFile() as capture:
        saved = os.dup(1), os.dup(2)
        try:
            os.dup2(capture.fileno(), 1)
            os.dup2(capture.fileno(), 2)
            yield capture.fileno()
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(saved[0], 1)
            os.dup2(saved[1], 2)
            os.close(saved[0])
            os.close(saved[1])


def _extract(lib: Any, pdf: Path, output: Path) -> str | None:
    pdf_bytes, output_bytes = os.fsencode(pdf), os.fsencode(output)
    if hasattr(lib, "pdf_to_json_with_error"):
        import ctypes

        error = lib.pdf_to_json_with_error(pdf_bytes, output_bytes)
        if not error:
            return None
        try:
            return ctypes.string_at(error).decode(errors="replace")
        finally:
            lib.free_string(error)

    with _redirect_legacy_c_output() as capture_fd:
        rc = lib.pdf_to_json(pdf_bytes, output_bytes)
        if rc == 0:
            return None
        os.lseek(capture_fd, 0, os.SEEK_SET)
        return os.read(capture_fd, 1 << 20).decode(errors="replace").strip() or None


@lru_cache(maxsize=1)
def _lib(path: Path | None = None):
    from ._cffi import find_library, load_library

    p = path or find_library()
    if not p or not p.exists():
        raise ExtractionError(
            "libtomd not found - build with 'make tomd' or set PYMUPDF4LLM_C_LIB"
        )
    log.info("using library: %s", p)
    return load_library(p)


class ConversionResult:
    """Lazy PDF conversion result backed by the generated JSON file."""

    def __init__(self, path: Path):
        """Reference an extraction result at ``path``."""
        self.path = path
        log.debug("result at %s", path)

    def _load(self) -> list[Any]:
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []

    @cached_property
    def markdown(self) -> str:
        from ._block_converter import block_to_markdown

        markdowns = []
        for page in self._load():
            if isinstance(page, dict) and isinstance(page.get("data"), list):
                page_md = "\n".join(
                    m for m in [block_to_markdown(b) for b in page["data"]] if m
                )
                if page_md:
                    markdowns.append(page_md)
        return "\n---\n\n".join(markdowns)

    def collect(self) -> "Pages":
        from .models import Page, Pages

        pages = Pages([Page(p["data"]) for p in self._load()])
        log.info("collected %d pages", len(pages))
        return pages

    def __iter__(self) -> Iterator["Page"]:
        """Stream parsed pages without loading the entire document."""
        import ijson
        from .models import Page

        with open(self.path, encoding="utf-8") as f:
            for i, p in enumerate(ijson.items(f, "item")):
                log.debug("page %d", i + 1)
                yield Page(p["data"])

    def __repr__(self) -> str:
        """Return a concise representation containing the output path."""
        return f"ConversionResult({self.path})"


def to_json(
    pdf_path: str | Path,
    output: str | Path | None = None,
    *,
    lib_path: Path | None = None,
) -> ConversionResult:
    pdf = Path(pdf_path).resolve()
    if not pdf.exists():
        raise FileNotFoundError(f"pdf not found: {pdf}")
    out = Path(output).resolve() if output else pdf.with_suffix(".json")
    out.parent.mkdir(parents=True, exist_ok=True)
    log.info("extracting %s -> %s", pdf, out)
    if error := _extract(_lib(lib_path), pdf, out):
        raise ExtractionError(f"extraction failed: {error}")
    log.info("done")
    return ConversionResult(out)


__all__ = ["ExtractionError", "to_json", "ConversionResult"]
