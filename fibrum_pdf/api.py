"""public api for pdf to json extraction."""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

from ._cffi import find_library, load_library
from .models import Page, Pages

log = logging.getLogger(__name__)
_CAPTURE = tempfile.NamedTemporaryFile(mode="w+", delete=False).name


class ExtractionError(Exception):
    pass


@contextmanager
def _redirect_c_output() -> Iterator[str]:
    saved = os.dup(1), os.dup(2)
    fd = os.open(_CAPTURE, os.O_WRONLY | os.O_TRUNC)
    try:
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        os.close(fd)
        yield _CAPTURE
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        os.close(saved[0])
        os.close(saved[1])


@lru_cache(maxsize=1)
def _lib(path: Path | None = None):
    p = path or find_library()
    if not p or not p.exists():
        raise ExtractionError(
            "libtomd not found - build with 'make tomd' or set PYMUPDF4LLM_C_LIB"
        )
    log.info("using library: %s", p)
    return load_library(p)


class ConversionResult:
    """lazy pdf conversion result."""

    def __init__(self, path: Path):
        self.path = path
        log.debug("result at %s", path)

    def _load(self) -> list[dict[str, Any]]:
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def collect(self) -> Pages:
        pages = Pages([Page(p["data"]) for p in self._load()])
        log.info("collected %d pages", len(pages))
        return pages

    def __iter__(self) -> Iterator[Page]:
        for i, p in enumerate(self._load()):
            log.debug("page %d", i + 1)
            yield Page(p["data"])

    def __repr__(self) -> str:
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

    with _redirect_c_output() as cap:
        rc = _lib(lib_path).pdf_to_json(str(pdf).encode(), str(out).encode())

    if rc != 0:
        try:
            with open(cap) as f:
                if msg := f.read().strip():
                    log.error("c output:\n%s", msg)
        except OSError:
            pass
        raise ExtractionError(f"extraction failed (code {rc})")

    log.info("done")
    return ConversionResult(out)


__all__ = ["ExtractionError", "to_json", "ConversionResult"]
