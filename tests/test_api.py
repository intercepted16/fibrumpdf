"""Tests for the Python/native extraction boundary."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path

from fibrum_pdf.api import _extract


class ModernLibrary:
    """Small fake for the current native ABI."""

    def __init__(self, error: str | None = None) -> None:
        """Create a fake returning an optional native error string."""
        self._buffer = ctypes.create_string_buffer(error.encode()) if error else None
        self.freed: int | None = None

    def pdf_to_json_with_error(self, pdf: bytes, output: bytes) -> int | None:
        assert pdf == os.fsencode(Path("input.pdf"))
        assert output == os.fsencode(Path("output.json"))
        return ctypes.addressof(self._buffer) if self._buffer is not None else None

    def free_string(self, pointer: int) -> None:
        self.freed = pointer


class LegacyLibrary:
    """Small fake for the original return-code ABI."""

    def pdf_to_json(self, pdf: bytes, output: bytes) -> int:
        os.write(2, b"legacy native failure")
        return -1


def test_extract_uses_direct_native_error() -> None:
    library = ModernLibrary("invalid PDF")

    assert _extract(library, Path("input.pdf"), Path("output.json")) == "invalid PDF"
    assert library.freed is not None


def test_extract_returns_none_on_success() -> None:
    assert _extract(ModernLibrary(), Path("input.pdf"), Path("output.json")) is None


def test_extract_captures_errors_from_legacy_libraries() -> None:
    assert (
        _extract(LegacyLibrary(), Path("input.pdf"), Path("output.json"))
        == "legacy native failure"
    )
