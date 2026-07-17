"""Tests for the Python/native extraction boundary."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path

import pytest

from fibrum_pdf.api import ConversionResult, _extract, to_json


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


def test_to_json_refuses_to_overwrite_input(tmp_path: Path) -> None:
    pdf = tmp_path / "document.pdf"
    pdf.write_bytes(b"%PDF-placeholder")

    with pytest.raises(ValueError, match="must be different"):
        to_json(pdf, pdf)

    assert pdf.read_bytes() == b"%PDF-placeholder"


def test_conversion_result_streams_markdown_to_file(tmp_path: Path) -> None:
    source = tmp_path / "document.json"
    source.write_text(
        json.dumps(
            [
                {
                    "data": [
                        {
                            "type": "heading",
                            "bbox": [0, 0, 100, 20],
                            "level": 1,
                            "spans": [{"text": "First", "font_size": 14}],
                        }
                    ]
                },
                {
                    "data": [
                        {
                            "type": "paragraph",
                            "bbox": [0, 0, 100, 20],
                            "spans": [{"text": "Second", "font_size": 10}],
                        }
                    ]
                },
            ]
        ),
        encoding="utf-8",
    )
    output = tmp_path / "nested" / "document.md"

    written = ConversionResult(source).write_markdown(output)

    assert written == output.resolve()
    assert output.read_text(encoding="utf-8") == "# First\n\n---\n\nSecond\n"
