"""Fast, structured PDF extraction for Python."""

from __future__ import annotations

import logging
from importlib import metadata
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .api import ConversionResult, ExtractionError, to_json
    from .models import Block, ListItem, Page, Pages, Span, TableCell, TableRow

__all__ = [
    "Block",
    "ListItem",
    "Page",
    "Pages",
    "Span",
    "TableCell",
    "TableRow",
    "ExtractionError",
    "to_json",
    "ConversionResult",
    "__version__",
]
logging.getLogger(__name__).addHandler(logging.NullHandler())


def __getattr__(name: str) -> Any:
    if name == "to_json":
        from .api import to_json

        return to_json
    if name == "ExtractionError":
        from .api import ExtractionError

        return ExtractionError
    if name == "ConversionResult":
        from .api import ConversionResult

        return ConversionResult
    if name in {"Block", "ListItem", "Page", "Pages", "Span", "TableCell", "TableRow"}:
        from . import models

        return getattr(models, name)
    raise AttributeError(name)


try:
    __version__ = metadata.version("fibrum-pdf")
except metadata.PackageNotFoundError:
    __version__ = "0.0.0"
