from __future__ import annotations

import logging
from importlib import metadata
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .api import ConversionResult, ExtractionError, to_json
    from .models import Block, Page, Pages

__all__ = [
    "Block",
    "Page",
    "Pages",
    "ExtractionError",
    "to_json",
    "ConversionResult",
    "__version__",
]
logging.getLogger(__name__).addHandler(logging.NullHandler())


def __getattr__(name: str) -> Any:
    if name in {"to_json", "ExtractionError", "ConversionResult"}:
        from .api import ConversionResult, ExtractionError, to_json

        mapping = {
            "to_json": to_json,
            "ExtractionError": ExtractionError,
            "ConversionResult": ConversionResult,
        }
        return mapping[name]
    if name in {"Block", "Page", "Pages"}:
        from .models import Block, Page, Pages

        mapping = {"Block": Block, "Page": Page, "Pages": Pages}
        return mapping[name]
    raise AttributeError(name)


try:
    __version__ = metadata.version("fibrum-pdf")
except metadata.PackageNotFoundError:
    __version__ = "0.0.0"
