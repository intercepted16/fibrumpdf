from __future__ import annotations

import logging
from importlib import metadata

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

try:
    __version__ = metadata.version("fibrum-pdf")
except metadata.PackageNotFoundError:
    __version__ = "0.0.0"
