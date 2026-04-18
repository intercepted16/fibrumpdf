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

_EXPORTS = {
    "to_json": (".api", "to_json"),
    "ExtractionError": (".api", "ExtractionError"),
    "ConversionResult": (".api", "ConversionResult"),
    "Block": (".models", "Block"),
    "Page": (".models", "Page"),
    "Pages": (".models", "Pages"),
}


def __getattr__(name: str) -> Any:
    import importlib

    if target := _EXPORTS.get(name):
        module_name, attr_name = target
        module = importlib.import_module(module_name, __name__)
        return getattr(module, attr_name)
    raise AttributeError(name)


try:
    __version__ = metadata.version("fibrum-pdf")
except metadata.PackageNotFoundError:
    __version__ = "0.0.0"
