"""Models for output of FibrumPDF."""

# ruff: noqa: D101, D102, D107
from __future__ import annotations

import logging
from functools import cached_property
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

log = logging.getLogger(__name__)


class Span(BaseModel):
    text: str
    font_size: float
    bold: bool = False
    italic: bool = False
    monospace: bool = False
    strikeout: bool = False
    superscript: bool = False
    subscript: bool = False
    link: str | bool = False


class TableCell(BaseModel):
    bbox: list[float]
    spans: list[Span] = Field(default_factory=list)


class TableRow(BaseModel):
    bbox: list[float]
    cells: list[TableCell] = Field(default_factory=list)


class Block(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    bbox: list[float]
    spans: list[Span] = Field(default_factory=list)
    length: int = 0
    lines: int | None = None
    level: int | None = None
    row_count: int | None = None
    col_count: int | None = None
    cell_count: int | None = None
    rows: list[TableRow] | None = None

    @cached_property
    def markdown(self) -> str:
        from ._block_converter import block_to_markdown

        return block_to_markdown(self.model_dump())


class Page(list[Block]):
    def __init__(self, items: list[Block | dict[str, Any]] | dict[str, Any]):
        super().__init__()
        source = items.get("data", []) if isinstance(items, dict) else items
        for item in source or []:
            self.append(Block(**item) if isinstance(item, dict) else item)
        log.debug("page: %d blocks", len(self))

    @cached_property
    def markdown(self) -> str:
        return "\n".join(filter(None, (block.markdown for block in self)))


class Pages(list[Page]):
    def __init__(self, pages: list[Page] | None = None):
        super().__init__(pages or [])

    @cached_property
    def markdown(self) -> str:
        return "\n---\n\n".join(filter(None, (page.markdown for page in self)))
