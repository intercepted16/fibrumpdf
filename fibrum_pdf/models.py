from __future__ import annotations

import logging
from functools import cached_property
from typing import Any

from pydantic import BaseModel, ConfigDict

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
    link: bool = False
    uri: str | bool | None = None


class TableCell(BaseModel):
    bbox: list[float]
    spans: list[Span] = []


class TableRow(BaseModel):
    bbox: list[float]
    cells: list[TableCell] = []


class Block(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    bbox: list[float]
    spans: list[Span] = []
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
        if isinstance(items, dict) and "data" in items:
            items = items["data"]
        for item in items or []:
            self.append(Block(**item) if isinstance(item, dict) else item)
        log.debug("page: %d blocks", len(self))

    @cached_property
    def markdown(self) -> str:
        return "\n".join(b.markdown for b in self if b.markdown)


class Pages(list[Page]):
    def __init__(self, pages: list[Page] | None = None):
        super().__init__(pages or [])

    @cached_property
    def markdown(self) -> str:
        return "\n---\n\n".join(p.markdown for p in self if p.markdown)
