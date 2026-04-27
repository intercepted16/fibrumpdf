"""Tree-edit-distance table similarity."""

import Levenshtein
from apted import APTED, Config
from apted.helpers import Tree
from lxml import html


def wrap_table_html(table_html: str) -> str:
    return f"<html><body>{table_html.strip()}</body></html>"


class TableTree(Tree):
    def __init__(self, node: html.HtmlElement) -> None:  # noqa: D107
        super().__init__(node.tag)
        self.tag = node.tag
        self.colspan = int(node.attrib.get("colspan", 1))
        self.rowspan = int(node.attrib.get("rowspan", 1))
        self.content = "".join(node.itertext()) if node.tag == "td" else ""
        self.children = [TableTree(child) for child in node]


class TableConfig(Config):
    def rename(self, node1: TableTree, node2: TableTree) -> int:
        shape1 = (node1.tag, node1.colspan, node1.rowspan)
        shape2 = (node2.tag, node2.colspan, node2.rowspan)
        if shape1 != shape2:
            return 1
        distance = Levenshtein.distance(node1.content, node2.content)
        return int(distance / max(len(node1.content), len(node2.content), 1))


def _table(document: str) -> html.HtmlElement | None:
    return next(iter(html.fromstring(document).xpath("body/table")), None)


def similarity_eval_html(pred: str, true: str) -> float:
    pred_table = _table(pred)
    true_table = _table(true)
    if pred_table is None or true_table is None:
        return 0.0

    nodes = max(len(pred_table.xpath(".//*")), len(true_table.xpath(".//*")))
    distance = APTED(
        TableTree(pred_table),
        TableTree(true_table),
        TableConfig(),
    ).compute_edit_distance()
    return 1.0 - int(distance) / nodes if nodes else 0.0
