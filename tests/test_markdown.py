"""Regression tests for structured Markdown conversion."""

from fibrum_pdf.models import Block


def test_list_markdown_keeps_markers_out_of_item_bodies() -> None:
    block = Block(
        type="list",
        bbox=[0, 0, 100, 100],
        items=[
            {
                "spans": [{"text": "First", "font_size": 10}],
                "list_type": "numbered",
                "prefix": "1.",
            },
            {
                "spans": [{"text": "Nested", "font_size": 10}],
                "list_type": "bulleted",
                "indent": 1,
            },
        ],
    )

    assert block.markdown == "1. First\n    - Nested\n"
