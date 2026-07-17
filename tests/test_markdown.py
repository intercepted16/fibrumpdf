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


def test_heading_uses_semantic_markdown_without_redundant_bold() -> None:
    block = Block(
        type="heading",
        bbox=[0, 0, 100, 20],
        level=4,
        spans=[{"text": "Details", "font_size": 14, "bold": True}],
    )

    assert block.markdown == "#### Details\n"


def test_code_block_uses_a_safe_fence() -> None:
    block = Block(
        type="code",
        bbox=[0, 0, 100, 20],
        spans=[{"text": "value = ```quoted```", "font_size": 10, "monospace": True}],
    )

    assert block.markdown == "````\nvalue = ```quoted```\n````\n"


def test_monospace_span_is_preserved_inline() -> None:
    block = Block(
        type="paragraph",
        bbox=[0, 0, 100, 20],
        spans=[
            {"text": "Run ", "font_size": 10},
            {"text": "fibrum-pdf", "font_size": 10, "monospace": True},
        ],
    )

    assert block.markdown == "Run `fibrum-pdf`\n"
