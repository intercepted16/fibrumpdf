"""cli entry point."""

from __future__ import annotations

import logging
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer

from .api import ExtractionError, to_json, to_markdown


class OutputFormat(str, Enum):
    """Supported CLI output formats."""

    json = "json"
    markdown = "markdown"


def run(
    pdf_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="PDF file to extract",
        ),
    ],
    output: Annotated[
        Optional[Path],
        typer.Argument(
            help="Output path (defaults to the input name with a new suffix)"
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format"),
    ] = OutputFormat.json,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
) -> None:
    """Extract structured PDF content to JSON or Markdown."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        force=True,
    )
    try:
        if output_format is OutputFormat.markdown:
            path = to_markdown(pdf_path, output)
        else:
            path = to_json(pdf_path, output).path
        logging.getLogger(__name__).info("wrote %s", path)
    except (FileNotFoundError, ValueError, ExtractionError) as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from e


def main() -> None:
    """CLI entry point."""
    typer.run(run)


if __name__ == "__main__":
    main()
