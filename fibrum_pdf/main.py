"""cli entry point."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Optional

import typer

from .api import ExtractionError, to_json


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
        typer.Argument(help="Output JSON path (defaults to pdf_path.json)"),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
) -> None:
    """Extract PDF content to JSON."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        force=True,
    )
    try:
        result = to_json(pdf_path, output)
        logging.getLogger(__name__).info("wrote %s", result.path)
    except (FileNotFoundError, ExtractionError) as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from e


def main() -> None:
    """CLI entry point."""
    typer.run(run)


if __name__ == "__main__":
    main()
