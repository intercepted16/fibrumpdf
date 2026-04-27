"""CLI for downloading and running extraction benchmarks."""

from pathlib import Path
from typing import Annotated

import typer
import polars as pl
from rich.console import Console

from benchmark.pipeline import BenchmarkConfig, run_benchmark
from benchmark.runner import TOOLS

app, console = typer.Typer(add_completion=False), Console()
SUMMARY_COLUMNS = {
    "tool": "Tool",
    "pages_per_s": "Speed (pg/s)",
    "marker_heuristic_score": "Text Score",
    "table_teds": "Table TEDS",
    "table_precision": "Table Precision",
    "table_recall": "Table Recall",
}


def _summary(csv_path: Path) -> None:
    rows = pl.read_csv(csv_path, schema_overrides={"pdf": pl.Utf8}).filter(
        pl.col("pdf") == "ALL"
    )
    if rows.is_empty():
        console.print("[yellow]Warning: no summary rows found in results.[/yellow]")
        return
    console.print()
    console.print("[bold magenta]Benchmark Summary (Averages)[/bold magenta]")
    console.print(rows.select(list(SUMMARY_COLUMNS)).rename(SUMMARY_COLUMNS))
    console.print()


def _download_dataset(
    output_path: Path,
    dataset_repo: str,
    max_rows: int | None,
    force: bool,
) -> Path:
    import datasets

    if output_path.exists() and not force:
        raise FileExistsError(f"Dataset exists at {output_path}; pass --force.")
    dataset = datasets.load_dataset(dataset_repo, split="train")
    if max_rows:
        dataset = dataset.select(range(min(max_rows, len(dataset))))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dataset.save_to_disk(str(output_path))
    console.print(f"[green]Saved {len(dataset)} rows to {output_path}[/green]")
    return output_path


def _config(
    *,
    dataset_path: Path | None,
    output: Path,
    tools: list[str] | None,
    runs: int,
    max_rows: int | None,
    seed: int,
    update_only: list[str] | None,
    graph_only: bool,
) -> BenchmarkConfig:
    selected = list(dict.fromkeys(update_only or tools or list(TOOLS)))
    unknown = sorted(set(selected) - set(TOOLS))
    if unknown:
        raise typer.BadParameter(f"Unknown tool(s): {', '.join(unknown)}")
    if runs < 1 or (max_rows or 1) < 1:
        raise typer.BadParameter("--runs and --max-rows must be positive")
    if not graph_only and dataset_path is None:
        raise typer.BadParameter("--dataset-path is required unless using --graph-only")
    return BenchmarkConfig(
        dataset_path=dataset_path,
        output=output,
        tools=selected,
        runs=runs,
        max_rows=max_rows,
        seed=seed,
        graph_only=graph_only,
        update_only=bool(update_only),
    )


@app.command()
def download(
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("data/dataset"),
    dataset_repo: Annotated[
        str, typer.Option("--repo")
    ] = "datalab-to/marker_benchmark",
    max_rows: Annotated[int | None, typer.Option("--max-rows")] = None,
    force: bool = False,
) -> None:
    _download_dataset(output, dataset_repo, max_rows, force)


@app.command()
def run(
    dataset_path: Annotated[Path | None, typer.Option()] = None,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("results"),
    tools: Annotated[list[str] | None, typer.Option("--tool", "-t")] = None,
    max_rows: Annotated[int | None, typer.Option("--max-rows")] = None,
    seed: Annotated[int, typer.Option("--seed")] = 0,
    runs: Annotated[int, typer.Option("--runs", "-r")] = 1,
    update_only: Annotated[list[str] | None, typer.Option("--update-only")] = None,
    graph_only: bool = False,
) -> None:
    csv_path = run_benchmark(
        _config(
            dataset_path=dataset_path,
            output=output,
            tools=tools,
            max_rows=max_rows,
            seed=seed,
            runs=runs,
            update_only=update_only,
            graph_only=graph_only,
        )
    )
    if csv_path.exists():
        _summary(csv_path)


if __name__ == "__main__":
    app()
