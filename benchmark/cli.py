from pathlib import Path
from typing import Annotated

import polars as pl
import typer
from rich.console import Console

from benchmark.pipeline import BenchmarkConfig, run_benchmark
from benchmark.results import SUMMARY_PDF, read_results
from benchmark.runner import TOOLS

app = typer.Typer(add_completion=False)
console = Console()

SUMMARY_COLUMNS = {
    "tool": "Tool",
    "pages_per_s": "Speed (pg/s)",
    "marker_heuristic_score": "Text Score",
    "table_teds": "Table TEDS",
    "table_precision": "Table Precision",
    "table_recall": "Table Recall",
}


def _print_summary(csv_path: Path):
    rows = read_results(csv_path).filter(pl.col("pdf") == SUMMARY_PDF)
    if rows.is_empty():
        console.print("[yellow]Warning: no summary rows found in results.[/yellow]")
        return
    console.print()
    console.print("[bold magenta]Benchmark Summary (Averages)[/bold magenta]")
    console.print(rows.select(list(SUMMARY_COLUMNS)).rename(SUMMARY_COLUMNS))
    console.print()


@app.command()
def download(
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("data/dataset"),
    dataset_repo: Annotated[
        str, typer.Option("--repo")
    ] = "datalab-to/marker_benchmark",
    max_rows: Annotated[int | None, typer.Option("--max-rows")] = None,
    force: bool = False,
) -> None:
    import datasets

    if output.exists() and not force:
        raise FileExistsError(f"Dataset exists at {output}; pass --force.")

    dataset = datasets.load_dataset(dataset_repo, split="train")
    if max_rows:
        dataset = dataset.select(range(min(max_rows, len(dataset))))
    output.parent.mkdir(parents=True, exist_ok=True)
    dataset.save_to_disk(output)
    console.print(f"[green]Saved {len(dataset)} rows to {output}[/green]")


@app.command()
def run(
    dataset_path: Annotated[Path | None, typer.Option()] = None,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("benchmark/results"),
    tools: Annotated[list[str] | None, typer.Option("--tool", "-t")] = None,
    max_rows: Annotated[int | None, typer.Option("--max-rows")] = None,
    seed: Annotated[int, typer.Option("--seed")] = 0,
    runs: Annotated[int, typer.Option("--runs", "-r")] = 1,
    update_only: Annotated[list[str] | None, typer.Option("--update-only")] = None,
    graph_only: bool = False,
) -> None:
    selected = list(dict.fromkeys(update_only or tools or TOOLS))
    if unknown := sorted(set(selected) - set(TOOLS)):
        raise typer.BadParameter(f"Unknown tool(s): {', '.join(unknown)}")
    if runs < 1 or (max_rows or 1) < 1:
        raise typer.BadParameter("--runs and --max-rows must be positive")
    if not graph_only and dataset_path is None:
        raise typer.BadParameter("--dataset-path is required unless using --graph-only")
    config = BenchmarkConfig(
        dataset_path=dataset_path,
        output=output,
        tools=selected,
        runs=runs,
        max_rows=max_rows,
        seed=seed,
        graph_only=graph_only,
        update_only=bool(update_only),
    )
    try:
        csv_path = run_benchmark(config)
    except FileNotFoundError as error:
        raise typer.BadParameter(str(error)) from error
    if csv_path.exists():
        _print_summary(csv_path)


if __name__ == "__main__":
    app()
