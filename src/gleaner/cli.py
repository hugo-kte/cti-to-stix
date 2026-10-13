"""Gleaner command-line interface."""

from __future__ import annotations

import json
import logging
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.logging import RichHandler

app = typer.Typer(
    help="Gleaner - threat reports to indicators, entities, ATT&CK techniques and STIX 2.1.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(stderr=True)

ModelsOpt = Annotated[Path, typer.Option("--models", help="Directory with trained models.")]
RawOpt = Annotated[Path, typer.Option("--raw", help="Directory with the downloaded datasets.")]
NEEDS_DATA = "run `gleaner download` first (and `gleaner train` before evaluating the CRF)"


def _fail(message: str) -> NoReturn:
    console.print(f"[red]error:[/red] {message}", highlight=False, soft_wrap=True)
    raise typer.Exit(1)


def _missing(exc: FileNotFoundError, hint: str) -> NoReturn:
    _fail(f"{exc.filename or exc} not found: {hint}")


def _read(path: Path) -> str:
    """A report or bundle as text: UTF-8, with or without a byte-order mark."""
    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        _fail(f"{path} is not UTF-8 text (invalid byte at offset {exc.start})")


class Format(StrEnum):
    stix = "stix"
    json = "json"
    md = "md"


class Tlp(StrEnum):
    clear = "clear"
    green = "green"
    amber = "amber"
    red = "red"


@app.callback()
def main(verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False)],
    )


@app.command()
def extract(
    report: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Report (text/Markdown).")
    ],
    fmt: Annotated[Format, typer.Option("--format", "-f", help="Output format.")] = Format.md,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write here instead of stdout.")
    ] = None,
    tlp: Annotated[
        Tlp, typer.Option(help="TLP marking of the STIX objects (clear is exported as TLP:WHITE).")
    ] = Tlp.amber,
    models: ModelsOpt = Path("models"),
) -> None:
    """Extract indicators, entities and ATT&CK techniques from a report."""
    from gleaner.pipeline import Extractor
    from gleaner.render import markdown
    from gleaner.stix import to_bundle, validate

    text_in = _read(report)
    try:
        extractor = Extractor.from_dir(models)
    except FileNotFoundError as exc:
        _missing(exc, "run from the repository root or pass --models DIR")
    except ValueError as exc:
        _fail(str(exc))
    result = extractor.extract(text_in, str(report))
    if fmt is Format.stix:
        bundle = to_bundle(result, extractor.catalog, tlp=tlp.value)
        text = bundle.serialize(pretty=True)
        valid, errors, _ = validate(text)
        if not valid:  # pragma: no cover - would be a bug in the exporter
            console.print(f"[red]bundle failed validation[/red]: {errors[:3]}")
            raise typer.Exit(1)
    elif fmt is Format.json:
        text = result.to_json()
    else:
        text = markdown(result, extractor.catalog)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        exported = sum(i.exported for i in result.iocs)
        console.print(
            f"{exported} indicators, {len(result.entities)} entities, "
            f"{len(result.techniques)} techniques -> [bold]{out}[/bold]"
        )
    else:
        sys.stdout.write(text + "\n")


@app.command()
def iocs(
    report: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    show_all: Annotated[
        bool, typer.Option("--all", help="Include references, benign, internal.")
    ] = False,
    safe: Annotated[bool, typer.Option("--defang/--raw", help="Defang network values.")] = True,
) -> None:
    """List the indicators of a report as tab-separated lines (no models needed)."""
    from gleaner.iocs import NETWORK_TYPES, defang, extract_iocs

    text = _read(report)
    sys.stdout.write("type\tvalue\tstatus\tscope\tmentions\n")
    for ioc in extract_iocs(text):
        if show_all or ioc.exported:
            value = defang(ioc.value) if safe and ioc.type in NETWORK_TYPES else ioc.value
            sys.stdout.write(f"{ioc.type}\t{value}\t{ioc.status}\t{ioc.scope}\t{ioc.count}\n")


@app.command()
def validate(bundle: Annotated[Path, typer.Argument(exists=True, dir_okay=False)]) -> None:
    """Validate a STIX 2.1 bundle with the OASIS validator (strict mode)."""
    from stix2validator import ValidationError

    from gleaner.stix import validate as run

    try:
        valid, errors, warnings = run(_read(bundle))
    except json.JSONDecodeError as exc:
        _fail(f"{bundle} is not JSON ({exc})")
    except ValidationError as exc:
        _fail(f"{bundle}: {exc}")
    for message in errors + warnings:
        console.print(f"  {message}")
    console.print(
        f"{bundle}: [bold]{'valid' if valid else 'INVALID'}[/bold] ({len(errors)} errors)"
    )
    if not valid:
        raise typer.Exit(1)


@app.command()
def download(raw: RawOpt = Path("data/raw"), force: bool = False) -> None:
    """Fetch TRAM, ATT&CK and AnnoCTR at their pinned commits and verify SHA-256 checksums."""
    from gleaner.datasets import download as run

    counts = run(raw, force=force)
    console.print(
        f"{counts['downloaded']} downloaded, {counts['present']} already present -> {raw}"
    )


@app.command()
def train(
    raw: RawOpt = Path("data/raw"),
    models: ModelsOpt = Path("models"),
    only: Annotated[str | None, typer.Option(help="ner or techniques")] = None,
    n_jobs: Annotated[int, typer.Option(help="Parallel jobs.")] = 8,
) -> None:
    """Select hyper-parameters (AnnoCTR dev, TRAM grouped CV) and train the models."""
    from gleaner.train import train_all

    if only not in (None, "ner", "techniques"):
        _fail(f"--only must be ner or techniques, not {only!r}")
    parts = (only,) if only else ("ner", "techniques")
    try:
        summary = train_all(raw, models, n_jobs, parts)
    except FileNotFoundError as exc:
        _missing(exc, NEEDS_DATA)
    console.print_json(
        json.dumps({k: v for k, v in summary.items() if k != "trained_at"}, default=str)
    )


@app.command()
def evaluate(
    raw: RawOpt = Path("data/raw"),
    models: ModelsOpt = Path("models"),
    out_dir: Annotated[Path, typer.Option("--out-dir")] = Path("reports"),
    only: Annotated[
        str | None, typer.Option(help="Comma list: iocs, entities, techniques, cross, stix")
    ] = None,
    n_jobs: Annotated[int, typer.Option(help="Parallel jobs.")] = 8,
) -> None:
    """Run the evaluation protocols -> reports/metrics.json, REPORT.md and figures."""
    from gleaner import plots, report
    from gleaner.evaluate import SECTIONS, run

    sections = tuple(s.strip() for s in only.split(",")) if only else SECTIONS
    if unknown := sorted(set(sections) - set(SECTIONS)):
        _fail(f"unknown section(s) {', '.join(unknown)}; choose from {', '.join(SECTIONS)}")
    try:
        metrics = run(raw, models, out_dir, sections, n_jobs)
    except FileNotFoundError as exc:
        _missing(exc, NEEDS_DATA)
    plots.all_figures(metrics, out_dir / "figures")
    (out_dir / "REPORT.md").write_text(report.render(metrics), encoding="utf-8")
    console.print(f"Report: [bold]{out_dir / 'REPORT.md'}[/bold]")


@app.command("audit-sample")
def audit_sample(
    raw: RawOpt = Path("data/raw"),
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("runtime/ioc_audit_sample.csv"),
    seed: int = 0,
) -> None:
    """Sample AnnoCTR test extractions (with context) for the manual IOC audit."""
    from gleaner.audit import write_sample

    try:
        n = write_sample(raw, out, seed)
    except FileNotFoundError as exc:
        _missing(exc, NEEDS_DATA)
    console.print(f"{n} rows -> {out} (contains raw indicators and corpus text: do not commit)")


if __name__ == "__main__":
    app()
