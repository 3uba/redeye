"""Command line entry point for redeye."""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console

from . import __version__
from .capture import CaptureConfig, CaptureResult, ChromiumMissingError, run_captures
from .inputs import InputError, collect_targets
from .report import render_report, status_color

_EPILOG = """\
examples:
  redeye --single https://example.com
  redeye -f urls.txt --threads 20
  redeye -x scan.xml -k                 # nmap XML, ignore self-signed certs
  redeye -f hosts.txt --scheme http     # force http for bare hosts

one-time setup (installs the native ARM64 browser):
  playwright install chromium

Only scan targets you are authorized to test.
"""


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="redeye",
        description=(
            "Screenshot and recon a set of web targets into one HTML report. "
            "Native on Apple Silicon — no Docker, no Selenium."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    inputs = parser.add_argument_group("inputs (at least one required)")
    inputs.add_argument("-f", "--file", type=Path, metavar="PATH",
                        help="line-separated file of URLs or host[:port] entries")
    inputs.add_argument("-x", "--nmap-xml", type=Path, metavar="PATH",
                        help="Nmap XML file; open web ports become targets")
    inputs.add_argument("--single", metavar="URL", help="a single target")

    parser.add_argument("--scheme", choices=("auto", "http", "https"), default="auto",
                        help="scheme for bare hosts (default: auto = https then http)")
    parser.add_argument("-t", "--threads", type=int, default=10, metavar="N",
                        help="concurrent captures (default: 10)")
    parser.add_argument("--timeout", type=float, default=10.0, metavar="SECONDS",
                        help="per-target timeout (default: 10)")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="ignore TLS certificate errors")
    parser.add_argument("-d", "--output-dir", type=Path, metavar="DIR",
                        help="output directory (default: redeye_<timestamp>)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress per-target progress")
    parser.add_argument("--version", action="version", version=f"redeye {__version__}")
    return parser


def _default_output_dir() -> Path:
    return Path(f"redeye_{datetime.now().strftime('%Y%m%d_%H%M%S')}")


def _progress_printer(console: Console, total: int):
    """Return an on_done callback that prints a colored progress line."""
    state = {"done": 0}
    color_map = {"green": "green", "cyan": "cyan", "yellow": "yellow",
                 "red": "red", "grey": "dim"}

    def on_done(result: CaptureResult) -> None:
        state["done"] += 1
        color = color_map.get(status_color(result), "white")
        label = result.outcome if result.outcome != "ok" else str(result.status)
        tags = f" [{', '.join(result.tech)}]" if result.tech else ""
        console.print(
            f"[dim]{state['done']:>4}/{total}[/dim] "
            f"[{color}]{label:>7}[/{color}] {result.url}"
            f"[magenta]{tags}[/magenta]"
        )

    return on_done


def main(argv: list[str] | None = None) -> int:
    """Run redeye. Returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    console = Console()
    err_console = Console(stderr=True)

    def fail(message: str, code: int) -> int:
        err_console.print(f"[bold red]redeye:[/bold red] {message}")
        return code

    if not (args.file or args.nmap_xml or args.single):
        parser.error("no input given — use -f, -x, or --single")
    if args.threads < 1:
        return fail("--threads must be >= 1", 2)
    if args.timeout <= 0:
        return fail("--timeout must be greater than 0", 2)

    try:
        targets = collect_targets(
            file=args.file,
            nmap_xml=args.nmap_xml,
            single=args.single,
            default_scheme=args.scheme,
        )
    except InputError as exc:
        return fail(str(exc), 2)

    output_dir = args.output_dir or _default_output_dir()
    config = CaptureConfig(
        threads=args.threads,
        timeout=args.timeout,
        insecure=args.insecure,
        screens_dir=output_dir / "screens",
    )

    if not args.quiet:
        console.print(
            f"[bold]redeye[/bold] — {len(targets)} target(s), "
            f"{args.threads} workers, {args.timeout:g}s timeout\n"
        )
    on_done = None if args.quiet else _progress_printer(console, len(targets))

    try:
        results = asyncio.run(run_captures(targets, config, on_done))
    except ChromiumMissingError as exc:
        return fail(str(exc), 3)
    except KeyboardInterrupt:
        return fail("interrupted", 130)

    report_path = render_report(results, output_dir)

    high = sum(1 for r in results if r.high_interest)
    ok = sum(1 for r in results if r.outcome == "ok")
    if not args.quiet:
        console.print(
            f"\n[green]done[/green] — {ok}/{len(results)} ok, "
            f"{high} high interest"
        )
    console.print(f"report: [bold]{report_path}[/bold]")
    console.print(f"json:   {output_dir / 'results.json'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
