"""``lory scan`` — scan the working tree locally and load what it finds.

The scanning is done by `lory-scan`, a separate program that runs entirely on
this machine. This command is the bridge: it runs the scan, puts the findings
into the same store the platform's findings live in, and leaves them where the
cockpit will pick them up.

After it, everything this tool does works on a locally scanned finding:

    lory scan                    # find them
    lory tui --cached            # triage them
    lory trace scan-a1b2c3d4e5   # locate the code
    lory fix scan-a1b2c3d4e5     # ask Lory for the change
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from lory_code_security.cli.common import (
    CONFIG_OPTION,
    console,
    die,
    err_console,
    load_config,
    open_store,
)
from lory_code_security.core.errors import LoryConsoleError
from lory_code_security.domain import scan as scanner
from lory_code_security.domain.findings import (
    Finding,
    TriageLog,
    severity_counts,
    sort_findings,
)
from lory_code_security.ui import render


@click.command()
@click.argument("path", type=click.Path(exists=True), required=False)
@CONFIG_OPTION
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Drop findings below this severity.")
@click.option("--diff", metavar="REF", help="Only scan files changed against this git ref.")
@click.option("--staged", is_flag=True, help="Only scan files staged in git.")
@click.option("--rule", "select", multiple=True, metavar="GLOB",
              help="Only run scanner rules matching this id glob. Repeatable.")
@click.option("--ignore-rule", "ignore_rules", multiple=True, metavar="GLOB",
              help="Skip scanner rules matching this id glob. Repeatable.")
@click.option("--scanner", "executable", metavar="PATH",
              help="Path to the lory-scan executable. Default: whatever is on PATH.")
@click.option("--timeout", type=int, default=scanner.DEFAULT_TIMEOUT, show_default=True,
              help="Seconds to allow the scan.")
@click.option("--json", "as_json", is_flag=True, help="Emit the findings as JSON.")
@click.option("--no-save", is_flag=True,
              help="Do not write the findings to the local cache.")
def scan(
    path: str | None, config_path: str, severity: str | None, diff: str | None,
    staged: bool, select: tuple[str, ...], ignore_rules: tuple[str, ...],
    executable: str | None, timeout: int, as_json: bool, no_save: bool,
) -> None:
    """Scan your code locally with lory-scan and load the findings here.

    PATH defaults to the repo_root in your config. Scanning needs no token and
    makes no network calls: the scanner runs on this machine, and the findings
    never leave it.

    \b
      lory scan                          Scan the whole repository.
      lory scan src --severity high      One subtree, serious findings only.
      lory scan --diff origin/main       Only what this branch changed.
      lory tui --cached                  Triage what it found.

    Findings from your Lorikeet account stay where they are; a local scan adds
    to the cockpit rather than replacing it.
    """
    cfg = load_config(config_path)
    root = Path(path).resolve() if path else cfg.repo_root

    try:
        info = scanner.describe(executable)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if not as_json:
        err_console.print(f"[dim]{info.summary()} · scanning {root}[/dim]")

    try:
        rows = scanner.run(
            root, info=info, severity=severity, diff=diff, staged=staged,
            select=select, ignore_rules=ignore_rules, timeout=timeout,
        )
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return

    if no_save:
        findings = sort_findings([Finding.from_row(row) for row in rows])
    else:
        # Offline on purpose: a local scan must work with no token and no
        # network. The cache is loaded first so the platform's findings are
        # still there to be written back alongside these.
        store = open_store(cfg, allow_offline=True)
        store.load_cache()
        findings = store.ingest(rows)

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    console.print(render.render_findings_table(findings, TriageLog(cfg.triage_path)))
    console.print()
    console.print(render.render_severity_summary(severity_counts(findings)))

    if not no_save:
        console.print(
            f"\n[dim]Saved to {cfg.findings_cache}. Triage them with[/dim] lory tui --cached"
        )
