"""Findings commands: list, show, export, trace, triage, retest.

Everything here reads from the platform over MCP: ``findings.search`` and
``findings.detail`` where the server has them, ``findings.list`` and
``findings.get`` on older servers. The local cache is a convenience for offline
reading; any command that acts on a finding re-reads it from the platform first.

Commands that name one finding take its ``ref`` (``engagement-12``) or a bare
id (``12``). A bare id is rejected rather than guessed when it matches findings
in more than one store.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import click
from rich.syntax import Syntax
from rich.text import Text

from lory_code_security.cli.common import (
    CONFIG_OPTION,
    console,
    die,
    lexer_for,
    load_config,
    open_store,
)
from lory_code_security.core.errors import AmbiguousFindingError, LoryConsoleError
from lory_code_security.domain.findings import (
    Finding,
    TriageLog,
    filter_findings,
    severity_counts,
)
from lory_code_security.ui import render


@click.group()
def findings() -> None:
    """List, inspect, and export findings pulled from the platform."""


@findings.command("list")
@CONFIG_OPTION
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--status", help="open | in_progress | resolved | risk_accepted")
@click.option("--asset", "affected_asset", help="Filter to one domain or URL.")
@click.option("--project", "project_id", type=int, help="Filter to one PTaaS project.")
@click.option("--limit", type=int, default=50, show_default=True,
              help="Max rows (the platform caps at 50).")
@click.option("--cached", is_flag=True, help="Read the local cache; do not call the platform.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table.")
def findings_list(
    config_path: str, severity: str | None, status: str | None, affected_asset: str | None,
    project_id: int | None, limit: int, cached: bool, as_json: bool,
) -> None:
    """List findings, most severe first."""
    cfg = load_config(config_path)
    store = open_store(cfg, allow_offline=cached)
    triage_log = TriageLog(cfg.triage_path)

    try:
        if cached:
            rows = filter_findings(store.load_cache(), severity=severity, status=status)
        else:
            rows = store.fetch(
                severity=severity, status=status, project_id=project_id,
                affected_asset=affected_asset, limit=limit,
            )
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if as_json:
        click.echo(json.dumps([f.to_dict() for f in rows], indent=2))
        return

    if not rows:
        console.print("[dim]No findings matched.[/dim]")
        return

    console.print(render.render_findings_table(rows, triage_log))
    console.print()
    console.print(render.render_severity_summary(severity_counts(rows)))


@findings.command("show")
@click.argument("finding")
@CONFIG_OPTION
@click.option("--json", "as_json", is_flag=True, help="Emit the raw finding as JSON.")
def findings_show(finding: str, config_path: str, as_json: bool) -> None:
    """Show the full body of one finding. FINDING is a ref or an id."""
    cfg = load_config(config_path)
    # Offline-tolerant: a finding produced by `lory scan` is complete on disk
    # and needs no platform call, so requiring a token here would lock a
    # scanner-only user out of their own findings. With a token configured
    # nothing changes — the platform is still consulted for the full body.
    store = open_store(cfg, allow_offline=True)
    store.load_cache()

    try:
        row = store.detail(finding)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if as_json:
        click.echo(json.dumps(row.to_dict(), indent=2))
        return

    console.print(
        render.render_finding_detail(row, TriageLog(cfg.triage_path).state(row.key))
    )


@findings.command("export")
@CONFIG_OPTION
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "markdown", "sarif"]),
              default="json", show_default=True)
@click.option("--out", type=click.Path(dir_okay=False, path_type=Path), help="Write to a file.")
@click.option("--cached", is_flag=True, help="Export the local cache without refetching.")
def findings_export(config_path: str, fmt: str, out: Path | None, cached: bool) -> None:
    """Export findings as JSON, CSV, Markdown, or SARIF.

    SARIF is generated locally from the findings this tool read, so it needs
    only the bearer token:

    \b
      lory findings export --format sarif --out findings.sarif
      gh api --method POST /repos/:owner/:repo/code-scanning/sarifs \\
        -f commit_sha="$(git rev-parse HEAD)" -f ref="refs/heads/main" \\
        -f sarif="$(gzip -c findings.sarif | base64 -w0)"
    """
    cfg = load_config(config_path)
    store = open_store(cfg, allow_offline=cached)

    try:
        rows = store.load_cache() if cached else store.fetch(limit=50)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    text = _export(rows, fmt)
    if out:
        out.write_text(text)
        console.print(f"[green]✓[/green] Wrote {len(rows)} findings to {out}")
    else:
        click.echo(text)


@click.command()
@click.argument("finding_ref")
@CONFIG_OPTION
@click.option("--limit", type=int, default=15, show_default=True, help="Max code leads to show.")
@click.option("--context", type=int, default=0, help="Lines of surrounding source to print.")
def trace(finding_ref: str, config_path: str, limit: int, context: int) -> None:
    """Show local source that may be responsible for a finding.

    FINDING_REF is a ref or an id. Heuristic: parameters, routes, and file
    paths named in the finding are grepped against your working tree, plus sink
    patterns for its CWE. Every hit is labelled with the token that produced
    it, so bad leads are obvious.
    """
    from lory_code_security.domain import codebase

    cfg = load_config(config_path)
    # Offline-tolerant: a finding produced by `lory scan` is complete on disk
    # and needs no platform call, so requiring a token here would lock a
    # scanner-only user out of their own findings. With a token configured
    # nothing changes — the platform is still consulted for the full body.
    store = open_store(cfg, allow_offline=True)
    store.load_cache()

    try:
        finding = store.detail(finding_ref)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    plan = codebase.build_plan(finding)
    console.print(render.render_finding_header(finding))
    console.print(
        f"\n[dim]Searching {cfg.repo_root} for: "
        f"{', '.join(plan.literals[:8]) or '(no literals derived)'}[/dim]\n"
    )

    matches = codebase.locate(finding, cfg.repo_root, limit=limit, plan=plan)
    if not matches:
        console.print(
            "[yellow]No local code matched.[/yellow] The finding may live in "
            "infrastructure, configuration, or a different repository."
        )
        return

    console.print(render.render_code_matches(matches, cfg.repo_root))

    for match in matches[:5] if context else []:
        window = codebase.read_context(match.path, match.line, context, context)
        if not window:
            continue
        console.print()
        console.print(f"[bold cyan]{match.display(cfg.repo_root)}[/bold cyan]")
        console.print(
            Syntax(
                "\n".join(text for _, text in window),
                lexer_for(match.path),
                line_numbers=True,
                start_line=window[0][0],
                theme="ansi_dark",
                word_wrap=False,
            )
        )


@click.command()
@click.argument("finding_ref")
@click.argument("state", type=click.Choice(["new", "reading", "fixing", "fixed", "wontfix"]))
@CONFIG_OPTION
@click.option("--note", default="", help="Attach a note to the triage entry.")
def triage(finding_ref: str, state: str, config_path: str, note: str) -> None:
    """Set your local workflow state on a finding.

    FINDING_REF is a ref or an id. Local only: it never changes the finding's
    status on the platform — only a retest closes a finding upstream.
    """
    cfg = load_config(config_path)

    # Resolve against the cache so the state lands on the finding's key rather
    # than on a bare id that may name a second finding in another store.
    key = finding_ref
    store = open_store(cfg, allow_offline=True)
    store.load_cache()
    try:
        key = store.resolve(finding_ref).key
    except LoryConsoleError as exc:
        if isinstance(exc, AmbiguousFindingError):
            die(str(exc))
            return

    TriageLog(cfg.triage_path).set_state(key, state, note)
    console.print(
        f"[green]✓[/green] {key} marked [bold]{state}[/bold] locally "
        f"({cfg.triage_path})"
    )
    if state == "fixed":
        console.print(f"[dim]  Ready for a retest? Run: lory retest {key}[/dim]")


@click.command()
@click.argument("finding_ref")
@CONFIG_OPTION
@click.option("--note", default="", help="What changed and how you fixed it.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def retest(finding_ref: str, config_path: str, note: str, yes: bool) -> None:
    """Ask the Lorikeet team to re-test a finding you have fixed.

    FINDING_REF is a ref or an id. This is outward facing: it files a request
    with a human team.
    """
    cfg = load_config(config_path)
    store = open_store(cfg)
    store.load_cache()

    try:
        finding = store.detail(finding_ref)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    console.print(render.render_finding_header(finding))
    if not note:
        note = click.prompt("What changed", default="", show_default=False)
    if not yes:
        click.confirm(
            f"\nFile a retest request for {finding.key} with the Lorikeet team?", abort=True
        )

    try:
        result = store.request_retest(finding, note)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    console.print(f"[green]✓[/green] Retest requested for {finding.key}")
    console.print(Text(json.dumps(result, indent=2), style="dim"))


# ── helpers ─────────────────────────────────────────────────────────────────


#: SARIF has three levels; map the five severities onto them.
_SARIF_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}


def _sarif(rows: list[Finding]) -> str:
    """SARIF 2.1.0, the format GitHub code scanning and Defender ingest."""
    from lory_code_security import __version__

    seen: dict[str, dict[str, Any]] = {}
    results = []
    for finding in rows:
        rule_id = finding.cwe_id or finding.category or "lorikeet-finding"
        if rule_id not in seen:
            seen[rule_id] = {
                "id": rule_id,
                "name": finding.category or "SecurityFinding",
                "shortDescription": {"text": finding.category or rule_id},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(finding.severity, "warning")
                },
            }
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(finding.severity, "warning"),
            "message": {"text": f"{finding.title}\n\n{finding.description}".strip()},
            "properties": {
                "ref": finding.key,
                "severity": finding.severity,
                "cvss_score": finding.cvss_score,
                "affected_asset": finding.affected_asset,
                "store": finding.store,
            },
            # No file/line: findings are about a deployed asset, not a source
            # location. `lory trace` is what maps one onto local code, and
            # guessing a path here would put a wrong annotation on a PR.
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.affected_asset or "unknown"}
                }
            }],
        })

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Lorikeet Security",
                "informationUri": "https://lorikeetsecurity.com",
                "version": __version__,
                "rules": list(seen.values()),
            }},
            "results": results,
        }],
    }, indent=2)


def _export(rows: list[Finding], fmt: str) -> str:
    if fmt == "sarif":
        return _sarif(rows)

    if fmt == "json":
        return json.dumps([f.to_dict() for f in rows], indent=2)

    if fmt == "csv":
        buffer = io.StringIO()
        columns = ["key", "id", "severity", "status", "title", "affected_asset",
                   "cwe_id", "cvss_score"]
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for finding in rows:
            writer.writerow(finding.to_dict())
        return buffer.getvalue()

    lines = ["# Findings", ""]
    for finding in rows:
        lines.append(f"## {finding.key} {finding.title}")
        lines.append("")
        lines.append(f"- **Severity:** {finding.severity}")
        if finding.cvss_score:
            lines.append(f"- **CVSS:** {finding.cvss_score}")
        if finding.cwe_id:
            lines.append(f"- **CWE:** {finding.cwe_id}")
        if finding.affected_asset:
            lines.append(f"- **Asset:** {finding.affected_asset}")
        if finding.description:
            lines.append(f"\n{finding.description}\n")
        lines.append("")
    return "\n".join(lines)
