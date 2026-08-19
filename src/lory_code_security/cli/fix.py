"""``lory fix`` — ask Lory for a code-level fix for one finding."""

from __future__ import annotations

import click
from rich.panel import Panel

from lory_code_security.cli.common import CONFIG_OPTION, console, die, load_config, open_store
from lory_code_security.client.chat import ChatClient, Conversation
from lory_code_security.core.errors import LoryConsoleError, PaywallError
from lory_code_security.ui import render


@click.command()
@click.argument("finding_ref")
@CONFIG_OPTION
@click.option("--code", "include_code", is_flag=True,
              help="Attach local source excerpts to the prompt. Off by default.")
@click.option("--no-kb", is_flag=True, help="Skip the knowledge base lookup.")
@click.option("--ask", "question", default="", help="Replace the default question.")
@click.option("--dry-run", is_flag=True, help="Print the exact prompt and send nothing.")
def fix(
    finding_ref: str, config_path: str, include_code: bool, no_kb: bool,
    question: str, dry_run: bool,
) -> None:
    """Ask Lory for a code-level fix for one finding.

    FINDING_REF is a ref or an id. Builds a prompt from the finding, optionally
    the knowledge base entry for its vulnerability class, and optionally
    excerpts of your local source, then sends it to Lory.

    Source is attached only with --code (or send_code_context: true in the
    config). Use --dry-run to see exactly what would be sent before sending it.
    """
    from lory_code_security.domain import codebase, remediate

    cfg = load_config(config_path)
    # Offline-tolerant: Lory's chat endpoint needs no credential of its own,
    # and a scanned finding carries its whole body, so asking for a fix works
    # without a platform token.
    store = open_store(cfg, allow_offline=True)
    store.load_cache()

    try:
        finding = store.detail(finding_ref)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    include_code = include_code or cfg.send_code_context
    matches = codebase.locate(finding, cfg.repo_root, limit=8) if include_code else []
    kb_entries = [] if no_kb else store.search_kb(remediate.kb_query(finding), limit=3)

    request = remediate.build_prompt(
        finding, matches=matches, kb_entries=kb_entries, repo_root=cfg.repo_root,
        include_code=include_code, max_context_lines=cfg.max_context_lines,
        question=question,
    )

    console.print(render.render_finding_header(finding))
    console.print(f"\n[dim]{request.describe()}[/dim]")
    if request.included_code:
        console.print(f"[yellow]![/yellow] Sending source from: {', '.join(request.code_files)}")

    if dry_run:
        console.print()
        console.print(
            Panel(request.prompt, title="[bold]Prompt (not sent)[/bold]", border_style="dim")
        )
        return

    console.print()
    conversation = Conversation(ChatClient(cfg))
    try:
        reply = conversation.send(request.prompt, stream=False)
    except PaywallError as exc:
        die(f"free message limit reached ({exc.used}/{exc.limit}). {exc}")
        return
    except LoryConsoleError as exc:
        die(str(exc))
        return

    console.print(render.render_reply(reply.blocks, reply.suggestions))

    problems = reply.contract_problems()
    if problems:
        console.print()
        console.print(render.render_problems(problems))

    console.print(
        f"\n[dim]When it is fixed:  lory triage {finding.key} fixed  "
        f"→  lory retest {finding.key}[/dim]"
    )
