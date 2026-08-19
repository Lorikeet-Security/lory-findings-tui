"""The findings cockpit.

Three columns:

* **left** — every finding on the account, severity-ordered, filterable.
* **middle** — the selected finding, plus the local code that may cause it.
* **right** — Lory, seeded with the selected finding when you press ``f``.

Two Textual details this leans on deliberately:

* Content panes are :class:`VerticalScroll` holding :class:`Static` widgets,
  **not** ``RichLog``. ``RichLog`` renders each write at the width it had at
  write time and never reflows, so anything wider than the pane is clipped
  rather than wrapped. ``Static`` re-renders on resize, which is what a
  three-column layout needs.
* Every network call is a ``@work(thread=True)`` worker, so the UI stays
  responsive and failures land in the status bar rather than as a traceback.

Nothing here scans anything: findings arrive from the platform already reviewed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Group, RenderableType
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, Label, Static

from lory_code_security.client.chat import ChatClient, Conversation
from lory_code_security.core.config import Config
from lory_code_security.core.errors import AuthError, LoryConsoleError
from lory_code_security.domain import codebase, remediate
from lory_code_security.domain.findings import (
    Finding,
    TriageLog,
    filter_findings,
    severity_counts,
)
from lory_code_security.ui import render


#: Shown when an action needs a finding and the table has none highlighted —
#: an empty filter result, or an account with nothing on it. Silence there read
#: as a dead key.
def _one_line(exc: Exception) -> str:
    """First line of an error, for a one-line status bar."""
    text = str(exc).strip()
    return text.splitlines()[0] if text else exc.__class__.__name__


_NO_SELECTION = "no finding selected"

SEVERITY_COLOURS = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "green",
    "info": "dim cyan",
}


class ConfirmScreen(ModalScreen[bool]):
    """Yes/no gate for anything that leaves the machine."""

    BINDINGS = [
        Binding("y", "confirm", "Yes"),
        Binding("n,escape", "cancel", "No"),
    ]

    def __init__(self, question: str, detail: str = "") -> None:
        super().__init__()
        self.question = question
        self.detail = detail

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Label(self.question, id="confirm-question")
            if self.detail:
                yield Static(self.detail, id="confirm-detail")
            yield Label("[bold]y[/bold] confirm     [bold]n[/bold] cancel")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class LoryApp(App[None]):
    """Findings triage and remediation, full screen."""

    CSS_PATH = "app.tcss"
    TITLE = "lory-code-security"

    BINDINGS = [
        Binding("q,ctrl+c", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("s", "scan_code", "Scan code"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("f", "ask_lory", "Fix with Lory"),
        Binding("t", "trace_code", "Trace code"),
        Binding("l", "toggle_lory", "Lory pane"),
        Binding("m", "mark_fixed", "Mark fixed"),
        Binding("R", "request_retest", "Request retest"),
        Binding("e", "open_editor", "Open in $EDITOR"),
        Binding("c", "toggle_code_context", "Code context"),
        Binding("escape", "clear_filter", "Clear filter", show=False),
    ]

    #: The selected finding's key (``engagement-12``), not its integer id:
    #: ids repeat across the platform's finding stores.
    selected_key: reactive[str | None] = reactive(None)

    def __init__(self, cfg: Config, start_cached: bool = False) -> None:
        super().__init__()
        self.cfg = cfg
        self.start_cached = start_cached
        self.store: Any = None
        self.triage = TriageLog(cfg.triage_path)
        self.conversation: Conversation | None = None
        self.all_findings: list[Finding] = []
        self.code_matches: list[codebase.CodeMatch] = []
        #: Which finding the current code leads belong to, so a table rebuild
        #: that re-fires RowHighlighted does not discard a trace the user ran.
        self.code_matches_key: str | None = None
        self.filter_text = ""
        self.send_code = cfg.send_code_context
        #: Set while a table rebuild is putting the cursor back where the user
        #: left it. Clearing the table drops the cursor to row 0 and fires
        #: RowHighlighted for a row nobody selected; acting on that event moves
        #: the selection and discards the trace. See :meth:`apply_filter`.
        self._restoring_key: str | None = None

    # ── layout ──────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="root"):
            with Horizontal(id="body"):
                with Vertical(id="sidebar"):
                    yield Static("▌ FINDINGS", classes="pane-title")
                    yield Input(placeholder="filter…", id="filter")
                    yield DataTable(id="findings-table", cursor_type="row")
                    yield Static("", id="counts")
                with Vertical(id="detail-pane"):
                    yield Static("▌ DETAIL", classes="pane-title")
                    with VerticalScroll(id="detail-scroll"):
                        yield Static(id="detail")
                with Vertical(id="lory-pane"):
                    yield Static("▌ LORY", classes="pane-title")
                    with VerticalScroll(id="lory-scroll"):
                        yield Static(id="lory-intro")
                    yield Input(placeholder="ask Lory…", id="lory-input")
            yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_column("sev", width=4)
        table.add_column("ref", width=14)
        table.add_column("title", width=26)
        table.add_column("st", width=2)
        table.focus()

        self.query_one("#lory-intro", Static).update(self._lory_intro())
        self.set_status(f"{self.cfg.base_url}  ·  repo {self.cfg.repo_root.name}")
        self.load_findings(refresh=not self.start_cached)

    def _lory_intro(self) -> RenderableType:
        """The empty state: what you can do here, not how it works inside.

        No hard line breaks. The pane squeezes to 34 columns in a narrow
        terminal, and pre-wrapped prose is clipped rather than reflowed.
        """
        body = Text()
        body.append("Ask Lory\n\n", style="bold")
        body.append(
            "Answers are grounded in the finding you have selected: its "
            "description, evidence, and knowledge base entry.\n\n",
            style="dim",
        )

        for key, label in (
            ("f", "Ask about this finding"),
            ("t", "Trace it to local code"),
        ):
            body.append(f" {key} ", style="reverse bold")
            body.append(f"  {label}\n", style="dim")

        # The one control worth stating outright: whether source leaves here.
        body.append(" c ", style="reverse bold")
        body.append("  Send source: ", style="dim")
        body.append(
            "on\n" if self.send_code else "off\n",
            style="bold yellow" if self.send_code else "dim",
        )
        return body

    def refresh_lory_intro(self) -> None:
        """Re-render the empty state, if it is still the only thing in the pane."""
        intro = self.query("#lory-intro")
        if intro:
            intro.first(Static).update(self._lory_intro())

    # ── data ────────────────────────────────────────────────────────────────

    @work(thread=True, exclusive=True, group="load")
    def load_findings(self, refresh: bool = True) -> None:
        from lory_code_security.cli.common import open_store

        if self.store is None:
            try:
                self.store = open_store(self.cfg, allow_offline=True)
            except SystemExit:
                self.call_from_thread(
                    self.show_empty,
                    "No read path configured.",
                    "Run `lory init` to set up an MCP token from your portal.",
                )
                return

        cached = self.store.load_cache()
        if cached:
            self.call_from_thread(self.set_findings, cached, "cache")

        if not refresh:
            return

        self.call_from_thread(self.set_status, "fetching findings…")
        try:
            rows = self.store.fetch(limit=50)
        except LoryConsoleError as exc:
            # A failed refresh must not destroy a cached view that is already
            # on screen: say so in the status bar and leave the findings up.
            if cached:
                self.call_from_thread(
                    self.set_status, f"refresh failed, showing {len(cached)} cached: {exc}"
                )
            else:
                self.call_from_thread(self.show_empty, "Could not read findings.", str(exc))
            return

        if not rows:
            self.call_from_thread(self.show_empty, "No findings returned.", self._explain_empty())
            return

        self.call_from_thread(self.set_findings, rows, self.store.last_source)

    def _explain_empty(self) -> str:
        """Why an empty list is empty. A blank pane just wastes the user's time.

        The platform keeps findings in more than one store, and the two read
        paths do not cover the same ground, so "no rows" usually means "wrong
        path" rather than "nothing to fix".
        """
        lines: list[str] = []

        if self.store is not None and self.store.last_source == "mcp":
            lines.append(
                "This server does not expose findings.search, so only manual "
                "pentest findings were read. Incident-response and Lory "
                "engagement findings need that tool."
            )

        return "\n\n".join(lines) or "This account has no findings on this read path."

    def show_empty(self, headline: str, detail: str = "") -> None:
        body = Text()
        body.append(f"{headline}\n", style="bold yellow")
        if detail:
            body.append(f"\n{detail}", style="dim")
        self.query_one("#detail", Static).update(body)
        self._update_counts(0)
        self.set_status(headline)

    def set_findings(self, rows: list[Finding], source: str) -> None:
        self.all_findings = rows
        self.apply_filter()
        self.set_status(f"{len(rows)} findings via {source}")

    def _update_counts(self, visible: int) -> None:
        """The counts line: severity mix of the account, and how much is shown.

        The severity breakdown always describes the whole account — it is the
        shape of the backlog, not of the current filter. The leading count does
        track the filter, because "22 findings" above three visible rows reads
        as a bug in the filter.
        """
        counts = severity_counts(self.all_findings)
        summary = "  ".join(
            f"{counts[s]} {s[0].upper()}"
            for s in ("critical", "high", "medium", "low", "info")
            if counts.get(s)
        )
        total = len(self.all_findings)
        shown = f"{visible} of {total} findings" if visible != total else f"{total} findings"
        self.query_one("#counts", Static).update(f"{shown}   {summary}")

    def apply_filter(self) -> None:
        rows = filter_findings(self.all_findings, query=self.filter_text)

        table = self.query_one("#findings-table", DataTable)
        # `clear()` resets the cursor to row 0 and re-fires RowHighlighted, so
        # the selection has to be captured before the rebuild and put back
        # after it. Without this, marking or refreshing from any row but the
        # first threw the user back to the top of the list.
        keep = self.selected_key
        table.clear()
        for finding in rows:
            state = self.triage.state(finding.key)
            table.add_row(
                Text(
                    finding.severity.upper()[:4],
                    style=SEVERITY_COLOURS.get(finding.severity, "dim"),
                ),
                Text(finding.key, style="dim"),
                Text(finding.title or "(untitled)"),
                Text(
                    _state_glyph(state),
                    style="bold green" if state == "fixed" else "yellow",
                ),
                # Keyed by the finding's key. Keying by id raised DuplicateKey
                # the moment two stores each held a finding with the same id.
                key=finding.key,
            )

        self._update_counts(len(rows))

        if not rows:
            # Nothing is selectable. Leaving `selected_key` pointing at a row
            # that is no longer on screen let f/t/m/R act on a finding the user
            # could not see — including filing a retest for it.
            self.selected_key = None
            self.code_matches = []
            self.code_matches_key = None
            self._restoring_key = None
            self.show_empty(
                f"No finding matches {self.filter_text!r}."
                if self.filter_text
                else "No findings to show.",
                "Press esc to clear the filter." if self.filter_text else "",
            )
            return

        keys = [f.key for f in rows]
        if keep in keys:
            index = keys.index(keep)
            # Row 0 is where the rebuild already left the cursor; moving to it
            # would fire no event, and the guard would never be released.
            if index:
                self._restoring_key = keep
                table.move_cursor(row=index, animate=False)
        else:
            self.selected_key = rows[0].key
            self.show_detail(rows[0])

    def current(self) -> Finding | None:
        if self.selected_key is None:
            return None
        return next((f for f in self.all_findings if f.key == self.selected_key), None)

    # ── events ──────────────────────────────────────────────────────────────

    @on(DataTable.RowHighlighted, "#findings-table")
    def _row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        key = str(event.row_key.value)

        # A rebuild emits a highlight for row 0 before the cursor is put back.
        # That is not a move the user made, so ignore everything until the
        # restored row arrives.
        if self._restoring_key is not None:
            if key != self._restoring_key:
                return
            self._restoring_key = None

        self.selected_key = key
        # Drop code leads only when the selection genuinely moved. Rebuilding
        # the table (filter, mark-fixed) re-fires this for the same row, and
        # discarding the trace there loses work the user just did.
        if self.code_matches_key != self.selected_key:
            self.code_matches = []
            self.code_matches_key = None
        finding = self.current()
        if finding is not None:
            self.show_detail(finding)
            if not finding.is_detailed:
                self.load_detail(finding.key)

    @on(Input.Submitted, "#filter")
    def _filter_submitted(self, event: Input.Submitted) -> None:
        self.filter_text = event.value.strip()
        self.apply_filter()
        self.query_one("#findings-table", DataTable).focus()

    @on(Input.Submitted, "#lory-input")
    def _lory_submitted(self, event: Input.Submitted) -> None:
        message = event.value.strip()
        if not message:
            return
        event.input.value = ""
        self.send_to_lory(message)

    # ── detail rendering ────────────────────────────────────────────────────

    def show_detail(self, finding: Finding) -> None:
        parts: list[RenderableType] = [
            render.render_finding_detail(finding, self.triage.state(finding.key))
        ]

        if finding.source:
            provenance = f"\nfound by: {finding.source}"
            if finding.vector:
                provenance += f"  ·  vector {finding.vector}"
            parts.append(Text(provenance, style="dim"))

        if self.code_matches:
            parts.append(Text("\nLocal code leads", style="bold"))
            parts.append(render.render_code_matches(self.code_matches, self.cfg.repo_root))

        self.query_one("#detail", Static).update(Group(*parts))

    @work(thread=True, group="detail")
    def load_detail(self, key: str) -> None:
        if self.store is None:
            return
        try:
            finding = self.store.detail(key)
        except LoryConsoleError as exc:
            self.call_from_thread(self.set_status, f"detail failed: {exc}")
            return
        for i, existing in enumerate(self.all_findings):
            if existing.key == finding.key:
                self.all_findings[i] = finding
                break
        if self.selected_key == key:
            self.call_from_thread(self.show_detail, finding)

    # ── actions ─────────────────────────────────────────────────────────────

    def action_refresh(self) -> None:
        self.load_findings(refresh=True)

    def action_scan_code(self) -> None:
        """Scan the working tree with lory-scan, without leaving the cockpit."""
        self.set_status(f"scanning {self.cfg.repo_root}…")
        self.scan_worker()

    @work(thread=True, exclusive=True, group="scan")
    def scan_worker(self) -> None:
        from lory_code_security.cli.common import open_store
        from lory_code_security.domain import scan as scanner

        if self.store is None:
            self.store = open_store(self.cfg, allow_offline=True)
            self.store.load_cache()

        try:
            rows = scanner.run(self.cfg.repo_root)
        except LoryConsoleError as exc:
            # A scan that cannot run must not clear the findings already on
            # screen — say why in the status bar and leave the view alone.
            self.call_from_thread(self.set_status, f"scan failed: {_one_line(exc)}")
            return

        found = self.store.ingest(rows)
        self.call_from_thread(self.set_findings, self.store.all(), "local scan")
        self.call_from_thread(
            self.set_status,
            f"{len(found)} findings from the local scan of {self.cfg.repo_root}",
        )

    def action_focus_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def action_clear_filter(self) -> None:
        self.query_one("#filter", Input).value = ""
        self.filter_text = ""
        self.apply_filter()

    def action_toggle_lory(self) -> None:
        pane = self.query_one("#lory-pane")
        pane.set_class(not pane.has_class("visible"), "visible")

    def action_toggle_code_context(self) -> None:
        self.send_code = not self.send_code
        self.refresh_lory_intro()
        self.set_status(
            "code context ON — source will be sent with fix requests"
            if self.send_code
            else "code context OFF"
        )

    def action_trace_code(self) -> None:
        finding = self.current()
        if finding is None:
            self.set_status(_NO_SELECTION)
            return
        self.set_status("searching the working tree…")
        self.trace_worker(finding)

    @work(thread=True, group="trace")
    def trace_worker(self, finding: Finding) -> None:
        matches = codebase.locate(finding, self.cfg.repo_root, limit=15)
        self.code_matches = matches
        self.code_matches_key = finding.key
        self.call_from_thread(self.show_detail, finding)
        self.call_from_thread(
            self.set_status,
            f"{len(matches)} code lead(s) in {self.cfg.repo_root}"
            if matches
            else "no local code matched this finding",
        )

    def action_ask_lory(self) -> None:
        finding = self.current()
        if finding is None:
            self.set_status(_NO_SELECTION)
            return

        self.query_one("#lory-pane").add_class("visible")

        request = remediate.build_prompt(
            finding,
            matches=self.code_matches,
            repo_root=self.cfg.repo_root,
            include_code=self.send_code,
            max_context_lines=self.cfg.max_context_lines,
        )

        label = f"Fix {finding.key} · {finding.title}"
        if request.included_code:
            label += f"  (+{len(request.code_files)} file(s) of source)"
            self.push_screen(
                ConfirmScreen(
                    f"Send source from {len(request.code_files)} file(s) to Lory?",
                    ", ".join(request.code_files),
                ),
                lambda ok: self.send_to_lory(request.prompt, label) if ok else None,
            )
        else:
            self.send_to_lory(request.prompt, label)

    def action_mark_fixed(self) -> None:
        finding = self.current()
        if finding is None:
            self.set_status(_NO_SELECTION)
            return
        state = "new" if self.triage.state(finding.key) == "fixed" else "fixed"
        self.triage.set_state(finding.key, state)
        self.apply_filter()
        self.set_status(f"{finding.key} marked {state} locally (not on the platform)")

    def action_request_retest(self) -> None:
        finding = self.current()
        if finding is None:
            self.set_status(_NO_SELECTION)
            return
        if self.store is None:
            self.set_status("no read path configured — run `lory init`")
            return
        self.push_screen(
            ConfirmScreen(
                f"File a retest request for {finding.key} with the Lorikeet team?",
                finding.title,
            ),
            lambda ok: self.retest_worker(finding) if ok else None,
        )

    @work(thread=True, group="retest")
    def retest_worker(self, finding: Finding) -> None:
        try:
            self.store.request_retest(finding, "Requested from lory-code-security")
        except LoryConsoleError as exc:
            self.call_from_thread(self.set_status, f"retest failed: {exc}")
            return
        self.call_from_thread(self.set_status, f"retest requested for {finding.key}")

    def action_open_editor(self) -> None:
        """Open the top code lead in $EDITOR, suspending the TUI.

        ``$EDITOR`` is a command line, not a program name: ``code -w`` and
        ``emacsclient -nw`` are both common. Running it unsplit looked for a
        program literally called ``code -w``, and the resulting
        FileNotFoundError propagated out of the action and took the whole
        cockpit down with it — losing the session over a typo in an env var.
        """
        import os
        import shlex
        import subprocess

        from textual.app import SuspendNotSupported

        if not self.code_matches:
            self.set_status("no code leads yet — press t to trace")
            return

        editor = os.environ.get("EDITOR", "").strip() or "vi"
        try:
            command = shlex.split(editor)
        except ValueError:  # an unbalanced quote in $EDITOR
            command = [editor]
        if not command:
            command = ["vi"]

        match = self.code_matches[0]
        argv = [*command, *_editor_target(command[0], match.path, match.line)]
        try:
            with self.suspend():
                subprocess.run(argv, check=False)
        except SuspendNotSupported:
            self.set_status(f"cannot suspend to run {command[0]} on this terminal")
        except OSError as exc:
            self.set_status(f"could not run $EDITOR ({command[0]}): {exc}")

    # ── Lory ────────────────────────────────────────────────────────────────

    def send_to_lory(self, message: str, label: str | None = None) -> None:
        """Send a turn, echoing ``label`` in place of the raw prompt.

        A finding-seeded ask builds a prompt twenty lines long. Echoing that
        verbatim buries the answer below the fold and misattributes it: the
        user pressed a key, they did not type it. What is actually sent stays
        auditable through the confirmation gate and `lory fix --dry-run`.
        """
        self.query_one("#lory-pane").add_class("visible")
        self.append_lory(Text(label or message[:400]), role="user")
        self.lory_worker(message)

    @work(thread=True, group="lory")
    def lory_worker(self, message: str) -> None:
        if self.conversation is None:
            self.conversation = Conversation(ChatClient(self.cfg))

        self.call_from_thread(self.set_status, "asking Lory…")
        try:
            reply = self.conversation.send(message, stream=False)
        except AuthError as exc:
            self.call_from_thread(self.append_lory, Text(str(exc), style="red"))
            self.call_from_thread(self.set_status, "Lory rejected the credentials")
            return
        except LoryConsoleError as exc:
            self.call_from_thread(self.append_lory, Text(f"error: {exc}", style="red"))
            self.call_from_thread(self.set_status, "Lory request failed")
            return

        self.call_from_thread(
            self.append_lory, render.render_reply(reply.blocks, reply.suggestions)
        )
        self.call_from_thread(
            self.set_status, f"Lory replied in {reply.elapsed_ms / 1000:.1f}s"
        )

    def append_lory(self, renderable: RenderableType, role: str = "lory") -> None:
        """Append one turn to the transcript and scroll to it.

        Each turn carries a speaker label and a coloured left rule, so a long
        remediation answer stays visibly separate from the question that
        prompted it. The empty state is removed on the first turn rather than
        left sitting at the top of the transcript.
        """
        scroll = self.query_one("#lory-scroll", VerticalScroll)
        self.query("#lory-intro").remove()

        speaker = Text("you" if role == "user" else "lory", style="bold")
        scroll.mount(
            Static(Group(speaker, renderable), classes=f"lory-message from-{role}")
        )
        scroll.scroll_end(animate=False)

    # ── misc ────────────────────────────────────────────────────────────────

    def set_status(self, message: str) -> None:
        self.query_one("#status", Static).update(message)


def _state_glyph(state: str) -> str:
    return {"new": "", "reading": "·", "fixing": "~", "fixed": "✓", "wontfix": "×"}.get(
        state, ""
    )


def _editor_target(editor: str, path: Path, line: int) -> list[str]:
    """Build the jump-to-line argument for the common editors."""
    name = Path(editor).name
    if name in ("vi", "vim", "nvim", "emacs", "emacsclient", "nano", "micro"):
        return [f"+{line}", str(path)]
    if name in ("code", "codium", "cursor"):
        return ["--goto", f"{path}:{line}"]
    return [str(path)]
