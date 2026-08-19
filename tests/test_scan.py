"""`lory scan` — the bridge to the local scanner.

The scanner is a separate program, so these tests stub the subprocess boundary
rather than requiring it to be installed. What they pin is the contract: what
we send it, what we accept back, and what happens to findings that are already
in the cache when a scan lands.
"""

from __future__ import annotations

import json
import subprocess

import pytest
from click.testing import CliRunner

from lory_code_security.cli.main import main
from lory_code_security.core.errors import LoryConsoleError
from lory_code_security.domain import scan as scanner
from lory_code_security.domain.findings import FindingStore

DESCRIBE = {
    "tool": "lory-scan",
    "version": "0.1.0",
    "contract_version": 1,
    "rules": {"count": 100},
}

ROW = {
    "ref": "scan-a1b2c3d4e5",
    "store": "scan",
    "id": 2712847316,
    "title": "Subprocess invoked with shell=True",
    "severity": "high",
    "status": "open",
    "affected_asset": "app.py:12",
    "category": "injection",
    "cwe_id": "CWE-78",
    "description": "With shell=True the argument is parsed by /bin/sh.",
    "evidence": "app.py:12\n\nsubprocess.run(cmd, shell=True)",
    "remediation": "Pass a list of arguments and drop shell=True.",
    "source": "lory_scan",
    "vector": "sast",
    "rule_id": "python.subprocess-shell-true",
}

FINDINGS_JSON = json.dumps({"fetched_at": "2026-01-01T00:00:00Z", "findings": [ROW]})


class FakeProc:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture
def fake_scanner(monkeypatch):
    """Stand in for the scanner binary, and record how it was invoked."""
    calls: list[list[str]] = []
    responses = {"describe": FakeProc(json.dumps(DESCRIBE)), "scan": FakeProc(FINDINGS_JSON)}

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return responses["describe" if "describe" in argv else "scan"]

    monkeypatch.setattr(scanner, "locate", lambda executable=None: ["lory-scan"])
    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls, responses


# ── the adapter ─────────────────────────────────────────────────────────────


def test_describe_reads_the_contract(fake_scanner):
    info = scanner.describe()
    assert info.version == "0.1.0"
    assert info.contract_version == 1
    assert info.rule_count == 100
    assert info.supported


def test_unsupported_contract_is_refused(fake_scanner, monkeypatch):
    """A scanner from the future must be named, not misread."""
    calls, responses = fake_scanner
    responses["describe"] = FakeProc(json.dumps({**DESCRIBE, "contract_version": 99}))

    with pytest.raises(LoryConsoleError, match="contract v99"):
        scanner.describe()


def test_missing_scanner_explains_how_to_get_it(monkeypatch):
    monkeypatch.setattr(scanner, "locate", lambda executable=None: None)
    with pytest.raises(LoryConsoleError, match="pip install lory-code-security-scanner"):
        scanner.describe()


def test_run_builds_the_expected_command(fake_scanner, tmp_path):
    calls, _ = fake_scanner
    scanner.run(tmp_path, severity="high", diff="origin/main", ignore_rules=("js.*",))

    argv = calls[-1]
    assert argv[:2] == ["lory-scan", "scan"]
    assert str(tmp_path) in argv
    assert argv[argv.index("--format") + 1] == "lory-json"
    assert argv[argv.index("--min-severity") + 1] == "high"
    assert argv[argv.index("--diff") + 1] == "origin/main"
    assert argv[argv.index("--ignore-rule") + 1] == "js.*"
    # Findings are not a failure here — the exit code must mean "did not run".
    assert argv[argv.index("--fail-on") + 1] == "never"


def test_scanner_failure_is_reported_with_its_message(fake_scanner, tmp_path):
    _, responses = fake_scanner
    responses["scan"] = FakeProc(stderr="error: no rules loaded", returncode=2)

    with pytest.raises(LoryConsoleError, match="no rules loaded"):
        scanner.run(tmp_path)


def test_unparseable_output_is_reported(fake_scanner, tmp_path):
    _, responses = fake_scanner
    responses["scan"] = FakeProc(stdout="not json")

    with pytest.raises(LoryConsoleError, match="could not read"):
        scanner.run(tmp_path)


def test_parse_accepts_a_bare_list():
    assert scanner.parse(json.dumps([ROW]))[0]["ref"] == "scan-a1b2c3d4e5"


# ── ingesting into the store ────────────────────────────────────────────────


def test_ingest_keeps_platform_findings(tmp_path):
    """A local scan must not make the platform's findings disappear."""
    cache = tmp_path / "findings.json"
    cache.write_text(json.dumps({"findings": [
        {"ref": "engagement-1652", "store": "engagement", "id": 1652,
         "title": "Platform finding", "severity": "critical"},
    ]}))

    store = FindingStore(None, cache_path=cache)
    store.load_cache()
    store.ingest([ROW])

    keys = {f.key for f in store.all()}
    assert keys == {"engagement-1652", "scan-a1b2c3d4e5"}


def test_ingest_replaces_the_previous_scan(tmp_path):
    """A finding that no longer matches has been fixed; it must not linger."""
    cache = tmp_path / "findings.json"
    store = FindingStore(None, cache_path=cache)
    store.ingest([ROW, {**ROW, "ref": "scan-stale00000", "id": 7}])
    store.ingest([ROW])

    assert {f.key for f in store.all()} == {"scan-a1b2c3d4e5"}


def test_ingest_writes_the_cache(tmp_path):
    cache = tmp_path / "findings.json"
    FindingStore(None, cache_path=cache).ingest([ROW])
    assert json.loads(cache.read_text())["findings"][0]["ref"] == "scan-a1b2c3d4e5"


# ── the command ─────────────────────────────────────────────────────────────


def test_scan_command_reports_findings(fake_scanner, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    # The table wraps in a narrow terminal, so match on what cannot wrap.
    assert "scan-a1b2c3d4e5" in result.output
    assert "app.py:12" in result.output
    assert (tmp_path / ".lory_state" / "findings.json").exists()


def test_scan_command_json(fake_scanner, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--json"])
    assert json.loads(result.output)[0]["ref"] == "scan-a1b2c3d4e5"


def test_scan_command_no_save_leaves_no_cache(fake_scanner, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    CliRunner().invoke(main, ["scan", str(tmp_path), "--no-save"])
    assert not (tmp_path / ".lory_state").exists()


def test_scan_command_works_without_a_token(fake_scanner, tmp_path, monkeypatch):
    """The whole point: scanning needs no account."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LORY_MCP_TOKEN", raising=False)

    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "mcp_token" not in result.output


def test_scan_command_without_the_scanner_installed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scanner, "locate", lambda executable=None: None)

    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "lory-code-security-scanner" in result.output


def test_scanned_findings_are_readable_offline(fake_scanner, tmp_path, monkeypatch):
    """`show` on a scanned finding must not demand a platform token."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LORY_MCP_TOKEN", raising=False)
    CliRunner().invoke(main, ["scan", str(tmp_path)])

    result = CliRunner().invoke(main, ["findings", "show", "scan-a1b2c3d4e5"])
    assert result.exit_code == 0
    assert "CWE-78" in result.output
    assert "mcp_token" not in result.output


def test_locate_finds_a_scanner_beside_the_interpreter(monkeypatch, tmp_path):
    """pip-installed into the same venv, with that venv not on PATH."""
    import shutil
    import sys

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / scanner.EXECUTABLE).write_text("#!/bin/sh\n")

    monkeypatch.setattr(shutil, "which", lambda _: None)
    monkeypatch.setattr(sys, "executable", str(bin_dir / "python"))

    assert scanner.locate() == [str(bin_dir / scanner.EXECUTABLE)]
