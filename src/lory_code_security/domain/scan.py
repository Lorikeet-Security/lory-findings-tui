"""Local scanning, delegated to `lory-scan`.

This tool reads findings; it does not look for them. The scanner is a separate
program — `lory-code-security-scanner
<https://github.com/Lorikeet-Security/lory-code-security-scanner>`_ — that runs
entirely on this machine, and this module is the adapter between the two.

The integration is a *contract*, not an import. The scanner publishes it as
JSON (``lory-scan describe``) with its own version number, so:

* neither package depends on the other, and either can be installed alone;
* an incompatible scanner is detected and named, rather than misread;
* the scanner is free to grow rules and flags without a release here.

Findings arrive already in this tool's vocabulary — the scanner's ``lory-json``
format is exactly what :meth:`Finding.from_row` consumes — so nothing is
translated twice, and a scanned finding behaves like a platform one everywhere
downstream: the same detail pane, the same trace, the same triage log.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from importlib.util import find_spec
from pathlib import Path
from typing import Any

from lory_code_security.core.errors import LoryConsoleError

#: The scanner's console script, as installed by pip.
EXECUTABLE = "lory-scan"

#: Output contracts this version understands. The scanner reports its own in
#: `describe`; anything outside this set is refused rather than guessed at.
SUPPORTED_CONTRACTS = frozenset({1})

#: A scan of a large repository is measured in tens of seconds, not seconds.
DEFAULT_TIMEOUT = 900

INSTALL_HINT = (
    "Install it with:\n"
    "  pip install lory-code-security-scanner\n\n"
    "It runs entirely on this machine — no account, no token, no network."
)


class ScannerUnavailable(LoryConsoleError):
    """The scanner is not installed, or is a version this tool cannot read."""


class ScannerFailed(LoryConsoleError):
    """The scanner ran and reported an error."""


@dataclass
class ScannerInfo:
    """What `lory-scan describe` says about itself."""

    #: How to invoke it, as an argv prefix.
    command: list[str] = field(default_factory=list)
    version: str = "?"
    contract_version: int = 0
    rule_count: int = 0

    @property
    def supported(self) -> bool:
        return self.contract_version in SUPPORTED_CONTRACTS

    @property
    def display(self) -> str:
        return " ".join(self.command)

    def summary(self) -> str:
        return f"lory-scan v{self.version} ({self.rule_count} rules)"


def locate(executable: str | None = None) -> list[str] | None:
    """How to invoke the scanner, or None if it is not installed.

    Four places, in order of how deliberate they are:

    1. an explicit path, taken as given — including one that does not exist,
       so a typo is reported as a typo rather than as "not installed";
    2. PATH;
    3. next to the interpreter running this process, which is where it lands
       when both packages are pip-installed into the same virtualenv and that
       venv is not on PATH — the common case for a tool invoked by its full
       path, or through pipx;
    4. as a module, which works whenever the package is merely importable.
    """
    if executable:
        return [executable]

    found = shutil.which(EXECUTABLE)
    if found:
        return [found]

    sibling = Path(sys.executable).parent / EXECUTABLE
    if sibling.is_file():
        return [str(sibling)]

    if find_spec("lory_scanner") is not None:
        return [sys.executable, "-m", "lory_scanner"]

    return None


def describe(executable: str | None = None) -> ScannerInfo:
    """Ask the scanner what it is, and whether we can read its output."""
    command = locate(executable)
    if command is None:
        raise ScannerUnavailable(f"{EXECUTABLE} is not installed.\n\n{INSTALL_HINT}")

    label = " ".join(command)

    try:
        proc = subprocess.run(
            [*command, "describe"], capture_output=True, text=True, timeout=30, check=False
        )
    except FileNotFoundError as exc:
        raise ScannerUnavailable(f"cannot run {label}: {exc}\n\n{INSTALL_HINT}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScannerUnavailable(f"cannot run {label}: {exc}") from exc

    if proc.returncode != 0:
        raise ScannerUnavailable(
            f"{label} describe failed: {_first_line(proc.stderr) or f'exit {proc.returncode}'}"
        )

    try:
        payload = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ScannerUnavailable(
            f"{label} describe returned output this version cannot parse: {exc}"
        ) from exc

    info = ScannerInfo(
        command=list(command),
        version=str(payload.get("version", "?")),
        contract_version=int(payload.get("contract_version", 0)),
        rule_count=int((payload.get("rules") or {}).get("count", 0)),
    )

    if not info.supported:
        raise ScannerUnavailable(
            f"{label} speaks output contract v{info.contract_version}; this version of "
            f"lory-code-security understands {sorted(SUPPORTED_CONTRACTS)}. "
            "Upgrade whichever of the two is older."
        )

    return info


def run(
    root: Path,
    info: ScannerInfo | None = None,
    executable: str | None = None,
    severity: str | None = None,
    diff: str | None = None,
    staged: bool = False,
    select: tuple[str, ...] = (),
    ignore_rules: tuple[str, ...] = (),
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    """Scan ``root`` and return finding rows ready for :meth:`Finding.from_row`.

    ``--fail-on never`` is deliberate: the scanner's exit code is its own CI
    signal, and here a non-zero status should mean "the scan did not run", not
    "the scan found something". Conflating the two would turn a successful scan
    of a vulnerable repository into an error message.
    """
    # A caller that already ran `describe` — to show the version before a long
    # scan, say — passes the result back rather than paying for it twice.
    if info is None:
        info = describe(executable)

    argv = [
        *info.command, "scan", str(root),
        "--format", "lory-json",
        "--quiet",
        "--fail-on", "never",
    ]
    if severity:
        argv += ["--min-severity", severity]
    if diff:
        argv += ["--diff", diff]
    if staged:
        argv.append("--staged")
    for pattern in select:
        argv += ["--select", pattern]
    for pattern in ignore_rules:
        argv += ["--ignore-rule", pattern]

    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerFailed(
            f"the scan of {root} took longer than {timeout}s. Narrow it with a path "
            "argument or --diff, or raise the timeout."
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScannerFailed(f"could not run {info.display}: {exc}") from exc

    if proc.returncode != 0:
        raise ScannerFailed(
            f"{EXECUTABLE} exited {proc.returncode}: "
            f"{_first_line(proc.stderr) or 'no error message'}"
        )

    return parse(proc.stdout)


def parse(payload: str) -> list[dict[str, Any]]:
    """Read the scanner's findings envelope."""
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ScannerFailed(f"could not read the scanner's output: {exc}") from exc

    rows = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ScannerFailed("the scanner's output had no findings list")

    return [row for row in rows if isinstance(row, dict)]


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""
