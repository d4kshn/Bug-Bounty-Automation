from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bbpipeline.events import EventInput
from bbpipeline.redaction import redact_text


MAX_CAPTURE_BYTES = 5 * 1024 * 1024


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass
class AdapterResult:
    events: list[EventInput] = field(default_factory=list)
    artifacts: list[tuple[str, str, bytes]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


def run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None = None,
    accepted_codes: set[int] | None = None,
    input_bytes: bytes | None = None,
) -> CommandResult:
    accepted = accepted_codes or {0}
    process_env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/home/bbpipeline"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if env:
        process_env.update(env)
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=process_env,
        capture_output=True,
        input=input_bytes,
        check=False,
        timeout=timeout,
    )
    stdout = completed.stdout[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    stderr = completed.stderr[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    result = CommandResult(
        command=command,
        returncode=completed.returncode,
        stdout=redact_text(stdout),
        stderr=redact_text(stderr),
    )
    if completed.returncode not in accepted:
        raise RuntimeError(
            f"command failed with exit code {completed.returncode}: {command[0]}: "
            f"{result.stderr[-2000:]}"
        )
    return result
