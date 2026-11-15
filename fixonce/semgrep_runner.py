"""Thin wrapper around the Semgrep CLI."""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass


@dataclass
class Match:
    path: str
    start: int
    end: int
    code: str


def _env() -> dict:
    env = dict(os.environ)
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    env["SEMGREP_SEND_METRICS"] = "off"
    return env


def validate(rule_path: str) -> str | None:
    """Return None if Semgrep accepts the rule file, else the error text."""
    out = subprocess.run(["semgrep", "scan", "--validate", "--metrics", "off", "--config", rule_path],
                         capture_output=True, text=True, env=_env())
    if out.returncode == 0:
        return None
    return (out.stderr or out.stdout).strip()[-1500:]


def scan(rule_path: str, target: str, unparsed: list[str] | None = None) -> list[Match]:
    """Run the rule. Files Semgrep could not parse are appended to `unparsed`, because a file
    that was not parsed was not checked, and that must not read as "clean"."""
    out = subprocess.run(
        ["semgrep", "scan", "--config", rule_path, "--json", "--metrics", "off", "--quiet",
         "--no-git-ignore", "--exclude", ".fixonce", target],
        capture_output=True, text=True, env=_env(), cwd=target)
    if out.returncode not in (0, 1):
        raise RuntimeError(f"semgrep scan failed: {(out.stderr or out.stdout)[-1500:]}")
    data = json.loads(out.stdout or "{}")
    if unparsed is not None:
        seen = {os.path.relpath(os.path.join(target, e["path"]), target)
                for e in data.get("errors", []) if e.get("path")}
        unparsed.extend(sorted(seen))
    matches = []
    for r in data.get("results", []):
        path = os.path.relpath(os.path.join(target, r["path"]), target)
        start, end = r["start"]["line"], r["end"]["line"]
        matches.append(Match(path, start, end, _read_lines(os.path.join(target, path), start, end)))
    return matches


def _read_lines(file_path: str, start: int, end: int) -> str:
    """Read the matched lines from disk (the CLI hides them unless you are logged in)."""
    try:
        with open(file_path, errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return ""
    return "\n".join(line.strip() for line in lines[start - 1:end])
