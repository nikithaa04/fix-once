"""Read a fix commit: which files changed, what they looked like before and after."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

SKIP_DIRS = {"node_modules", "vendor", "dist", "build", "test", "tests", "__tests__", ".fixonce"}
SKIP_NAMES = {"package-lock.json", "yarn.lock", "poetry.lock", "pnpm-lock.yaml", "go.sum"}
SKIP_SUFFIXES = (".md", ".lock", ".min.js", ".min.css", ".snap")
SKIP_INFIXES = (".spec.", ".test.")


def is_skipped(path: str) -> bool:
    """Skip tests, docs, lockfiles and vendored code: the bug lives in source files."""
    parts = path.split("/")
    name = parts[-1]
    return (any(p in SKIP_DIRS for p in parts[:-1]) or name in SKIP_NAMES
            or name.endswith(SKIP_SUFFIXES) or name.startswith("test_")
            or any(x in name for x in SKIP_INFIXES))


MAX_FILE_BYTES = 60_000
MAX_FILES = 5
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.M)


@dataclass
class ChangedFile:
    path: str
    before: str
    after: str
    diff: str
    old_ranges: list[tuple[int, int]] = field(default_factory=list)  # lines touched, pre-fix
    new_ranges: list[tuple[int, int]] = field(default_factory=list)  # lines touched, post-fix


def git(repo: str, *args: str) -> str:
    out = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout


def parse_ranges(diff_u0: str) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Line ranges touched on each side. A pure insertion or deletion has length 0 on
    one side, so it is recorded as the single line where the change sits."""
    old, new = [], []
    for a, b, c, d in HUNK_RE.findall(diff_u0):
        a, c = int(a), int(c)
        b = int(b) if b != "" else 1
        d = int(d) if d != "" else 1
        old.append((a, a + b - 1) if b else (max(a, 1), max(a, 1) + 1))
        new.append((c, c + d - 1) if d else (max(c, 1), max(c, 1) + 1))
    return old, new


def changed_files(repo: str, base: str, head: str) -> list[ChangedFile]:
    names = git(repo, "diff", "--name-only", "--diff-filter=M", base, head).splitlines()
    files: list[ChangedFile] = []
    for path in names:
        if is_skipped(path):
            continue
        try:
            before = git(repo, "show", f"{base}:{path}")
            after = git(repo, "show", f"{head}:{path}")
        except (RuntimeError, UnicodeDecodeError):
            continue
        if max(len(before), len(after)) > MAX_FILE_BYTES:
            continue
        diff = git(repo, "diff", "-U8", base, head, "--", path)
        old, new = parse_ranges(git(repo, "diff", "-U0", base, head, "--", path))
        files.append(ChangedFile(path, before, after, diff, old, new))
        if len(files) >= MAX_FILES:
            break
    return files
