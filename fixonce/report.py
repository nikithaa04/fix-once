"""Markdown report, used as the pull request body."""
from __future__ import annotations

from .learn import Result


def render(result: Result, source: str = "") -> str:
    lines = ["## fix-once report", ""]
    if source:
        lines += [f"Learned from: {source}", ""]
    if not result.ok:
        lines += [f"**No rule was added.** {result.reason}", ""]
        if result.attempts:
            lines += ["Attempts:"] + [f"- Attempt {a.number}: {a.feedback.splitlines()[0]}"
                                      for a in result.attempts] + [""]
        return "\n".join(lines)
    lines += [f"**Bug class:** {result.bug_class}", "", f"**Root cause:** {result.root_cause}", "",
              f"**New rule:** `{result.rule_path}` (passed on attempt {len(result.attempts)} of testing: "
              "it matches the pre-fix code and does not match the fixed code)", ""]
    if result.variants:
        lines += [f"### {len(result.variants)} possible variant(s) elsewhere in the repo", "",
                  "These match the same pattern and were not touched by the fix. Review each one.", ""]
        for m in result.variants[:50]:
            lines.append(f"- `{m.path}:{m.start}`" + (f"  `{m.code.splitlines()[0][:120]}`" if m.code else ""))
        if len(result.variants) > 50:
            lines.append(f"- ... and {len(result.variants) - 50} more")
        lines.append("")
    else:
        lines += ["### No variants found", "", "The pattern does not appear anywhere else right now. "
                  "The rule will still flag it if it is reintroduced.", ""]
    if result.unparsed:
        lines += [f"### {len(result.unparsed)} file(s) could not be checked", "",
                  "Semgrep could not parse these, so the rule did not run on them. They are not "
                  "known to be clean.", ""]
        lines += [f"- `{p}`" for p in result.unparsed[:30]]
        if len(result.unparsed) > 30:
            lines.append(f"- ... and {len(result.unparsed) - 30} more")
        lines.append("")
    lines += ["<details><summary>Rule</summary>", "", "```yaml", result.rule_yaml.rstrip(), "```", "",
              "</details>", ""]
    return "\n".join(lines)
