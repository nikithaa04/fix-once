from __future__ import annotations

import argparse
import os
import sys

from .learn import learn
from .llm import anthropic_complete
from .report import render


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fixonce")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("learn", help="turn a fix commit into a tested Semgrep rule")
    p.add_argument("--base", required=True, help="commit before the fix (e.g. <sha>^)")
    p.add_argument("--head", required=True, help="commit with the fix")
    p.add_argument("--repo", default=".")
    p.add_argument("--source", default="", help="link to the PR or incident, stored in the rule")
    p.add_argument("--rules-dir", default=".fixonce/rules")
    p.add_argument("--report", default="", help="write the markdown report to this file")
    p.add_argument("--model", default=None)
    p.add_argument("--max-attempts", type=int, default=3)
    args = parser.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        return 2
    result = learn(args.repo, args.base, args.head, anthropic_complete(args.model),
                   source=args.source, rules_dir=args.rules_dir, max_attempts=args.max_attempts)
    report = render(result, args.source)
    print(report)
    if args.report:
        with open(args.report, "w") as fh:
            fh.write(report)
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as fh:
            fh.write(f"rule-added={'true' if result.ok else 'false'}\n")
            fh.write(f"rule-path={result.rule_path}\n")
            fh.write(f"variants={len(result.variants)}\n")
    return 0  # "no rule" is a normal outcome, not a CI failure


if __name__ == "__main__":
    sys.exit(main())
