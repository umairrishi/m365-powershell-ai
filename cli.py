"""Command-line interface for m365ai.

    m365ai generate "Block external chat for contractors in Teams" -o block.ps1
    m365ai check block.ps1 --fail-on high
    m365ai explain block.ps1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from . import __version__
from .prompts import EXPLAIN_SYSTEM, GENERATE_SYSTEM
from .providers import ProviderError, get_provider
from .safety import SEVERITY_ORDER, Report, scan

# --- Terminal colors -------------------------------------------------------

_COLORS = {"high": "31", "medium": "33", "low": "36", "info": "90", "ok": "32", "bold": "1"}


def _use_color(stream) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def _c(text: str, color: str, stream=sys.stdout) -> str:
    if not _use_color(stream):
        return text
    return f"\033[{_COLORS[color]}m{text}\033[0m"


# --- Helpers ---------------------------------------------------------------

def extract_powershell(text: str) -> str:
    """Pull the PowerShell code block out of a model reply."""
    match = re.search(r"```(?:powershell|ps1|pwsh)?\s*\n(.*?)```", text, re.S | re.I)
    return (match.group(1) if match else text).strip() + "\n"


def format_report(report: Report, title: str = "Safety report") -> str:
    lines = [_c(f"== {title} ==", "bold")]
    risk = report.risk
    risk_color = {"high": "high", "medium": "medium"}.get(risk, "ok")
    lines.append(f"Overall risk: {_c(risk.upper(), risk_color)}")
    if report.modules:
        lines.append(f"Modules:      {', '.join(report.modules)}")
    if report.graph_scopes:
        lines.append(f"Graph scopes: {', '.join(report.graph_scopes)}")
    if not report.findings:
        lines.append(_c("No issues found.", "ok"))
        return "\n".join(lines)
    lines.append("")
    for f in report.findings:
        tag = _c(f"[{f.severity.upper():6}]", f.severity)
        lines.append(f"{tag} {f.rule_id} line {f.line}: {f.message}")
        lines.append(f"         > {f.code[:110]}")
        lines.append(f"         fix: {f.advice}")
    summary = ", ".join(
        f"{report.count(s)} {s}" for s in ("high", "medium", "low", "info") if report.count(s)
    )
    lines.append("")
    lines.append(f"Findings: {summary}")
    return "\n".join(lines)


def _read_script(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    return p.read_text(encoding="utf-8-sig")


# --- Commands --------------------------------------------------------------

def cmd_generate(args) -> int:
    provider = get_provider(args.provider, args.model)
    print(_c(f"Asking {provider.name} to write the script...", "info", sys.stderr), file=sys.stderr)
    reply = provider.complete(GENERATE_SYSTEM, args.task)
    script = extract_powershell(reply)
    report = scan(script)

    if args.output:
        Path(args.output).write_text(script, encoding="utf-8")
        print(f"Saved script to {args.output}")
    else:
        print(script)

    print(format_report(report))
    if report.risk == "high":
        print(_c("\nHIGH RISK: review every flagged line and run with -WhatIf before using this.", "high"))
    return 0


def cmd_check(args) -> int:
    exit_code = 0
    results = {}
    for path in args.files:
        report = scan(_read_script(path))
        results[path] = report
        if args.fail_on and report.at_or_above(args.fail_on):
            exit_code = 2

    if args.json:
        print(json.dumps({p: r.to_dict() for p, r in results.items()}, indent=2))
    else:
        for i, (path, report) in enumerate(results.items()):
            if i:
                print()
            print(format_report(report, title=path))
    return exit_code


def cmd_explain(args) -> int:
    script = _read_script(args.file)
    provider = get_provider(args.provider, args.model)
    print(_c(f"Asking {provider.name} to explain the script...", "info", sys.stderr), file=sys.stderr)
    print(provider.complete(EXPLAIN_SYSTEM, f"```powershell\n{script}\n```"))
    print()
    print(format_report(scan(script)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365ai",
        description="AI assistant for Microsoft 365 admins: write, explain and safety-check PowerShell.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    ai_opts = argparse.ArgumentParser(add_help=False)
    ai_opts.add_argument("--provider", choices=["anthropic", "openai", "azure"],
                         help="AI provider (default: whichever API key is set)")
    ai_opts.add_argument("--model", help="Model or Azure deployment name")

    g = sub.add_parser("generate", parents=[ai_opts],
                       help="Describe a task in plain English and get a PowerShell script")
    g.add_argument("task", help='e.g. "Find Teams users without a phone number assigned"')
    g.add_argument("-o", "--output", help="Save the script to this file")
    g.set_defaults(func=cmd_generate)

    c = sub.add_parser("check", help="Safety-check PowerShell scripts (offline, no AI needed)")
    c.add_argument("files", nargs="+", help="Script file(s), or - for stdin")
    c.add_argument("--fail-on", choices=[s for s in SEVERITY_ORDER if s != "info"],
                   help="Exit with code 2 if any finding is at or above this level (for CI)")
    c.add_argument("--json", action="store_true", help="Print results as JSON")
    c.set_defaults(func=cmd_check)

    e = sub.add_parser("explain", parents=[ai_opts], help="Explain a script in plain English")
    e.add_argument("file", help="Script file, or - for stdin")
    e.set_defaults(func=cmd_explain)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ProviderError, FileNotFoundError) as exc:
        print(_c(f"Error: {exc}", "high", sys.stderr), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
