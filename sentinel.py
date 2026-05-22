#!/usr/bin/env python3
"""Scan agent-ready repositories for leaked secrets and risky MCP config."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
}

TEXT_EXTENSIONS = {
    "",
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".js",
    ".jsx",
    ".md",
    ".mjs",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    advice: str


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    path: str
    line: int
    snippet: str
    advice: str


RULES = [
    Rule(
        "secret.github_pat",
        "GitHub fine-grained token",
        "critical",
        re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
        "Revoke the token, rotate it, and move the replacement to a local secret store.",
    ),
    Rule(
        "secret.github_classic",
        "GitHub classic token",
        "critical",
        re.compile(r"ghp_[A-Za-z0-9]{30,}"),
        "Revoke the token and replace it with a fine-grained token scoped to the minimum repos.",
    ),
    Rule(
        "secret.openai",
        "OpenAI API key",
        "critical",
        re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
        "Rotate the key and load it from an environment variable or secret manager.",
    ),
    Rule(
        "secret.generic_assignment",
        "Likely secret assignment",
        "high",
        re.compile(
            r"(?i)\b(api[_-]?key|token|secret|password|private[_-]?key)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{16,}"
        ),
        "Move this value out of source control and commit only an example placeholder.",
    ),
    Rule(
        "mcp.shell_eval",
        "MCP server runs shell evaluator",
        "high",
        re.compile(r"(?i)\b(bash|sh|zsh|powershell|cmd)\b\s+-c"),
        "Avoid shell string evaluators in MCP server config; use fixed command arguments.",
    ),
    Rule(
        "mcp.network_pipe",
        "Network download piped to shell",
        "critical",
        re.compile(r"(?i)\b(curl|wget)\b.+\|\s*(bash|sh|zsh)"),  # sentinel: allow
        "Never pipe remote scripts into a shell from agent-accessible config.",
    ),
    Rule(
        "mcp.write_home",
        "Agent config references broad home directory",
        "medium",
        re.compile(r"(?i)(/Users/[^/]+|~)(/|\")"),  # sentinel: allow
        "Prefer project-scoped paths over broad home-directory access.",
    ),
]


def is_probably_text(path: Path) -> bool:
    if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {".env", ".gitignore"}:
        return False
    try:
        chunk = path.read_bytes()[:2048]
    except OSError:
        return False
    return b"\0" not in chunk


def iter_files(root: Path) -> Iterable[Path]:
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in DEFAULT_IGNORE_DIRS]
        for filename in filenames:
            path = Path(current_root) / filename
            if is_probably_text(path):
                yield path


def redact(snippet: str) -> str:
    snippet = snippet.strip()
    snippet = re.sub(r"(github_pat_)[A-Za-z0-9_]{8,}", r"\1...redacted", snippet)
    snippet = re.sub(r"(ghp_)[A-Za-z0-9]{8,}", r"\1...redacted", snippet)
    snippet = re.sub(r"(sk-)[A-Za-z0-9_-]{8,}", r"\1...redacted", snippet)
    snippet = re.sub(
        r"(?i)(api[_-]?key|token|secret|password)(\s*[:=]\s*['\"]?)[^'\"\s]+",
        r"\1\2...redacted",
        snippet,
    )
    return snippet[:180]


def scan_file(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    relpath = str(path.relative_to(root))
    for index, line in enumerate(lines, start=1):
        if "sentinel: allow" in line:
            continue
        for rule in RULES:
            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        rule.rule_id,
                        rule.title,
                        rule.severity,
                        relpath,
                        index,
                        redact(line),
                        rule.advice,
                    )
                )
    return findings


def scan(root: Path) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    for path in iter_files(root):
        findings.extend(scan_file(path, root))
    return sorted(findings, key=lambda item: (severity_rank(item.severity), item.path, item.line))


def severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity, 9)


def print_text(findings: list[Finding]) -> None:
    if not findings:
        print("No obvious agent secrets or risky MCP config found.")
        return

    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.title}")
        print(f"  {finding.path}:{finding.line}")
        print(f"  {finding.snippet}")
        print(f"  fix: {finding.advice}")


def print_json(findings: list[Finding]) -> None:
    print(json.dumps([finding.__dict__ for finding in findings], indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Scan agent-ready repositories for leaked secrets and risky MCP config.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a repository or project directory")
    scan_parser.add_argument("path", nargs="?", default=".", help="directory to scan")
    scan_parser.add_argument("--json", action="store_true", help="print machine-readable findings")
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="exit non-zero when this severity or worse is found",
    )

    args = parser.parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"Path does not exist: {root}", file=sys.stderr)
        return 2

    findings = scan(root)
    if args.json:
        print_json(findings)
    else:
        print_text(findings)

    threshold = severity_rank(args.fail_on)
    if any(severity_rank(finding.severity) <= threshold for finding in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
