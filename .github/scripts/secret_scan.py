#!/usr/bin/env python3
"""Scan for credentials that should never reach the repository.

Two modes:

  diff  Scan only the lines ADDED between BASE_SHA and HEAD_SHA. Used on pull
        requests, where only the contribution itself is in scope.
  tree  Scan every tracked file in the working tree. Used on a schedule and on
        pushes to the default branch, so that anything merged before this check
        existed -- or pushed directly, bypassing pull requests -- is still found.

Exit codes: 0 clean, 1 findings, 2 usage/environment error.

This script is a safety net, not the primary control. GitHub's native secret
scanning with push protection blocks a leak at push time and validates
candidates against the issuing provider; enable it on every repository. See
TEMPLATE.md for the required repository settings.

Suppressing a false positive
----------------------------
Add a `pragma: allowlist secret` comment to the offending line. It is explicit,
greppable, and shows up in review -- unlike matching on words that happen to
appear in the line.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass

# --------------------------------------------------------------------------
# Detection rules
# --------------------------------------------------------------------------
# Each rule carries a `heuristic` flag. High-confidence rules match a documented
# credential format and are ALWAYS reported. Heuristic rules guess from shape
# alone, produce most of the noise, and are suppressed inside allowlisted paths
# (tests, fixtures, docs) where fake credentials are legitimate.


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    heuristic: bool = False


RULES: list[Rule] = [
    Rule(
        "AWS Access Key ID",
        re.compile(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
    ),
    Rule("AWS Secret Access Key", re.compile(r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]")),
    Rule("GitHub Token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}\b")),
    Rule("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")),
    Rule("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Rule(
        "Slack Webhook",
        re.compile(
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"
        ),
    ),
    Rule("Stripe API Key", re.compile(r"\b(sk|rk)_(test|live)_[A-Za-z0-9]{20,}\b")),
    Rule("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    Rule("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b")),
    Rule("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    Rule("npm Token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    Rule("OpenAI API Key", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    Rule("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    Rule(
        "Private Key Block",
        re.compile(
            r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----"
        ),
    ),
    Rule(
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b"),
    ),
    Rule(
        "Heroku API Key",
        re.compile(
            r"(?i)heroku.{0,20}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
        ),
    ),
    Rule("Password in URL", re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@[^\s]+")),
    Rule(
        "Generic API Key/Secret assignment",
        re.compile(
            r"(?i)[\w.-]*(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|"
            r"secret[_-]?key|private[_-]?key|password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"
        ),
        heuristic=True,
    ),
]

# Explicit, auditable per-line suppression.
PRAGMA = re.compile(r"(?i)pragma:\s*allowlist[\s-]secret")

# Paths where fake credentials are expected. Only heuristic rules are relaxed
# here -- a real provider-formatted token in a test fixture is still a leak.
# Covers both test DIRECTORIES and the common test FILE naming conventions,
# since plenty of projects keep tests beside the code they exercise.
HEURISTIC_EXEMPT_PATHS = re.compile(
    r"(?i)"
    r"(^|/)(tests?|__tests__|spec|fixtures?|testdata|examples?|docs?)(/|$)"
    r"|(^|/)(test_[^/]+|[^/]+_test|conftest)\.(py|go|rb|js|ts|rs|java)$"
    r"|[^/]+\.(test|spec)\.(js|jsx|ts|tsx)$"
    r"|\.(md|rst|txt|lock)$"
)

# Literal values published in vendor documentation. These are not secrets and
# defeat word-boundary matching (there is no boundary inside AKIAIOSFODNN7EXAMPLE).
KNOWN_DUMMY_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAIOSFODNN7EXAMPLF",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
}

# Placeholder shapes appearing INSIDE the matched value -- ${VAR}, {{ var }},
# <your-token>, xxxx, ****, or an obvious stand-in word delimited by separators.
PLACEHOLDER_IN_MATCH = re.compile(
    r"\$\{[^}]*\}|\{\{[^}]*\}\}|<[^>]{2,}>|x{6,}|\*{4,}|\.{3,}"
    r"|(^|[^A-Za-z0-9])(changeme|placeholder|redacted|your[_-]?\w+|dummy|sample)([^A-Za-z0-9]|$)",
    re.IGNORECASE,
)

# Entropy heuristic. Note the ceiling: Shannon entropy of a hex string maxes out
# at 4.0 bits/char, so a hex-encoded secret can NEVER trip a 4.5 threshold. Hex
# credentials are covered by the named rules above and nothing else -- do not
# assume the entropy check provides a backstop for them.
ENTROPY_THRESHOLD = 4.5
ENTROPY_MIN_LENGTH = 32
# Quoted values, and bare `KEY=value` assignments as found in .env / YAML /
# Dockerfiles, which the previous quoted-only candidate regex missed entirely.
ENTROPY_CANDIDATES = [
    re.compile(r"['\"]([A-Za-z0-9+/=\-_]{32,})['\"]"),
    re.compile(r"(?:^|[\s;])[\w.-]{2,}\s*[:=]\s*([A-Za-z0-9+/=\-_]{32,})(?=$|[\s;,])"),
]

# Diff parsing. Require the `b/` or `/dev/null` suffix so that an added line
# whose own content starts with `++` is not mistaken for a file header.
DIFF_FILE_HEADER = re.compile(r"^\+\+\+ (?:b/(.*)|/dev/null)$")
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

MAX_FILE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    path: str
    line_no: int
    kind: str
    masked_line: str


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for ch in set(data):
        p = data.count(ch) / len(data)
        entropy -= p * math.log2(p)
    return entropy


def mask(secret: str) -> str:
    """Replace a secret with a non-recoverable stand-in.

    CI logs on a public repository are world-readable. Printing the matched text
    would republish the very credential this check exists to catch, so only a
    short provider-identifying prefix survives.
    """
    prefix = secret[:4] if len(secret) > 12 else ""
    return f"{prefix}{'*' * 8}[{len(secret)} chars redacted]"


def mask_line(line: str, spans: list[tuple[int, int]], max_len: int = 120) -> str:
    """Blank out every matched span, keeping the rest of the line for context."""
    out = []
    cursor = 0
    for start, end in sorted(spans):
        if start < cursor:  # overlapping matches
            continue
        out.append(line[cursor:start])
        out.append(mask(line[start:end]))
        cursor = end
    out.append(line[cursor:])
    masked = "".join(out).strip()
    return masked if len(masked) <= max_len else masked[:max_len] + "..."


def scan_line(path: str, line: str) -> tuple[list[str], list[tuple[int, int]]]:
    """Return (rule names that fired, spans to mask) for a single line."""
    if PRAGMA.search(line):
        return [], []

    relax_heuristics = bool(HEURISTIC_EXEMPT_PATHS.search(path))
    kinds: list[str] = []
    spans: list[tuple[int, int]] = []

    for rule in RULES:
        if rule.heuristic and relax_heuristics:
            continue
        for match in rule.pattern.finditer(line):
            value = match.group(0)
            # Allowlisting is applied to the MATCHED VALUE, never to the whole
            # line. Testing the line meant an unrelated word ("latest", "protest")
            # could suppress a genuine credential sitting next to it.
            if value in KNOWN_DUMMY_VALUES or PLACEHOLDER_IN_MATCH.search(value):
                continue
            kinds.append(rule.name)
            spans.append(match.span())

    if not kinds and not relax_heuristics:
        for candidate_re in ENTROPY_CANDIDATES:
            for match in candidate_re.finditer(line):
                value = match.group(1)
                if len(value) < ENTROPY_MIN_LENGTH:
                    continue
                if value in KNOWN_DUMMY_VALUES or PLACEHOLDER_IN_MATCH.search(value):
                    continue
                if shannon_entropy(value) >= ENTROPY_THRESHOLD:
                    kinds.append("High-entropy string")
                    spans.append(match.span(1))
                    break
            if kinds:
                break

    return kinds, spans


def record(path: str, line_no: int, line: str) -> list[Finding]:
    kinds, spans = scan_line(path, line)
    if not kinds:
        return []
    masked = mask_line(line, spans)
    # De-duplicate rule names while preserving order.
    seen: list[str] = []
    for kind in kinds:
        if kind not in seen:
            seen.append(kind)
    return [Finding(path, line_no, ", ".join(seen), masked)]


# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------


def run_git(args: list[str]) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    return result.stdout


def scan_diff(diff_text: str) -> list[Finding]:
    findings: list[Finding] = []
    current_file: str | None = None
    line_number = 0

    for raw_line in diff_text.splitlines():
        header = DIFF_FILE_HEADER.match(raw_line)
        if header:
            current_file = header.group(1)  # None for /dev/null (deletion)
            continue

        hunk = HUNK_HEADER.match(raw_line)
        if hunk:
            line_number = int(hunk.group(1)) - 1
            continue

        if not raw_line.startswith("+"):
            continue

        line_number += 1
        if current_file is None:
            continue
        findings.extend(record(current_file, line_number, raw_line[1:]))

    return findings


def scan_tree() -> list[Finding]:
    findings: list[Finding] = []
    for path in run_git(["ls-files", "-z"]).split("\0"):
        if not path:
            continue
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, encoding="utf-8") as handle:
                for line_no, line in enumerate(handle, start=1):
                    findings.extend(record(path, line_no, line.rstrip("\n")))
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable
    return findings


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def report(findings: list[Finding], mode: str) -> None:
    print(f"Found {len(findings)} potential secret(s):\n")
    for finding in findings:
        print(f"  {finding.path}:{finding.line_no} [{finding.kind}] {finding.masked_line}")
        print(
            f"::error file={finding.path},line={finding.line_no}::"
            f"Potential secret detected ({finding.kind}). Remove it and rotate the "
            f"credential if it was ever real."
        )

    print(
        "\nIf a finding is a false positive, add a `pragma: allowlist secret` "
        "comment to that line so the exemption is visible in review."
    )

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = [
        f"## :rotating_light: {len(findings)} potential secret(s) found ({mode} scan)",
        "",
        "| File | Line | Kind |",
        "| --- | --- | --- |",
    ]
    lines += [f"| `{f.path}` | {f.line_no} | {f.kind} |" for f in findings]
    lines += [
        "",
        (
            "Matched values are redacted here on purpose. Remove the credential "
            "and **rotate it** -- assume anything committed is compromised."
        ),
    ]
    try:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("diff", "tree"), default="diff")
    parser.add_argument("--base", default=os.environ.get("BASE_SHA"))
    parser.add_argument("--head", default=os.environ.get("HEAD_SHA"))
    args = parser.parse_args(argv)

    if args.mode == "diff":
        if not args.base or not args.head:
            print("::error::BASE_SHA and HEAD_SHA are required for --mode diff")
            return 2
        diff_text = run_git(["diff", f"{args.base}...{args.head}", "--unified=0", "--no-color"])
        findings = scan_diff(diff_text)
    else:
        findings = scan_tree()

    if not findings:
        print(f"No potential secrets found ({args.mode} scan).")
        return 0

    report(findings, args.mode)
    return 1


if __name__ == "__main__":
    sys.exit(main())
