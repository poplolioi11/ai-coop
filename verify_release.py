#!/usr/bin/env python3
"""Offline, fail-closed checks for the explicitly approved public source set.

This checks the working copy, not Git history or files outside the supplied root.
Findings contain only a file name, a line number and a rule identifier. Never add
matched text to a finding: the rejected text could itself be a credential.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


PUBLIC_FILES = frozenset({
    "bridge.py", "server.py", "local_qwen.py", "gemini_tool_guard.py",
    "configure_domains.py", "coop_config.py", "setup_gemini.py",
    "verify_release.py", "README.md", "LICENSE", "PROVENANCE.md", "SECURITY.md",
    "CONTRIBUTING.md", ".gitignore", "CHANGELOG.md", "SHA256SUMS",
    "skills/ai-coop/SKILL.md", "examples/mcp.json", "examples/task.txt",
    "bin/ai-coop", ".github/workflows/ci.yml", "tests/test_bridge.py",
    "tests/test_mcp.py", "tests/test_local_qwen.py", "tests/test_config.py",
    "tests/test_setup_gemini.py", "tests/test_release.py",
})
HASHED_FILES = PUBLIC_FILES - {"SHA256SUMS"}
PUBLIC_DIRECTORIES = frozenset(
    str(parent)
    for name in PUBLIC_FILES
    for parent in PurePosixPath(name).parents
    if str(parent) != "."
)
MAX_FILE_BYTES = 2 * 1024 * 1024
SYNTHETIC_MARKER = "ai-coop-synthetic-secret"


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str

    def __str__(self) -> str:
        # Escape file-name control characters without ever including file text.
        safe_path = self.path.encode("unicode_escape").decode("ascii")
        return f"{safe_path}:{self.line}: {self.rule}"


# There is deliberately no directory exemption for tests or examples.
CONTENT_RULES = (
    ("personal-home-path", re.compile(r"(?:/Users/|/home/)[A-Za-z0-9._-]+(?:/|\b)|[A-Za-z]:\\{1,2}Users\\{1,2}[^\\\s\"']+")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("provider-token", re.compile(r"\b(?:sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("cloud-access-token", re.compile(r"\b(?:(?:AKIA|ASIA)[A-Z0-9]{16}|glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|ya29\.[A-Za-z0-9_-]{20,})\b")),
    ("secret-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+", re.IGNORECASE)),
    ("bearer-token", re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{20,}", re.IGNORECASE)),
    ("jwt-token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("authenticated-url", re.compile(r"(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^/\s:@]+:[^/@\s]+@", re.IGNORECASE)),
    ("account-price", re.compile(r"(?:[$€£¥]\s*\d+(?:[.,]\d+)?|\b(?:USD|TWD|NTD|CNY|EUR|GBP)\s*\d+|\d+\s*(?:USD|TWD|NTD|CNY|EUR|GBP)\b)", re.IGNORECASE)),
    ("named-subscription-plan", re.compile(r"\b(?:ChatGPT|Claude|Gemini)\s+(?:Plus|Pro|Max|Team|Ultra)\b", re.IGNORECASE)),
    ("private-job-receipt", re.compile(r"\b\d{8}T\d{6}Z-[0-9a-f]{8,}\b", re.IGNORECASE)),
    ("private-session-receipt", re.compile(r"\b(?:session_id|conversation_id|job_id)[\"']?\s*[:=]\s*[\"'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\"']", re.IGNORECASE)),
)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
EXAMPLE_EMAIL_DOMAINS = frozenset({"example.com", "example.org", "example.net", "example.test", "example.invalid"})
CREDENTIAL_ASSIGNMENT = re.compile(
    r"\b(?:[A-Z0-9_]*(?:API_KEY|ACCESS_TOKEN|REFRESH_TOKEN|AUTH_TOKEN|CLIENT_SECRET)|PASSWORD|PASSWD|SECRET_KEY)"
    r"[\"']?\s*[:=]\s*[\"'](?P<value>[^\"'\r\n]+)[\"']",
    re.IGNORECASE,
)
UNQUOTED_CREDENTIAL = re.compile(
    r"\b(?:[A-Z0-9_]*(?:API_KEY|ACCESS_TOKEN|REFRESH_TOKEN|AUTH_TOKEN|CLIENT_SECRET)|PASSWORD|PASSWD|SECRET_KEY)"
    r"\s*=\s*(?P<value>[^\s\"']+)", re.IGNORECASE,
)
SYNTHETIC_VALUE = re.compile(r"(?:DUMMY|SYNTHETIC|EXAMPLE)_[A-Z0-9_]{3,}\Z")
FORBIDDEN_PART = re.compile(
    r"(?:jobs?|runtime|backups?|receipts?|sources?|private|\.env(?:\..*)?|"
    r"auth(?:\.json)?|credentials?(?:\.json)?|oauth_creds\.json|token(?:s)?(?:\.json)?|"
    r"cookies?(?:\.json)?|\.claude|\.codex|\.gemini|\.ssh)\Z", re.IGNORECASE,
)


def scan_text(name: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(content.splitlines(), 1):
        for rule, pattern in CONTENT_RULES:
            if pattern.search(line):
                findings.append(Finding(name, number, rule))
        for match in EMAIL.finditer(line):
            if match.group(1).lower() not in EXAMPLE_EMAIL_DOMAINS:
                findings.append(Finding(name, number, "personal-email"))
        for pattern in (CREDENTIAL_ASSIGNMENT, UNQUOTED_CREDENTIAL):
            for match in pattern.finditer(line):
                value = match.group("value")
                # A narrow, explicit placeholder exception; the token/private-key
                # rules above still apply even to a marked line.
                synthetic = SYNTHETIC_MARKER in line and SYNTHETIC_VALUE.fullmatch(value)
                if not synthetic:
                    findings.append(Finding(name, number, "credential-assignment"))
    return sorted(set(findings))


def _inventory(root: Path) -> tuple[set[str], list[Finding]]:
    approved: set[str] = set()
    findings: list[Finding] = []

    def visit(folder: Path) -> None:
        try:
            entries = sorted(os.scandir(folder), key=lambda item: item.name)
        except OSError:
            findings.append(Finding(folder.relative_to(root).as_posix(), 0, "unreadable-directory"))
            return
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError:
                findings.append(Finding(relative, 0, "unreadable-entry"))
                continue
            if stat.S_ISLNK(mode):
                findings.append(Finding(relative, 0, "symlink"))
                continue
            if stat.S_ISDIR(mode):
                # Only real directories are ignored. Neither is a public file.
                if relative == ".git" or entry.name == "__pycache__":
                    continue
                if relative not in PUBLIC_DIRECTORIES:
                    findings.append(Finding(relative, 0, "unapproved-directory"))
                    if any(FORBIDDEN_PART.fullmatch(part) for part in path.relative_to(root).parts):
                        findings.append(Finding(relative, 0, "private-runtime-or-auth-path"))
                    # Unknown directories cannot contribute public material.
                    continue
                visit(path)
            elif not stat.S_ISREG(mode):
                findings.append(Finding(relative, 0, "non-regular-file"))
            elif relative not in PUBLIC_FILES:
                findings.append(Finding(relative, 0, "unapproved-file"))
                if any(FORBIDDEN_PART.fullmatch(part) for part in path.relative_to(root).parts):
                    findings.append(Finding(relative, 0, "private-runtime-or-auth-path"))
            else:
                approved.add(relative)

    visit(root)
    for missing in sorted(PUBLIC_FILES - approved):
        findings.append(Finding(missing, 0, "missing-public-file"))
    return approved, findings


def inspect_release(root: Path, *, verify_hashes: bool = True) -> list[Finding]:
    root = Path(root)
    if root.is_symlink():
        return [Finding(".", 0, "symlink-root")]
    if not root.is_dir():
        return [Finding(".", 0, "missing-release-directory")]
    approved, findings = _inventory(root)
    data: dict[str, bytes] = {}
    for name in sorted(approved):
        try:
            path = root / name
            if path.stat().st_size > MAX_FILE_BYTES:
                findings.append(Finding(name, 0, "oversized-file"))
                continue
            blob = path.read_bytes()
        except OSError:
            findings.append(Finding(name, 0, "unreadable-file"))
            continue
        data[name] = blob
        try:
            content = blob.decode("utf-8")
        except UnicodeDecodeError:
            findings.append(Finding(name, 0, "binary-or-invalid-utf8"))
            continue
        if any(ord(character) < 32 and character not in "\t\r\n" for character in content):
            findings.append(Finding(name, 0, "binary-control-character"))
        findings.extend(scan_text(name, content))

    if verify_hashes:
        findings.extend(_check_manifest(data))
    return sorted(set(findings))


def _check_manifest(data: dict[str, bytes]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        manifest = data["SHA256SUMS"].decode("utf-8")
    except (KeyError, UnicodeDecodeError):
        return [Finding("SHA256SUMS", 0, "missing-or-invalid-manifest")]
    entries: dict[str, str] = {}
    for number, line in enumerate(manifest.splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if not match:
            findings.append(Finding("SHA256SUMS", number, "invalid-manifest-line"))
            continue
        digest, name = match.groups()
        if name not in HASHED_FILES:
            findings.append(Finding("SHA256SUMS", number, "unapproved-manifest-entry"))
            continue
        if name in entries:
            findings.append(Finding("SHA256SUMS", number, "duplicate-manifest-entry"))
            continue
        entries[name] = digest
    for name in sorted(HASHED_FILES - entries.keys()):
        findings.append(Finding(name, 0, "missing-manifest-entry"))
    for name, digest in entries.items():
        if name not in data:
            findings.append(Finding(name, 0, "missing-hashed-file"))
        elif hashlib.sha256(data[name]).hexdigest() != digest:
            findings.append(Finding(name, 0, "checksum-mismatch"))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args(argv)
    findings = inspect_release(args.root)
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        print(f"Public release verification failed: {len(findings)} finding(s).", file=sys.stderr)
        return 1
    print(f"Public release verified: {len(HASHED_FILES)} checksummed text files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
