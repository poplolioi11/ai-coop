#!/usr/bin/env python3
"""Gate Gemini worker tools before execution using the native hook contract."""

import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import socket
import sys
import threading
import time
from urllib.parse import urlsplit

from coop_config import GEMINI_SETTINGS, RUNTIME_ROOT


MAX_INPUT_BYTES = 1048576
SETTINGS = GEMINI_SETTINGS
AUDIT = RUNTIME_ROOT / "gemini_tool_guard.audit.ndjson"
JOBS = RUNTIME_ROOT / "jobs"


def current_job_id():
    value = os.environ.get("AI_COOP_JOB_ID", "")
    pattern = r"[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}"
    if re.fullmatch(pattern, value):
        return value
    try:
        relative = Path.cwd().resolve().relative_to(JOBS.resolve())
        if len(relative.parts) >= 2 and relative.parts[1] == "workspace" and re.fullmatch(pattern, relative.parts[0]):
            return relative.parts[0]
    except (OSError, ValueError):
        pass
    return None


def public_domain(value):
    if not isinstance(value, str):
        return None
    try:
        domain = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except (ValueError, UnicodeError):
        return None
    if len(domain) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", domain):
        return None
    if "." not in domain or any(not x or len(x) > 63 or x.startswith("-") or x.endswith("-") for x in domain.split(".")):
        return None
    if domain.endswith((".local", ".localhost", ".internal", ".test", ".invalid", ".lan", ".home", ".localdomain", ".onion", ".arpa")):
        return None
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    return None


def approved_domains():
    try:
        if SETTINGS.is_symlink() or SETTINGS.stat().st_size > MAX_INPUT_BYTES:
            return frozenset()
        settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
        rules = settings.get("permissions", {}).get("allow", [])
        if not isinstance(rules, list):
            return frozenset()
        domains = set()
        for rule in rules:
            if not isinstance(rule, str):
                continue
            match = re.fullmatch(r"read_url\(([^()]+)\)", rule)
            domain = public_domain(match.group(1)) if match else None
            if domain:
                domains.add(domain)
        return frozenset(domains)
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError):
        return frozenset()


def resolves_publicly(host):
    outcomes = queue.Queue(maxsize=1)

    def resolve():
        try:
            addresses = {row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
            outcomes.put(bool(addresses) and all(ipaddress.ip_address(value).is_global for value in addresses))
        except (OSError, ValueError):
            outcomes.put(False)

    threading.Thread(target=resolve, daemon=True).start()
    try:
        return outcomes.get(timeout=2)
    except queue.Empty:
        return False


def evaluate(mode, payload):
    decision = {"decision": "deny", "reason": "The shared AI worker denies this tool before execution."}
    if mode not in ("analyze", "research") or not isinstance(payload, dict):
        return decision
    call = payload.get("toolCall")
    if not isinstance(call, dict):
        return decision
    name = call.get("name")
    args = call.get("args")
    if not isinstance(name, str) or not isinstance(args, dict):
        return decision
    if mode == "analyze":
        decision["reason"] = "Analysis workers use supplied text only; all native tool calls are denied."
        return decision
    if name == "search_web":
        query = args.get("query")
        if isinstance(query, str) and query.strip() and len(query) <= 10000:
            return {"decision": "allow", "reason": "Public web search is permitted for this research worker."}
        decision["reason"] = "A research search requires a nonempty query within the allowed size."
        return decision
    if name != "read_url_content":
        return decision
    url = args.get("Url")
    if not isinstance(url, str) or len(url) > 10000 or any(ord(c) < 32 for c in url):
        return decision
    try:
        parsed = urlsplit(url)
        host = public_domain(parsed.hostname or "")
        valid_port = parsed.port in (None, 443)
    except (ValueError, UnicodeError):
        return decision
    host_allowed = bool(host) and any(host == allowed or host.endswith("." + allowed) for allowed in approved_domains())
    if parsed.scheme.lower() == "https" and valid_port and not parsed.username and not parsed.password and host_allowed and resolves_publicly(host):
        return {"decision": "allow", "reason": "Reading this authorized public source is permitted."}
    decision["reason"] = "The source URL must use HTTPS on an explicitly authorized public source host."
    return decision


def record(mode, payload, result):
    call = payload.get("toolCall", {}) if isinstance(payload, dict) else {}
    name = call.get("name") if isinstance(call, dict) else None
    conversation = payload.get("conversationId") if isinstance(payload, dict) else None
    job_id = current_job_id()
    entry = {
        "epoch": time.time(),
        "job_id": job_id,
        "mode": mode,
        "conversation_id": conversation[:128] if isinstance(conversation, str) else None,
        "tool": name[:256] if isinstance(name, str) else None,
        "decision": result["decision"],
    }
    try:
        audit = JOBS / job_id / "hook-audit.ndjson" if job_id else AUDIT
        if audit.parent.is_symlink() or not audit.parent.is_dir() or (job_id and JOBS.is_symlink()):
            raise OSError("Invalid job audit directory")
        fd = os.open(str(audit), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        result = {"decision": "deny", "reason": "The tool guard could not record its enforcement decision."}
    return result


def main():
    payload = None
    mode = sys.argv[2] if len(sys.argv) == 3 and sys.argv[1] == "--mode" else None
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) <= MAX_INPUT_BYTES:
            payload = json.loads(raw)
    except (ValueError, UnicodeError, OSError):
        pass
    result = record(mode, payload, evaluate(mode, payload))
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
