#!/usr/bin/env python3
"""Explicitly authorize one public source domain in an existing local config.

This helper is never run by setup or task submission. Backups stay in the
private runtime directory and must not be distributed with the source code.
"""
import argparse
import datetime
import fcntl
import json
import os
import uuid

from coop_config import GEMINI_SETTINGS, RUNTIME_ROOT
from gemini_tool_guard import public_domain as normalize_domain, resolves_publicly

ROOT = RUNTIME_ROOT
CONFIG = GEMINI_SETTINGS
MAX_SETTINGS_BYTES = 1024 * 1024


def public_domain(value):
    domain = normalize_domain(value)
    if domain is None:
        raise ValueError('Provide one public hostname without a scheme, path, port, wildcard or IP address.')
    if not resolves_publicly(domain):
        raise ValueError('Source hostname does not resolve exclusively to public addresses.')
    return domain


def _private_directory(path):
    if path.is_symlink():
        raise ValueError('A local runtime directory must not be a symbolic link.')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise ValueError('A local runtime directory is unavailable.')
    path.chmod(0o700)


def _exclusive_bytes(path, content):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def add(value):
    domain = public_domain(value)
    _private_directory(ROOT)
    lock_path = ROOT / 'domain-settings.lock'
    lock_fd = os.open(str(lock_path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'a') as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        if CONFIG.is_symlink() or not CONFIG.is_file() or CONFIG.stat().st_size > MAX_SETTINGS_BYTES:
            raise ValueError('An existing regular settings file is required; this helper does not create one.')
        original = CONFIG.read_bytes()
        data = json.loads(original)
        if not isinstance(data, dict):
            raise ValueError('Settings must contain a JSON object.')
        permissions = data.setdefault('permissions', {})
        if not isinstance(permissions, dict):
            raise ValueError('Settings permissions must be a JSON object.')
        deny = permissions.get('deny', [])
        allow = permissions.setdefault('allow', [])
        if any(not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules) for rules in (deny, allow)):
            raise ValueError('Settings permission rules must be lists of strings.')
        if 'read_url(*)' in deny or '*' in deny:
            raise ValueError('A wildcard deny is active; inspect the configuration rather than bypassing it.')
        rule = 'read_url(' + domain + ')'
        if rule in allow:
            return {'allowed_domain': domain, 'rule': rule, 'changed': False}
        allow.append(rule)
        updated = (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
        backup_dir = ROOT / 'backups'
        _private_directory(backup_dir)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup = backup_dir / ('gemini-domain-' + stamp + '-' + uuid.uuid4().hex + '.json')
        _exclusive_bytes(backup, original)
        temporary = CONFIG.with_name(CONFIG.name + '.ai-coop-' + uuid.uuid4().hex + '.tmp')
        try:
            _exclusive_bytes(temporary, updated)
            if CONFIG.is_symlink() or CONFIG.read_bytes() != original:
                raise ValueError('Settings changed during this update; no configuration was replaced.')
            os.replace(str(temporary), str(CONFIG))
        finally:
            temporary.unlink(missing_ok=True)
        return {'allowed_domain': domain, 'rule': rule, 'changed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['add'])
    parser.add_argument('hostname')
    args = parser.parse_args()
    try:
        print(json.dumps(add(args.hostname), ensure_ascii=False))
    except Exception as error:
        message = str(error) if isinstance(error, ValueError) else 'Could not verify or update the source hostname.'
        print(json.dumps({'error': message}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
