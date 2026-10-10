"""Portable local paths shared by the bridge, guards and setup utilities.

Only the explicitly named AI_COOP settings are forwarded to child jobs.
Provider credentials, tokens, proxies and unrelated account settings are never
copied from the controller's environment.
"""
import getpass
import os
from pathlib import Path
import shutil
import sys

SOURCE_ROOT = Path(__file__).resolve().parent
HOME = Path.home()


def _path_setting(name, default):
    value = os.environ.get(name)
    path = Path(value).expanduser() if value else Path(default)
    if not path.is_absolute():
        raise ValueError(name + ' must be an absolute path')
    return path.resolve()


RUNTIME_ROOT = _path_setting('AI_COOP_RUNTIME', HOME / '.local/state/ai-coop')
GEMINI_SETTINGS = _path_setting('AI_COOP_GEMINI_SETTINGS', HOME / '.gemini/antigravity-cli/settings.json')
GEMINI_AGENTS_DIR = _path_setting('AI_COOP_GEMINI_AGENTS', HOME / '.gemini/config/agents')
GUARD_PATH = SOURCE_ROOT / 'gemini_tool_guard.py'
DEFAULT_PATH = os.pathsep.join(('/usr/bin', '/bin', '/usr/sbin', '/sbin',
    '/usr/local/bin', '/opt/homebrew/bin', str(HOME / '.local/bin')))


def child_path():
    """Use an explicitly selected executable search path, not ambient proxies."""
    return os.environ.get('AI_COOP_PATH') or DEFAULT_PATH


def python_path():
    value = os.environ.get('AI_COOP_PYTHON') or sys.executable
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError('AI_COOP_PYTHON must be an absolute path')
    return str(path.resolve())


def binary_path(provider, runtime=None):
    """Resolve an explicit executable or discover an installed official CLI."""
    variable = 'AI_COOP_' + provider.upper() + '_BIN'
    configured = os.environ.get(variable)
    if configured:
        path = Path(configured).expanduser()
        if not path.is_absolute():
            raise ValueError(variable + ' must be an absolute path')
        return str(path.resolve())
    if provider == 'qwen':
        return str(Path(runtime or RUNTIME_ROOT) / 'runtime/ollama/ollama')
    names = {'claude': 'claude', 'gemini': 'agy', 'codex': 'codex'}
    name = names[provider]
    found = shutil.which(name, path=os.environ.get('AI_COOP_PATH') or os.environ.get('PATH', DEFAULT_PATH))
    # Keep unavailable providers addressable; preflight reports the limitation.
    return str(Path(found).resolve()) if found else str(HOME / '.local/bin' / name)


def safe_config_environment(runtime=None):
    """Configuration required by detached workers and Gemini guard hooks."""
    selected = Path(runtime or RUNTIME_ROOT)
    return {'AI_COOP_RUNTIME': str(selected), 'AI_COOP_PYTHON': python_path(),
        'AI_COOP_PATH': child_path(), 'AI_COOP_GEMINI_SETTINGS': str(GEMINI_SETTINGS),
        'AI_COOP_GEMINI_AGENTS': str(GEMINI_AGENTS_DIR),
        **{'AI_COOP_' + provider.upper() + '_BIN': binary_path(provider, selected)
           for provider in ('claude', 'gemini', 'codex', 'qwen')}}


def local_identity():
    return getpass.getuser()
