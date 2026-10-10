"""One bounded local Qwen job on an isolated, short-lived Ollama server.

This module never pulls models, authenticates, calls a cloud service, supplies
tools, or executes generated content. Its caller must hold the bridge's local
provider scope before acquiring a global job slot.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
import uuid
import coop_config

MODEL = 'qwen3.5:9b-q4_K_M'
HOST, PORT = '127.0.0.1', 11435
ENDPOINT = 'http://127.0.0.1:11435'
QUANTIZATION = 'Q4_K_M'
MAX_PROMPT_BYTES = 12000
NUM_CTX, NUM_PREDICT = 16384, 2048
MAX_RESPONSE_BYTES = 1024 * 1024


class LocalQwenError(RuntimeError):
    def __init__(self, code, message, state='failed'):
        super().__init__(message)
        self.code, self.state = code, state


def _paths(root):
    root = Path(root)
    models = root / 'models' / 'ollama'
    return (Path(coop_config.binary_path('qwen', root)), models,
            models / 'manifests' / 'registry.ollama.ai' / 'library' / 'qwen3.5' / '9b-q4_K_M')


def _plain_file(path, boundary):
    path, boundary = Path(path), Path(boundary)
    return (path.is_file() and not path.is_symlink()
            and all(not parent.is_symlink() for parent in path.parents if parent == boundary or boundary in parent.parents))


def normalize_digest(value):
    """Accept native bare hex or sha256:hex; reject any other spelling."""
    if not isinstance(value, str) or not re.fullmatch(r'(?:sha256:)?[a-fA-F0-9]{64}', value):
        return None
    return 'sha256:' + value.removeprefix('sha256:').lower()


def status(root):
    """Inspect local files only. Do not start a process, server or model."""
    binary, models, manifest = _paths(root)
    if not _plain_file(binary, root) or not os.access(binary, os.X_OK):
        raise LocalQwenError('binary_unavailable', 'The private local Ollama runner is unavailable.', 'needs_owner')
    try:
        if not _plain_file(manifest, root) or manifest.stat().st_size > 1024 * 1024:
            raise ValueError()
        raw = manifest.read_bytes()
        # Ollama v0.40.2 prefers manifests-v2 over the downgrade anchor.
        # Its named V2 manifest may be a symlink to a verified manifest blob.
        # Keep the anchor's raw SHA separate from the model's canonical digest.
        canonical_path = models / 'manifests-v2' / 'ollama.com' / 'library' / 'qwen3.5' / '9b-q4_K_M'
        canonical_raw = raw
        if canonical_path.exists() or canonical_path.is_symlink():
            if any(parent.is_symlink() for parent in canonical_path.parents
                    if parent == Path(root) or Path(root) in parent.parents):
                raise ValueError()
            target = canonical_path.resolve(strict=True)
            if canonical_path.is_symlink() and (target.parent != (models / 'blobs').resolve(strict=True)
                    or not re.fullmatch(r'sha256-[a-f0-9]{64}', target.name)):
                raise ValueError()
            if not _plain_file(target, Path(root).resolve(strict=True)) or target.stat().st_size > 1024 * 1024:
                raise ValueError()
            canonical_raw = target.read_bytes()
            if canonical_path.is_symlink() and hashlib.sha256(canonical_raw).hexdigest() != target.name.removeprefix('sha256-'):
                raise ValueError()
        else:
            canonical_path = manifest
        data = json.loads(canonical_raw)
        if not isinstance(data, dict) or data.get('schemaVersion') != 2:
            raise ValueError()
        layers, config = data.get('layers'), data.get('config')
        if not isinstance(layers, list) or not layers or not isinstance(config, dict):
            raise ValueError()
        if not any(isinstance(item, dict) and item.get('mediaType') == 'application/vnd.ollama.image.model' for item in layers):
            raise ValueError()
        total_size = 0
        for item in [config, *layers]:
            if not isinstance(item, dict) or not isinstance(item.get('digest'), str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', item['digest']):
                raise ValueError()
            size = item.get('size')
            if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
                raise ValueError()
            blob = models / 'blobs' / item['digest'].replace(':', '-')
            if not _plain_file(blob, root) or blob.stat().st_size != size:
                raise ValueError()
            total_size += size
    except (OSError, ValueError, UnicodeError, TypeError, RuntimeError):
        raise LocalQwenError('model_unavailable', 'The complete Qwen model is not installed locally; no download was attempted.', 'needs_owner') from None
    return {'auth': 'local model; no account or API key', 'requested_model': MODEL,
            'endpoint': ENDPOINT, 'runner_binary': str(binary), 'models_path': str(models),
            'runner_home': str(Path(root) / 'runtime' / 'ollama-home'),
            'model_manifest_digest': 'sha256:' + hashlib.sha256(canonical_raw).hexdigest(),
            'model_manifest_raw_sha256': hashlib.sha256(raw).hexdigest(),
            'model_manifest_raw_path': str(manifest), 'model_manifest_canonical_path': str(canonical_path),
            'model_disk_bytes': total_size, 'quantization': QUANTIZATION,
            'available': True, 'server_started': False, 'max_concurrent_local_jobs': 1,
            'full_prompt_utf8_byte_limit': MAX_PROMPT_BYTES, 'num_ctx': NUM_CTX,
            'num_predict': NUM_PREDICT, 'think': False, 'keep_alive': 0,
            'temperature': 0, 'presence_penalty': 0}


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LocalQwenError('timeout', 'The local model exceeded its time budget; its owned runner was stopped.')
    return remaining


@contextmanager
def _inference_lock(root, deadline):
    path = Path(root) / 'slots' / 'qwen-inference.lock'
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(fd, 0o600)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(0.1, _remaining(deadline)))
        yield
    finally:
        os.close(fd)


def _port_busy():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.1)
        return probe.connect_ex((HOST, PORT)) == 0


def _http(method, route, deadline, payload=None, timeout_cap=None):
    # Direct http.client calls neither consult proxy variables nor follow redirects.
    timeout = _remaining(deadline)
    if timeout_cap is not None:
        timeout = min(timeout, timeout_cap)
    connection = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode('utf-8')
    try:
        connection.request(method, route, body=body, headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        _remaining(deadline)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LocalQwenError('output_limit', 'The local runner returned an oversized response.')
        if response.status != 200:
            raise LocalQwenError('local_http_error', 'The local runner rejected the request; no fallback or retry was attempted.')
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get('error'):
            raise LocalQwenError('invalid_output', 'The local runner did not return a valid result.')
        return value
    except (socket.timeout, TimeoutError):
        raise LocalQwenError('timeout', 'The local model exceeded its time budget; its owned runner was stopped.') from None
    except (http.client.HTTPException, OSError, ValueError, UnicodeError):
        _remaining(deadline)
        raise LocalQwenError('local_connection_failed', 'The local runner connection failed; no fallback or retry was attempted.') from None
    finally:
        connection.close()


def _stop_owned(process):
    # The deadline watchdog and the main thread can both reach cleanup.
    # Keep the unreaped leader's PID reserved until every group signal has
    # been sent. wait()/poll() between TERM and KILL would release that anchor.
    with process._qwen_cleanup_lock:
        if process._qwen_cleanup_complete:
            return
        error = getattr(process, '_qwen_cleanup_error', None)
        if error:
            raise LocalQwenError('cleanup_failed', error)
        if process.returncode is not None:
            process._qwen_cleanup_error = 'The local runner leader was already reaped; its process group cannot be safely verified.'
            raise LocalQwenError('cleanup_failed', process._qwen_cleanup_error)
        group_gone = False
        try:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                group_gone = True
            if not group_gone:
                time.sleep(0.3)
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            # Reap only after the final possible process-group signal. The
            # cleanup lock prevents another thread from signaling this ID.
            try:
                process.wait(timeout=0.3)
            except subprocess.TimeoutExpired:
                process._qwen_cleanup_error = 'The owned local runner did not stop within its cleanup budget.'
                raise LocalQwenError('cleanup_failed', process._qwen_cleanup_error) from None
        except PermissionError:
            # Some systems return EPERM for an exited group whose leader has
            # not yet been reaped. Reap once and never signal this ID again.
            # A live leader still makes the cleanup fail; an exited leader
            # does not independently prove that all descendants have exited.
            try:
                process.wait(timeout=0.3)
            except subprocess.TimeoutExpired:
                process._qwen_cleanup_error = 'The owned local runner process group could not be stopped.'
                raise LocalQwenError('cleanup_failed', process._qwen_cleanup_error) from None
            process._qwen_group_cleanup_verified = False
            process._qwen_cleanup_complete = True
            return
        process._qwen_group_cleanup_verified = True
        process._qwen_cleanup_complete = True


def _cleanup_evidence(process):
    """Describe leader, group and endpoint evidence without conflating them."""
    if not process._qwen_cleanup_complete or process.returncode is None:
        raise LocalQwenError('cleanup_failed', 'The owned local runner leader did not stop.')
    endpoint_released = not _port_busy()
    evidence = {'server_stopped': True, 'server_stop_scope': 'owned runner leader',
                'endpoint_released': endpoint_released,
                'process_group_stop_confirmed': process._qwen_group_cleanup_verified and endpoint_released}
    limitations = []
    if not process._qwen_group_cleanup_verified:
        limitations.append('The operating system denied a process-group signal; surviving descendants were not independently verified.')
    if not endpoint_released:
        limitations.append('The configured loopback endpoint is still occupied; endpoint release was not confirmed.')
    if limitations:
        evidence['cleanup_limitation'] = ' '.join(limitations)
    return evidence


def _owns_endpoint(process, deadline):
    try:
        checked = subprocess.run([shutil.which('lsof', path=coop_config.child_path()) or 'lsof', '-nP', '-a', '-p', str(process.pid),
            '-iTCP:' + str(PORT), '-sTCP:LISTEN', '-Fpn'],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8'},
            timeout=min(5, _remaining(deadline)))
        return (checked.returncode == 0 and 'p' + str(process.pid) in checked.stdout.splitlines()
                and 'n' + HOST + ':' + str(PORT) in checked.stdout.splitlines())
    except (OSError, subprocess.TimeoutExpired):
        _remaining(deadline)
        return False


def _parse(data):
    if not isinstance(data, dict) or data.get('error') or data.get('model') != MODEL:
        raise LocalQwenError('invalid_output', 'The local runner returned an error or an unexpected model.')
    if data.get('done') is not True or data.get('done_reason') != 'stop':
        raise LocalQwenError('incomplete_output', 'The local answer was incomplete or reached its output limit; split the assignment and review it before rerunning.')
    message = data.get('message')
    if not isinstance(message, dict) or message.get('role') != 'assistant':
        raise LocalQwenError('invalid_output', 'The local runner returned no assistant answer.')
    if message.get('tool_calls') or data.get('tool_calls'):
        raise LocalQwenError('unsafe_tools', 'The local worker returned a tool call; it was rejected and never executed.')
    answer = message.get('content')
    if not isinstance(answer, str) or not answer.strip() or '\x00' in answer:
        raise LocalQwenError('invalid_output', 'The local runner returned no usable complete answer.')
    usage = {}
    for field in ('total_duration', 'load_duration', 'prompt_eval_count', 'prompt_eval_duration', 'eval_count', 'eval_duration'):
        value = data.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise LocalQwenError('invalid_output', 'The local runner did not provide valid token and timing evidence.')
        usage[field] = value
    if not usage['prompt_eval_count'] or not usage['eval_count'] or usage['prompt_eval_count'] > NUM_CTX - NUM_PREDICT:
        raise LocalQwenError('invalid_output', 'The local runner returned invalid or excessive token counts.')
    usage.update({'input_tokens': usage['prompt_eval_count'], 'output_tokens': usage['eval_count'],
                  'duration_unit': 'nanoseconds'})
    return {'answer': answer, 'actual_model': data['model'], 'usage': usage,
            'provider_session_id': None, 'tool_actions': []}


def _save_native(job, data):
    """Keep rejected native evidence private without promoting it to an answer."""
    destination = Path(job) / 'provider.json'
    temporary = destination.with_name(destination.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(data, output, ensure_ascii=False, indent=2)
        os.replace(str(temporary), str(destination))
        destination.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def run(prompt, deadline, job, root):
    """Run once, unload with keep_alive:0, then stop only this owned runner."""
    if not isinstance(prompt, str) or not prompt.strip():
        raise LocalQwenError('invalid_prompt', 'A nonempty local task is required.')
    try:
        size = len(prompt.encode('utf-8'))
    except UnicodeError:
        raise LocalQwenError('invalid_prompt', 'The local prompt must be valid UTF-8.') from None
    if size > MAX_PROMPT_BYTES:
        raise LocalQwenError('local_input_limit', 'The full local prompt exceeds 12000 UTF-8 bytes; split the supplied text into smaller batches.')
    local = status(root)
    binary, models, _ = _paths(root)
    runner_home = Path(root) / 'runtime' / 'ollama-home'
    runner_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    if runner_home.is_symlink() or any(parent.is_symlink() for parent in runner_home.parents
            if parent == Path(root) or Path(root) in parent.parents):
        raise LocalQwenError('unsafe_path', 'The private local runner home is a symlink.')
    runner_home.chmod(0o700)
    identity = coop_config.local_identity()
    env = {'HOME': str(runner_home), 'USER': identity, 'LOGNAME': identity,
           'PATH': coop_config.child_path(), 'LANG': 'en_US.UTF-8',
           'OLLAMA_HOST': HOST + ':' + str(PORT), 'OLLAMA_MODELS': str(models),
           'OLLAMA_NO_CLOUD': '1', 'OLLAMA_NUM_PARALLEL': '1',
           'OLLAMA_MAX_LOADED_MODELS': '1', 'OLLAMA_MAX_QUEUE': '1',
           'OLLAMA_KEEP_ALIVE': '0', 'OLLAMA_CONTEXT_LENGTH': str(NUM_CTX)}
    process, prior_handlers, watchdog, parsed = None, {}, None, None
    with _inference_lock(root, deadline):
        if _port_busy():
            raise LocalQwenError('local_endpoint_busy', 'The private local endpoint is already occupied; the bridge will not share or stop an unknown service.', 'needs_owner')
        log_path = Path(job) / 'local-runner.log'
        log_fd = os.open(str(log_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(log_fd, 'wb') as log:
                try:
                    process = subprocess.Popen([str(binary), 'serve'], cwd=str(root), env=env,
                        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                        start_new_session=True, close_fds=True)
                except OSError:
                    raise LocalQwenError('launch_failed', 'The private local runner could not start.', 'needs_owner') from None
                process._qwen_cleanup_lock = threading.Lock()
                process._qwen_cleanup_complete = False
                # A server-side inference stall cannot extend the caller's
                # absolute deadline, including slow HTTP reads.
                watchdog = threading.Timer(_remaining(deadline), _stop_owned, args=(process,))
                watchdog.daemon = True
                watchdog.start()
                # Detached bridge workers still clean up on ordinary termination.
                # Thread-based unit harnesses cannot install signal handlers.
                def interrupted(signum, frame):
                    raise LocalQwenError('cancelled', 'The local job was interrupted; its owned runner was stopped.')
                try:
                    for sig in (signal.SIGTERM, signal.SIGINT):
                        prior_handlers[sig] = signal.getsignal(sig)
                        signal.signal(sig, interrupted)
                except ValueError:
                    prior_handlers.clear()
                while not _port_busy():
                    if process.poll() is not None:
                        raise LocalQwenError('launch_failed', 'The private local runner exited before becoming ready.')
                    time.sleep(min(0.1, _remaining(deadline)))
                if process.poll() is not None:
                    raise LocalQwenError('launch_failed', 'The private local runner did not retain its endpoint.')
                if not _owns_endpoint(process, deadline):
                    raise LocalQwenError('local_endpoint_unverified', 'The endpoint does not belong to this job runner; no model request was made.', 'needs_owner')
                version = _http('GET', '/api/version', deadline, timeout_cap=5).get('version')
                if not isinstance(version, str) or not version.strip() or len(version) > 128:
                    raise LocalQwenError('invalid_output', 'The local runner version could not be verified.')
                tags = _http('GET', '/api/tags', deadline, timeout_cap=5).get('models')
                selected = [entry for entry in tags if isinstance(entry, dict) and entry.get('name') == MODEL] if isinstance(tags, list) else []
                if len(selected) != 1 or normalize_digest(selected[0].get('digest')) != local['model_manifest_digest']:
                    raise LocalQwenError('model_mismatch', 'The local endpoint model differs from the installed model manifest.')
                shown = _http('POST', '/api/show', deadline, {'model': MODEL}, timeout_cap=10)
                details, capabilities = shown.get('details'), shown.get('capabilities')
                if not isinstance(details, dict) or details.get('quantization_level') != QUANTIZATION:
                    raise LocalQwenError('model_mismatch', 'The local model is not the required Q4_K_M quantization.')
                if not isinstance(capabilities, list) or 'completion' not in capabilities or 'thinking' not in capabilities:
                    raise LocalQwenError('model_mismatch', 'The local model does not report the expected text and thinking capabilities.')
                native = _http('POST', '/api/chat', deadline, {
                    'model': MODEL, 'messages': [{'role': 'user', 'content': prompt}],
                    'stream': False, 'think': False, 'keep_alive': 0,
                    'options': {'num_ctx': NUM_CTX, 'num_predict': NUM_PREDICT, 'temperature': 0, 'presence_penalty': 0}})
                _save_native(job, native)
                parsed = _parse(native)
                parsed['local_runtime'] = {**local, 'runner_version': version,
                    'api_model_digest': selected[0]['digest'],
                    'parameter_size': details.get('parameter_size'), 'family': details.get('family'),
                    'capabilities': capabilities, 'server_started': True,
                    'server_owned_by_job': True, 'full_prompt_utf8_bytes': size,
                    'done': True, 'done_reason': native['done_reason'], 'cloud_disabled': True,
                    'cleanup': 'keep_alive:0 then stop owned runner'}
            return parsed, native
        finally:
            try:
                if watchdog is not None:
                    watchdog.cancel()
                if process is not None:
                    _stop_owned(process)
            finally:
                if watchdog is not None:
                    watchdog.join(timeout=1)
                for sig, handler in prior_handlers.items():
                    signal.signal(sig, handler)
            if process is not None and not process._qwen_cleanup_complete:
                raise LocalQwenError('cleanup_failed', 'The local runner did not stop; the job cannot be treated as complete.')
            if parsed is not None:
                parsed['local_runtime'].update(_cleanup_evidence(process))
