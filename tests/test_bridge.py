import importlib.util
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import stat
import signal
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bridge_tested', Path(__file__).parents[1] / 'bridge.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'runtime'
        self.root.mkdir()
        self.root_patch = patch.object(b, 'ROOT', self.root)
        self.root_patch.start()
        # Preflight tests must not depend on an installed provider or account.
        self.binary_patch = patch.object(b, 'BINARIES', {provider: sys.executable for provider in b.BINARIES})
        self.binary_patch.start()

    def tearDown(self):
        self.root_patch.stop()
        self.binary_patch.stop()
        self.temp.cleanup()

    def submit(self, **changes):
        params = {'provider': 'claude', 'prompt': 'Analyze this supplied task.'}
        params.update(changes)
        with patch.object(b.subprocess, 'Popen', return_value=types.SimpleNamespace(pid=os.getpid())):
            return b.submit(params)

    def claude_output(self, **changes):
        value = {'is_error': False, 'subtype': 'success', 'result': 'Verified finding.',
            'modelUsage': {'claude-opus-test': {'provider': 'firstParty'}}, 'usage': {'input_tokens': 4},
            'session_id': 'provider-session', 'num_turns': 1}
        value.update(changes)
        return json.dumps(value)

    def gemini_output(self, tools=None, **changes):
        result = {'status': 'SUCCESS', 'response': 'Finding with https://example.com/source',
            'conversation_id': 'remote-session', 'usage': {'total_tokens': 5}}
        result.update(changes)
        return '\n'.join(map(json.dumps, [
            {'event': 'init', 'init': {'model': b.GEMINI_MODEL, 'tools': tools or []}},
            {'event': 'result', 'result': result}]))

    def test_secret_environment_is_not_inherited(self):
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'DUMMY_SECRET', 'GOOGLE_API_KEY': 'DUMMY_SECRET',  # ai-coop-synthetic-secret
            'OPENAI_API_KEY': 'DUMMY_SECRET', 'HTTPS_PROXY': 'evil', 'CODEX_HOME': '/evil'}):  # ai-coop-synthetic-secret
            env = b._env()
        self.assertNotIn('DUMMY_SECRET', env.values())
        self.assertNotIn('CODEX_HOME', env)
        self.assertNotIn('HTTPS_PROXY', env)

    def test_validation_has_no_launch_or_record_side_effects(self):
        with patch.object(b.subprocess, 'Popen') as launch:
            b.validate_params({'provider': 'gemini', 'prompt': 'Task'})
        launch.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_malformed_types_and_nul_are_safe_errors(self):
        cases = [ {'provider': [], 'prompt': 'task'}, {'provider': 'claude', 'prompt': '\ud800'},
            {'provider': 'claude', 'prompt': 'task', 'files': ['/tmp/a\x00b']},
            {'provider': 'claude', 'prompt': 'task', 'previous': []} ]
        for params in cases:
            with self.subTest(params=str(params)), self.assertRaises(b.BridgeError):
                b.validate_params(params)

    def test_corrupt_job_record_is_safe_error(self):
        submitted = self.submit()
        folder = Path(submitted['job_dir'])
        request = b._read_json(folder / 'request.json')
        request.pop('created_epoch')
        b._write(folder / 'request.json', request)
        with self.assertRaises(b.BridgeError) as raised:
            b.result(submitted['job_id'])
        self.assertEqual(raised.exception.code, 'invalid_record')

    def test_exited_child_is_not_reported_alive(self):
        child = b.subprocess.Popen([sys.executable, '-c', 'pass'])
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and b._alive(child.pid):
            time.sleep(0.02)
        self.assertFalse(b._alive(child.pid))
        child.wait()

    def test_explicit_file_copy_only_private_permissions(self):
        source = Path(self.temp.name) / 'input.txt'
        source.write_text('Quoted reference', encoding='utf-8')
        unrelated = Path(self.temp.name) / 'other.txt'
        unrelated.write_text('Do not copy me')
        job = self.submit(files=[{'source': str(source), 'relative_path': 'refs/input.txt'}])
        folder = Path(job['job_dir'])
        self.assertEqual((folder / 'workspace/refs/input.txt').read_text(), 'Quoted reference')
        self.assertFalse((folder / 'workspace/other.txt').exists())
        for path in folder.rglob('*'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        self.assertNotIn('Quoted reference', (folder / 'request.json').read_text())

    def test_paths_credentials_and_binary_files_rejected_before_launch(self):
        source = Path(self.temp.name) / 'input.txt'
        source.write_text('reference')
        for relative in ('../escape', '/absolute', 'a/../../escape', 'a\\escape'):
            with self.subTest(relative=relative), self.assertRaises(b.BridgeError):
                b.validate_params({'provider': 'claude', 'prompt': 'Task', 'files': [{'source': str(source), 'relative_path': relative}]})
        credential = source.with_name('oauth_creds.json')
        credential.write_text('sensitive')
        with self.assertRaises(b.BridgeError) as raised:
            b.validate_params({'provider': 'claude', 'prompt': 'Task', 'files': [str(credential)]})
        self.assertEqual(raised.exception.code, 'sensitive_file')
        source.write_bytes(b'\xff\x00')
        with self.assertRaises(b.BridgeError):
            b.validate_params({'provider': 'claude', 'prompt': 'Task', 'files': [str(source)]})

    def test_duplicate_and_parent_child_file_destinations_rejected(self):
        source = Path(self.temp.name) / 'input.txt'
        source.write_text('reference')
        for names in (('x', 'x'), ('x', 'x/y')):
            with self.assertRaises(b.BridgeError):
                b.validate_params({'provider': 'claude', 'prompt': 'Task', 'files': [
                    {'source': str(source), 'relative_path': name} for name in names]})

    def test_batch_is_validated_before_any_job_is_started(self):
        jobs = [{'provider': 'claude', 'prompt': 'Good'}, {'provider': 'claude', 'prompt': 'Bad', 'timeout': True}]
        with patch.object(b, 'submit') as submit, self.assertRaises(b.BridgeError):
            b.batch(jobs)
        submit.assert_not_called()
        with self.assertRaises(b.BridgeError):
            b.batch([{'provider': 'claude', 'prompt': 'Task'}] * 21)

    def test_identical_concurrent_tasks_spawn_once_and_rerun_is_explicit(self):
        request = {'provider': 'claude', 'prompt': 'Identical bounded input', 'task_key': 'owner/task'}
        with patch.object(b.subprocess, 'Popen', return_value=types.SimpleNamespace(pid=os.getpid())) as launch:
            with ThreadPoolExecutor(max_workers=4) as pool:
                values = list(pool.map(b.submit, [dict(request) for _ in range(4)]))
            self.assertEqual(len({value['job_id'] for value in values}), 1)
            self.assertEqual(launch.call_count, 1)
            again = b.submit(dict(request, rerun=True))
            self.assertNotEqual(again['job_id'], values[0]['job_id'])
            self.assertEqual(launch.call_count, 2)
        with self.assertRaises(b.BridgeError) as raised:
            b.submit(dict(request, prompt='Different assignment'))
        self.assertEqual(raised.exception.code, 'task_key_conflict')

    def test_batch_alias_conflict_never_partially_dispatches(self):
        jobs = [{'provider': 'claude', 'prompt': value, 'task_key': 'same'} for value in ('one', 'two')]
        with patch.object(b.subprocess, 'Popen') as launch, self.assertRaises(b.BridgeError) as raised:
            b.batch(jobs)
        self.assertEqual(raised.exception.code, 'task_key_conflict')
        launch.assert_not_called()
        self.assertEqual(list((self.root / 'jobs').iterdir()), [])

    def test_scope_change_cannot_silently_reuse_unscoped_job(self):
        submitted = self.submit(prompt='same input')
        with patch.object(b.subprocess, 'Popen') as launch, self.assertRaises(b.BridgeError) as raised:
            b.submit({'provider': 'claude', 'prompt': 'same input', 'scope': 'research/topic'})
        launch.assert_not_called()
        self.assertEqual(raised.exception.code, 'scope_conflict')
        self.assertEqual(b.result(submitted['job_id'])['state'], 'queued')

    def test_scope_parent_child_and_original_file_overlap(self):
        original = Path(self.temp.name) / 'project/code.py'
        original.parent.mkdir()
        original.write_text('original')
        request = b.validate_params({'provider': 'claude', 'mode': 'code', 'prompt': 'Edit', 'files': [str(original)]})
        named = b.validate_params({'provider': 'claude', 'prompt': 'Task', 'scope': str(original.parent)})
        self.assertTrue(b._scopes_overlap(request['scopes'][0], named['scopes'][0]))
        self.assertTrue(b._scopes_overlap('scope:research/topic', 'scope:research'))
        self.assertFalse(b._scopes_overlap('scope:research/topic2', 'scope:research/topic'))
        request.update(job_id='first')
        b._acquire_scope(request, time.monotonic() + 1)
        named.update(job_id='second')
        try:
            with self.assertRaises(b.BridgeError) as raised:
                b._acquire_scope(named, time.monotonic() + 0.05)
            self.assertEqual(raised.exception.code, 'scope_timeout')
        finally:
            b._release_scope(request)
        b._acquire_scope(named, time.monotonic() + 1)
        b._release_scope(named)

    def test_followup_includes_prior_answer_only(self):
        first = self.submit(prompt='PRIVATE PRIOR REQUEST')
        job = Path(first['job_dir'])
        request = b._read_json(job / 'request.json')
        b._finish(job, request, parsed={'answer': 'PRIOR ANSWER', 'actual_model': 'claude-opus-test'})
        second = self.submit(prompt='NEW FEEDBACK', previous=first['job_id'])
        prompt = (Path(second['job_dir']) / 'prompt.txt').read_text()
        self.assertIn('PRIOR ANSWER', prompt)
        self.assertIn('NEW FEEDBACK', prompt)
        self.assertNotIn('PRIVATE PRIOR REQUEST', prompt)
        with self.assertRaises(b.BridgeError):
            b.validate_params({'provider': 'claude', 'prompt': 'Next', 'previous': second['job_id']})

    def test_incomplete_worker_is_detected_and_not_left_running(self):
        submitted = self.submit()
        job = Path(submitted['job_dir'])
        request = b._read_json(job / 'request.json')
        request['created_epoch'] -= 5
        b._write(job / 'request.json', request)
        b._write(job / 'state.json', {'job_id': submitted['job_id'], 'state': 'running'})
        with patch.object(b, '_alive', return_value=False):
            value = b.result(submitted['job_id'])
        self.assertEqual(value['state'], 'failed')
        self.assertEqual(value['error']['code'], 'worker_lost')
        self.assertFalse((job / 'answer.md').exists())

    def test_readonly_status_snapshot_does_not_mutate_abandoned_job(self):
        submitted = self.submit()
        job = Path(submitted['job_dir'])
        request = b._read_json(job / 'request.json')
        request['created_epoch'] -= 5
        b._write(job / 'request.json', request)
        with patch.object(b, '_alive', return_value=False):
            value = b._result(submitted['job_id'], refresh=False)
        self.assertEqual(value['state'], 'failed')
        self.assertFalse((job / 'result.json').exists())

    def test_success_and_changed_files_need_owner_review(self):
        source = Path(self.temp.name) / 'code.py'
        source.write_text('before')
        submitted = self.submit(mode='code', files=[str(source)])
        job = Path(submitted['job_dir'])
        (job / 'workspace/code.py').write_text('after')
        request = b._read_json(job / 'request.json')
        b._finish(job, request, parsed=b._parse('claude', self.claude_output(), 'code'))
        value = b.result(submitted['job_id'])
        self.assertEqual(value['state'], 'ready_for_review')
        self.assertEqual(value['changed_files'][0]['change'], 'modified')
        self.assertEqual(source.read_text(), 'before')
        self.assertEqual(value['actual_model'], 'claude-opus-test')

    def test_symlink_output_never_passes_review_state(self):
        submitted = self.submit(mode='code')
        job = Path(submitted['job_dir'])
        (job / 'workspace/escape').symlink_to(Path(self.temp.name) / 'outside')
        b._finish(job, b._read_json(job / 'request.json'), parsed=b._parse('claude', self.claude_output(), 'code'))
        self.assertEqual(b.result(submitted['job_id'])['state'], 'failed')

    def test_semantic_errors_denials_models_and_tool_activity_rejected(self):
        cases = [self.claude_output(is_error=True, result='quota exceeded secret'),
            self.claude_output(permission_denials=[{'tool_name': 'Write'}]),
            self.claude_output(modelUsage={'claude-sonnet-other': {}}),
            self.claude_output(modelUsage={'claude-opus-a': {}, 'claude-opus-b': {}}),
            self.claude_output(tool_calls=[{}])]
        for output in cases:
            with self.assertRaises(b.BridgeError) as raised:
                b._parse('claude', output)
            self.assertNotIn('secret', str(raised.exception))
        for output in [self.gemini_output(denied_actions=['read_url']),
            self.gemini_output(tools=['search_web']),
            '{"event":"init","init":{"model":"other","tools":[]}}']:
            with self.assertRaises(b.BridgeError):
                b._parse('gemini', output)

    def test_research_has_exact_tool_profile_and_records_model(self):
        output = self.gemini_output(tools=list(b.GEMINI_RESEARCH_TOOLS))
        result = b._parse('gemini', output, 'research')
        self.assertEqual(result['actual_model'], b.GEMINI_MODEL)
        events = [json.loads(line) for line in output.splitlines()]
        events.insert(1, {'event': 'step_update', 'step_update': {'step_type': 'tool', 'state': 'DONE', 'tool_info': {'name': 'search_web', 'parameters': {'query': 'test'}}}})
        parsed = b._parse('gemini', '\n'.join(map(json.dumps, events)), 'research')
        self.assertIn('search_web', parsed['tool_actions'])
        events.insert(1, {'event': 'tool_call', 'name': 'run_command'})
        with self.assertRaises(b.BridgeError):
            b._parse('gemini', '\n'.join(map(json.dumps, events)), 'research')

    def test_broad_native_schema_requires_guard_and_matching_agent(self):
        events = [json.loads(line) for line in self.gemini_output().splitlines()]
        events[0]['init']['tools'] = ['run_command', 'call_mcp_tool', 'search_web', 'read_url_content']
        events[0]['init']['agent'] = 'ai-coop-research'
        output = '\n'.join(map(json.dumps, events))
        with self.assertRaises(b.BridgeError):
            b._parse('gemini', output, 'research')
        value = b._parse('gemini', output, 'research', guard_verified=True)
        self.assertEqual(value['actual_model'], b.GEMINI_MODEL)
        events.insert(1, {'event': 'step_update', 'step_update': {'step_type': 'tool', 'tool_info': {'name': 'run_command'}}})
        with self.assertRaises(b.BridgeError):
            b._parse('gemini', '\n'.join(map(json.dumps, events)), 'research', guard_verified=True)

    def test_guard_audit_requires_each_dispatch_and_rejects_denials(self):
        job = self.root / 'audit-job'
        job.mkdir()
        request = {'job_id': 'owned-job', 'mode': 'research'}
        parsed = {'tool_actions': ['search_web', 'search_web', 'read_url_content']}
        with self.assertRaises(b.BridgeError) as raised:
            b._verify_guard_audit(job, request, parsed, 100)
        self.assertEqual(raised.exception.code, 'guard_unverified')
        rows = [{'epoch': 101 + i, 'job_id': 'owned-job', 'mode': 'research', 'tool': tool, 'decision': 'allow'}
            for i, tool in enumerate(parsed['tool_actions'])]
        b._write(job / 'hook-audit.ndjson', '\n'.join(map(json.dumps, rows)))
        proof = b._verify_guard_audit(job, request, parsed, 100)
        self.assertEqual(proof['required_tool_calls'], 3)
        self.assertEqual(proof['matched_allow_records'], 3)
        rows.append({'epoch': 110, 'job_id': 'owned-job', 'mode': 'research', 'tool': 'run_command', 'decision': 'deny'})
        b._write(job / 'hook-audit.ndjson', '\n'.join(map(json.dumps, rows)))
        with self.assertRaises(b.BridgeError) as raised:
            b._verify_guard_audit(job, request, parsed, 100)
        self.assertEqual(raised.exception.code, 'tool_denied')

    def test_native_active_done_phases_count_one_tool_dispatch(self):
        events = [json.loads(line) for line in self.gemini_output(tools=list(b.GEMINI_RESEARCH_TOOLS)).splitlines()]
        for state in ('ACTIVE', 'DONE'):
            events.insert(-1, {'event': 'step_update', 'step_update': {'step_index': 4, 'step_type': 'tool', 'state': state, 'tool_info': {'name': 'search_web'}}})
        parsed = b._parse('gemini', '\n'.join(map(json.dumps, events)), 'research')
        self.assertEqual(parsed['tool_actions'], ['search_web'])

    def test_codex_missing_model_is_explicit_and_tools_rejected(self):
        output = '\n'.join(map(json.dumps, [
            {'type': 'thread.started', 'thread_id': 'session'},
            {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'Answer'}},
            {'type': 'turn.completed', 'usage': {'input_tokens': 5}}]))
        value = b._parse('codex', output)
        self.assertEqual(value['actual_model'], 'not reported by CLI')
        with self.assertRaises(b.BridgeError):
            b._parse('codex', '{"type":"item.started","item":{"type":"command_execution"}}')

    def test_commands_use_stdin_no_api_or_permission_bypass(self):
        job, workspace = self.root / 'job', self.root / 'job/workspace'
        for provider, mode in [('claude', 'analyze'), ('claude', 'code'), ('gemini', 'analyze'), ('gemini', 'research'), ('codex', 'analyze')]:
            args = b._command({'provider': provider, 'mode': mode}, workspace, 30, job)
            self.assertNotIn('task text', args)
            self.assertFalse(any('dangerously' in value or 'fallback-model' in value for value in args))
        args = b._command({'provider': 'claude', 'mode': 'code'}, workspace, 30, job)
        self.assertIn('Read(/' + str(workspace) + '/**)', args)
        self.assertIn('Edit(/' + str(workspace) + '/**)', args)
        self.assertFalse(any(value.startswith('Write(') for value in args))
        self.assertIn('dontAsk', args)
        self.assertNotIn('Bash', args)
        codex = b._command({'provider': 'codex', 'mode': 'analyze'}, workspace, 30, job)
        self.assertNotIn('--model', codex)
        self.assertIn('--ignore-user-config', codex)
        self.assertNotIn('--ignore-rules', codex)
        gemini = b._command({'provider': 'gemini', 'mode': 'analyze'}, workspace, 30, job)
        self.assertIn('--input-format', gemini)
        self.assertNotIn('-p', gemini)

    def test_claude_api_key_preflight_fails_without_model_request(self):
        with patch.object(b, '_run', return_value=(0, json.dumps({'loggedIn': True, 'authMethod': 'apiKey', 'apiProvider': 'firstParty'}), '')) as run, self.assertRaises(b.BridgeError):
            b._preflight('claude', 'analyze', self.root, time.monotonic() + 30)
        self.assertEqual(run.call_count, 1)
        self.assertIn('status', run.call_args[0][0])

    def test_claude_nonzero_logged_out_is_owner_action(self):
        with patch.object(b, '_run', return_value=(1, '{"loggedIn":false}', '')) as run, self.assertRaises(b.BridgeError) as raised:
            b._preflight('claude', 'analyze', self.root, time.monotonic() + 30)
        self.assertEqual(raised.exception.code, 'auth')
        self.assertEqual(raised.exception.state, 'needs_owner')
        self.assertEqual(run.call_count, 1)

    def test_gemini_credits_preflight_fails_before_model_request(self):
        output = json.dumps({'status': 'SUCCESS', 'num_turns': 0, 'command': {'data': {'config': {'useG1Credits': True}}}})
        with patch.object(b, '_run', return_value=(0, output, '')) as run, self.assertRaises(b.BridgeError) as raised:
            b._preflight('gemini', 'analyze', self.root, time.monotonic() + 30)
        self.assertEqual(raised.exception.code, 'unsafe_config')
        self.assertEqual(run.call_count, 1)

    def test_two_global_flock_slots(self):
        (self.root / 'slots').mkdir()
        first, second = b._slot(), b._slot()
        try:
            with patch.object(b, 'QUEUE_TIMEOUT', 0.05), self.assertRaises(b.BridgeError) as raised:
                b._slot()
            self.assertEqual(raised.exception.code, 'queue_timeout')
        finally:
            os.close(first)
            os.close(second)
        freed = b._slot()
        os.close(freed)

    def test_real_pipe_roundtrip_timeout_and_output_limit(self):
        output = b._run([sys.executable, '-c', 'import sys;print(sys.stdin.read())'], self.root, 3, '$(literal no shell)')
        self.assertEqual(output[1].strip(), '$(literal no shell)')
        with self.assertRaises(b.BridgeError) as raised:
            b._run([sys.executable, '-c', 'import time;time.sleep(3)'], self.root, 0.1)
        self.assertEqual(raised.exception.code, 'timeout')
        with patch.object(b, 'MAX_OUTPUT', 100), self.assertRaises(b.BridgeError) as raised:
            b._run([sys.executable, '-c', 'print("x" * 1000)'], self.root, 3)
        self.assertEqual(raised.exception.code, 'output_limit')

    def test_cleanup_does_not_signal_an_already_reaped_group(self):
        process = types.SimpleNamespace(pid=12345, returncode=0)
        with patch.object(b.os, 'killpg') as kill:
            b._stop(process)
        kill.assert_not_called()

    def test_cleanup_permission_denied_is_only_a_race_after_exit(self):
        from unittest.mock import Mock
        process = Mock(pid=12345, returncode=None)
        process.poll.return_value = 0
        with patch.object(b.os, 'killpg', side_effect=PermissionError()) as kill:
            b._stop(process)
        self.assertEqual(kill.call_count, 1)
        process.wait.assert_not_called()

    def test_cleanup_permission_denied_for_live_provider_is_failure(self):
        from unittest.mock import Mock
        process = Mock(pid=12345, returncode=None)
        process.poll.return_value = None
        with patch.object(b.os, 'killpg', side_effect=PermissionError()), self.assertRaises(b.BridgeError) as caught:
            b._stop(process)
        self.assertEqual(caught.exception.code, 'cleanup_failed')

    def test_output_limit_cleanup_stops_child_that_ignores_term(self):
        ready = self.root / 'synthetic-child-ready'
        survived = self.root / 'synthetic-child-survived'
        child = ('import pathlib,signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);'
            'pathlib.Path(' + repr(str(ready)) + ').write_text("ready");'
            'time.sleep(0.8);pathlib.Path(' + repr(str(survived)) + ').write_text("survived")')
        parent = ('import pathlib,subprocess,sys,time;'
            'subprocess.Popen([sys.executable,"-c",' + repr(child) + ']);'
            '\nwhile not pathlib.Path(' + repr(str(ready)) + ').exists(): time.sleep(0.01)'
            '\nprint("x"*1000,flush=True)')
        with patch.object(b, 'MAX_OUTPUT', 100), self.assertRaises(b.BridgeError) as caught:
            b._run([sys.executable, '-c', parent], self.root, 5)
        self.assertEqual(caught.exception.code, 'output_limit')
        self.assertTrue(ready.exists(), 'The synthetic child must install its TERM handler before cleanup.')
        time.sleep(0.8)
        self.assertFalse(survived.exists(), 'Cleanup must stop descendants even when the leader has exited.')

    def test_cleanup_failure_still_closes_all_provider_pipes(self):
        launched = []
        original_spawn = b.subprocess.Popen
        def capture(*args, **kwargs):
            process = original_spawn(*args, **kwargs)
            launched.append(process)
            return process
        try:
            with patch.object(b.subprocess, 'Popen', side_effect=capture), \
                 patch.object(b, '_stop', side_effect=b.BridgeError('cleanup_failed', 'Synthetic cleanup failure.')), \
                 self.assertRaises(b.BridgeError) as caught:
                b._run([sys.executable, '-c', 'print("synthetic")'], self.root, 3)
            self.assertEqual(caught.exception.code, 'cleanup_failed')
            self.assertTrue(all(stream.closed for process in launched
                for stream in (process.stdin, process.stdout, process.stderr)))
        finally:
            for process in launched:
                process.wait(timeout=3)

    def test_worker_rejects_success_exit_with_semantic_error(self):
        submitted = self.submit()
        with patch.object(b, '_preflight', return_value={'auth': 'subscription'}), patch.object(b, '_run', return_value=(0, self.claude_output(is_error=True, result='quota exceeded secret'), '')):
            b.worker(submitted['job_id'])
        value = b.result(submitted['job_id'])
        self.assertEqual(value['state'], 'quota_limited')
        self.assertNotIn('secret', value['error']['message'])
        self.assertFalse((Path(submitted['job_dir']) / 'answer.md').exists())

    def test_worker_success_preserves_private_raw_and_answer(self):
        submitted = self.submit()
        with patch.object(b, '_preflight', return_value={'auth': 'subscription'}), patch.object(b, '_run', return_value=(0, self.claude_output(), '')):
            b.worker(submitted['job_id'])
        value = b.result(submitted['job_id'])
        self.assertEqual(value['state'], 'ready_for_review')
        self.assertEqual(value['answer'], 'Verified finding.')
        folder = Path(submitted['job_dir'])
        self.assertTrue((folder / 'provider.json').exists())
        self.assertEqual(stat.S_IMODE((folder / 'provider.json').stat().st_mode), 0o600)


if __name__ == '__main__':
    unittest.main()
