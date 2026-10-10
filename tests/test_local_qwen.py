"""Local-only contract checks; no downloads or real model inference."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bridge
import local_qwen as q
import server


def native_answer(**changes):
    answer = {'model': q.MODEL, 'message': {'role': 'assistant', 'content': '已整理供核對。'},
              'done': True, 'done_reason': 'stop', 'total_duration': 100,
              'load_duration': 20, 'prompt_eval_count': 10, 'prompt_eval_duration': 30,
              'eval_count': 5, 'eval_duration': 50}
    answer.update(changes)
    return answer


FAKE_RUNNER = '#!' + sys.executable + '''
import http.server,json,os,time
from pathlib import Path
models=Path(os.environ['OLLAMA_MODELS'])
root=models.parents[1]
manifest=models/'manifests/registry.ollama.ai/library/qwen3.5/9b-q4_K_M'
v2=models/'manifests-v2/ollama.com/library/qwen3.5/9b-q4_K_M'
import hashlib
digest=hashlib.sha256((v2 if v2.exists() else manifest).read_bytes()).hexdigest()
model='qwen3.5:9b-q4_K_M'
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self): self.answer()
 def do_POST(self): self.answer()
 def answer(self):
  n=int(self.headers.get('Content-Length','0'))
  payload=json.loads(self.rfile.read(n)) if n else None
  with (root/'calls.jsonl').open('a') as log:
   log.write(json.dumps({'route':self.path,'payload':payload,
    'using_shared_default_state':any((Path(os.environ['HOME'])/'.ollama'/name).exists() for name in ['config.json','id_ed25519']),
    'env':{k:os.environ.get(k) for k in ['HOME','OLLAMA_NO_CLOUD','OLLAMA_MODELS','OLLAMA_NUM_PARALLEL','OLLAMA_MAX_LOADED_MODELS','HTTPS_PROXY','OPENAI_API_KEY']}})+'\\n')
  if self.path=='/api/version': out={'version':'contract-test'}
  elif self.path=='/api/tags': out={'models':[{'name':model,'digest':digest}]}
  elif self.path=='/api/show': out={'details':{'quantization_level':'Q4_K_M','parameter_size':'9.7B','family':'qwen35'},'capabilities':['completion','thinking']}
  elif self.path=='/api/chat':
   mode=(root/'mode.txt').read_text() if (root/'mode.txt').exists() else 'success'
   if mode=='timeout': time.sleep(60)
   out={'model':model,'message':{'role':'assistant','content':'已整理供核對。'},'done':True,'done_reason':'stop','total_duration':100,'load_duration':20,'prompt_eval_count':10,'prompt_eval_duration':30,'eval_count':5,'eval_duration':50}
   if mode=='length': out['done_reason']='length'
  else: out={'error':'unexpected route'}
  raw=json.dumps(out,ensure_ascii=False).encode()
  self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
host,port=os.environ['OLLAMA_HOST'].split(':')
http.server.HTTPServer((host,int(port)),Handler).serve_forever()
'''


class LocalInstallation(unittest.TestCase):
    def setUp(self):
        self.binary_environment = mock.patch.dict(os.environ, {'AI_COOP_QWEN_BIN': ''})
        self.binary_environment.start()
        self.temp = tempfile.TemporaryDirectory(prefix='ai-coop-qwen-contract-')
        self.root = Path(self.temp.name)
        self.job = self.root / 'job'
        self.job.mkdir()
        (self.root / 'slots').mkdir()
        binary, models, manifest = q._paths(self.root)
        binary.parent.mkdir(parents=True)
        binary.write_text(FAKE_RUNNER)
        binary.chmod(0o700)
        manifest.parent.mkdir(parents=True)
        (models / 'blobs').mkdir()
        descriptors = []
        for kind, raw in (('config', b'{}'), ('model', b'fake-model-not-for-inference')):
            digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
            (models / 'blobs' / digest.replace(':', '-')).write_bytes(raw)
            descriptors.append({'mediaType': 'application/vnd.ollama.image.' + kind,
                                'digest': digest, 'size': len(raw)})
        manifest.write_text(json.dumps({'schemaVersion': 2, 'config': descriptors[0], 'layers': [descriptors[1]]}))
        with socket.socket() as temporary:
            temporary.bind(('127.0.0.1', 0))
            self.port = temporary.getsockname()[1]
        self.port_patch = mock.patch.object(q, 'PORT', self.port)
        self.port_patch.start()

    def tearDown(self):
        self.port_patch.stop()
        self.binary_environment.stop()
        self.temp.cleanup()

    def add_v2_wrapper(self):
        _, models, manifest = q._paths(self.root)
        original = manifest.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        blob = models / 'blobs' / ('sha256-' + digest)
        blob.write_bytes(original)
        v2 = models / 'manifests-v2/ollama.com/library/qwen3.5/9b-q4_K_M'
        v2.parent.mkdir(parents=True)
        v2.symlink_to(blob)
        anchor = json.loads(original)
        anchor['layers'].append({'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
                                 'digest': 'sha256:' + digest, 'size': len(original)})
        anchor.update({'runner': 'llamacpp', 'format': 'gguf'})
        manifest.write_text(json.dumps(anchor))
        return digest, blob, v2

    def test_v2_symlink_digest_differs_from_anchor_raw_sha_and_native_bare_hex_matches(self):
        digest, blob, v2 = self.add_v2_wrapper()
        status = q.status(self.root)
        _, _, anchor = q._paths(self.root)
        self.assertEqual(status['model_manifest_digest'], 'sha256:' + digest)
        self.assertEqual(status['model_manifest_raw_sha256'], hashlib.sha256(anchor.read_bytes()).hexdigest())
        self.assertNotEqual(status['model_manifest_digest'], 'sha256:' + status['model_manifest_raw_sha256'])
        self.assertEqual(status['model_manifest_canonical_path'], str(v2))
        parsed, _ = q.run('整理合成文字。', time.monotonic() + 5, self.job, self.root)
        self.assertEqual(parsed['local_runtime']['api_model_digest'], digest)
        self.assertEqual(parsed['local_runtime']['model_manifest_digest'], 'sha256:' + digest)
        self.assertEqual(parsed['local_runtime']['presence_penalty'], 0)

    def test_v2_symlink_content_hash_checked_even_when_blob_size_unchanged(self):
        digest, blob, v2 = self.add_v2_wrapper()
        original = blob.read_bytes()
        blob.write_bytes(b'[' + original[1:])
        with mock.patch.object(q.subprocess, 'Popen') as launched:
            with self.assertRaises(q.LocalQwenError) as caught:
                q.status(self.root)
        self.assertEqual(caught.exception.code, 'model_unavailable')
        launched.assert_not_called()

    def test_v2_symlink_outside_dedicated_blobs_rejected(self):
        digest, blob, v2 = self.add_v2_wrapper()
        outside = self.root / ('sha256-' + digest)
        outside.write_bytes(blob.read_bytes())
        v2.unlink()
        v2.symlink_to(outside)
        with self.assertRaises(q.LocalQwenError) as caught:
            q.status(self.root)
        self.assertEqual(caught.exception.code, 'model_unavailable')

    def test_status_never_launches_or_loads_a_model(self):
        with mock.patch.object(q.subprocess, 'Popen') as launched, mock.patch.object(q, '_http') as http:
            status = q.status(self.root)
        launched.assert_not_called()
        http.assert_not_called()
        self.assertTrue(status['available'])
        self.assertFalse(status['server_started'])
        self.assertEqual(status['requested_model'], q.MODEL)

    def test_incomplete_manifest_or_blob_rejected_before_start(self):
        _, models, manifest = q._paths(self.root)
        descriptor = json.loads(manifest.read_text())['layers'][0]
        (models / 'blobs' / descriptor['digest'].replace(':', '-')).write_text('broken')
        with mock.patch.object(q.subprocess, 'Popen') as launched:
            with self.assertRaises(q.LocalQwenError) as caught:
                q.run('任務', time.monotonic() + 3, self.job, self.root)
        self.assertEqual(caught.exception.code, 'model_unavailable')
        launched.assert_not_called()

    def test_occupied_endpoint_never_shared_or_stopped(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', self.port))
            listener.listen(1)
            with mock.patch.object(q.subprocess, 'Popen') as launched, mock.patch.object(q, '_http') as http:
                with self.assertRaises(q.LocalQwenError) as caught:
                    q.run('任務', time.monotonic() + 3, self.job, self.root)
            self.assertEqual(caught.exception.code, 'local_endpoint_busy')
            self.assertEqual(listener.getsockname()[1], self.port)
        launched.assert_not_called()
        http.assert_not_called()

    def test_real_local_http_roundtrip_fixed_payload_receipt_and_cleanup(self):
        shared_home = self.root / 'shared-user-home'
        (shared_home / '.ollama').mkdir(parents=True)
        (shared_home / '.ollama/config.json').write_text('unrelated shared settings')
        (shared_home / '.ollama/id_ed25519').write_text('synthetic shared identity sentinel')
        with mock.patch.dict(os.environ, {'HOME': str(shared_home), 'OPENAI_API_KEY': 'DUMMY_NEVER_FORWARD', 'HTTPS_PROXY': 'http://never.invalid'}):  # ai-coop-synthetic-secret
            parsed, native = q.run('只整理明示文字。', time.monotonic() + 5, self.job, self.root)
        self.assertEqual(parsed['answer'], '已整理供核對。')
        self.assertEqual(parsed['actual_model'], q.MODEL)
        self.assertEqual(parsed['usage']['input_tokens'], 10)
        self.assertEqual(parsed['local_runtime']['runner_version'], 'contract-test')
        self.assertTrue(parsed['local_runtime']['server_stopped'])
        self.assertEqual(native['done_reason'], 'stop')
        calls = [json.loads(line) for line in (self.root / 'calls.jsonl').read_text().splitlines()]
        self.assertEqual([call['route'] for call in calls], ['/api/version', '/api/tags', '/api/show', '/api/chat'])
        request = calls[-1]['payload']
        self.assertEqual(request['model'], q.MODEL)
        self.assertIs(request['think'], False)
        self.assertEqual(request['keep_alive'], 0)
        self.assertEqual(request['options']['num_ctx'], 16384)
        self.assertEqual(request['options']['num_predict'], 2048)
        self.assertEqual(request['options']['temperature'], 0)
        self.assertEqual(request['options']['presence_penalty'], 0)
        self.assertNotIn('tools', request)
        self.assertEqual(calls[-1]['env']['OLLAMA_NO_CLOUD'], '1')
        runner_home = self.root / 'runtime' / 'ollama-home'
        self.assertEqual(calls[-1]['env']['HOME'], str(runner_home))
        self.assertNotEqual(calls[-1]['env']['HOME'], str(shared_home))
        self.assertEqual(stat.S_IMODE(runner_home.stat().st_mode), 0o700)
        self.assertFalse(calls[-1]['using_shared_default_state'])
        self.assertEqual((shared_home / '.ollama/config.json').read_text(), 'unrelated shared settings')
        self.assertEqual((shared_home / '.ollama/id_ed25519').read_text(), 'synthetic shared identity sentinel')
        self.assertIsNone(calls[-1]['env']['OPENAI_API_KEY'])
        self.assertIsNone(calls[-1]['env']['HTTPS_PROXY'])
        self.assertFalse(q._port_busy())
        self.assertEqual(stat.S_IMODE((self.job / 'local-runner.log').stat().st_mode), 0o600)

    def test_incomplete_answer_stops_owned_runtime(self):
        (self.root / 'mode.txt').write_text('length')
        with self.assertRaises(q.LocalQwenError) as caught:
            q.run('任務', time.monotonic() + 5, self.job, self.root)
        self.assertEqual(caught.exception.code, 'incomplete_output')
        self.assertFalse(q._port_busy())
        raw = json.loads((self.job / 'provider.json').read_text())
        self.assertEqual(raw['done_reason'], 'length')
        self.assertEqual(stat.S_IMODE((self.job / 'provider.json').stat().st_mode), 0o600)
        self.assertFalse((self.job / 'answer.md').exists())

    def test_timeout_stops_owned_runtime_with_no_retry(self):
        (self.root / 'mode.txt').write_text('timeout')
        began = time.monotonic()
        with self.assertRaises(q.LocalQwenError) as caught:
            q.run('任務', began + 1.2, self.job, self.root)
        self.assertEqual(caught.exception.code, 'timeout')
        self.assertLess(time.monotonic() - began, 3)
        self.assertFalse(q._port_busy())
        calls = [json.loads(line) for line in (self.root / 'calls.jsonl').read_text().splitlines()]
        self.assertEqual(sum(call['route'] == '/api/chat' for call in calls), 1)

    def test_failed_ownership_proof_never_submits_model_request(self):
        with mock.patch.object(q, '_owns_endpoint', return_value=False), mock.patch.object(q, '_http') as http:
            with self.assertRaises(q.LocalQwenError) as caught:
                q.run('任務', time.monotonic() + 5, self.job, self.root)
        self.assertEqual(caught.exception.code, 'local_endpoint_unverified')
        http.assert_not_called()
        self.assertFalse(q._port_busy())


class LocalPayloadAndMCP(unittest.TestCase):
    def test_digest_normalization_accepts_only_bare_hex_or_sha256_prefix(self):
        digest = '0123456789abcdef' * 4
        self.assertEqual(q.normalize_digest(digest), 'sha256:' + digest)
        self.assertEqual(q.normalize_digest('sha256:' + digest), 'sha256:' + digest)
        self.assertEqual(q.normalize_digest(digest.upper()), 'sha256:' + digest)
        for bad in (None, [], {}, 1, 'sha256-' + digest, ' ' + digest, digest[:-1], 'sha256:' + 'z' * 64):
            with self.subTest(bad=bad):
                self.assertIsNone(q.normalize_digest(bad))

    def test_timeout_and_main_cleanup_signal_each_owned_group_once(self):
        process = types.SimpleNamespace(pid=424242, _qwen_cleanup_lock=threading.Lock(),
                                        _qwen_cleanup_complete=False)
        waits = []
        process.wait = lambda timeout: waits.append(timeout)
        process.poll = lambda: 0 if waits else None
        with mock.patch.object(q.os, 'killpg') as killed:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(q._stop_owned, process) for _ in range(2)]
                for future in futures:
                    future.result(1)
        self.assertEqual(killed.call_args_list, [mock.call(424242, signal.SIGTERM), mock.call(424242, signal.SIGKILL)])
        self.assertTrue(process._qwen_cleanup_complete)

    def test_bad_native_results_are_not_complete_answers(self):
        cases = [native_answer(done=False), native_answer(done_reason='length'),
                 native_answer(model='other-model'), native_answer(error='failed'),
                 native_answer(message={'role': 'assistant', 'content': ''}),
                 native_answer(message={'role': 'assistant', 'content': 'result', 'tool_calls': [{'function': {'name': 'run'}}]}),
                 native_answer(eval_count=0), native_answer(load_duration=True),
                 native_answer(prompt_eval_count=q.NUM_CTX)]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(q.LocalQwenError):
                q._parse(case)

    def test_qwen_mcp_provider_schema_and_no_settings_override(self):
        reply = server.handle({'id': 1, 'method': 'tools/list'})
        submit = next(tool for tool in reply['result']['tools'] if tool['name'] == 'ai_submit')
        self.assertIn('qwen', submit['inputSchema']['properties']['provider']['enum'])
        for mode in ('research', 'code'):
            with self.assertRaises(bridge.BridgeError):
                bridge.validate_params({'provider': 'qwen', 'mode': mode, 'prompt': 'Task'})
        for field in ('model', 'base_url', 'endpoint', 'tools'):
            with mock.patch.object(bridge.subprocess, 'Popen') as launched:
                reply = server.handle({'id': 2, 'method': 'tools/call', 'params': {'name': 'ai_submit',
                    'arguments': {'provider': 'qwen', 'prompt': 'Task', field: 'override'}}})
            self.assertTrue(reply['result']['isError'])
            launched.assert_not_called()

    def test_full_prompt_utf8_boundary_includes_instruction_files_and_prior(self):
        checked = bridge.validate_params({'provider': 'qwen', 'prompt': 'a'})
        overhead = len(bridge._prompt(checked).encode()) - 1
        checked = bridge.validate_params({'provider': 'qwen', 'prompt': 'a' * (q.MAX_PROMPT_BYTES - overhead)})
        self.assertEqual(len(bridge._prompt(checked).encode()), q.MAX_PROMPT_BYTES)
        with self.assertRaises(bridge.BridgeError) as caught:
            bridge.validate_params({'provider': 'qwen', 'prompt': 'a' * (q.MAX_PROMPT_BYTES - overhead + 1)})
        self.assertEqual(caught.exception.code, 'local_input_limit')
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'only.txt'
            source.write_text('界' * 4000)
            with mock.patch.object(bridge.subprocess, 'Popen') as launched:
                with self.assertRaises(bridge.BridgeError):
                    bridge.submit({'provider': 'qwen', 'prompt': '分類', 'files': [str(source)]})
            launched.assert_not_called()
        checked['previous_answer'] = 'x'
        with self.assertRaises(bridge.BridgeError):
            bridge._prompt(checked)

    def test_local_worker_uses_existing_job_and_native_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'runtime'
            with mock.patch.object(bridge, 'ROOT', root), \
                 mock.patch.object(bridge.subprocess, 'Popen', return_value=types.SimpleNamespace(pid=os.getpid())), \
                 mock.patch.object(bridge, '_preflight', return_value={'available': True}), \
                 mock.patch.object(q, 'run', return_value=(dict(q._parse(native_answer()), local_runtime={'server_stopped': True}), native_answer())) as run:
                submitted = bridge.submit({'provider': 'qwen', 'prompt': '整理文字', 'task_key': 'local/stable'})
                reused = bridge.submit({'provider': 'qwen', 'prompt': '整理文字', 'task_key': 'local/stable'})
                self.assertEqual(reused['job_id'], submitted['job_id'])
                self.assertTrue(reused['reused'])
                bridge.worker(submitted['job_id'])
                reply = server.execute('ai_result', {'job_id': submitted['job_id']})
                self.assertEqual(reply['state'], 'ready_for_review')
                self.assertEqual(reply['actual_model'], q.MODEL)
                self.assertEqual(reply['tool_actions'], [])
                self.assertEqual(reply['changed_files'], [])
                self.assertIn('provider:qwen', reply['scopes'])
                self.assertTrue((root / 'jobs' / submitted['job_id'] / 'provider.json').exists())
                run.assert_called_once()

    def test_second_local_job_queues_without_holding_cloud_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'runtime'
            first_entered, release_first, second_entered = threading.Event(), threading.Event(), threading.Event()
            def local_run(prompt, deadline, job, runtime):
                if 'first' in prompt:
                    first_entered.set()
                    self.assertTrue(release_first.wait(3))
                else:
                    second_entered.set()
                return q._parse(native_answer()), native_answer()
            with mock.patch.object(bridge, 'ROOT', root), \
                 mock.patch.object(bridge.subprocess, 'Popen', return_value=types.SimpleNamespace(pid=os.getpid())), \
                 mock.patch.object(bridge, '_preflight', return_value={'available': True}), \
                 mock.patch.object(q, 'run', side_effect=local_run):
                first = bridge.submit({'provider': 'qwen', 'prompt': 'first'})
                second = bridge.submit({'provider': 'qwen', 'prompt': 'second'})
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    future1 = executor.submit(bridge.worker, first['job_id'])
                    self.assertTrue(first_entered.wait(2))
                    future2 = executor.submit(bridge.worker, second['job_id'])
                    try:
                        self.assertFalse(second_entered.wait(0.25))
                        # One global slot is still available to a cloud worker.
                        cloud_slot = bridge._slot(time.monotonic() + 0.5)
                        os.close(cloud_slot)
                        self.assertEqual(bridge.result(second['job_id'])['state'], 'queued')
                    finally:
                        release_first.set()
                    future1.result(3)
                    future2.result(3)
                self.assertTrue(second_entered.is_set())
                self.assertEqual(json.loads((root / 'scopes.json').read_text()), {})


if __name__ == '__main__':
    unittest.main()
