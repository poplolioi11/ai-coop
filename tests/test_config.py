"""Offline configuration and privacy contracts; no provider programs run."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bridge
import coop_config as config


class Configuration(unittest.TestCase):
    def test_defaults_keep_runtime_outside_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            script = ('import json,coop_config as c;print(json.dumps({"home":str(c.HOME),'
                '"runtime":str(c.RUNTIME_ROOT),"source":str(c.SOURCE_ROOT)}))')
            output = subprocess.check_output([sys.executable, '-c', script],
                cwd=str(config.SOURCE_ROOT), env={'HOME': str(home)}, text=True)
            actual = json.loads(output)
            self.assertEqual(actual['runtime'], str((home / '.local/state/ai-coop').resolve()))
            self.assertNotEqual(actual['runtime'], actual['source'])

    def test_explicit_paths_are_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {'HOME': str(root), 'AI_COOP_RUNTIME': str(root / 'private-runtime'),
                'AI_COOP_GEMINI_SETTINGS': str(root / 'settings.json'),
                'AI_COOP_GEMINI_AGENTS': str(root / 'agents')}
            script = ('import json,coop_config as c;print(json.dumps([str(c.RUNTIME_ROOT),'
                'str(c.GEMINI_SETTINGS),str(c.GEMINI_AGENTS_DIR)]))')
            output = subprocess.check_output([sys.executable, '-c', script],
                cwd=str(config.SOURCE_ROOT), env=env, text=True)
            self.assertEqual(json.loads(output), [str(Path(env[key]).resolve()) for key in
                ('AI_COOP_RUNTIME', 'AI_COOP_GEMINI_SETTINGS', 'AI_COOP_GEMINI_AGENTS')])

    def test_relative_settings_and_interpreters_are_rejected(self):
        with mock.patch.dict(os.environ, {'AI_COOP_TEST_PATH': 'relative'}):
            with self.assertRaises(ValueError):
                config._path_setting('AI_COOP_TEST_PATH', config.HOME)
        with mock.patch.dict(os.environ, {'AI_COOP_PYTHON': 'python3'}):
            with self.assertRaises(ValueError):
                config.python_path()

    def test_explicit_binary_and_path_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            explicit = str((Path(tmp) / 'official-client').resolve())
            with mock.patch.dict(os.environ, {'AI_COOP_CLAUDE_BIN': explicit}):
                self.assertEqual(config.binary_path('claude'), explicit)
            with mock.patch.dict(os.environ, {'AI_COOP_CLAUDE_BIN': ''}), \
                 mock.patch.object(config.shutil, 'which', return_value=explicit):
                self.assertEqual(config.binary_path('claude'), explicit)

    def test_worker_configuration_is_forwarded_but_secrets_are_not(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(bridge, 'ROOT', Path(tmp)), \
             mock.patch.dict(os.environ, {'OPENAI_API_KEY': 'DUMMY_SECRET',  # ai-coop-synthetic-secret
                'ANTHROPIC_API_KEY': 'DUMMY_SECRET', 'HTTPS_PROXY': 'synthetic-proxy',  # ai-coop-synthetic-secret
                'AI_COOP_UNRELATED_TOKEN': 'DUMMY_SECRET', 'AI_COOP_PATH': '/usr/bin:/bin'}):  # ai-coop-synthetic-secret
            environment = bridge._env()
            self.assertEqual(environment['AI_COOP_RUNTIME'], tmp)
            self.assertEqual(environment['AI_COOP_PATH'], '/usr/bin:/bin')
            self.assertIn('AI_COOP_GEMINI_SETTINGS', environment)
            self.assertIn('AI_COOP_GEMINI_AGENTS', environment)
            self.assertIn('AI_COOP_PYTHON', environment)
            self.assertNotIn('DUMMY_SECRET', environment.values())
            self.assertNotIn('HTTPS_PROXY', environment)

    def test_detached_worker_runs_source_with_private_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'private-runtime'
            with mock.patch.object(bridge, 'ROOT', root), \
                 mock.patch.object(bridge.subprocess, 'Popen', return_value=types.SimpleNamespace(pid=os.getpid())) as launch:
                submitted = bridge.submit({'provider': 'claude', 'prompt': 'Synthetic example.'})
            self.assertEqual(launch.call_args.kwargs['cwd'], str(root))
            self.assertEqual(launch.call_args.kwargs['env']['AI_COOP_RUNTIME'], str(root))
            self.assertEqual(launch.call_args.args[0][1], str(config.SOURCE_ROOT / 'bridge.py'))
            self.assertTrue(Path(submitted['job_dir']).is_relative_to(root))

    def test_status_does_not_query_account_usage(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(bridge, 'ROOT', Path(tmp)), \
             mock.patch.object(bridge, '_preflight', return_value={'auth': 'synthetic first-party sign-in'}), \
             mock.patch.object(bridge, '_run') as run:
            result = bridge.status()
        run.assert_not_called()
        self.assertNotIn('usage_counts', json.dumps(result))
        self.assertNotIn('subscription_type', json.dumps(result))

    def test_claude_auth_response_does_not_expose_plan(self):
        native = {'loggedIn': True, 'authMethod': 'claude.ai', 'apiProvider': 'firstParty',
            'subscriptionType': 'synthetic-plan', 'email': 'synthetic@example.invalid', 'balance': 99}
        with mock.patch.object(bridge, 'BINARIES', {'claude': sys.executable}), \
             mock.patch.object(bridge, '_run', return_value=(0, json.dumps(native), '')):
            result = bridge._preflight('claude', 'analyze', config.SOURCE_ROOT, float('inf'))
        self.assertNotIn('synthetic-plan', json.dumps(result))
        self.assertNotIn('synthetic@example.invalid', json.dumps(result))
        self.assertNotIn('balance', result)


if __name__ == '__main__':
    unittest.main()
