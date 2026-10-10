import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import configure_domains as domains
import gemini_tool_guard as guard
import setup_gemini as setup


class GeminiSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.agents = self.root / 'agent files with spaces'
        self.settings = self.root / 'settings.json'
        self.settings.write_text(json.dumps({'ui': {'synthetic': 'keep'}, 'permissions': {'allow': [], 'deny': []}}))

    def tearDown(self):
        self.temp.cleanup()

    def test_default_is_preview_without_configuration_reads_or_writes(self):
        with patch.object(setup, 'GEMINI_AGENTS_DIR', self.agents), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('Preview must not read configuration')), \
                patch.object(Path, 'read_text', side_effect=AssertionError('Preview must not read configuration')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(setup.main([]), 0)
        self.assertFalse(self.agents.exists())
        result = json.loads(output.getvalue())
        self.assertFalse(result['installed'])
        self.assertFalse(result['settings_changed'])
        self.assertEqual(len(result['files']), 4)

    def test_install_is_explicit_private_idempotent_and_preserves_settings(self):
        original = self.settings.read_bytes()
        with patch.object(setup, 'GEMINI_AGENTS_DIR', self.agents), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(setup.main(['--install']), 0)
        self.assertEqual(self.settings.read_bytes(), original)
        files = list(self.agents.iterdir())
        self.assertEqual(len(files), 4)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in files))
        self.assertEqual(setup.install_agents(self.agents)['created_files'], 0)

    def test_conflicting_file_blocks_every_write(self):
        self.agents.mkdir()
        custom = self.agents / 'ai-coop-research-hooks.json'
        custom.write_text('a synthetic custom hook')
        with self.assertRaises(ValueError):
            setup.install_agents(self.agents)
        self.assertEqual(list(self.agents.iterdir()), [custom])
        self.assertEqual(custom.read_text(), 'a synthetic custom hook')

    def test_symlink_target_and_directory_are_rejected(self):
        self.agents.mkdir()
        target = self.agents / 'ai-coop-analyze.md'
        target.symlink_to(self.settings)
        with self.assertRaises(ValueError):
            setup.install_agents(self.agents)
        original = self.settings.read_bytes()
        link = self.root / 'agent-link'
        link.symlink_to(self.agents, target_is_directory=True)
        with self.assertRaises(ValueError):
            setup.install_agents(link)
        self.assertEqual(self.settings.read_bytes(), original)

    def test_shell_command_preserves_spaces_and_metacharacters(self):
        interpreter = self.root / 'python bin' / 'python3'
        guard_path = self.root / "guard files # literal $text's" / 'gemini_tool_guard.py'
        command = setup.hook_command('research', guard_path, interpreter)
        self.assertEqual(shlex.split(command), [str(interpreter), str(guard_path), '--mode', 'research'])
        directory = self.root / 'agents # with: spaces'
        files = setup.render_agents(directory, guard_path, interpreter)
        text = files[directory / 'ai-coop-research.md'].decode()
        hook_scalar = next(line[4:] for line in text.splitlines() if line.startswith('  - "'))
        self.assertEqual(json.loads(hook_scalar), str(directory / 'ai-coop-research-hooks.json'))


class GeminiGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.settings = self.root / 'synthetic-settings.json'
        self.settings.write_text(json.dumps({'permissions': {'allow': ['read_url(example.com)']}}))
        self.jobs = self.root / 'runtime' / 'jobs'
        self.jobs.mkdir(parents=True)
        self.audit = self.root / 'runtime' / 'guard-audit.ndjson'
        self.patches = [patch.object(guard, 'SETTINGS', self.settings),
                        patch.object(guard, 'JOBS', self.jobs), patch.object(guard, 'AUDIT', self.audit)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def call(self, name, **args):
        return {'toolCall': {'name': name, 'args': args}}

    def test_analysis_denies_all_tools_and_malformed_input_fails_closed(self):
        for payload in (self.call('search_web', query='synthetic query'), None, [], {'toolCall': {'name': 'search_web'}}):
            self.assertEqual(guard.evaluate('analyze', payload)['decision'], 'deny')
            if payload != self.call('search_web', query='synthetic query'):
                self.assertEqual(guard.evaluate('research', payload)['decision'], 'deny')

    def test_research_limits_tools_hosts_protocol_and_credentials(self):
        with patch.object(guard, 'resolves_publicly', return_value=True):
            self.assertEqual(guard.evaluate('research', self.call('search_web', query='query'))['decision'], 'allow')
            self.assertEqual(guard.evaluate('research', self.call('read_url_content', Url='https://docs.example.com/source'))['decision'], 'allow')
            synthetic_auth_url = 'https://' + 'owner:password' + '@example.com/'
            for url in ('http://example.com/', 'https://example.com:444/', synthetic_auth_url,
                        'https://example.com.evil.example/', 'https://localhost/', 'https://127.0.0.1/',
                        'https://example.com/\ncontrol', 'https://example.com:bad/'):
                with self.subTest(url=url):
                    self.assertEqual(guard.evaluate('research', self.call('read_url_content', Url=url))['decision'], 'deny')
            self.assertEqual(guard.evaluate('research', self.call('run_command', command='anything'))['decision'], 'deny')
        with patch.object(guard, 'resolves_publicly', return_value=False):
            self.assertEqual(guard.evaluate('research', self.call('read_url_content', Url='https://example.com/'))['decision'], 'deny')

    def test_allowlist_rejects_malformed_or_symlink_settings(self):
        self.settings.write_text('{malformed')
        self.assertEqual(guard.approved_domains(), frozenset())
        self.settings.unlink()
        regular = self.root / 'regular.json'
        regular.write_text(json.dumps({'permissions': {'allow': ['read_url(example.com)']}}))
        self.settings.symlink_to(regular)
        self.assertEqual(guard.approved_domains(), frozenset())

    def test_private_dns_addresses_are_rejected_without_network_access(self):
        public = (None, None, None, None, ('93.184.216.34', 443))
        private = (None, None, None, None, ('127.0.0.1', 443))
        with patch.object(guard.socket, 'getaddrinfo', return_value=[public]):
            self.assertTrue(guard.resolves_publicly('example.com'))
        with patch.object(guard.socket, 'getaddrinfo', return_value=[public, private]):
            self.assertFalse(guard.resolves_publicly('example.com'))

    def test_audit_uses_private_runtime_and_does_not_store_arguments(self):
        job_id = '20000101' + 'T000000Z-' + 'abcdef123456'
        job = self.jobs / job_id
        job.mkdir()
        payload = self.call('search_web', query='synthetic-sensitive-text')
        with patch.dict(os.environ, {'AI_COOP_JOB_ID': job_id}):
            result = guard.record('research', payload, {'decision': 'allow', 'reason': 'test'})
        self.assertEqual(result['decision'], 'allow')
        audit = job / 'hook-audit.ndjson'
        self.assertNotIn('synthetic-sensitive-text', audit.read_text())
        self.assertEqual(stat.S_IMODE(audit.stat().st_mode), 0o600)
        self.assertEqual(json.loads(audit.read_text())['job_id'], job_id)

    def test_unrecordable_decision_is_denied(self):
        with patch.object(guard, 'current_job_id', return_value=None), \
                patch.object(guard, 'AUDIT', self.root / 'missing' / 'audit.ndjson'):
            result = guard.record('research', self.call('search_web', query='query'), {'decision': 'allow', 'reason': 'test'})
        self.assertEqual(result['decision'], 'deny')


class DomainConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.runtime = self.root / 'private-runtime'
        self.settings = self.root / 'synthetic-settings.json'
        self.settings.write_text(json.dumps({'ui': {'synthetic': 'keep'}, 'permissions': {'allow': [], 'deny': []}}))
        self.patches = [patch.object(domains, 'ROOT', self.runtime), patch.object(domains, 'CONFIG', self.settings),
                        patch.object(domains, 'resolves_publicly', return_value=True)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def test_explicit_add_preserves_settings_and_backups_stay_in_runtime(self):
        original = self.settings.read_bytes()
        result = domains.add('EXAMPLE.COM.')
        self.assertTrue(result['changed'])
        value = json.loads(self.settings.read_text())
        self.assertEqual(value['ui'], {'synthetic': 'keep'})
        self.assertEqual(value['permissions']['allow'], ['read_url(example.com)'])
        backups = list((self.runtime / 'backups').iterdir())
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)
        self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)
        self.assertFalse(domains.add('example.com')['changed'])
        self.assertEqual(list((self.runtime / 'backups').iterdir()), backups)

    def test_wildcard_deny_is_preserved_and_not_bypassed(self):
        for rule in ('read_url(*)', '*'):
            self.settings.write_text(json.dumps({'permissions': {'deny': [rule], 'allow': []}}))
            original = self.settings.read_bytes()
            with self.assertRaises(ValueError):
                domains.add('example.com')
            self.assertEqual(self.settings.read_bytes(), original)
            self.assertFalse((self.runtime / 'backups').exists())

    def test_invalid_hosts_are_rejected_before_settings_access(self):
        self.settings.unlink()
        for value in ('https://example.com/', '*.example.com', '127.0.0.1', 'host.local', 'host.lan', 'host.home', 'host.onion'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                domains.add(value)
        self.assertFalse(self.runtime.exists())

    def test_malformed_permission_lists_and_symlinks_are_rejected(self):
        self.settings.write_text(json.dumps({'permissions': {'allow': 'wrong-type'}}))
        original = self.settings.read_bytes()
        with self.assertRaises(ValueError):
            domains.add('example.com')
        self.assertEqual(self.settings.read_bytes(), original)
        self.settings.unlink()
        destination = self.root / 'destination.json'
        destination.write_text('{}')
        self.settings.symlink_to(destination)
        with self.assertRaises(ValueError):
            domains.add('example.com')
        self.assertEqual(destination.read_text(), '{}')


if __name__ == '__main__':
    unittest.main()
