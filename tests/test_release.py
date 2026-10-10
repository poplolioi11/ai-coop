"""Synthetic privacy fixtures; no production account data or task records."""
from contextlib import redirect_stderr
import hashlib
import importlib.util
from io import StringIO
from pathlib import Path
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("release_tested", Path(__file__).parents[1] / "verify_release.py")
release = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = release
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in release.HASHED_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Synthetic public fixture.\n", encoding="utf-8")
        self.manifest()

    def tearDown(self):
        self.temp.cleanup()

    def manifest(self):
        lines = [f"{hashlib.sha256((self.root / name).read_bytes()).hexdigest()}  {name}\n"
                 for name in sorted(release.HASHED_FILES)]
        (self.root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")

    def rules(self, **kwargs):
        return {finding.rule for finding in release.inspect_release(self.root, **kwargs)}

    def test_complete_whitelisted_fixture_verifies(self):
        self.assertEqual(release.inspect_release(self.root), [])
        self.assertNotIn("SHA256SUMS", release.HASHED_FILES)

    def test_missing_file_and_checksum_change_fail(self):
        (self.root / "README.md").write_text("Changed public fixture.\n", encoding="utf-8")
        self.assertIn("checksum-mismatch", self.rules())
        (self.root / "README.md").unlink()
        self.assertIn("missing-public-file", self.rules())
        self.assertIn("missing-hashed-file", self.rules())

    def test_unknown_and_hidden_private_files_fail(self):
        for name in ("unapproved.txt", ".env", "oauth_creds.json"):
            with self.subTest(name=name):
                path = self.root / name
                path.write_text("Synthetic file which must not be read.\n", encoding="utf-8")
                self.assertIn("unapproved-file", self.rules())
                path.unlink()

    def test_runtime_and_auth_directories_fail_without_scanning(self):
        for name in ("runtime", "jobs", "backups", "private", "sources", ".gemini"):
            with self.subTest(name=name):
                folder = self.root / name
                folder.mkdir()
                (folder / "unknown.json").write_bytes(b"\xff")
                findings = release.inspect_release(self.root)
                self.assertTrue(any(f.path == name and f.rule == "private-runtime-or-auth-path" for f in findings))
                self.assertFalse(any(f.path.startswith(name + "/") for f in findings))
                (folder / "unknown.json").unlink()
                folder.rmdir()

    def test_git_and_python_caches_are_not_public_entries(self):
        for name in (".git", "tests/__pycache__"):
            folder = self.root / name
            folder.mkdir()
            (folder / "ignored.bin").write_bytes(b"\xff")
        self.assertEqual(release.inspect_release(self.root), [])
        self.assertFalse(any("__pycache__" in name or name.startswith(".git/") for name in release.PUBLIC_FILES))

    def test_symlinks_are_rejected_including_ignored_directory_names(self):
        target = self.root / "README.md"
        for name in (".git", "__pycache__", "unexpected-link"):
            with self.subTest(name=name):
                link = self.root / name
                link.symlink_to(target)
                self.assertIn("symlink", self.rules())
                link.unlink()
        target.unlink()
        target.symlink_to(self.root / "LICENSE")
        self.assertIn("symlink", self.rules())
        self.assertIn("missing-public-file", self.rules())

    def test_binary_and_control_characters_fail(self):
        path = self.root / "README.md"
        path.write_bytes(b"\xff")
        self.assertIn("binary-or-invalid-utf8", self.rules())
        path.write_bytes(b"binary\x00fixture")
        self.assertIn("binary-control-character", self.rules())

    def test_oversized_text_is_rejected(self):
        (self.root / "README.md").write_bytes(b"x" * (release.MAX_FILE_BYTES + 1))
        self.assertIn("oversized-file", self.rules())

    def test_manifest_is_strict_and_cannot_expand_whitelist(self):
        manifest = self.root / "SHA256SUMS"
        valid = manifest.read_text(encoding="utf-8")
        cases = [
            ("0" * 64 + "  ../private.txt\n", "unapproved-manifest-entry"),
            (valid.splitlines()[0] + "\n", "duplicate-manifest-entry"),
            ("invalid manifest line\n", "invalid-manifest-line"),
            ("0" * 64 + "  SHA256SUMS\n", "unapproved-manifest-entry"),
        ]
        for extra, rule in cases:
            with self.subTest(rule=rule):
                manifest.write_text(valid + extra, encoding="utf-8")
                self.assertIn(rule, self.rules())
        manifest.write_text("\n".join(valid.splitlines()[1:]) + "\n", encoding="utf-8")
        self.assertIn("missing-manifest-entry", self.rules())

    def test_personal_paths_are_rejected_in_tests_and_examples(self):
        synthetic_path = "/Users/" + "synthetic-person/input.txt"
        for name in ("tests/test_bridge.py", "examples/task.txt", "README.md"):
            with self.subTest(name=name):
                findings = release.scan_text(name, "public first line\n" + synthetic_path)
                self.assertEqual(findings, [release.Finding(name, 2, "personal-home-path")])
        self.assertTrue(release.scan_text("README.md", "/home/" + "synthetic-person/input.txt"))
        windows_path = "C:" + chr(92) + "Users" + chr(92) + "synthetic-person"
        self.assertTrue(release.scan_text("README.md", windows_path))
        self.assertTrue(release.scan_text("README.md", windows_path.replace(chr(92), chr(92) * 2)))

    def test_credential_formats_are_rejected_without_printing_values(self):
        synthetic_tokens = [
            "sk-" + "A" * 30,
            "ghp_" + "B" * 35,
            "AIza" + "C" * 35,
            "AKIA" + "A" * 16,
            "glpat-" + "B" * 25,
            "hf_" + "C" * 25,
            "ya29." + "D" * 25,
            "Bearer " + "D" * 30,
            "eyJ" + "E" * 15 + "." + "F" * 15 + "." + "G" * 15,
            "-----BEGIN " + "PRIVATE KEY-----",
        ]
        for synthetic in synthetic_tokens:
            with self.subTest(kind=synthetic[:4]):
                findings = release.scan_text("tests/test_bridge.py", synthetic)
                self.assertTrue(findings)
                self.assertTrue(all(synthetic not in str(finding) for finding in findings))

    def test_synthetic_secret_exception_is_narrow_and_explicit(self):
        assignment = "API_KEY = 'DUMMY_NOT_A_REAL_CREDENTIAL'"  # ai-coop-synthetic-secret
        self.assertTrue(release.scan_text("tests/test_bridge.py", assignment))
        self.assertEqual(release.scan_text("tests/test_bridge.py", assignment + " # " + release.SYNTHETIC_MARKER), [])
        real_shaped = "API_KEY = '" + "sk-" + "A" * 30 + "' # " + release.SYNTHETIC_MARKER
        rules = {f.rule for f in release.scan_text("tests/test_bridge.py", real_shaped)}
        self.assertIn("provider-token", rules)
        self.assertIn("credential-assignment", rules)

    def test_personal_email_price_plan_and_receipt_are_rejected(self):
        cases = [
            ("synthetic-person@" + "personal.test", "personal-email"),
            ("USD " + "20", "account-price"),
            ("Claude " + "Max", "named-subscription-plan"),
            ("20000101" + "T000000Z-" + "abcdefff", "private-job-receipt"),
            ("session_id = '" + "00000000-0000-0000-0000-000000000000" + "'", "private-session-receipt"),
        ]
        for content, rule in cases:
            with self.subTest(rule=rule):
                self.assertIn(rule, {finding.rule for finding in release.scan_text("README.md", content)})
        self.assertEqual(release.scan_text("examples/task.txt", "sample@example.com"), [])

    def test_cli_failure_output_never_contains_matched_secret(self):
        synthetic = "ghp_" + "Z" * 35
        (self.root / "README.md").write_text(synthetic, encoding="utf-8")
        self.manifest()
        output = StringIO()
        with redirect_stderr(output):
            self.assertEqual(release.main([str(self.root)]), 1)
        self.assertNotIn(synthetic, output.getvalue())
        self.assertIn("README.md:1: provider-token", output.getvalue())


if __name__ == "__main__":
    unittest.main()
