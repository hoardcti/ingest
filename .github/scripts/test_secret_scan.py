#!/usr/bin/env python3
"""Tests for secret_scan.py.

Run with: python -m unittest discover -s .github/scripts -v

Fake credentials are assembled at runtime rather than written as literals, so
this file stays clean under the scanner's own tree scan.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import secret_scan as scanner

GH_TOKEN = "ghp_" + "a" * 36
AWS_KEY = "AKIA" + "IOSFODNN7ABCDEFG"
HIGH_ENTROPY = "Xk29Lm4pQr7Zt1Wv8Yb3Nc6Hd5Jf0Ge2Ai"


class AllowlistScoping(unittest.TestCase):
    """The allowlist must consider the matched value, never the whole line.

    Regression: an unanchored `(?i)test|example|...` line filter meant that
    `latest_token`, `protest`, `greatest` and friends silently suppressed real
    credentials sitting on the same line.
    """

    def test_unrelated_word_containing_test_does_not_suppress(self):
        for name in ("latest_token", "PROTEST", "greatest_key", "contest"):
            with self.subTest(name=name):
                kinds, _ = scanner.scan_line("src/app.py", f'{name} = "{GH_TOKEN}"')
                self.assertIn("GitHub Token", kinds)

    def test_word_example_in_variable_name_does_not_suppress(self):
        kinds, _ = scanner.scan_line("src/app.py", f'examples_token = "{GH_TOKEN}"')
        self.assertIn("GitHub Token", kinds)

    def test_known_vendor_dummy_value_is_ignored(self):
        kinds, _ = scanner.scan_line("src/app.py", 'key = "AKIAIOSFODNN7EXAMPLE"')
        self.assertEqual([], kinds)

    def test_templated_placeholder_is_ignored(self):
        for value in ("${AWS_KEY}", "{{ aws_key }}", "<your-token-here>", "xxxxxxxxxx"):
            with self.subTest(value=value):
                kinds, _ = scanner.scan_line("src/app.py", f'api_key = "{value}"')
                self.assertEqual([], kinds)

    def test_pragma_suppresses_the_line(self):
        line = f'token = "{GH_TOKEN}"  # pragma: allowlist secret'
        kinds, _ = scanner.scan_line("src/app.py", line)
        self.assertEqual([], kinds)


class PathScoping(unittest.TestCase):
    """Heuristics relax in test/doc paths; provider formats never do."""

    def test_generic_assignment_relaxed_in_test_paths(self):
        line = 'password = "sup3rl0ngf4kepassword"'
        self.assertEqual([], scanner.scan_line("tests/test_login.py", line)[0])
        self.assertIn(
            "Generic API Key/Secret assignment",
            scanner.scan_line("src/login.py", line)[0],
        )

    def test_real_token_format_still_flagged_in_test_paths(self):
        kinds, _ = scanner.scan_line("tests/fixtures/creds.py", f'tok = "{GH_TOKEN}"')
        self.assertIn("GitHub Token", kinds)

    def test_entropy_relaxed_in_docs(self):
        line = f'value = "{HIGH_ENTROPY}"'
        self.assertEqual([], scanner.scan_line("docs/guide.md", line)[0])

    def test_test_files_are_exempt_by_filename_not_just_directory(self):
        """Tests often sit beside the code they exercise, not under tests/."""
        line = f'value = "{HIGH_ENTROPY}"'
        for path in (
            "src/test_parser.py",
            "src/parser_test.go",
            "src/conftest.py",
            "src/parser.test.ts",
            "src/parser.spec.tsx",
        ):
            with self.subTest(path=path):
                self.assertEqual([], scanner.scan_line(path, line)[0])

    def test_similarly_named_non_test_file_is_not_exempt(self):
        # "latest.py" must not inherit the exemption meant for "test_*.py".
        kinds, _ = scanner.scan_line("src/latest.py", f'value = "{HIGH_ENTROPY}"')
        self.assertIn("High-entropy string", kinds)


class Redaction(unittest.TestCase):
    """Findings must never republish the credential into public CI logs.

    Regression: the previous `redact()` only truncated to 60 characters, so any
    secret shorter than that was printed verbatim.
    """

    def test_masked_line_excludes_the_secret(self):
        line = f'GITHUB_TOKEN = "{GH_TOKEN}"'
        kinds, spans = scanner.scan_line("src/app.py", line)
        self.assertTrue(kinds)
        masked = scanner.mask_line(line, spans)
        self.assertNotIn(GH_TOKEN, masked)
        self.assertIn("redacted", masked)
        self.assertIn("GITHUB_TOKEN", masked)  # context is preserved

    def test_report_output_excludes_the_secret(self):
        finding = scanner.record("src/app.py", 12, f'aws = "{AWS_KEY}"')
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            scanner.report(finding, "diff")
        self.assertNotIn(AWS_KEY, buffer.getvalue())

    def test_mask_keeps_only_a_short_prefix(self):
        masked = scanner.mask(GH_TOKEN)
        self.assertTrue(masked.startswith("ghp_"))
        self.assertNotIn("a" * 10, masked)


class EntropyDetection(unittest.TestCase):
    def test_unquoted_env_style_assignment_is_detected(self):
        kinds, _ = scanner.scan_line("deploy/.env.prod", f"SESSION_KEY={HIGH_ENTROPY}")
        self.assertIn("High-entropy string", kinds)

    def test_ordinary_prose_is_not_flagged(self):
        line = "This sentence is long enough to exceed thirty-two characters easily."
        self.assertEqual([], scanner.scan_line("src/app.py", line)[0])

    def test_hex_never_reaches_the_threshold(self):
        # Documents the documented ceiling: hex entropy maxes at 4.0 bits/char.
        self.assertLess(scanner.shannon_entropy("0123456789abcdef" * 4), 4.5)


class DiffParsing(unittest.TestCase):
    def _diff(self, body):
        return "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n" + body

    def test_line_numbers_follow_hunk_headers(self):
        diff = self._diff(f'+++ b/src/app.py\n@@ -0,0 +42,1 @@\n+token = "{GH_TOKEN}"\n')
        findings = scanner.scan_diff(diff)
        self.assertEqual(1, len(findings))
        self.assertEqual(42, findings[0].line_no)
        self.assertEqual("src/app.py", findings[0].path)

    def test_added_line_starting_with_plus_plus_does_not_shift_numbering(self):
        """Regression: content beginning with `++` rendered as `+++` in the diff
        and was skipped without advancing the counter, shifting every later line."""
        diff = self._diff(
            "+++ b/CHANGELOG.md\n"
            "@@ -0,0 +1,3 @@\n"
            "++ nested bullet\n"
            "+ ordinary line\n"
            f'+token = "{GH_TOKEN}"\n'
        )
        findings = scanner.scan_diff(diff)
        self.assertEqual(1, len(findings))
        self.assertEqual(3, findings[0].line_no)

    def test_removed_lines_are_ignored(self):
        diff = self._diff(f'+++ b/src/app.py\n@@ -1,1 +0,0 @@\n-token = "{GH_TOKEN}"\n')
        self.assertEqual([], scanner.scan_diff(diff))

    def test_deletion_to_dev_null_is_ignored(self):
        diff = self._diff(f'+++ /dev/null\n@@ -1,1 +0,0 @@\n-token = "{GH_TOKEN}"\n')
        self.assertEqual([], scanner.scan_diff(diff))

    def test_clean_diff_produces_no_findings(self):
        diff = self._diff("+++ b/src/app.py\n@@ -0,0 +1,1 @@\n+import os\n")
        self.assertEqual([], scanner.scan_diff(diff))


class Cli(unittest.TestCase):
    def test_diff_mode_requires_shas(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = scanner.main(["--mode", "diff", "--base", "", "--head", ""])
        self.assertEqual(2, code)


if __name__ == "__main__":
    unittest.main()
