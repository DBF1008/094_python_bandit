#
# SPDX-License-Identifier: Apache-2.0
"""Tests for the SuppressedIssue dataclass."""
import testtools

from bandit.core.suppression import SuppressedIssue


class SuppressedIssueTests(testtools.TestCase):
    def test_create_blanket(self):
        """A blanket nosec produces a valid SuppressedIssue."""
        s = SuppressedIssue(
            test_id="B101",
            test_name="assert_used",
            filename="app.py",
            lineno=10,
            issue_text="Use of assert detected.",
            severity="LOW",
            confidence="HIGH",
            nosec_type="blanket",
            suppressed_tests=[],
            nosec_lineno=10,
        )
        self.assertEqual("B101", s.test_id)
        self.assertEqual("assert_used", s.test_name)
        self.assertEqual("blanket", s.nosec_type)
        self.assertEqual([], s.suppressed_tests)
        self.assertEqual(10, s.nosec_lineno)

    def test_create_specific(self):
        """A specific ``#nosec B101, B102`` produces a valid SuppressedIssue.
        """
        s = SuppressedIssue(
            test_id="B101",
            test_name="assert_used",
            filename="app.py",
            lineno=10,
            issue_text="Use of assert detected.",
            severity="LOW",
            confidence="HIGH",
            nosec_type="specific",
            suppressed_tests=["B101", "B102"],
            nosec_lineno=10,
        )
        self.assertEqual("specific", s.nosec_type)
        self.assertEqual(["B101", "B102"], s.suppressed_tests)

    def test_as_dict(self):
        """as_dict() returns a plain serialisable dictionary."""
        s = SuppressedIssue(
            test_id="B301",
            test_name="blacklist_calls",
            filename="loader.py",
            lineno=5,
            issue_text="Use of unsafe yaml load.",
            severity="MEDIUM",
            confidence="HIGH",
            nosec_type="specific",
            suppressed_tests=["B301"],
            nosec_lineno=5,
        )
        d = s.as_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual("B301", d["test_id"])
        self.assertEqual("blacklist_calls", d["test_name"])
        self.assertEqual("loader.py", d["filename"])
        self.assertEqual(5, d["lineno"])
        self.assertEqual("Use of unsafe yaml load.", d["issue_text"])
        self.assertEqual("MEDIUM", d["issue_severity"])
        self.assertEqual("HIGH", d["issue_confidence"])
        self.assertEqual("specific", d["nosec_type"])
        self.assertEqual(["B301"], d["suppressed_tests"])
        self.assertEqual(5, d["nosec_lineno"])

    def test_default_nosec_lineno(self):
        """nosec_lineno defaults to 0 when not provided."""
        s = SuppressedIssue(
            test_id="B101",
            test_name="assert_used",
            filename="app.py",
            lineno=10,
            issue_text="Use of assert detected.",
            severity="LOW",
            confidence="HIGH",
            nosec_type="blanket",
        )
        self.assertEqual(0, s.nosec_lineno)
