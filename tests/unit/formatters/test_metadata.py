#
# SPDX-License-Identifier: Apache-2.0
"""Tests for the shared formatter metadata module."""
import tempfile
from unittest import mock

import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.core import metrics
from bandit.core.suppression import SuppressedIssue
from bandit.formatters import metadata as b_metadata


def _make_issue():
    i = issue.Issue(
        bandit.MEDIUM,
        issue.Cwe.MULTIPLE_BINDS,
        bandit.MEDIUM,
        "Possible binding to all interfaces.",
    )
    i.fname = "code.py"
    i.test = "hardcoded_bind_all_interfaces"
    i.test_id = "B104"
    i.lineno = 1
    i.linerange = [1]
    return i


class BuildConfigMetadataTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()

    def _make_manager(self, config_file=None):
        conf = config.BanditConfig(config_file=config_file)
        return manager.BanditManager(conf, "file")

    def test_default_config(self):
        mgr = self._make_manager()
        meta = b_metadata.build_config_metadata(mgr)
        self.assertIsNone(meta["config_file"])
        self.assertEqual("default", meta["config_format"])

    def test_yaml_config(self):
        # Create a minimal YAML config file
        with tempfile.NamedTemporaryFile(
            suffix=".yaml", mode="w", delete=False
        ) as f:
            f.write("tests:\n  include:\n    - B101\n")
            yaml_path = f.name
        mgr = self._make_manager(config_file=yaml_path)
        meta = b_metadata.build_config_metadata(mgr)
        self.assertEqual(yaml_path, meta["config_file"])
        self.assertEqual("yaml", meta["config_format"])


class BuildIssueMetadataTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")

    def test_contains_rule_doc_url(self):
        i = _make_issue()
        meta = b_metadata.build_issue_metadata(i, self.manager)
        self.assertIn("rule_doc_url", meta)
        self.assertIsInstance(meta["rule_doc_url"], str)
        self.assertTrue(meta["rule_doc_url"].startswith("https://"))

    def test_contains_config_source(self):
        i = _make_issue()
        meta = b_metadata.build_issue_metadata(i, self.manager)
        self.assertIn("config_source", meta)
        self.assertIsInstance(meta["config_source"], dict)
        self.assertIn("config_file", meta["config_source"])
        self.assertIn("config_format", meta["config_source"])

    def test_rule_doc_url_points_to_correct_plugin(self):
        i = _make_issue()
        meta = b_metadata.build_issue_metadata(i, self.manager)
        # B104 should resolve to its plugin doc page
        self.assertIn("b104", meta["rule_doc_url"].lower())


class BuildSuppressionsListTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")

    def test_empty_suppressions(self):
        result = b_metadata.build_suppressions_list(self.manager)
        self.assertEqual([], result)

    def test_populated_suppressions(self):
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
        self.manager.suppressed_issues.append(s)
        result = b_metadata.build_suppressions_list(self.manager)
        self.assertEqual(1, len(result))
        self.assertEqual("B101", result[0]["test_id"])
        self.assertEqual("blanket", result[0]["nosec_type"])
