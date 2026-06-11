# Copyright (c) 2015 VMware, Inc.
#
# SPDX-License-Identifier: Apache-2.0
import collections
import json
import tempfile
from unittest import mock

import testtools

import bandit
from bandit.core import config
from bandit.core import constants
from bandit.core import issue
from bandit.core import manager
from bandit.core import metrics
from bandit.core.suppression import SuppressedIssue
from bandit.formatters import json as b_json


class JsonFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, "file")
        (tmp_fd, self.tmp_fname) = tempfile.mkstemp()
        self.context = {
            "filename": self.tmp_fname,
            "lineno": 4,
            "linerange": [4],
        }
        self.check_name = "hardcoded_bind_all_interfaces"
        self.issue = issue.Issue(
            bandit.MEDIUM,
            issue.Cwe.MULTIPLE_BINDS,
            bandit.MEDIUM,
            "Possible binding to all interfaces.",
        )

        self.candidates = [
            issue.Issue(
                issue.Cwe.MULTIPLE_BINDS,
                bandit.LOW,
                bandit.LOW,
                "Candidate A",
                lineno=1,
            ),
            issue.Issue(
                bandit.HIGH,
                issue.Cwe.MULTIPLE_BINDS,
                bandit.HIGH,
                "Candiate B",
                lineno=2,
            ),
        ]

        self.manager.out_file = self.tmp_fname

        self.issue.fname = self.context["filename"]
        self.issue.lineno = self.context["lineno"]
        self.issue.linerange = self.context["linerange"]
        self.issue.test = self.check_name

        self.manager.results.append(self.issue)
        self.manager.metrics = metrics.Metrics()

        # mock up the metrics
        for key in ["_totals", "binding.py"]:
            self.manager.metrics.data[key] = {"loc": 4, "nosec": 2}
            for criteria, default in constants.CRITERIA:
                for rank in constants.RANKING:
                    self.manager.metrics.data[key][f"{criteria}.{rank}"] = 0

    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report(self, get_issue_list):
        self.manager.files_list = ["binding.py"]
        self.manager.scores = [
            {
                "SEVERITY": [0] * len(constants.RANKING),
                "CONFIDENCE": [0] * len(constants.RANKING),
            }
        ]

        get_issue_list.return_value = collections.OrderedDict(
            [(self.issue, self.candidates)]
        )

        with open(self.tmp_fname, "w") as tmp_file:
            b_json.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            self.assertIsNotNone(data["generated_at"])
            self.assertEqual(self.tmp_fname, data["results"][0]["filename"])
            self.assertEqual(
                self.issue.severity, data["results"][0]["issue_severity"]
            )
            self.assertEqual(
                self.issue.confidence, data["results"][0]["issue_confidence"]
            )
            self.assertEqual(self.issue.text, data["results"][0]["issue_text"])
            self.assertEqual(
                self.context["lineno"], data["results"][0]["line_number"]
            )
            self.assertEqual(
                self.context["linerange"], data["results"][0]["line_range"]
            )
            self.assertEqual(self.check_name, data["results"][0]["test_name"])
            self.assertIn("candidates", data["results"][0])
            self.assertIn("more_info", data["results"][0])
            self.assertIsNotNone(data["results"][0]["more_info"])

    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report_rich_metadata(self, get_issue_list):
        """Results include rule_doc_url and config_source."""
        self.manager.files_list = ["binding.py"]
        self.manager.scores = [
            {
                "SEVERITY": [0] * len(constants.RANKING),
                "CONFIDENCE": [0] * len(constants.RANKING),
            }
        ]
        get_issue_list.return_value = [self.issue]

        with open(self.tmp_fname, "w") as tmp_file:
            b_json.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            result = data["results"][0]

            # rule_doc_url
            self.assertIn("rule_doc_url", result)
            self.assertIsInstance(result["rule_doc_url"], str)
            self.assertTrue(result["rule_doc_url"].startswith("https://"))

            # config_source
            self.assertIn("config_source", result)
            self.assertIn("config_file", result["config_source"])
            self.assertIn("config_format", result["config_source"])
            self.assertEqual("default", result["config_source"]["config_format"])

    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report_top_level_config_source(self, get_issue_list):
        """Top-level output includes config_source."""
        self.manager.files_list = ["binding.py"]
        self.manager.scores = [
            {
                "SEVERITY": [0] * len(constants.RANKING),
                "CONFIDENCE": [0] * len(constants.RANKING),
            }
        ]
        get_issue_list.return_value = []

        with open(self.tmp_fname, "w") as tmp_file:
            b_json.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            self.assertIn("config_source", data)
            self.assertEqual("default", data["config_source"]["config_format"])

    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report_suppressions_empty(self, get_issue_list):
        """suppressions array is present and empty when nothing suppressed."""
        self.manager.files_list = ["binding.py"]
        self.manager.scores = [
            {
                "SEVERITY": [0] * len(constants.RANKING),
                "CONFIDENCE": [0] * len(constants.RANKING),
            }
        ]
        get_issue_list.return_value = [self.issue]

        with open(self.tmp_fname, "w") as tmp_file:
            b_json.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            self.assertIn("suppressions", data)
            self.assertEqual([], data["suppressions"])

    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report_suppressions_populated(self, get_issue_list):
        """Suppressed issues appear in the suppressions array."""
        self.manager.files_list = ["binding.py"]
        self.manager.scores = [
            {
                "SEVERITY": [0] * len(constants.RANKING),
                "CONFIDENCE": [0] * len(constants.RANKING),
            }
        ]
        get_issue_list.return_value = []

        suppressed = SuppressedIssue(
            test_id="B104",
            test_name="hardcoded_bind_all_interfaces",
            filename="binding.py",
            lineno=4,
            issue_text="Possible binding to all interfaces.",
            severity="MEDIUM",
            confidence="MEDIUM",
            nosec_type="blanket",
            suppressed_tests=[],
            nosec_lineno=4,
        )
        self.manager.suppressed_issues.append(suppressed)

        with open(self.tmp_fname, "w") as tmp_file:
            b_json.report(
                self.manager,
                tmp_file,
                self.issue.severity,
                self.issue.confidence,
            )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            self.assertEqual(1, len(data["suppressions"]))
            s = data["suppressions"][0]
            self.assertEqual("B104", s["test_id"])
            self.assertEqual("blanket", s["nosec_type"])
            self.assertEqual("binding.py", s["filename"])
            self.assertEqual(4, s["lineno"])

