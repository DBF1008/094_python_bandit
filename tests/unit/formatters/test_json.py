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
    def test_report_no_explanations_by_default(self, get_issue_list):
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
                constants.LOW,
                constants.LOW,
            )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            self.assertNotIn("rule_explanations", data)

    @mock.patch("bandit.core.manager.BanditManager.get_issue_list")
    def test_report_with_explanations(self, get_issue_list):
        from bandit.core.test_set import RuleExplanation

        self.manager.files_list = ["binding.py"]
        self.manager.scores = [
            {
                "SEVERITY": [0] * len(constants.RANKING),
                "CONFIDENCE": [0] * len(constants.RANKING),
            }
        ]

        get_issue_list.return_value = []

        # Mock rule_explanations on the manager
        mock_explanations = {
            "B201": RuleExplanation(
                test_id="B201",
                test_name="flask_debug_true",
                enabled=True,
                sources=[
                    {
                        "source": "default",
                        "action": "included",
                        "detail": "all tests included by default",
                    }
                ],
                final_reason="enabled: all tests included by default",
            ),
            "B101": RuleExplanation(
                test_id="B101",
                test_name="assert_used",
                enabled=False,
                sources=[
                    {
                        "source": "cli:--skip",
                        "action": "excluded",
                        "detail": "excluded via CLI --skip",
                    }
                ],
                final_reason="disabled: excluded via CLI --skip",
            ),
        }
        with mock.patch.object(
            type(self.manager),
            "rule_explanations",
            new_callable=mock.PropertyMock,
            return_value=mock_explanations,
        ):
            with open(self.tmp_fname, "w") as tmp_file:
                b_json.report(
                    self.manager,
                    tmp_file,
                    constants.LOW,
                    constants.LOW,
                )

        with open(self.tmp_fname) as f:
            data = json.loads(f.read())
            self.assertIn("rule_explanations", data)
            explanations = data["rule_explanations"]
            self.assertEqual(2, len(explanations))
            # Should be sorted by test_id
            self.assertEqual("B101", explanations[0]["test_id"])
            self.assertEqual("B201", explanations[1]["test_id"])
            # Check structure
            self.assertFalse(explanations[0]["enabled"])
            self.assertTrue(explanations[1]["enabled"])
            self.assertIsInstance(explanations[0]["sources"], list)
            self.assertIn("final_reason", explanations[0])
