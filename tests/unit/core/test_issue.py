#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
from unittest import mock

import testtools

import bandit
from bandit.core import constants
from bandit.core import issue


class IssueTests(testtools.TestCase):
    def test_issue_create(self):
        new_issue = _get_issue_instance()
        self.assertIsInstance(new_issue, issue.Issue)

    def test_issue_str(self):
        test_issue = _get_issue_instance()
        expect = (
            "Issue: 'Test issue' from B999:bandit_plugin:"
            " CWE: %s,"
            " Severity: MEDIUM "
            "Confidence: MEDIUM at code.py:1:8"
        )

        self.assertEqual(
            expect % str(issue.Cwe(issue.Cwe.MULTIPLE_BINDS)), str(test_issue)
        )

    def test_issue_as_dict(self):
        test_issue = _get_issue_instance()
        test_issue_dict = test_issue.as_dict(with_code=False)
        self.assertIsInstance(test_issue_dict, dict)
        self.assertEqual("code.py", test_issue_dict["filename"])
        self.assertEqual("bandit_plugin", test_issue_dict["test_name"])
        self.assertEqual("B999", test_issue_dict["test_id"])
        self.assertEqual("MEDIUM", test_issue_dict["issue_severity"])
        self.assertEqual(
            {
                "id": 605,
                "link": "https://cwe.mitre.org/data/definitions/605.html",
            },
            test_issue_dict["issue_cwe"],
        )
        self.assertEqual("MEDIUM", test_issue_dict["issue_confidence"])
        self.assertEqual("Test issue", test_issue_dict["issue_text"])
        self.assertEqual(1, test_issue_dict["line_number"])
        self.assertEqual([], test_issue_dict["line_range"])
        self.assertEqual(8, test_issue_dict["col_offset"])
        self.assertEqual(16, test_issue_dict["end_col_offset"])

    def test_issue_filter_severity(self):
        levels = [bandit.LOW, bandit.MEDIUM, bandit.HIGH]
        issues = [_get_issue_instance(level, bandit.HIGH) for level in levels]

        for level in levels:
            rank = constants.RANKING.index(level)
            for i in issues:
                test = constants.RANKING.index(i.severity)
                result = i.filter(level, bandit.UNDEFINED)
                self.assertTrue((test >= rank) == result)

    def test_issue_filter_confidence(self):
        levels = [bandit.LOW, bandit.MEDIUM, bandit.HIGH]
        issues = [_get_issue_instance(bandit.HIGH, level) for level in levels]

        for level in levels:
            rank = constants.RANKING.index(level)
            for i in issues:
                test = constants.RANKING.index(i.confidence)
                result = i.filter(bandit.UNDEFINED, level)
                self.assertTrue((test >= rank) == result)

    def test_matches_issue(self):
        issue_a = _get_issue_instance()

        issue_b = _get_issue_instance(severity=bandit.HIGH)

        issue_c = _get_issue_instance(confidence=bandit.LOW)

        issue_d = _get_issue_instance()
        issue_d.text = "ABCD"

        issue_e = _get_issue_instance()
        issue_e.fname = "file1.py"

        issue_f = issue_a

        issue_g = _get_issue_instance()
        issue_g.test = "ZZZZ"

        issue_h = issue_a
        issue_h.lineno = 12345

        # positive tests
        self.assertEqual(issue_a, issue_a)
        self.assertEqual(issue_a, issue_f)
        self.assertEqual(issue_f, issue_a)

        # severity doesn't match
        self.assertNotEqual(issue_a, issue_b)

        # confidence doesn't match
        self.assertNotEqual(issue_a, issue_c)

        # text doesn't match
        self.assertNotEqual(issue_a, issue_d)

        # filename doesn't match
        self.assertNotEqual(issue_a, issue_e)

        # plugin name doesn't match
        self.assertNotEqual(issue_a, issue_g)

        # line number doesn't match but should pass because we don't test that
        self.assertEqual(issue_a, issue_h)

    @mock.patch("linecache.getline")
    def test_get_code(self, getline):
        getline.return_value = b"\x08\x30"
        new_issue = issue.Issue(
            bandit.MEDIUM, cwe=issue.Cwe.MULTIPLE_BINDS, lineno=1
        )

        try:
            new_issue.get_code()
        except UnicodeDecodeError:
            self.fail("Bytes not properly decoded in issue.get_code()")

    def test_issue_hash_consistent_with_eq(self):
        # Equal issues must have equal hashes
        issue_a = _get_issue_instance()
        issue_b = _get_issue_instance()
        self.assertEqual(issue_a, issue_b)
        self.assertEqual(hash(issue_a), hash(issue_b))

        # Issues differing only in lineno are still equal and hash-equal
        issue_c = _get_issue_instance()
        issue_c.lineno = 999
        self.assertEqual(issue_a, issue_c)
        self.assertEqual(hash(issue_a), hash(issue_c))

        # Issues with different severity are not equal
        issue_d = _get_issue_instance(severity=bandit.HIGH)
        self.assertNotEqual(issue_a, issue_d)

        # Issues with different fname are not equal
        issue_e = _get_issue_instance()
        issue_e.fname = "other.py"
        self.assertNotEqual(issue_a, issue_e)

        # Equal issues can be used as dict keys without duplication
        d = {issue_a: "first"}
        d[issue_b] = "second"
        self.assertEqual(1, len(d))
        self.assertEqual("second", d[issue_a])

    def test_cwe_hash_consistent_with_eq(self):
        cwe_a = issue.Cwe(issue.Cwe.MULTIPLE_BINDS)
        cwe_b = issue.Cwe(issue.Cwe.MULTIPLE_BINDS)
        self.assertEqual(cwe_a, cwe_b)
        self.assertEqual(hash(cwe_a), hash(cwe_b))

        cwe_c = issue.Cwe(issue.Cwe.SQL_INJECTION)
        self.assertNotEqual(cwe_a, cwe_c)


def _get_issue_instance(
    severity=bandit.MEDIUM,
    cwe=issue.Cwe.MULTIPLE_BINDS,
    confidence=bandit.MEDIUM,
):
    new_issue = issue.Issue(severity, cwe, confidence, "Test issue")
    new_issue.fname = "code.py"
    new_issue.test = "bandit_plugin"
    new_issue.test_id = "B999"
    new_issue.lineno = 1
    new_issue.col_offset = 8
    new_issue.end_col_offset = 16

    return new_issue
