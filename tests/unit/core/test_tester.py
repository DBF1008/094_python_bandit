#
# SPDX-License-Identifier: Apache-2.0
from unittest import mock

import testtools

from bandit.core import metrics as b_metrics
from bandit.core import tester as b_tester


class GetNosecsFromContextsTests(testtools.TestCase):
    """Tests for BanditTester._get_nosecs_from_contexts."""

    def setUp(self):
        super().setUp()
        self.nosec_lines = {}
        self.test_metrics = b_metrics.Metrics()
        self.test_metrics.begin("test.py")
        self.tester = b_tester.BanditTester(
            testset=mock.MagicMock(),
            debug=False,
            nosec_lines=self.nosec_lines,
            metrics=self.test_metrics,
        )

    def _make_result(self, lineno):
        result = mock.MagicMock()
        result.lineno = lineno
        return result

    def _make_context(self, linerange):
        return {"linerange": linerange}

    def test_no_nosec_anywhere(self):
        context = self._make_context([1, 2])
        result = self._make_result(1)
        self.assertIsNone(
            self.tester._get_nosecs_from_contexts(context, result)
        )

    def test_blanket_nosec_on_result_line(self):
        self.nosec_lines[5] = set()
        context = self._make_context([5])
        result = self._make_result(5)
        self.assertEqual(
            set(),
            self.tester._get_nosecs_from_contexts(context, result),
        )

    def test_blanket_nosec_on_context_line(self):
        self.nosec_lines[3] = set()
        context = self._make_context([3, 4, 5])
        result = self._make_result(5)
        self.assertEqual(
            set(),
            self.tester._get_nosecs_from_contexts(context, result),
        )

    def test_specific_nosec_on_result_line(self):
        self.nosec_lines[5] = {"B602"}
        context = self._make_context([5])
        result = self._make_result(5)
        self.assertEqual(
            {"B602"},
            self.tester._get_nosecs_from_contexts(context, result),
        )

    def test_specific_nosec_on_context_line(self):
        self.nosec_lines[3] = {"B607"}
        context = self._make_context([3, 4, 5])
        result = self._make_result(5)
        self.assertEqual(
            {"B607"},
            self.tester._get_nosecs_from_contexts(context, result),
        )

    def test_blanket_base_plus_specific_context_blanket_wins(self):
        self.nosec_lines[5] = set()  # blanket on result line
        self.nosec_lines[3] = {"B607"}  # specific on context line
        context = self._make_context([3, 4, 5])
        result = self._make_result(5)
        self.assertEqual(
            set(),
            self.tester._get_nosecs_from_contexts(context, result),
        )

    def test_specific_base_plus_blanket_context_blanket_wins(self):
        self.nosec_lines[5] = {"B602"}  # specific on result line
        self.nosec_lines[3] = set()  # blanket on context line
        context = self._make_context([3, 4, 5])
        result = self._make_result(5)
        self.assertEqual(
            set(),
            self.tester._get_nosecs_from_contexts(context, result),
        )

    def test_two_specific_sets_union(self):
        self.nosec_lines[5] = {"B602"}
        self.nosec_lines[3] = {"B607"}
        context = self._make_context([3, 4, 5])
        result = self._make_result(5)
        self.assertEqual(
            {"B602", "B607"},
            self.tester._get_nosecs_from_contexts(context, result),
        )

    def test_no_test_result_uses_context_only(self):
        self.nosec_lines[3] = {"B607"}
        context = self._make_context([3, 4, 5])
        self.assertEqual(
            {"B607"},
            self.tester._get_nosecs_from_contexts(context, test_result=None),
        )
