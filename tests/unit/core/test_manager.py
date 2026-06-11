#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import os
from unittest import mock

import fixtures
import testtools

from bandit.core import config
from bandit.core import constants
from bandit.core import issue
from bandit.core import manager


class ManagerTests(testtools.TestCase):
    def _get_issue_instance(
        self,
        sev=constants.MEDIUM,
        cwe=issue.Cwe.MULTIPLE_BINDS,
        conf=constants.MEDIUM,
    ):
        new_issue = issue.Issue(sev, cwe, conf, "Test issue")
        new_issue.fname = "code.py"
        new_issue.test = "bandit_plugin"
        new_issue.lineno = 1
        return new_issue

    def setUp(self):
        super().setUp()
        self.profile = {}
        self.profile["include"] = {
            "any_other_function_with_shell_equals_true",
            "assert_used",
        }

        self.config = config.BanditConfig()
        self.manager = manager.BanditManager(
            config=self.config, agg_type="file", debug=False, verbose=False
        )

    def test_create_manager(self):
        # make sure we can create a manager
        self.assertEqual(False, self.manager.debug)
        self.assertEqual(False, self.manager.verbose)
        self.assertEqual("file", self.manager.agg_type)

    def test_create_manager_with_profile(self):
        # make sure we can create a manager
        m = manager.BanditManager(
            config=self.config,
            agg_type="file",
            debug=False,
            verbose=False,
            profile=self.profile,
        )

        self.assertEqual(False, m.debug)
        self.assertEqual(False, m.verbose)
        self.assertEqual("file", m.agg_type)

    def test_matches_globlist(self):
        self.assertTrue(manager._matches_glob_list("test", ["*tes*"]))
        self.assertFalse(manager._matches_glob_list("test", ["*fes*"]))

    def test_is_file_included(self):
        a = manager._is_file_included(
            path="a.py",
            included_globs=["*.py"],
            excluded_path_strings=[],
            enforce_glob=True,
        )

        b = manager._is_file_included(
            path="a.dd",
            included_globs=["*.py"],
            excluded_path_strings=[],
            enforce_glob=False,
        )

        c = manager._is_file_included(
            path="a.py",
            included_globs=["*.py"],
            excluded_path_strings=["a.py"],
            enforce_glob=True,
        )

        d = manager._is_file_included(
            path="a.dd",
            included_globs=["*.py"],
            excluded_path_strings=[],
            enforce_glob=True,
        )

        e = manager._is_file_included(
            path="x_a.py",
            included_globs=["*.py"],
            excluded_path_strings=["x_*.py"],
            enforce_glob=True,
        )

        f = manager._is_file_included(
            path="x.py",
            included_globs=["*.py"],
            excluded_path_strings=["x_*.py"],
            enforce_glob=True,
        )
        self.assertTrue(a)
        self.assertTrue(b)
        self.assertFalse(c)
        self.assertFalse(d)
        self.assertFalse(e)
        self.assertTrue(f)

    @mock.patch("os.walk")
    def test_get_files_from_dir(self, os_walk):
        os_walk.return_value = [
            ("/", ("a"), ()),
            ("/a", (), ("a.py", "b.py", "c.ww")),
        ]

        inc, exc = manager._get_files_from_dir(
            files_dir="", included_globs=["*.py"], excluded_path_strings=None
        )

        self.assertEqual({"/a/c.ww"}, exc)
        self.assertEqual({"/a/a.py", "/a/b.py"}, inc)

    def test_populate_baseline_success(self):
        # Test populate_baseline with valid JSON
        baseline_data = """{
            "results": [
                {
                    "code": "test code",
                    "filename": "example_file.py",
                    "issue_severity": "low",
                    "issue_cwe": {
                        "id": 605,
                        "link": "%s"
                    },
                    "issue_confidence": "low",
                    "issue_text": "test issue",
                    "test_name": "some_test",
                    "test_id": "x",
                    "line_number": "n",
                    "line_range": "n-m"
                }
            ]
        }
        """ % (
            "https://cwe.mitre.org/data/definitions/605.html"
        )
        issue_dictionary = {
            "code": "test code",
            "filename": "example_file.py",
            "issue_severity": "low",
            "issue_cwe": issue.Cwe(issue.Cwe.MULTIPLE_BINDS).as_dict(),
            "issue_confidence": "low",
            "issue_text": "test issue",
            "test_name": "some_test",
            "test_id": "x",
            "line_number": "n",
            "line_range": "n-m",
        }
        baseline_items = [issue.issue_from_dict(issue_dictionary)]
        self.manager.populate_baseline(baseline_data)
        self.assertEqual(baseline_items, self.manager.baseline)

    @mock.patch("logging.Logger.warning")
    def test_populate_baseline_invalid_json(self, mock_logger_warning):
        # Test populate_baseline with invalid JSON content
        baseline_data = """{"data": "bad"}"""
        self.manager.populate_baseline(baseline_data)
        # Default value for manager.baseline is []
        self.assertEqual([], self.manager.baseline)
        self.assertTrue(mock_logger_warning.called)

    def test_results_count(self):
        levels = [constants.LOW, constants.MEDIUM, constants.HIGH]
        self.manager.results = [
            issue.Issue(
                severity=level, cwe=issue.Cwe.MULTIPLE_BINDS, confidence=level
            )
            for level in levels
        ]

        r = [
            self.manager.results_count(sev_filter=level, conf_filter=level)
            for level in levels
        ]

        self.assertEqual([3, 2, 1], r)

    def test_output_results_invalid_format(self):
        # Test that output_results succeeds given an invalid format
        temp_directory = self.useFixture(fixtures.TempDir()).path
        lines = 5
        sev_level = constants.LOW
        conf_level = constants.LOW
        output_filename = os.path.join(temp_directory, "_temp_output")
        output_format = "invalid"
        with open(output_filename, "w") as tmp_file:
            self.manager.output_results(
                lines, sev_level, conf_level, tmp_file, output_format
            )
        self.assertTrue(os.path.isfile(output_filename))

    def test_output_results_valid_format(self):
        # Test that output_results succeeds given a valid format
        temp_directory = self.useFixture(fixtures.TempDir()).path
        lines = 5
        sev_level = constants.LOW
        conf_level = constants.LOW
        output_filename = os.path.join(temp_directory, "_temp_output.txt")
        output_format = "txt"
        with open(output_filename, "w") as tmp_file:
            self.manager.output_results(
                lines, sev_level, conf_level, tmp_file, output_format
            )
        self.assertTrue(os.path.isfile(output_filename))

    @mock.patch("os.path.isdir")
    def test_discover_files_recurse_skip(self, isdir):
        isdir.return_value = True
        self.manager.discover_files(["thing"], False)
        self.assertEqual([], self.manager.files_list)
        self.assertEqual([], self.manager.excluded_files)

    @mock.patch("os.path.isdir")
    def test_discover_files_recurse_files(self, isdir):
        isdir.return_value = True
        with mock.patch.object(manager, "_get_files_from_dir") as m:
            m.return_value = ({"files"}, {"excluded"})
            self.manager.discover_files(["thing"], True)
            self.assertEqual(["files"], self.manager.files_list)
            self.assertEqual(["excluded"], self.manager.excluded_files)

    @mock.patch("os.path.isdir")
    def test_discover_files_exclude(self, isdir):
        isdir.return_value = False
        with mock.patch.object(manager, "_is_file_included") as m:
            m.return_value = False
            self.manager.discover_files(["thing"], True)
            self.assertEqual([], self.manager.files_list)
            self.assertEqual(["thing"], self.manager.excluded_files)

    @mock.patch("os.path.isdir")
    def test_discover_files_exclude_dir(self, isdir):
        isdir.return_value = False

        # Test exclude dir using wildcard
        self.manager.discover_files(["./x/y.py"], True, "./x/*")
        self.assertEqual([], self.manager.files_list)
        self.assertEqual(["./x/y.py"], self.manager.excluded_files)

        # Test exclude dir without wildcard
        isdir.side_effect = [True, False]
        self.manager.discover_files(["./x/y.py"], True, "./x/")
        self.assertEqual([], self.manager.files_list)
        self.assertEqual(["./x/y.py"], self.manager.excluded_files)

        # Test exclude dir without wildcard or trailing slash
        isdir.side_effect = [True, False]
        self.manager.discover_files(["./x/y.py"], True, "./x")
        self.assertEqual([], self.manager.files_list)
        self.assertEqual(["./x/y.py"], self.manager.excluded_files)

        # Test exclude dir without prefix or suffix
        isdir.side_effect = [False, False]
        self.manager.discover_files(["./x/y/z.py"], True, "y")
        self.assertEqual([], self.manager.files_list)
        self.assertEqual(["./x/y/z.py"], self.manager.excluded_files)

    @mock.patch("os.path.isdir")
    def test_discover_files_exclude_cmdline(self, isdir):
        isdir.return_value = False
        with mock.patch.object(manager, "_is_file_included") as m:
            self.manager.discover_files(
                ["a", "b", "c"], True, excluded_paths="a,b"
            )
            m.assert_called_with(
                "c", ["*.py", "*.pyw"], ["a", "b"], enforce_glob=False
            )

    @mock.patch("os.path.isdir")
    def test_discover_files_exclude_glob(self, isdir):
        isdir.return_value = False
        self.manager.discover_files(
            ["a.py", "test_a.py", "test.py"], True, excluded_paths="test_*.py"
        )
        self.assertEqual(["./a.py", "./test.py"], self.manager.files_list)
        self.assertEqual(["test_a.py"], self.manager.excluded_files)

    @mock.patch("os.path.isdir")
    def test_discover_files_include(self, isdir):
        isdir.return_value = False
        with mock.patch.object(manager, "_is_file_included") as m:
            m.return_value = True
            self.manager.discover_files(["thing"], True)
            self.assertEqual(["./thing"], self.manager.files_list)
            self.assertEqual([], self.manager.excluded_files)

    def test_run_tests_keyboardinterrupt(self):
        # Test that bandit manager exits when there is a keyboard interrupt
        temp_directory = self.useFixture(fixtures.TempDir()).path
        some_file = os.path.join(temp_directory, "some_code_file.py")
        with open(some_file, "w") as fd:
            fd.write("some_code = x + 1")
        self.manager.files_list = [some_file]
        with mock.patch(
            "bandit.core.metrics.Metrics.count_issues"
        ) as mock_count_issues:
            mock_count_issues.side_effect = KeyboardInterrupt
            # assert a SystemExit with code 2
            self.assertRaisesRegex(SystemExit, "2", self.manager.run_tests)

    def test_run_tests_ioerror(self):
        # Test that a file name is skipped and added to the manager.skipped
        # list when there is an IOError attempting to open/read the file
        temp_directory = self.useFixture(fixtures.TempDir()).path
        no_such_file = os.path.join(temp_directory, "no_such_file.py")
        self.manager.files_list = [no_such_file]
        self.manager.run_tests()
        # since the file name and the IOError.strerror text are added to
        # manager.skipped, we convert skipped to str to find just the file name
        # since IOError is not constant
        self.assertIn(no_such_file, str(self.manager.skipped))

    def test_compare_baseline(self):
        issue_a = self._get_issue_instance()
        issue_a.fname = "file1.py"

        issue_b = self._get_issue_instance()
        issue_b.fname = "file2.py"

        issue_c = self._get_issue_instance(sev=constants.HIGH)
        issue_c.fname = "file1.py"

        # issue c is in results, not in baseline
        self.assertEqual(
            [issue_c],
            manager._compare_baseline_results(
                [issue_a, issue_b], [issue_a, issue_b, issue_c]
            ),
        )

        # baseline and results are the same
        self.assertEqual(
            [],
            manager._compare_baseline_results(
                [issue_a, issue_b, issue_c], [issue_a, issue_b, issue_c]
            ),
        )

        # results are better than baseline
        self.assertEqual(
            [],
            manager._compare_baseline_results(
                [issue_a, issue_b, issue_c], [issue_a, issue_b]
            ),
        )

    def test_find_candidate_matches(self):
        issue_a = self._get_issue_instance()
        issue_b = self._get_issue_instance()

        issue_c = self._get_issue_instance()
        issue_c.fname = "file1.py"

        # issue a and b are the same, both should be returned as candidates
        self.assertEqual(
            {issue_a: [issue_a, issue_b]},
            manager._find_candidate_matches([issue_a], [issue_a, issue_b]),
        )

        # issue a and c are different, only a should be returned
        self.assertEqual(
            {issue_a: [issue_a]},
            manager._find_candidate_matches([issue_a], [issue_a, issue_c]),
        )

        # c doesn't match a, empty list should be returned
        self.assertEqual(
            {issue_a: []},
            manager._find_candidate_matches([issue_a], [issue_c]),
        )

        # a and b match, a and b should both return a and b candidates
        self.assertEqual(
            {issue_a: [issue_a, issue_b], issue_b: [issue_a, issue_b]},
            manager._find_candidate_matches(
                [issue_a, issue_b], [issue_a, issue_b, issue_c]
            ),
        )


class ParseNosecCommentTests(testtools.TestCase):
    """Tests for _parse_nosec_comment and related nosec parsing."""

    def setUp(self):
        super().setUp()
        self.mock_extman = mock.MagicMock()
        self.known_ids = {
            "B101", "B102", "B301", "B303", "B404",
            "B601", "B602", "B607",
        }
        self.mock_extman.check_id.side_effect = (
            lambda x: x in self.known_ids
        )
        self.name_to_id = {
            "subprocess_popen_with_shell_equals_true": "B602",
            "start_process_with_partial_path": "B607",
            "import_subprocess": "B404",
            "md5": "B303",
        }
        self.mock_extman.get_test_id.side_effect = (
            lambda x: self.name_to_id.get(x)
        )
        self.patch_extman = mock.patch(
            "bandit.core.manager.extension_loader.MANAGER",
            self.mock_extman,
        )
        self.patch_extman.start()

    def tearDown(self):
        self.patch_extman.stop()
        super().tearDown()

    def test_not_a_nosec_comment(self):
        self.assertIsNone(manager._parse_nosec_comment("# regular comment"))

    def test_blanket_nosec(self):
        self.assertEqual(set(), manager._parse_nosec_comment("# nosec"))

    def test_blanket_nosec_no_space(self):
        self.assertEqual(set(), manager._parse_nosec_comment("#nosec"))

    def test_blanket_nosec_with_trailing_space(self):
        self.assertEqual(set(), manager._parse_nosec_comment("# nosec  "))

    def test_nosec_with_colon_blanket(self):
        self.assertEqual(set(), manager._parse_nosec_comment("# nosec:"))

    def test_single_id(self):
        self.assertEqual(
            {"B601"}, manager._parse_nosec_comment("# nosec B601")
        )

    def test_comma_separated_ids_no_space(self):
        self.assertEqual(
            {"B601", "B602"},
            manager._parse_nosec_comment("# nosec B601,B602"),
        )

    def test_comma_separated_ids_with_space(self):
        self.assertEqual(
            {"B601", "B602"},
            manager._parse_nosec_comment("# nosec B601, B602"),
        )

    def test_three_comma_separated_ids(self):
        self.assertEqual(
            {"B601", "B602", "B607"},
            manager._parse_nosec_comment("# nosec B601,B602,B607"),
        )

    def test_space_separated_ids(self):
        self.assertEqual(
            {"B601", "B602"},
            manager._parse_nosec_comment("# nosec B601 B602"),
        )

    def test_plugin_name(self):
        self.assertEqual(
            {"B602"},
            manager._parse_nosec_comment(
                "# nosec subprocess_popen_with_shell_equals_true"
            ),
        )

    def test_mixed_id_and_name_comma_no_space(self):
        self.assertEqual(
            {"B601", "B602"},
            manager._parse_nosec_comment(
                "# nosec B601,subprocess_popen_with_shell_equals_true"
            ),
        )

    def test_trailing_comment_with_dash(self):
        self.assertEqual(
            {"B601"},
            manager._parse_nosec_comment("# nosec B601 - safe to use"),
        )

    def test_trailing_comment_with_paren(self):
        self.assertEqual(
            {"B601"},
            manager._parse_nosec_comment("# nosec B601 (reason)"),
        )

    def test_invalid_id_no_blanket_fallback(self):
        self.assertIsNone(
            manager._parse_nosec_comment("# nosec B999")
        )

    def test_valid_and_invalid_id_keeps_valid(self):
        self.assertEqual(
            {"B601"},
            manager._parse_nosec_comment("# nosec B601, B999"),
        )

    def test_nosec_after_type_comment(self):
        self.assertEqual(
            set(),
            manager._parse_nosec_comment(
                "# type: ... # nosec # noqa: E501"
            ),
        )

    def test_nosec_with_id_before_noqa(self):
        self.assertEqual(
            {"B607"},
            manager._parse_nosec_comment("# nosec B607 # noqa"),
        )

    def test_nosec_with_colon_and_name(self):
        self.assertEqual(
            {"B404"},
            manager._parse_nosec_comment("# nosec: import_subprocess"),
        )

    def test_multiple_names_space_separated(self):
        self.assertEqual(
            {"B602", "B607"},
            manager._parse_nosec_comment(
                "# nosec subprocess_popen_with_shell_equals_true "
                "start_process_with_partial_path"
            ),
        )

    def test_nosec_with_plain_comment_word(self):
        # "# nosec TODO" should be blanket nosec (TODO is a comment, not a test ID)
        self.assertEqual(
            set(),
            manager._parse_nosec_comment("# nosec TODO"),
        )

    def test_nosec_with_valid_id_and_plain_word(self):
        # Valid ID + plain comment word keeps only the valid ID
        self.assertEqual(
            {"B601"},
            manager._parse_nosec_comment("# nosec B601 TODO"),
        )
