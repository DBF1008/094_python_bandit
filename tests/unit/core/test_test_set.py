#
# Copyright (c) 2016 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
from unittest import mock

import testtools
from stevedore import extension

from bandit.blacklists import utils
from bandit.core import extension_loader
from bandit.core import issue
from bandit.core import test_properties as test
from bandit.core import test_set


@test.checks("Str")
@test.test_id("B000")
def test_plugin():
    sets = []
    sets.append(
        utils.build_conf_dict(
            "telnet",
            "B401",
            issue.Cwe.CLEARTEXT_TRANSMISSION,
            ["telnetlib"],
            "A telnet-related module is being imported.  Telnet is "
            "considered insecure. Use SSH or some other encrypted protocol.",
            "HIGH",
        )
    )

    sets.append(
        utils.build_conf_dict(
            "marshal",
            "B302",
            issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
            ["marshal.load", "marshal.loads"],
            "Deserialization with the marshal module is possibly dangerous.",
        )
    )

    return {"Import": sets, "ImportFrom": sets, "Call": sets}


class BanditTestSetTests(testtools.TestCase):
    def _make_test_manager(self, plugin):
        return extension.ExtensionManager.make_test_instance(
            [extension.Extension("test_plugin", None, test_plugin, None)]
        )

    def setUp(self):
        super().setUp()
        mngr = self._make_test_manager(mock.Mock)
        self.patchExtMan = mock.patch("stevedore.extension.ExtensionManager")
        self.mockExtMan = self.patchExtMan.start()
        self.mockExtMan.return_value = mngr
        self.old_ext_man = extension_loader.MANAGER
        extension_loader.MANAGER = extension_loader.Manager()
        self.config = mock.MagicMock()
        self.config.get_setting.return_value = None

    def tearDown(self):
        self.patchExtMan.stop()
        super().tearDown()
        extension_loader.MANAGER = self.old_ext_man

    def test_has_defaults(self):
        ts = test_set.BanditTestSet(self.config)
        self.assertEqual(1, len(ts.get_tests("Str")))

    def test_profile_include_id(self):
        profile = {"include": ["B000"]}
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(1, len(ts.get_tests("Str")))

    def test_profile_exclude_id(self):
        profile = {"exclude": ["B000"]}
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(0, len(ts.get_tests("Str")))

    def test_profile_include_none(self):
        profile = {"include": []}  # same as no include
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(1, len(ts.get_tests("Str")))

    def test_profile_exclude_none(self):
        profile = {"exclude": []}  # same as no exclude
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(1, len(ts.get_tests("Str")))

    def test_profile_has_builtin_blacklist(self):
        ts = test_set.BanditTestSet(self.config)
        self.assertEqual(1, len(ts.get_tests("Import")))
        self.assertEqual(1, len(ts.get_tests("ImportFrom")))
        self.assertEqual(1, len(ts.get_tests("Call")))

    def test_profile_exclude_builtin_blacklist(self):
        profile = {"exclude": ["B001"]}
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(0, len(ts.get_tests("Import")))
        self.assertEqual(0, len(ts.get_tests("ImportFrom")))
        self.assertEqual(0, len(ts.get_tests("Call")))

    def test_profile_exclude_builtin_blacklist_specific(self):
        profile = {"exclude": ["B302", "B401"]}
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(0, len(ts.get_tests("Import")))
        self.assertEqual(0, len(ts.get_tests("ImportFrom")))
        self.assertEqual(0, len(ts.get_tests("Call")))

    def test_profile_filter_blacklist_none(self):
        ts = test_set.BanditTestSet(self.config)
        blacklist = ts.get_tests("Import")[0]

        self.assertEqual(2, len(blacklist._config["Import"]))
        self.assertEqual(2, len(blacklist._config["ImportFrom"]))
        self.assertEqual(2, len(blacklist._config["Call"]))

    def test_profile_filter_blacklist_one(self):
        profile = {"exclude": ["B401"]}
        ts = test_set.BanditTestSet(self.config, profile)
        blacklist = ts.get_tests("Import")[0]

        self.assertEqual(1, len(blacklist._config["Import"]))
        self.assertEqual(1, len(blacklist._config["ImportFrom"]))
        self.assertEqual(1, len(blacklist._config["Call"]))

    def test_profile_filter_blacklist_include(self):
        profile = {"include": ["B001", "B401"]}
        ts = test_set.BanditTestSet(self.config, profile)
        blacklist = ts.get_tests("Import")[0]

        self.assertEqual(1, len(blacklist._config["Import"]))
        self.assertEqual(1, len(blacklist._config["ImportFrom"]))
        self.assertEqual(1, len(blacklist._config["Call"]))

    def test_profile_filter_blacklist_all(self):
        profile = {"exclude": ["B401", "B302"]}
        ts = test_set.BanditTestSet(self.config, profile)

        # if there is no blacklist data for a node type then we wont add a
        # blacklist test to it, as this would be pointless.
        self.assertEqual(0, len(ts.get_tests("Import")))
        self.assertEqual(0, len(ts.get_tests("ImportFrom")))
        self.assertEqual(0, len(ts.get_tests("Call")))

    def test_profile_blacklist_compat(self):
        data = [
            utils.build_conf_dict(
                "marshal",
                "B302",
                issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
                ["marshal.load", "marshal.loads"],
                (
                    "Deserialization with the marshal module is possibly "
                    "dangerous."
                ),
            )
        ]

        profile = {"include": ["B001"], "blacklist": {"Call": data}}

        ts = test_set.BanditTestSet(self.config, profile)
        blacklist = ts.get_tests("Call")[0]

        self.assertNotIn("Import", blacklist._config)
        self.assertNotIn("ImportFrom", blacklist._config)
        self.assertEqual(1, len(blacklist._config["Call"]))


class BanditTestSetExplainTests(testtools.TestCase):
    """Tests for rule provenance tracking (explain mode)."""

    def _make_test_manager(self, plugin):
        return extension.ExtensionManager.make_test_instance(
            [extension.Extension("test_plugin", None, test_plugin, None)]
        )

    def setUp(self):
        super().setUp()
        mngr = self._make_test_manager(mock.Mock)
        self.patchExtMan = mock.patch("stevedore.extension.ExtensionManager")
        self.mockExtMan = self.patchExtMan.start()
        self.mockExtMan.return_value = mngr
        self.old_ext_man = extension_loader.MANAGER
        extension_loader.MANAGER = extension_loader.Manager()
        self.config = mock.MagicMock()
        self.config.get_setting.return_value = None

    def tearDown(self):
        self.patchExtMan.stop()
        super().tearDown()
        extension_loader.MANAGER = self.old_ext_man

    def test_explain_false_returns_empty(self):
        ts = test_set.BanditTestSet(self.config, explain=False)
        self.assertEqual({}, ts.explanations)

    def test_explain_default_all_enabled(self):
        ts = test_set.BanditTestSet(self.config, explain=True)
        self.assertIn("B000", ts.explanations)
        exp = ts.explanations["B000"]
        self.assertTrue(exp.enabled)
        self.assertEqual("B000", exp.test_id)
        self.assertEqual("test_plugin", exp.test_name)
        # Default source
        self.assertTrue(
            any(s["source"] == "default" for s in exp.sources)
        )

    def test_explain_all_blacklist_enabled_by_default(self):
        ts = test_set.BanditTestSet(self.config, explain=True)
        for tid in ("B401", "B302"):
            self.assertIn(tid, ts.explanations)
            self.assertTrue(ts.explanations[tid].enabled)

    def test_explain_profile_include(self):
        profile = {
            "include": ["B000"],
            "sources": {
                "B000": [
                    ("config_file", "included", "included via config file tests list")
                ],
            },
        }
        ts = test_set.BanditTestSet(self.config, profile, explain=True)
        exp = ts.explanations["B000"]
        self.assertTrue(exp.enabled)
        self.assertTrue(
            any(s["source"] == "config_file" for s in exp.sources)
        )
        # B401 should be disabled (not in include list)
        self.assertFalse(ts.explanations["B401"].enabled)
        self.assertIn(
            "not in profile include list",
            ts.explanations["B401"].final_reason,
        )

    def test_explain_profile_exclude(self):
        profile = {
            "exclude": ["B000"],
            "sources": {
                "B000": [
                    ("config_file", "excluded", "excluded via config file skips list")
                ],
            },
        }
        ts = test_set.BanditTestSet(self.config, profile, explain=True)
        exp = ts.explanations["B000"]
        self.assertFalse(exp.enabled)
        self.assertIn("disabled", exp.final_reason)
        self.assertTrue(
            any(s["action"] == "excluded" for s in exp.sources)
        )

    def test_explain_cli_override_skip(self):
        profile = {
            "include": set(),
            "exclude": {"B000"},
            "sources": {
                "B000": [
                    ("cli:--skip", "excluded", "excluded via CLI --skip")
                ],
            },
        }
        ts = test_set.BanditTestSet(self.config, profile, explain=True)
        exp = ts.explanations["B000"]
        self.assertFalse(exp.enabled)
        self.assertTrue(
            any(s["source"] == "cli:--skip" for s in exp.sources)
        )

    def test_explain_cli_override_tests(self):
        profile = {
            "include": {"B000"},
            "exclude": set(),
            "sources": {
                "B000": [
                    ("cli:--tests", "included", "included via CLI --tests")
                ],
            },
        }
        ts = test_set.BanditTestSet(self.config, profile, explain=True)
        exp = ts.explanations["B000"]
        self.assertTrue(exp.enabled)
        self.assertTrue(
            any(s["source"] == "cli:--tests" for s in exp.sources)
        )

    def test_explain_combined_sources(self):
        profile = {
            "include": {"B000", "B401"},
            "exclude": {"B401"},
            "sources": {
                "B000": [
                    ("config_file", "included", "included via config file tests list"),
                    ("cli:--tests", "included", "included via CLI --tests"),
                ],
                "B401": [
                    ("config_file", "included", "included via config file tests list"),
                    ("cli:--skip", "excluded", "excluded via CLI --skip"),
                ],
            },
        }
        # This profile is invalid (overlap), but _get_filter handles it
        # by subtracting exclude from include. We bypass validate_profile.
        ts = test_set.BanditTestSet(self.config, profile, explain=True)
        # B401 should be disabled (excluded wins)
        self.assertFalse(ts.explanations["B401"].enabled)
        # B000 should be enabled
        self.assertTrue(ts.explanations["B000"].enabled)
        # B000 should have both sources recorded
        b000_sources = [
            s["source"] for s in ts.explanations["B000"].sources
        ]
        self.assertIn("config_file", b000_sources)
        self.assertIn("cli:--tests", b000_sources)

    def test_explain_as_dict(self):
        ts = test_set.BanditTestSet(self.config, explain=True)
        exp = ts.explanations["B000"]
        d = exp.as_dict()
        self.assertEqual("B000", d["test_id"])
        self.assertEqual("test_plugin", d["test_name"])
        self.assertIsInstance(d["enabled"], bool)
        self.assertIsInstance(d["sources"], list)
        self.assertIsInstance(d["final_reason"], str)

    def test_explain_named_profile_source(self):
        profile = {
            "include": ["B000"],
            "exclude": [],
            "sources": {
                "B000": [
                    ("profile:strict", "included", "included by profile 'strict'")
                ],
            },
        }
        ts = test_set.BanditTestSet(self.config, profile, explain=True)
        exp = ts.explanations["B000"]
        self.assertTrue(exp.enabled)
        self.assertTrue(
            any(s["source"] == "profile:strict" for s in exp.sources)
        )
