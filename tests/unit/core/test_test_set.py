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

    def test_validate_profile_b001_in_both_include_exclude(self):
        """B001 in both include and exclude should not raise ValueError."""
        profile = {"include": {"B001", "B000"}, "exclude": {"B001"}}
        # Should not raise - B001 is a meta ID handled specially by _get_filter
        extension_loader.MANAGER.validate_profile(profile)

    def test_validate_profile_specific_test_conflict_still_raises(self):
        """A real test ID in both include and exclude must still raise."""
        profile = {"include": {"B000"}, "exclude": {"B000"}}
        self.assertRaises(
            ValueError, extension_loader.MANAGER.validate_profile, profile
        )

    def test_validate_profile_b001_only_in_both(self):
        """B001 alone in both include and exclude should not raise."""
        profile = {"include": {"B001"}, "exclude": {"B001"}}
        extension_loader.MANAGER.validate_profile(profile)

    def test_get_filter_b001_include_and_exclude(self):
        """When B001 in both include and exclude, blacklists are excluded."""
        profile = {"include": {"B000", "B001"}, "exclude": {"B001"}}
        filtering = test_set.BanditTestSet._get_filter(self.config, profile)
        # B000 (non-blacklist plugin) should be included
        self.assertIn("B000", filtering)
        # B001 should not appear in the final filter
        self.assertNotIn("B001", filtering)
        # Specific blacklist tests should be excluded
        self.assertNotIn("B401", filtering)
        self.assertNotIn("B302", filtering)

    def test_get_filter_b001_include_with_specific_exclude(self):
        """B001 in include with specific blacklist ID in exclude."""
        profile = {"include": {"B000", "B001"}, "exclude": {"B401"}}
        filtering = test_set.BanditTestSet._get_filter(self.config, profile)
        self.assertIn("B000", filtering)
        # B401 excluded, B302 should remain
        self.assertNotIn("B401", filtering)
        self.assertIn("B302", filtering)

    def test_get_filter_include_exclude_disjoint(self):
        """Normal disjoint include/exclude should work as expected."""
        profile = {"include": {"B000", "B401"}, "exclude": {"B401"}}
        filtering = test_set.BanditTestSet._get_filter(self.config, profile)
        self.assertIn("B000", filtering)
        self.assertNotIn("B401", filtering)

    def test_profile_blacklist_compat_with_include_and_exclude(self):
        """Legacy blacklist profile with both include and exclude works."""
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
        profile = {
            "include": {"B001", "B000"},
            "exclude": set(),
            "blacklist": {"Call": data},
        }
        ts = test_set.BanditTestSet(self.config, profile)
        # B000 plugin should be loaded
        self.assertEqual(1, len(ts.get_tests("Str")))
        # Blacklist should be loaded with legacy data
        self.assertEqual(1, len(ts.get_tests("Call")))
