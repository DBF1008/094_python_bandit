#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import dataclasses
import importlib
import logging

from bandit.core import blacklisting
from bandit.core import extension_loader

LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class RuleExplanation:
    """Tracks the provenance of a single test rule's enabled/disabled state."""

    test_id: str
    test_name: str
    enabled: bool
    sources: list  # list of dicts: {"source": str, "action": str, "detail": str}
    final_reason: str

    def as_dict(self):
        return dataclasses.asdict(self)


class BanditTestSet:
    def __init__(self, config, profile=None, explain=False):
        if not profile:
            profile = {}
        extman = extension_loader.MANAGER
        filtering = self._get_filter(config, profile)
        self.plugins = [
            p for p in extman.plugins if p.plugin._test_id in filtering
        ]
        self.plugins.extend(self._load_builtins(filtering, profile))
        self._load_tests(config, self.plugins)

        if explain:
            self.explanations = self._build_explanations(
                profile, filtering
            )
        else:
            self.explanations = {}

    @staticmethod
    def _get_filter(config, profile):
        extman = extension_loader.MANAGER

        inc = set(profile.get("include", []))
        exc = set(profile.get("exclude", []))

        all_blacklist_tests = set()
        for _, tests in extman.blacklist.items():
            all_blacklist_tests.update(t["id"] for t in tests)

        # this block is purely for backwards compatibility, the rules are as
        # follows:
        # B001,B401 means B401
        # B401 means B401
        # B001 means all blacklist tests
        if "B001" in inc:
            if not inc.intersection(all_blacklist_tests):
                inc.update(all_blacklist_tests)
            inc.discard("B001")
        if "B001" in exc:
            if not exc.intersection(all_blacklist_tests):
                exc.update(all_blacklist_tests)
            exc.discard("B001")

        if inc:
            filtered = inc
        else:
            filtered = set(extman.plugins_by_id.keys())
            filtered.update(extman.builtin)
            filtered.update(all_blacklist_tests)
        return filtered - exc

    def _load_builtins(self, filtering, profile):
        """loads up builtin functions, so they can be filtered."""

        class Wrapper:
            def __init__(self, name, plugin):
                self.name = name
                self.plugin = plugin

        extman = extension_loader.MANAGER
        blacklist = profile.get("blacklist")
        if not blacklist:  # not overridden by legacy data
            blacklist = {}
            for node, tests in extman.blacklist.items():
                values = [t for t in tests if t["id"] in filtering]
                if values:
                    blacklist[node] = values

        if not blacklist:
            return []

        # this dresses up the blacklist to look like a plugin, but
        # the '_checks' data comes from the blacklist information.
        # the '_config' is the filtered blacklist data set.
        blacklisting.blacklist._test_id = "B001"
        blacklisting.blacklist._checks = blacklist.keys()
        blacklisting.blacklist._config = blacklist

        return [Wrapper("blacklist", blacklisting.blacklist)]

    def _load_tests(self, config, plugins):
        """Builds a dict mapping tests to node types."""
        self.tests = {}
        for plugin in plugins:
            if hasattr(plugin.plugin, "_takes_config"):
                # TODO(??): config could come from profile ...
                cfg = config.get_option(plugin.plugin._takes_config)
                if cfg is None:
                    genner = importlib.import_module(plugin.plugin.__module__)
                    cfg = genner.gen_config(plugin.plugin._takes_config)
                plugin.plugin._config = cfg
            for check in plugin.plugin._checks:
                self.tests.setdefault(check, []).append(plugin.plugin)
                LOG.debug(
                    "added function %s (%s) targeting %s",
                    plugin.name,
                    plugin.plugin._test_id,
                    check,
                )

    def get_tests(self, checktype):
        """Returns all tests that are of type checktype

        :param checktype: The type of test to filter on
        :return: A list of tests which are of the specified type
        """
        return self.tests.get(checktype) or []

    @staticmethod
    def _build_explanations(profile, filtering):
        """Build a dict of RuleExplanation for every known test ID.

        :param profile: The resolved profile dict (include, exclude, sources)
        :param filtering: The final set of enabled test IDs
        :return: dict mapping test_id -> RuleExplanation
        """
        extman = extension_loader.MANAGER

        # Gather all known test IDs and names
        all_tests = {}
        for tid, ext in extman.plugins_by_id.items():
            all_tests[tid] = ext.name
        for tid in extman.builtin:
            all_tests[tid] = "blacklist"
        for node_tests in extman.blacklist.values():
            for t in node_tests:
                all_tests[t["id"]] = t["name"]

        inc = set(profile.get("include", []))
        exc = set(profile.get("exclude", []))
        sources_map = profile.get("sources", {})

        explanations = {}
        for tid, tname in sorted(all_tests.items()):
            sources = []
            recorded = sources_map.get(tid, [])

            # Determine the base inclusion reason
            if inc:
                if tid in inc:
                    base_source = [
                        s for s in recorded if s[1] == "included"
                    ]
                    if base_source:
                        src, _, origin = (
                            base_source[0][0],
                            base_source[0][1],
                            base_source[0][2] if len(base_source[0]) > 2
                            else base_source[0][0],
                        )
                        sources.append({
                            "source": src,
                            "action": "included",
                            "detail": origin,
                        })
                    else:
                        sources.append({
                            "source": "profile",
                            "action": "included",
                            "detail": "included by profile include list",
                        })
                # else: not in include list, no inclusion source
            else:
                sources.append({
                    "source": "default",
                    "action": "included",
                    "detail": "all tests included by default",
                })

            # Record exclusion sources
            exc_recorded = [s for s in recorded if s[1] == "excluded"]
            if exc_recorded:
                for entry in exc_recorded:
                    src = entry[0]
                    origin = entry[2] if len(entry) > 2 else src
                    sources.append({
                        "source": src,
                        "action": "excluded",
                        "detail": origin,
                    })
            elif tid in exc:
                sources.append({
                    "source": "profile",
                    "action": "excluded",
                    "detail": "excluded by profile exclude list",
                })

            # Record any CLI override sources not yet captured
            for entry in recorded:
                src, action = entry[0], entry[1]
                origin = entry[2] if len(entry) > 2 else src
                already = any(
                    s["source"] == src and s["action"] == action
                    for s in sources
                )
                if not already:
                    sources.append({
                        "source": src,
                        "action": action,
                        "detail": origin,
                    })

            enabled = tid in filtering

            # Determine final reason
            if enabled:
                inc_sources = [
                    s for s in sources if s["action"] == "included"
                ]
                if inc_sources:
                    final_reason = (
                        f"enabled: {inc_sources[-1]['detail']}"
                    )
                else:
                    final_reason = "enabled: included by default"
            else:
                exc_sources = [
                    s for s in sources if s["action"] == "excluded"
                ]
                if exc_sources:
                    final_reason = (
                        f"disabled: {exc_sources[-1]['detail']}"
                    )
                elif inc:
                    final_reason = (
                        "disabled: not in profile include list"
                    )
                else:
                    final_reason = "disabled"

            explanations[tid] = RuleExplanation(
                test_id=tid,
                test_name=tname,
                enabled=enabled,
                sources=sources,
                final_reason=final_reason,
            )

        return explanations
