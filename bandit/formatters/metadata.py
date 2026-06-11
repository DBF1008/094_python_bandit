#
# SPDX-License-Identifier: Apache-2.0
"""Shared metadata builders for bandit formatters.

This module centralises the construction of enriched metadata dicts
that are added to JSON and SARIF output.  Both formatters import from
here so that serialisation logic is not duplicated.

Three kinds of metadata are provided:

* **Issue metadata** — rule documentation URL and config source for
  each reported issue.
* **Config metadata** — which config file was used and its format.
* **Suppression metadata** — details of issues that were silenced by
  ``#nosec`` comments.
"""
from __future__ import annotations

from bandit.core import docs_utils


# ------------------------------------------------------------------
# Config metadata
# ------------------------------------------------------------------

def build_config_metadata(manager) -> dict:
    """Return a dict describing the config source for the current scan.

    Parameters:
        manager: The active :class:`~bandit.core.manager.BanditManager`.

    Returns:
        A dict with ``config_file`` (``str | None``) and
        ``config_format`` (``"yaml"`` | ``"toml"`` | ``"default"``).
    """
    b_conf = manager.b_conf
    return {
        "config_file": b_conf.config_file,
        "config_format": b_conf.config_format,
    }


# ------------------------------------------------------------------
# Per-issue enriched metadata
# ------------------------------------------------------------------

def build_issue_metadata(issue, manager) -> dict:
    """Return a dict of enriched fields to merge into a result dict.

    The returned dict contains:

    * ``rule_doc_url`` — direct URL to the plugin documentation page.
    * ``config_source`` — output of :func:`build_config_metadata`.

    Parameters:
        issue: An :class:`~bandit.core.issue.Issue` instance.
        manager: The active :class:`~bandit.core.manager.BanditManager`.

    Returns:
        A dict to merge (``dict.update()``) into the formatter's
        per-result dictionary.
    """
    return {
        "rule_doc_url": docs_utils.get_url(issue.test_id),
        "config_source": build_config_metadata(manager),
    }


# ------------------------------------------------------------------
# Suppression metadata
# ------------------------------------------------------------------

def build_suppression_entry(suppressed) -> dict:
    """Convert a :class:`~bandit.core.suppression.SuppressedIssue` to a
    serializable dict.

    Parameters:
        suppressed: A ``SuppressedIssue`` instance.

    Returns:
        A plain ``dict`` suitable for JSON serialisation.
    """
    return suppressed.as_dict()


def build_suppressions_list(manager) -> list[dict]:
    """Return a list of suppression dicts for the whole scan.

    Parameters:
        manager: The active :class:`~bandit.core.manager.BanditManager`.

    Returns:
        A list (possibly empty) of suppression dicts.
    """
    return [
        build_suppression_entry(s)
        for s in manager.get_suppressed_issues()
    ]
