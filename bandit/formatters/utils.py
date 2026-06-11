# Copyright (c) 2016 Rackspace, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""Utility functions for formatting plugins for Bandit."""
import io

from bandit.core import docs_utils


def wrap_file_object(fileobj):
    """If the fileobj passed in cannot handle text, use TextIOWrapper
    to handle the conversion.
    """
    if isinstance(fileobj, io.TextIOBase):
        return fileobj
    return io.TextIOWrapper(fileobj)


def enrich_issue(issue_dict):
    """Add more_info URL to an issue dict. Mutates and returns the dict."""
    issue_dict["more_info"] = docs_utils.get_url(issue_dict["test_id"])
    return issue_dict
