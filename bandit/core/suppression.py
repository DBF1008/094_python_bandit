#
# SPDX-License-Identifier: Apache-2.0
"""Suppression tracking data structures for bandit.

This module provides the dataclass used to track issues that were
suppressed by ``#nosec`` comments during a scan.  Formatters can use
the information here to explain *why* a particular finding was not
reported.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SuppressedIssue:
    """Records a single issue that was suppressed by a ``#nosec`` comment.

    Attributes:
        test_id: The bandit test identifier (e.g. ``B101``).
        test_name: The plugin/test function name that produced the issue.
        filename: Path to the file where the issue was found.
        lineno: Line number of the issue.
        issue_text: Human-readable description of the issue.
        severity: Issue severity level (``LOW``, ``MEDIUM``, ``HIGH``).
        confidence: Issue confidence level.
        nosec_type: Either ``"blanket"`` (bare ``#nosec``) or
            ``"specific"`` (``#nosec B101``).
        suppressed_tests: The list of test IDs mentioned in the nosec
            comment.  Empty for blanket suppressions.
        nosec_lineno: The line number where the ``#nosec`` comment
            appeared (may differ from *lineno* for multi-line
            expressions).
    """

    test_id: str
    test_name: str
    filename: str
    lineno: int
    issue_text: str
    severity: str
    confidence: str
    nosec_type: str  # "blanket" | "specific"
    suppressed_tests: list[str] = field(default_factory=list)
    nosec_lineno: int = 0

    def as_dict(self) -> dict:
        """Serialize to a plain dictionary for formatter output."""
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "filename": self.filename,
            "lineno": self.lineno,
            "issue_text": self.issue_text,
            "issue_severity": self.severity,
            "issue_confidence": self.confidence,
            "nosec_type": self.nosec_type,
            "suppressed_tests": list(self.suppressed_tests),
            "nosec_lineno": self.nosec_lineno,
        }
