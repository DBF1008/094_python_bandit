#
# SPDX-License-Identifier: Apache-2.0
"""Checkpoint support for incremental scanning mode.

This module provides the data model and utilities for saving and loading
scan checkpoints, enabling bandit to skip unchanged files on subsequent runs.
"""
import hashlib
import json
import logging
import time

LOG = logging.getLogger(__name__)

CHECKPOINT_VERSION = 1


class FileRecord:
    """Records the scan state of a single file.

    :param fname: file path
    :param status: "success", "syntax_error", or "failed"
    :param content_hash: SHA-256 hash of file content (success only)
    :param issues: list of issue dicts (success only)
    :param metrics: metrics dict for this file (success only)
    :param score: score dict for this file (success only)
    """

    def __init__(self, fname, status, content_hash=None,
                 issues=None, metrics=None, score=None):
        self.fname = fname
        self.status = status
        self.content_hash = content_hash
        self.issues = issues or []
        self.metrics = metrics or {}
        self.score = score or {}

    def as_dict(self):
        d = {
            "status": self.status,
            "content_hash": self.content_hash,
        }
        if self.status == "success":
            d["issues"] = self.issues
            d["metrics"] = self.metrics
            d["score"] = self.score
        return d

    @classmethod
    def from_dict(cls, fname, data):
        return cls(
            fname=fname,
            status=data["status"],
            content_hash=data.get("content_hash"),
            issues=data.get("issues", []),
            metrics=data.get("metrics", {}),
            score=data.get("score", {}),
        )


class Checkpoint:
    """Top-level checkpoint data model.

    :param config_hash: hash of the scan configuration
    :param files: dict mapping filename to FileRecord
    :param timestamp: scan timestamp (epoch seconds)
    """

    def __init__(self, config_hash, files=None, timestamp=None):
        self.version = CHECKPOINT_VERSION
        self.config_hash = config_hash
        self.timestamp = timestamp or time.time()
        self.files = files or {}

    def save(self, filepath):
        """Serialize checkpoint to a JSON file."""
        data = {
            "version": self.version,
            "config_hash": self.config_hash,
            "timestamp": self.timestamp,
            "files": {
                fname: record.as_dict()
                for fname, record in self.files.items()
            },
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))
        LOG.info(
            "Checkpoint saved to %s (%d files)", filepath, len(self.files)
        )

    @classmethod
    def load(cls, filepath):
        """Load a checkpoint from a JSON file.

        :returns: Checkpoint instance, or None on failure.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            LOG.warning("Failed to load checkpoint file %s: %s", filepath, e)
            return None

        version = data.get("version")
        if version != CHECKPOINT_VERSION:
            LOG.warning(
                "Checkpoint version mismatch: expected %d, got %s. "
                "Ignoring checkpoint.",
                CHECKPOINT_VERSION,
                version,
            )
            return None

        files = {}
        for fname, fdata in data.get("files", {}).items():
            files[fname] = FileRecord.from_dict(fname, fdata)

        return cls(
            config_hash=data["config_hash"],
            files=files,
            timestamp=data.get("timestamp"),
        )


def compute_file_hash(filepath):
    """Compute the SHA-256 hash of a file's contents.

    Uses chunked reading to handle large files without excessive memory.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_config_hash(b_conf, profile):
    """Compute a deterministic hash of the scan configuration.

    :param b_conf: BanditConfig instance
    :param profile: profile dict with 'include' and 'exclude' sets
    :returns: SHA-256 hex string
    """
    config_data = {
        "config": b_conf.config,
        "profile_include": sorted(profile.get("include", [])),
        "profile_exclude": sorted(profile.get("exclude", [])),
    }
    serialized = json.dumps(config_data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
