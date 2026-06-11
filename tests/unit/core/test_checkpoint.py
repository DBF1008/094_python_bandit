#
# SPDX-License-Identifier: Apache-2.0
import json
import os

import fixtures
import testtools

from bandit.core import checkpoint
from bandit.core import config


class FileRecordTests(testtools.TestCase):
    def test_success_as_dict(self):
        record = checkpoint.FileRecord(
            fname="test.py",
            status="success",
            content_hash="abc123",
            issues=[{"test_id": "B101", "issue_text": "assert used"}],
            metrics={"loc": 10, "nosec": 0},
            score={"SEVERITY": [0, 0, 0, 0], "CONFIDENCE": [0, 0, 0, 0]},
        )
        d = record.as_dict()
        self.assertEqual("success", d["status"])
        self.assertEqual("abc123", d["content_hash"])
        self.assertEqual(1, len(d["issues"]))
        self.assertEqual(10, d["metrics"]["loc"])
        self.assertIn("score", d)

    def test_failed_as_dict(self):
        record = checkpoint.FileRecord(
            fname="bad.py", status="failed"
        )
        d = record.as_dict()
        self.assertEqual("failed", d["status"])
        self.assertIsNone(d["content_hash"])
        self.assertNotIn("issues", d)
        self.assertNotIn("metrics", d)

    def test_syntax_error_as_dict(self):
        record = checkpoint.FileRecord(
            fname="broken.py", status="syntax_error"
        )
        d = record.as_dict()
        self.assertEqual("syntax_error", d["status"])
        self.assertNotIn("issues", d)

    def test_success_roundtrip(self):
        original = checkpoint.FileRecord(
            fname="test.py",
            status="success",
            content_hash="def456",
            issues=[{"test_id": "B102", "issue_text": "exec used"}],
            metrics={"loc": 20, "nosec": 1},
            score={"SEVERITY": [0, 3, 0, 0], "CONFIDENCE": [0, 0, 5, 0]},
        )
        d = original.as_dict()
        restored = checkpoint.FileRecord.from_dict("test.py", d)
        self.assertEqual(original.fname, restored.fname)
        self.assertEqual(original.status, restored.status)
        self.assertEqual(original.content_hash, restored.content_hash)
        self.assertEqual(original.issues, restored.issues)
        self.assertEqual(original.metrics, restored.metrics)
        self.assertEqual(original.score, restored.score)

    def test_failed_roundtrip(self):
        original = checkpoint.FileRecord(
            fname="bad.py", status="failed"
        )
        d = original.as_dict()
        restored = checkpoint.FileRecord.from_dict("bad.py", d)
        self.assertEqual("failed", restored.status)
        self.assertIsNone(restored.content_hash)


class CheckpointTests(testtools.TestCase):
    def test_save_and_load(self):
        tmp_dir = self.useFixture(fixtures.TempDir()).path
        ckpt_path = os.path.join(tmp_dir, "test.checkpoint")

        original = checkpoint.Checkpoint(config_hash="hash123")
        original.files["a.py"] = checkpoint.FileRecord(
            fname="a.py",
            status="success",
            content_hash="aaa",
            issues=[],
            metrics={"loc": 5},
            score={"SEVERITY": [0, 0, 0, 0]},
        )
        original.files["b.py"] = checkpoint.FileRecord(
            fname="b.py", status="syntax_error"
        )
        original.save(ckpt_path)

        loaded = checkpoint.Checkpoint.load(ckpt_path)
        self.assertIsNotNone(loaded)
        self.assertEqual("hash123", loaded.config_hash)
        self.assertEqual(checkpoint.CHECKPOINT_VERSION, loaded.version)
        self.assertIn("a.py", loaded.files)
        self.assertIn("b.py", loaded.files)
        self.assertEqual("success", loaded.files["a.py"].status)
        self.assertEqual("aaa", loaded.files["a.py"].content_hash)
        self.assertEqual("syntax_error", loaded.files["b.py"].status)

    def test_load_missing_file(self):
        result = checkpoint.Checkpoint.load("/nonexistent/path.json")
        self.assertIsNone(result)

    def test_load_invalid_json(self):
        tmp_dir = self.useFixture(fixtures.TempDir()).path
        bad_file = os.path.join(tmp_dir, "bad.json")
        with open(bad_file, "w") as f:
            f.write("not valid json{{{")
        result = checkpoint.Checkpoint.load(bad_file)
        self.assertIsNone(result)

    def test_load_version_mismatch(self):
        tmp_dir = self.useFixture(fixtures.TempDir()).path
        ckpt_path = os.path.join(tmp_dir, "old.checkpoint")
        with open(ckpt_path, "w") as f:
            json.dump({
                "version": 999,
                "config_hash": "x",
                "timestamp": 0,
                "files": {},
            }, f)
        result = checkpoint.Checkpoint.load(ckpt_path)
        self.assertIsNone(result)


class FileHashTests(testtools.TestCase):
    def test_consistent_hash(self):
        tmp_dir = self.useFixture(fixtures.TempDir()).path
        fpath = os.path.join(tmp_dir, "test.py")
        with open(fpath, "w") as f:
            f.write("print('hello')\n")
        h1 = checkpoint.compute_file_hash(fpath)
        h2 = checkpoint.compute_file_hash(fpath)
        self.assertEqual(h1, h2)

    def test_different_content_different_hash(self):
        tmp_dir = self.useFixture(fixtures.TempDir()).path
        f1 = os.path.join(tmp_dir, "a.py")
        f2 = os.path.join(tmp_dir, "b.py")
        with open(f1, "w") as f:
            f.write("x = 1\n")
        with open(f2, "w") as f:
            f.write("x = 2\n")
        self.assertNotEqual(
            checkpoint.compute_file_hash(f1),
            checkpoint.compute_file_hash(f2),
        )


class ConfigHashTests(testtools.TestCase):
    def test_deterministic(self):
        conf = config.BanditConfig()
        profile = {"include": {"B101", "B102"}, "exclude": {"B201"}}
        h1 = checkpoint.compute_config_hash(conf, profile)
        h2 = checkpoint.compute_config_hash(conf, profile)
        self.assertEqual(h1, h2)

    def test_changes_on_profile_change(self):
        conf = config.BanditConfig()
        p1 = {"include": {"B101"}, "exclude": set()}
        p2 = {"include": {"B101", "B102"}, "exclude": set()}
        h1 = checkpoint.compute_config_hash(conf, p1)
        h2 = checkpoint.compute_config_hash(conf, p2)
        self.assertNotEqual(h1, h2)

    def test_set_order_invariant(self):
        conf = config.BanditConfig()
        # Sets are unordered, but sorted() in compute_config_hash
        # should make the hash deterministic regardless of iteration order
        p1 = {"include": {"B102", "B101", "B103"}, "exclude": set()}
        p2 = {"include": {"B103", "B101", "B102"}, "exclude": set()}
        h1 = checkpoint.compute_config_hash(conf, p1)
        h2 = checkpoint.compute_config_hash(conf, p2)
        self.assertEqual(h1, h2)
