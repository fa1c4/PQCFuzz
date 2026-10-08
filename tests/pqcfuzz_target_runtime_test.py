"""Acceptance tests for the registered target-package vertical slice."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "src/runtime/target_package.py"
spec = importlib.util.spec_from_file_location("target_package", RUNTIME)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def command(*args):
    return subprocess.run([sys.executable, str(ROOT / "scripts/pqcfuzz_target.py"), *args],
                          cwd=ROOT, capture_output=True, text=True)


class TargetRuntimeAcceptance(unittest.TestCase):
    def test_unknown_oracle_fails_closed(self):
        result = command("preflight", "--target", "demo-stream-hash", "--algorithm",
                         "DEMO-HASH", "--api", "stream", "--profile", "healthy",
                         "--oracle", "DOES-NOT-EXIST")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown oracle ID", result.stderr)

    def test_missing_capability_fails_closed(self):
        args = type("Args", (), {"target": "demo-stream-hash", "algorithm": "DEMO-HASH",
                 "api": "stream", "profile": "healthy", "oracle": None, "iterations": None})()
        original = Path.read_text
        manifest_path = ROOT / "oracles/demo-stream-hash/manifest.json"
        def modified(path, *a, **kw):
            content = original(path, *a, **kw)
            if Path(path) == manifest_path:
                data = json.loads(content)
                data["capabilities"]["streaming"] = False
                return json.dumps(data)
            return content
        with patch.object(Path, "read_text", modified):
            with self.assertRaisesRegex(runtime.ConfigError, "unsupported capabilities"):
                runtime.validate(args)

    def test_out_of_scope_primitive_is_not_applicable(self):
        args = type("Args", (), {"target": "demo-stream-hash", "algorithm": "DEMO-HASH",
                 "api": "stream", "profile": "healthy", "oracle": None, "iterations": None})()
        original = Path.read_text
        manifest_path = ROOT / "oracles/demo-stream-hash/manifest.json"
        def modified(path, *a, **kw):
            content = original(path, *a, **kw)
            if Path(path) == manifest_path:
                data = json.loads(content)
                data["oracles"][0]["applicable_primitives"] = ["signature"]
                return json.dumps(data)
            return content
        with patch.object(Path, "read_text", modified):
            with self.assertRaisesRegex(runtime.NotApplicableError, "not applicable"):
                runtime.validate(args)

    def test_unknown_schema_fails_closed(self):
        args = type("Args", (), {"target": "demo-stream-hash", "algorithm": "DEMO-HASH",
                 "api": "stream", "profile": "healthy", "oracle": None, "iterations": None})()
        original = Path.read_text
        config_path = ROOT / "configs/targets.json"
        def modified(path, *a, **kw):
            content = original(path, *a, **kw)
            if Path(path) == config_path:
                data = json.loads(content)
                data["schema_version"] = 999
                return json.dumps(data)
            return content
        with patch.object(Path, "read_text", modified):
            with self.assertRaisesRegex(runtime.ConfigError, "unknown registry schema"):
                runtime.validate(args)

    def test_verified_spec_state_is_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spec.md"
            path.write_text("---\nstatus: verified\ntarget: x\nalgorithm: a\nsource_path: x\n"
                            "source_sha256: abc\ndocument_path: x\ndocument_sha256: abc\nsource_version: 1\nextract_version: 1\n"
                            "reviewer: human\nreview_date: 2026-10-08\n---\n## S1 — claim\n",
                            encoding="utf-8")
            status, _ = runtime.spec_status(path)
            self.assertEqual(status["status"], "verified")

    def test_healthy_and_injected_runs_preserve_candidate_evidence(self):
        for profile, expected in (("healthy", 0), ("injected", 2)):
            result = command("run", "--target", "demo-stream-hash", "--algorithm",
                             "DEMO-HASH", "--api", "stream", "--profile", profile)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["counts"]["counterexample_candidate"], expected)
            run = Path(summary["run"])
            manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(runtime.verify_run(run)["integrity"], "ok")
            self.assertTrue((run / "package/implement/adapter.py").is_file())
            self.assertTrue((run / "snapshots/original_spec.md").is_file())
            report = json.loads((run / "report.json").read_text(encoding="utf-8"))
            trace = json.loads((run / "trace.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["spec_status"], "draft")
            self.assertEqual(manifest["evidence_class"], "unverified_spec")
            self.assertEqual(report["replay_status"], "not_run")
            self.assertEqual(report["confirmed_findings"], 0)
            for candidate in report["candidates"]:
                self.assertEqual(candidate["claim_id"], "S1")
                self.assertIn("Section 1", candidate["source_locator"])
                self.assertTrue(candidate["limitations"])
            self.assertTrue(any(t["kind"] == "negative" and t["verdict"] == "inconclusive"
                                for t in trace))
            self.assertTrue(any(t["kind"] == "positive" and t["verdict"] == "pass"
                                and t["fault_relation"]["holds"] is False for t in trace))
            for rel, digest in manifest["file_hashes"].items():
                self.assertEqual(runtime.sha(run / rel), digest)


if __name__ == "__main__":
    unittest.main()
