#!/usr/bin/env python3
"""Compact baseline fuzzer result trees after an eval campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ARTIFACT_PREFIXES = ("crash-", "timeout-", "leak-", "oom-", "hang-")
COUNT_KEYS = ("crash", "timeout", "leak", "oom", "hang")
LIBFUZZER_TARGETS = ("kem", "sig")
LIBFUZZER_PROFILE_NAMES = ("memory-safety", "semantic")
CRYPTOTESTING_TARGETS = {
    "0.14.0": "ches_liboqs",
    "0.8.0": "cur_liboqs",
    "0.4.0": "mid_liboqs",
}


class ReplayValidationError(RuntimeError):
    """A structured finding was retained but did not reproduce its relation.

    This is deliberately separate from ordinary compaction errors.  The main
    entry point writes a non-compacted manifest for it so an evaluator can see
    why the evidence was preserved instead of silently treating it as a valid
    semantic finding.
    """

    def __init__(self, message: str, validation: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.validation = validation


def empty_artifact_counts() -> dict[str, int]:
    return {key: 0 for key in COUNT_KEYS}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: Path) -> str:
    try:
        return os.path.relpath(path)
    except ValueError:
        return str(path)


def rel_to(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return rel(path)


def is_within(path: Path, root: Path) -> bool:
    path_abs = os.path.abspath(path)
    root_abs = os.path.abspath(root)
    try:
        return os.path.commonpath([path_abs, root_abs]) == root_abs
    except ValueError:
        return False


def path_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file() or path.is_symlink():
        try:
            return path.stat().st_size
        except OSError:
            return 0

    total = 0
    for child in path.rglob("*"):
        if not child.is_file() and not child.is_symlink():
            continue
        try:
            total += child.stat().st_size
        except OSError:
            pass
    return total


def count_prefix_artifact(path: Path, counts: dict[str, int]) -> bool:
    kind = prefix_artifact_kind(path)
    if kind is None:
        return False
    counts[kind] += 1
    return True


def prefix_artifact_kind(path: Path) -> str | None:
    for prefix in ARTIFACT_PREFIXES:
        if path.name.startswith(prefix):
            return prefix[:-1]
    return None


class Compactor:
    def __init__(self, workspace_root: Path, baseline: str, version: str) -> None:
        self.workspace_root = workspace_root
        self.baseline = baseline
        self.version = version
        self.baseline_root = workspace_root / baseline
        self.build_root = self.baseline_root / "targets-build"
        self.run_root = self.baseline_root / "targets-run"
        self.manifest_path = self.baseline_root / "compaction_manifest.json"
        self.retained_paths: set[str] = set()
        self.removed_paths: list[str] = []
        self.removed_bytes_estimate = 0
        self.retained_artifact_counts = empty_artifact_counts()
        self.retained_artifact_counts_by_target: dict[str, dict[str, int]] = {}
        self.retained_artifact_counts_by_target_profile: dict[str, dict[str, dict[str, int]]] = {}
        self.retained_semantic_finding_counts_by_target: dict[str, int] = {}
        self.retained_semantic_finding_counts_by_target_profile: dict[str, dict[str, int]] = {}
        self.retained_operation_diagnostic_counts_by_target: dict[str, int] = {}
        self.retained_operation_diagnostic_counts_by_target_profile: dict[str, dict[str, int]] = {}
        self.libfuzzer_validation: dict[str, Any] = {"status": "passed", "targets": {}}
        self._libfuzzer_target_profiles: dict[str, set[str]] = {}
        self._libfuzzer_path_profiles: dict[tuple[str, str], set[str]] = {}
        self._libfuzzer_target_records: dict[str, dict[str, list[Path]]] = {}

        # cryptofuzz and CLFuzz have one version campaign root rather than
        # libFuzzer's KEM/SIG target hierarchy.  Keep their accounting local
        # to that root nonetheless: a global counter must never be copied into
        # an unrelated target summary when the layout grows another target.
        self.single_style_target_roots: dict[str, Path] = {}
        self.single_style_artifact_counts_by_target: dict[str, dict[str, int]] = {}
        self.single_style_semantic_finding_counts_by_target: dict[str, int] = {}
        self.single_style_operation_diagnostic_counts_by_target: dict[str, int] = {}
        self.single_style_validation: dict[str, Any] = {"status": "passed", "targets": {}}
        self._single_style_target_records: dict[str, dict[str, list[Path]]] = {}
        self._single_style_logical_hang_paths: dict[str, set[str]] = {}
        self.crypto_testing_campaigns: dict[str, dict[str, Any]] = {}

    def require_safe_path(self, path: Path) -> None:
        if not is_within(path, self.baseline_root):
            raise RuntimeError(f"refusing to modify path outside baseline workspace: {path}")

    def retain(self, path: Path) -> None:
        if path.exists():
            self.retained_paths.add(rel(path))

    def retain_tree_files(self, root: Path) -> None:
        if not root.is_dir():
            return
        for path in sorted(root.rglob("*")):
            if path.is_file():
                self.retain(path)

    def remove_path(self, path: Path) -> None:
        if not path.exists():
            return
        self.require_safe_path(path)
        self.removed_bytes_estimate += path_size(path)
        self.removed_paths.append(rel(path))
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()

    def remove_children_except_prefix_artifacts(self, root: Path, artifact_handler: Any = None) -> None:
        if not root.is_dir():
            return
        self.require_safe_path(root)
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_file() and count_prefix_artifact(path, self.retained_artifact_counts):
                if artifact_handler is not None:
                    artifact_handler(path)
                self.retain(path)
                continue
            if path.is_dir():
                if not any(path.iterdir()):
                    self.remove_path(path)
                continue
            self.remove_path(path)

    def libfuzzer_target_roots(self, version_run_root: Path) -> list[tuple[str, Path]]:
        return [
            (target, version_run_root / target)
            for target in LIBFUZZER_TARGETS
            if (version_run_root / target).exists()
        ]

    @staticmethod
    def json_files(root: Path) -> list[Path]:
        if not root.is_dir():
            return []
        return [path for path in sorted(root.rglob("*.json")) if path.is_file()]

    @staticmethod
    def summary_profile_from_filename(path: Path) -> str | None:
        name = path.name
        if not name.startswith("summary.") or not name.endswith(".json"):
            return None
        profile = name[len("summary.") : -len(".json")]
        return profile or None

    def libfuzzer_profile_records(self, target_root: Path) -> list[tuple[str | None, dict[str, Any]]]:
        """Return profile records from both the target index and detail summaries.

        A newer run has ``summary.json`` with a ``profiles`` mapping as well as
        ``summary.<profile>.json`` files.  Older runs have one direct summary.
        Reading both lets compaction validate either layout without making the
        index file a source of cross-profile counts.
        """

        records: list[tuple[str | None, dict[str, Any]]] = []
        for path in sorted(target_root.glob("summary*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue

            profiles = data.get("profiles")
            if isinstance(profiles, dict):
                for profile, profile_data in profiles.items():
                    if isinstance(profile, str) and isinstance(profile_data, dict):
                        records.append((profile, profile_data))

                # Some transition summaries may retain direct fields alongside
                # their profile index.  Do not discard those references.
                if any(
                    key in data
                    for key in (
                        "sanitizer_artifacts",
                        "crashes",
                        "semantic_findings",
                        "structured_findings",
                        "operation_diagnostics",
                        "diagnostics",
                    )
                ):
                    profile = data.get("profile")
                    records.append((profile if isinstance(profile, str) else None, data))
                continue

            profile = data.get("profile")
            if not isinstance(profile, str):
                profile = self.summary_profile_from_filename(path)
            records.append((profile, data))
        return records

    @staticmethod
    def flatten_summary_paths(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            paths: list[str] = []
            for item in value:
                paths.extend(Compactor.flatten_summary_paths(item))
            return paths
        if isinstance(value, dict):
            paths = []
            for key in ("path", "file", "record", "artifact", "relative_path", "name"):
                if key in value:
                    paths.extend(Compactor.flatten_summary_paths(value[key]))
            return paths
        return []

    def summary_entries(
        self,
        records: list[tuple[str | None, dict[str, Any]]],
        fields: tuple[str, ...],
    ) -> tuple[bool, list[tuple[str | None, str]]]:
        present = False
        entries: list[tuple[str | None, str]] = []
        for profile, data in records:
            for field in fields:
                if field not in data:
                    continue
                present = True
                entries.extend((profile, path) for path in self.flatten_summary_paths(data[field]))
        return present, entries

    @staticmethod
    def normalise_summary_path(path: str, target_root: Path) -> str | None:
        candidate = Path(path)
        if candidate.is_absolute():
            try:
                return candidate.relative_to(target_root).as_posix()
            except ValueError:
                return None

        normalised = os.path.normpath(path.replace("\\", "/"))
        while normalised.startswith("./"):
            normalised = normalised[2:]
        if normalised in {"", "."} or normalised == ".." or normalised.startswith("../"):
            return None
        return normalised.replace("\\", "/")

    def summary_entry_matches(
        self,
        path: Path,
        target_root: Path,
        category_root: Path,
        entry: str,
        allow_basename: bool,
    ) -> bool:
        normalised = self.normalise_summary_path(entry, target_root)
        if normalised is None:
            return False
        try:
            target_relative = path.relative_to(target_root).as_posix()
        except ValueError:
            return False
        candidates = {target_relative}
        try:
            candidates.add(path.relative_to(category_root).as_posix())
        except ValueError:
            pass
        if allow_basename:
            candidates.add(path.name)
        return normalised in candidates

    def infer_profile_from_path(
        self,
        target: str,
        path: Path,
        category_root: Path,
    ) -> set[str]:
        try:
            relative = path.relative_to(category_root)
        except ValueError:
            return set()
        if len(relative.parts) < 2:
            return set()
        known_profiles = self._libfuzzer_target_profiles.get(target, set()) | set(LIBFUZZER_PROFILE_NAMES)
        return {relative.parts[0]} if relative.parts[0] in known_profiles else set()

    def set_path_profiles(
        self,
        target: str,
        target_root: Path,
        path: Path,
        category_root: Path,
        profiles: set[str],
    ) -> None:
        if not profiles:
            profiles = self.infer_profile_from_path(target, path, category_root)
        for profile in profiles:
            self._libfuzzer_target_profiles.setdefault(target, set()).add(profile)
        try:
            relative = path.relative_to(target_root).as_posix()
        except ValueError:
            return
        self._libfuzzer_path_profiles[(target, relative)] = set(profiles)

    def validate_retained_paths(
        self,
        *,
        target: str,
        target_root: Path,
        category_root: Path,
        paths: list[Path],
        records: list[tuple[str | None, dict[str, Any]]],
        fields: tuple[str, ...],
        label: str,
        required: bool,
        legacy_fields: tuple[str, ...] = (),
    ) -> dict[str, int]:
        """Validate retained files against profile-local summary entries.

        ``sanitizer_artifacts`` is a new, recursive inventory and is strict.
        The old ``crashes`` list only covered direct children, so it remains a
        best-effort compatibility source rather than rejecting older trees.
        """

        primary_present, primary_entries = self.summary_entries(records, fields)
        legacy_present, legacy_entries = self.summary_entries(records, legacy_fields)
        entries = primary_entries if primary_present else legacy_entries
        strict = primary_present

        if paths and not entries:
            if required or strict:
                raise RuntimeError(
                    f"retained {label} has no matching summary entry for libFuzzer target {target}"
                )
            return {"retained": len(paths), "validated": 0, "legacy_unlisted": len(paths)}

        unmatched: list[Path] = []
        validated = 0
        for path in paths:
            profiles = {
                profile
                for profile, entry in entries
                if self.summary_entry_matches(
                    path, target_root, category_root, entry, allow_basename=not strict
                ) and profile is not None
            }
            if not profiles and entries:
                # A direct legacy summary has no profile, but still records the
                # artifact/finding itself.  The on-disk profile path, if any,
                # supplies the local count later.
                matched = any(
                    self.summary_entry_matches(
                        path, target_root, category_root, entry, allow_basename=not strict
                    )
                    for _, entry in entries
                )
                if not matched:
                    unmatched.append(path)
                    continue
            elif not profiles and not entries:
                unmatched.append(path)
                continue

            self.set_path_profiles(target, target_root, path, category_root, profiles)
            validated += 1

        if unmatched and strict:
            names = ", ".join(rel_to(path, target_root) for path in unmatched)
            raise RuntimeError(
                f"retained {label} missing from {', '.join(fields)} for libFuzzer target {target}: {names}"
            )

        # Old summaries did not recursively enumerate crash artifacts.  Keep
        # those files, but make the reduced validation visible in the manifest.
        legacy_unlisted = len(unmatched)
        for path in unmatched:
            self.set_path_profiles(target, target_root, path, category_root, set())
        return {
            "retained": len(paths),
            "validated": validated,
            "legacy_unlisted": legacy_unlisted,
            "summary_entries_present": int(primary_present or legacy_present),
        }

    def inspect_libfuzzer_target(self, target: str, target_root: Path) -> None:
        records = self.libfuzzer_profile_records(target_root)
        profiles = {profile for profile, _ in records if profile is not None}
        self._libfuzzer_target_profiles[target] = set(profiles)

        crashes_root = target_root / "crashes"
        crash_artifacts = [
            path
            for path in sorted(crashes_root.rglob("*"))
            if path.is_file() and prefix_artifact_kind(path) is not None
        ] if crashes_root.is_dir() else []

        findings_root = target_root / "findings"
        finding_records = [
            path
            for path in self.json_files(findings_root)
            if "diagnostics" not in path.relative_to(findings_root).parts
        ]

        diagnostics_root = target_root / "diagnostics"
        diagnostic_records = set(self.json_files(diagnostics_root))
        diagnostic_records.update(
            path
            for path in self.json_files(findings_root)
            if "diagnostics" in path.relative_to(findings_root).parts
        )
        sorted_diagnostics = sorted(diagnostic_records)

        crash_validation = self.validate_retained_paths(
            target=target,
            target_root=target_root,
            category_root=crashes_root,
            paths=crash_artifacts,
            records=records,
            fields=("sanitizer_artifacts",),
            legacy_fields=("crashes",),
            label="sanitizer artifact",
            required=False,
        )
        finding_validation = self.validate_retained_paths(
            target=target,
            target_root=target_root,
            category_root=findings_root,
            paths=finding_records,
            records=records,
            fields=("semantic_findings", "structured_findings"),
            label="structured finding",
            required=True,
        )
        diagnostic_validation = self.validate_retained_paths(
            target=target,
            target_root=target_root,
            category_root=diagnostics_root,
            paths=sorted_diagnostics,
            records=records,
            fields=("operation_diagnostics",),
            legacy_fields=("diagnostics",),
            label="operation diagnostic",
            required=False,
        )

        self._libfuzzer_target_records[target] = {
            "findings": finding_records,
            "diagnostics": sorted_diagnostics,
        }
        self.libfuzzer_validation["targets"][target] = {
            "status": "passed",
            "sanitizer_artifacts": crash_validation,
            "semantic_findings": finding_validation,
            "operation_diagnostics": diagnostic_validation,
        }

    def ensure_libfuzzer_target(self, target: str) -> None:
        self.retained_artifact_counts_by_target.setdefault(target, empty_artifact_counts())
        self.retained_semantic_finding_counts_by_target.setdefault(target, 0)
        self.retained_operation_diagnostic_counts_by_target.setdefault(target, 0)
        self._libfuzzer_target_profiles.setdefault(target, set())

    def ensure_libfuzzer_profile(self, target: str, profile: str) -> None:
        self.ensure_libfuzzer_target(target)
        self._libfuzzer_target_profiles[target].add(profile)
        self.retained_artifact_counts_by_target_profile.setdefault(target, {}).setdefault(
            profile, empty_artifact_counts()
        )
        self.retained_semantic_finding_counts_by_target_profile.setdefault(target, {}).setdefault(profile, 0)
        self.retained_operation_diagnostic_counts_by_target_profile.setdefault(target, {}).setdefault(profile, 0)

    def retained_path_profiles(
        self,
        target: str,
        target_root: Path,
        path: Path,
        category_root: Path,
    ) -> set[str]:
        try:
            relative = path.relative_to(target_root).as_posix()
        except ValueError:
            return set()
        profiles = self._libfuzzer_path_profiles.get((target, relative), set())
        if profiles:
            return set(profiles)
        return self.infer_profile_from_path(target, path, category_root)

    def record_libfuzzer_artifact(self, target: str, target_root: Path, path: Path) -> None:
        kind = prefix_artifact_kind(path)
        if kind is None:
            return
        self.ensure_libfuzzer_target(target)
        self.retained_artifact_counts_by_target[target][kind] += 1
        for profile in self.retained_path_profiles(target, target_root, path, target_root / "crashes"):
            self.ensure_libfuzzer_profile(target, profile)
            self.retained_artifact_counts_by_target_profile[target][profile][kind] += 1

    def record_libfuzzer_semantic_finding(self, target: str, target_root: Path, path: Path) -> None:
        self.ensure_libfuzzer_target(target)
        self.retained_semantic_finding_counts_by_target[target] += 1
        for profile in self.retained_path_profiles(target, target_root, path, target_root / "findings"):
            self.ensure_libfuzzer_profile(target, profile)
            self.retained_semantic_finding_counts_by_target_profile[target][profile] += 1

    def record_libfuzzer_operation_diagnostic(self, target: str, target_root: Path, path: Path) -> None:
        self.ensure_libfuzzer_target(target)
        self.retained_operation_diagnostic_counts_by_target[target] += 1
        category_root = target_root / "diagnostics"
        if not is_within(path, category_root):
            category_root = target_root / "findings"
        for profile in self.retained_path_profiles(target, target_root, path, category_root):
            self.ensure_libfuzzer_profile(target, profile)
            self.retained_operation_diagnostic_counts_by_target_profile[target][profile] += 1

    def compact_libfuzzer(self) -> None:
        version_run_root = self.run_root / f"liboqs-{self.version}"
        target_roots = self.libfuzzer_target_roots(version_run_root)

        # Validate the retained evidence before removing corpus/build output.
        # A failed validation therefore leaves the campaign tree untouched.
        for target, target_root in target_roots:
            self.inspect_libfuzzer_target(target, target_root)
            self.ensure_libfuzzer_target(target)
            for profile in self._libfuzzer_target_profiles[target]:
                self.ensure_libfuzzer_profile(target, profile)

        for summary in sorted(version_run_root.rglob("summary*.json")):
            self.retain(summary)
        for logs_dir in sorted(version_run_root.rglob("logs")):
            self.retain_tree_files(logs_dir)
        for target, target_root in target_roots:
            self.retain_tree_files(target_root / "findings")
            self.retain_tree_files(target_root / "diagnostics")
            self.retain_tree_files(target_root / "metadata")
            self.remove_children_except_prefix_artifacts(
                target_root / "crashes",
                lambda path, name=target, root=target_root: self.record_libfuzzer_artifact(name, root, path),
            )
            for path in self._libfuzzer_target_records[target]["findings"]:
                self.record_libfuzzer_semantic_finding(target, target_root, path)
            for path in self._libfuzzer_target_records[target]["diagnostics"]:
                self.record_libfuzzer_operation_diagnostic(target, target_root, path)
            self.remove_path(target_root / "corpus")
            self.remove_path(target_root / "artifacts")
        self.remove_path(self.build_root)

    @staticmethod
    def read_json_object(path: Path) -> dict[str, Any] | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def single_style_summary_records(self, target_root: Path) -> list[dict[str, Any]]:
        """Read only summaries owned by one campaign target root.

        ``rglob`` is intentionally not used here.  A finding can itself carry
        JSON metadata, and applying the campaign-wide artifact totals to it
        would recreate the cross-target accounting bug that compaction is
        meant to prevent.
        """

        records: list[dict[str, Any]] = []
        for path in sorted(target_root.glob("summary*.json")):
            data = self.read_json_object(path)
            if data is not None:
                records.append(data)
        return records

    @staticmethod
    def single_style_target_name(records: list[dict[str, Any]]) -> str:
        for record in records:
            target = record.get("target")
            if isinstance(target, str) and target:
                return target
        return "liboqs"

    @staticmethod
    def structured_record_paths(
        root: Path,
        *,
        kind: str,
        filename_prefix: str,
    ) -> list[Path]:
        """Return finding/diagnostic records, not their auxiliary JSON files."""

        records: list[Path] = []
        if not root.is_dir():
            return records
        for path in sorted(root.rglob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                # A file named like an atomically-written record must be
                # readable before compaction destroys any replay material.
                if path.name.startswith(filename_prefix):
                    raise RuntimeError(f"invalid structured {kind} record: {path}")
                continue
            if not isinstance(data, dict):
                if path.name.startswith(filename_prefix):
                    raise RuntimeError(f"invalid structured {kind} record: {path}")
                continue

            # ``kind`` is the concise schema used by newer writers; the
            # cryptofuzz module's versioned envelope calls the same concept
            # ``classification``.  Both identify the record independently of
            # its digest-based filename.
            record_kind = data.get("kind")
            if not isinstance(record_kind, str):
                record_kind = data.get("classification")
            if record_kind == kind:
                records.append(path)
            elif record_kind is None and path.name.startswith(filename_prefix):
                # Keep compatibility with early, pre-schema result trees.  A
                # current writer always includes ``kind`` and schema_version.
                records.append(path)
        return records

    def validate_single_style_paths(
        self,
        *,
        target: str,
        target_root: Path,
        category_root: Path,
        paths: list[Path],
        records: list[dict[str, Any]],
        fields: tuple[str, ...],
        label: str,
        required: bool,
        legacy_fields: tuple[str, ...] = (),
    ) -> dict[str, int]:
        """Check that every retained record is inventoried by its target.

        Structured evidence is strict: a writer that reports a finding must
        list the matching record in the target summary.  Crash inventories
        retain compatibility with older campaigns that had no recursive list.
        """

        summary_records = [(None, record) for record in records]
        primary_present, primary_entries = self.summary_entries(summary_records, fields)
        legacy_present, legacy_entries = self.summary_entries(summary_records, legacy_fields)
        entries = primary_entries if primary_present else legacy_entries
        strict = primary_present

        if paths and not entries:
            if required or strict:
                raise RuntimeError(
                    f"retained {label} has no matching summary entry for {self.baseline} target {target}"
                )
            return {
                "retained": len(paths),
                "validated": 0,
                "legacy_unlisted": len(paths),
                "summary_entries_present": int(primary_present or legacy_present),
            }

        unmatched: list[Path] = []
        validated = 0
        for path in paths:
            matched = any(
                self.summary_entry_matches(
                    path, target_root, category_root, entry, allow_basename=not strict
                )
                for _, entry in entries
            )
            if matched:
                validated += 1
            else:
                unmatched.append(path)

        if unmatched and (required or strict):
            names = ", ".join(rel_to(path, target_root) for path in unmatched)
            raise RuntimeError(
                f"retained {label} missing from {', '.join(fields)} for {self.baseline} "
                f"target {target}: {names}"
            )

        return {
            "retained": len(paths),
            "validated": validated,
            "legacy_unlisted": len(unmatched),
            "summary_entries_present": int(primary_present or legacy_present),
        }

    @staticmethod
    def summary_count_value(value: Any, *, field: str) -> int:
        if isinstance(value, bool):
            raise RuntimeError(f"invalid boolean {field} count")
        if isinstance(value, int) and value >= 0:
            return value
        if isinstance(value, str) and value.isdecimal():
            return int(value)
        raise RuntimeError(f"invalid {field} count: {value!r}")

    def validate_single_style_declared_count(
        self,
        *,
        target: str,
        records: list[dict[str, Any]],
        fields: tuple[str, ...],
        actual: int,
        label: str,
    ) -> dict[str, Any]:
        """Ensure a target summary's reported count owns its local evidence."""

        declared: list[tuple[str, int]] = []
        for record in records:
            for field in fields:
                if field in record:
                    declared.append(
                        (field, self.summary_count_value(record[field], field=field))
                    )
        if not declared:
            return {"status": "not-reported", "actual": actual}

        values = {value for _, value in declared}
        if len(values) != 1:
            details = ", ".join(f"{field}={value}" for field, value in declared)
            raise RuntimeError(
                f"conflicting {label} counts for {self.baseline} target {target}: {details}"
            )
        expected = values.pop()
        if expected != actual:
            raise RuntimeError(
                f"{label} count mismatch for {self.baseline} target {target}: "
                f"summary={expected}, retained={actual}"
            )
        return {"status": "passed", "declared": expected, "actual": actual}

    @staticmethod
    def required_string(record: dict[str, Any], *names: str) -> str | None:
        for name in names:
            value = record.get(name)
            if isinstance(value, str) and value:
                return value
        return None

    def validate_single_style_finding_replays(self, paths: list[Path]) -> dict[str, Any]:
        """Validate the persisted replay identity for current finding records.

        The module writer emits a semantic finding only after an in-process
        replay.  A non-reproduced or identity-mismatched record is evidence to
        preserve, but not a valid semantic result to compact as successful.
        Legacy synthetic records without a structured replay envelope remain
        accepted and are visibly marked as unverified.
        """

        validation: dict[str, Any] = {
            "required": len(paths),
            "verified": 0,
            "legacy_unverified": 0,
            "not_reproduced": 0,
            "identity_mismatches": 0,
        }
        if self.baseline == "CLFuzz":
            validation["fixture_mismatches"] = 0
        failures: list[str] = []

        for path in paths:
            record = self.read_json_object(path)
            if record is None:
                raise RuntimeError(f"invalid structured semantic finding record: {path}")

            modern = (
                record.get("kind") == "semantic_finding"
                or record.get("classification") == "semantic_finding"
                or "schema_version" in record
                or "format_version" in record
                or path.name.startswith("finding-")
            )
            if not modern:
                validation["legacy_unverified"] += 1
                continue

            algorithm = self.required_string(record, "algorithm")
            property_id = self.required_string(record, "property_id")
            relation = self.required_string(record, "semantic_relation", "relation")
            missing = [
                label
                for label, value in (
                    ("algorithm", algorithm),
                    ("property_id", property_id),
                    ("semantic_relation", relation),
                )
                if value is None
            ]
            if missing:
                failures.append(f"{rel(path)} missing {', '.join(missing)}")
                continue

            replay = record.get("replay")
            if not isinstance(replay, dict) or replay.get("result") != "reproduced":
                validation["not_reproduced"] += 1
                failures.append(f"{rel(path)} was not reproduced")
                continue

            # CLFuzz findings are admitted only after three fresh, exact-input
            # module replays.  Older cryptofuzz records predate this stronger
            # contract, so retain their existing compatibility path above.
            if self.baseline == "CLFuzz":
                attempts = replay.get("attempts_completed", replay.get("attempts"))
                try:
                    attempts = int(attempts)
                except (TypeError, ValueError):
                    attempts = 0
                results = replay.get("attempt_results")
                reproduced_count = replay.get("reproduced_count")
                try:
                    reproduced_count = int(reproduced_count)
                except (TypeError, ValueError):
                    reproduced_count = -1
                if (
                    attempts < 3
                    or not isinstance(results, list)
                    or len(results) != attempts
                    or any(result != "reproduced" for result in results)
                    or reproduced_count != attempts
                ):
                    validation["not_reproduced"] += 1
                    failures.append(f"{rel(path)} lacks unanimous exact-input replay evidence")
                    continue

                input_record = record.get("input")
                input_record = input_record if isinstance(input_record, dict) else {}
                fixture_sha256 = self.required_string(input_record, "fixture_sha256")
                replay_sha256 = self.required_string(replay, "input_sha256")
                fixture_path = self.required_string(input_record, "fixture_path")
                replay_path = self.required_string(replay, "input_path")
                if fixture_sha256 is None:
                    fixture_sha256 = replay_sha256
                if fixture_path is None:
                    fixture_path = replay_path
                if (
                    fixture_sha256 is None
                    or fixture_path is None
                    or replay_sha256 not in (None, fixture_sha256)
                    or replay_path not in (None, fixture_path)
                    or len(fixture_sha256) != 64
                    or any(character not in "0123456789abcdef" for character in fixture_sha256)
                    or Path(fixture_path).is_absolute()
                ):
                    validation["fixture_mismatches"] += 1
                    failures.append(f"{rel(path)} lacks a valid exact-input fixture identity")
                    continue

                fixture = (path.parent / fixture_path).resolve()
                findings_root = path.parent.resolve()
                if not is_within(fixture, findings_root) or not fixture.is_file():
                    validation["fixture_mismatches"] += 1
                    failures.append(f"{rel(path)} fixture is missing or escapes findings directory")
                    continue
                digest = hashlib.sha256()
                try:
                    with fixture.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(chunk)
                except OSError:
                    validation["fixture_mismatches"] += 1
                    failures.append(f"{rel(path)} fixture could not be read")
                    continue
                if digest.hexdigest() != fixture_sha256:
                    validation["fixture_mismatches"] += 1
                    failures.append(f"{rel(path)} fixture SHA-256 mismatched its record")
                    continue

            # Permit a compact replay result to repeat the identity at the
            # top-level only, but reject any identity it *does* supply when it
            # differs from the stored finding.
            replay_identity = replay.get("identity")
            if not isinstance(replay_identity, dict):
                replay_identity = replay
            mismatches = []
            for label, expected, names in (
                ("algorithm", algorithm, ("algorithm",)),
                ("property_id", property_id, ("property_id", "property")),
                ("semantic_relation", relation, ("semantic_relation", "relation")),
            ):
                observed = self.required_string(replay_identity, *names)
                if observed is not None and observed != expected:
                    mismatches.append(label)
            if mismatches:
                validation["identity_mismatches"] += 1
                failures.append(f"{rel(path)} replay mismatched {', '.join(mismatches)}")
                continue

            validation["verified"] += 1

        if failures:
            validation["status"] = "failed"
            validation["failures"] = failures
            # Record the detail before the exception so the failed manifest
            # can report it without deleting the campaign tree.
            raise ReplayValidationError("; ".join(failures), validation)

        validation["status"] = "passed" if validation["legacy_unverified"] == 0 else "legacy-unverified"
        return validation

    def single_style_artifact_paths(self, target_root: Path) -> list[tuple[Path, str]]:
        artifacts: list[tuple[Path, str]] = []
        crashes_root = target_root / "crashes"
        if crashes_root.is_dir():
            for path in sorted(crashes_root.rglob("*")):
                kind = prefix_artifact_kind(path) if path.is_file() else None
                if kind is not None:
                    artifacts.append((path, kind))

        # Some engines use an AFL-style hangs directory instead of a
        # libFuzzer-style ``hang-`` artifact name.  Keep both forms distinct.
        hangs_root = target_root / "hangs"
        if hangs_root.is_dir():
            for path in sorted(hangs_root.rglob("*")):
                if path.is_file() and path.name != "README.txt":
                    artifacts.append((path, "hang"))
        return artifacts

    @staticmethod
    def single_style_path_key(path: Path) -> str:
        return os.path.abspath(path)

    def single_style_paths_listed_in_summary(
        self,
        *,
        target_root: Path,
        category_root: Path,
        paths: list[Path],
        records: list[dict[str, Any]],
        fields: tuple[str, ...],
    ) -> tuple[bool, set[str]]:
        """Return on-disk paths named by an optional target-local inventory."""

        present, entries = self.summary_entries([(None, record) for record in records], fields)
        matched: set[str] = set()
        for path in paths:
            if any(
                self.summary_entry_matches(
                    path, target_root, category_root, entry, allow_basename=not present
                )
                for _, entry in entries
            ):
                matched.add(self.single_style_path_key(path))
        return present, matched

    def ensure_single_style_target(self, target: str, target_root: Path) -> None:
        self.single_style_target_roots[target] = target_root
        self.single_style_artifact_counts_by_target.setdefault(target, empty_artifact_counts())
        self.single_style_semantic_finding_counts_by_target.setdefault(target, 0)
        self.single_style_operation_diagnostic_counts_by_target.setdefault(target, 0)

    def record_single_style_artifact(
        self,
        target: str,
        path: Path,
        kind: str | None = None,
        *,
        count_global: bool = True,
    ) -> None:
        if kind is None:
            kind = prefix_artifact_kind(path)
        if kind is None:
            return
        self.ensure_single_style_target(target, self.single_style_target_roots[target])
        if count_global:
            self.retained_artifact_counts[kind] += 1
        self.single_style_artifact_counts_by_target[target][kind] += 1
        # A libFuzzer timeout artifact can be the campaign's recorded hang.
        # Retain the raw ``timeout`` count and add the semantic ``hang`` count
        # separately so consumers do not have to infer that classification
        # from a filename after compaction.
        is_logical_hang = (
            kind != "hang"
            and self.single_style_path_key(path)
            in self._single_style_logical_hang_paths.get(target, set())
        )
        if is_logical_hang:
            self.retained_artifact_counts["hang"] += 1
            self.single_style_artifact_counts_by_target[target]["hang"] += 1

    def inspect_single_style_target(self, target: str, target_root: Path) -> None:
        records = self.single_style_summary_records(target_root)
        self.ensure_single_style_target(target, target_root)

        findings_root = target_root / "findings"
        diagnostics_root = target_root / "diagnostics"
        finding_records = self.structured_record_paths(
            findings_root, kind="semantic_finding", filename_prefix="finding"
        )
        diagnostic_records = self.structured_record_paths(
            diagnostics_root, kind="operation_diagnostic", filename_prefix="diagnostic"
        )
        artifact_records = self.single_style_artifact_paths(target_root)

        artifact_validation = self.validate_single_style_paths(
            target=target,
            target_root=target_root,
            category_root=target_root / "crashes",
            paths=[path for path, _ in artifact_records if is_within(path, target_root / "crashes")],
            records=records,
            fields=("sanitizer_artifacts",),
            legacy_fields=("crashes",),
            label="sanitizer artifact",
            required=False,
        )
        crash_like_paths = [
            path for path, kind in artifact_records if kind in {"crash", "leak", "oom"}
        ]
        crash_inventory_present, listed_crash_paths = self.single_style_paths_listed_in_summary(
            target_root=target_root,
            category_root=target_root / "crashes",
            paths=crash_like_paths,
            records=records,
            fields=("sanitizer_crashes",),
        )
        crash_validation = self.validate_single_style_paths(
            target=target,
            target_root=target_root,
            category_root=target_root / "crashes",
            paths=crash_like_paths,
            records=records,
            fields=("sanitizer_crashes",),
            label="sanitizer crash",
            required=False,
        )
        hang_candidate_paths = [
            path for path, kind in artifact_records if kind in {"timeout", "hang"}
        ]
        _, listed_hang_paths = self.single_style_paths_listed_in_summary(
            target_root=target_root,
            category_root=target_root,
            paths=hang_candidate_paths,
            records=records,
            fields=("hangs", "timeouts"),
        )
        hang_validation = self.validate_single_style_paths(
            target=target,
            target_root=target_root,
            category_root=target_root,
            paths=hang_candidate_paths,
            records=records,
            fields=("hangs", "timeouts"),
            label="hang artifact",
            required=False,
        )
        logical_hang_paths = {
            self.single_style_path_key(path) for path, kind in artifact_records if kind == "hang"
        }
        logical_hang_paths.update(listed_hang_paths)
        self._single_style_logical_hang_paths[target] = logical_hang_paths
        finding_validation = self.validate_single_style_paths(
            target=target,
            target_root=target_root,
            category_root=findings_root,
            paths=finding_records,
            records=records,
            fields=("semantic_findings", "structured_findings", "findings"),
            label="structured finding",
            required=True,
        )
        diagnostic_validation = self.validate_single_style_paths(
            target=target,
            target_root=target_root,
            category_root=diagnostics_root,
            paths=diagnostic_records,
            records=records,
            fields=("operation_diagnostics", "diagnostics"),
            label="operation diagnostic",
            required=True,
        )
        artifact_count = sum(1 for _, kind in artifact_records if kind != "hang")
        crash_count = len(listed_crash_paths) if crash_inventory_present else len(crash_like_paths)
        hang_count = len(logical_hang_paths)
        declared_counts = {
            "semantic_findings": self.validate_single_style_declared_count(
                target=target,
                records=records,
                fields=("semantic_finding_count", "structured_finding_count"),
                actual=len(finding_records),
                label="semantic finding",
            ),
            "operation_diagnostics": self.validate_single_style_declared_count(
                target=target,
                records=records,
                fields=("operation_diagnostic_count", "diagnostic_count"),
                actual=len(diagnostic_records),
                label="operation diagnostic",
            ),
            "sanitizer_artifacts": self.validate_single_style_declared_count(
                target=target,
                records=records,
                fields=("sanitizer_artifact_count",),
                actual=artifact_count,
                label="sanitizer artifact",
            ),
            "sanitizer_crashes": self.validate_single_style_declared_count(
                target=target,
                records=records,
                fields=("sanitizer_crash_count",),
                actual=crash_count,
                label="sanitizer crash",
            ),
            "hangs": self.validate_single_style_declared_count(
                target=target,
                records=records,
                fields=("hang_count",),
                actual=hang_count,
                label="hang",
            ),
        }
        # The evidence is already durable at this point.  Set the target-local
        # record counts before replay validation so a failed replay manifest
        # still describes the finding/diagnostic evidence it preserved.
        self._single_style_target_records[target] = {
            "findings": finding_records,
            "diagnostics": diagnostic_records,
            "artifacts": [path for path, _ in artifact_records],
            "hang_artifacts": [path for path, kind in artifact_records if kind == "hang"],
        }
        self.single_style_semantic_finding_counts_by_target[target] = len(finding_records)
        self.single_style_operation_diagnostic_counts_by_target[target] = len(diagnostic_records)
        replay_validation: dict[str, Any]
        try:
            replay_validation = self.validate_single_style_finding_replays(finding_records)
        except ReplayValidationError as exc:
            replay_validation = exc.validation or {
                "status": "failed",
                "required": len(finding_records),
            }
            replay_validation["error"] = str(exc)
            self.single_style_validation["status"] = "failed"
            self.single_style_validation["targets"][target] = {
                "status": "failed",
                "sanitizer_artifacts": artifact_validation,
                "sanitizer_crashes": crash_validation,
                "hangs": hang_validation,
                "semantic_findings": finding_validation,
                "operation_diagnostics": diagnostic_validation,
                "declared_counts": declared_counts,
                "replay": replay_validation,
            }
            raise

        self.single_style_validation["targets"][target] = {
            "status": "passed",
            "sanitizer_artifacts": artifact_validation,
            "sanitizer_crashes": crash_validation,
            "hangs": hang_validation,
            "semantic_findings": finding_validation,
            "operation_diagnostics": diagnostic_validation,
            "declared_counts": declared_counts,
            "replay": replay_validation,
        }

    def remove_hang_children(self, root: Path, target: str) -> None:
        if not root.is_dir():
            return
        self.require_safe_path(root)
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_file() and path.name != "README.txt":
                self.record_single_style_artifact(target, path, "hang")
                self.retain(path)
                continue
            if path.is_dir():
                if not any(path.iterdir()):
                    self.remove_path(path)
                continue
            self.remove_path(path)

    @staticmethod
    def single_style_campaign_roots(version_run_root: Path) -> list[tuple[str | None, Path]]:
        """Return legacy direct roots and current CLFuzz profile roots."""

        roots: list[tuple[str | None, Path]] = []
        if any(version_run_root.glob("summary*.json")):
            roots.append((None, version_run_root))
        if version_run_root.is_dir():
            for child in sorted(version_run_root.iterdir()):
                if child.is_dir() and any(child.glob("summary*.json")):
                    roots.append((child.name, child))
        return roots or [(None, version_run_root)]

    @staticmethod
    def single_style_target_key(target: str, profile: str | None) -> str:
        return target if profile is None else f"{target}/{profile}"

    def compact_single_libfuzzer_style(self) -> None:
        version_run_root = self.run_root / f"liboqs-{self.version}"
        campaign_roots = self.single_style_campaign_roots(version_run_root)

        # Validate every profile before deleting any corpus/build output.  A
        # bad replay leaves every sibling profile available for investigation.
        campaigns: list[tuple[str, Path]] = []
        for profile, campaign_root in campaign_roots:
            records = self.single_style_summary_records(campaign_root)
            target = self.single_style_target_name(records)
            target_key = self.single_style_target_key(target, profile)
            self.inspect_single_style_target(target_key, campaign_root)
            campaigns.append((target_key, campaign_root))

        for target, campaign_root in campaigns:
            for summary in sorted(campaign_root.glob("summary*.json")):
                self.retain(summary)
            self.retain_tree_files(campaign_root / "logs")
            self.retain_tree_files(campaign_root / "findings")
            self.retain_tree_files(campaign_root / "diagnostics")
            self.retain_tree_files(campaign_root / "metadata")
            self.retain_tree_files(campaign_root / "outcomes")
            self.remove_children_except_prefix_artifacts(
                campaign_root / "crashes",
                lambda path, name=target: self.record_single_style_artifact(
                    name, path, count_global=False
                ),
            )
            self.remove_hang_children(campaign_root / "hangs", target)
            self.remove_path(campaign_root / "corpus")
            self.remove_path(campaign_root / "artifacts")
        self.remove_path(self.build_root)

    def crypto_testing_target(self) -> str:
        return CRYPTOTESTING_TARGETS.get(self.version, f"liboqs-{self.version}")

    def crypto_testing_roots(self) -> list[tuple[str, Path]]:
        raw_root = self.run_root / "raw"
        prefix = f"cryptoTesting-{self.version}-"
        roots: list[tuple[str, Path]] = []
        canonical_root = raw_root / f"cryptoTesting-{self.version}"
        for mode in ("functional", "vanilla"):
            candidate = canonical_root / mode
            if candidate.is_dir():
                roots.append((mode, candidate))
        if raw_root.is_dir():
            for path in sorted(raw_root.glob(f"{prefix}*")):
                if not path.is_dir():
                    continue
                mode = path.name[len(prefix) :]
                if mode in {"functional", "vanilla"} and all(existing_mode != mode for existing_mode, _ in roots):
                    roots.append((mode, path))
        return roots

    @staticmethod
    def crypto_testing_checksum(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def compact_crypto_testing_campaign(self, mode: str, raw_root: Path) -> None:
        manifest_path = raw_root / "manifest.json"
        source_manifest = self.read_json_object(manifest_path)
        if source_manifest is None:
            raise ReplayValidationError(f"cryptoTesting raw output has no valid manifest: {manifest_path}")
        if source_manifest.get("mode") != mode or source_manifest.get("version") != self.version:
            raise ReplayValidationError(f"cryptoTesting raw manifest does not match {mode}/{self.version}")
        artifacts = source_manifest.get("artifacts")
        if not isinstance(artifacts, list):
            raise ReplayValidationError(f"cryptoTesting raw manifest has no artifact list: {manifest_path}")

        property_counts: dict[str, dict[str, int]] = {}
        raw_counts = empty_artifact_counts()
        validated_target_hangs = 0
        for item in artifacts:
            if not isinstance(item, dict):
                raise ReplayValidationError(f"invalid cryptoTesting artifact record in {manifest_path}")
            relative_path = item.get("relative_artifact_path")
            kind = item.get("kind")
            prop = item.get("property")
            if not isinstance(relative_path, str) or not isinstance(kind, str) or not isinstance(prop, str):
                raise ReplayValidationError(f"incomplete cryptoTesting artifact record in {manifest_path}")
            source = raw_root / relative_path
            if not source.is_file() or not is_within(source, raw_root):
                raise ReplayValidationError(f"cryptoTesting manifest references missing raw artifact: {source}")
            expected_size = item.get("size")
            if not isinstance(expected_size, int) or source.stat().st_size != expected_size:
                raise ReplayValidationError(f"cryptoTesting raw artifact size changed: {source}")
            expected_digest = item.get("sha256")
            if not isinstance(expected_digest, str) or self.crypto_testing_checksum(source) != expected_digest:
                raise ReplayValidationError(f"cryptoTesting raw artifact checksum changed: {source}")
            self.retain(source)
            counts = property_counts.setdefault(prop, empty_artifact_counts())
            if kind == "crash":
                counts["crash"] += 1
                raw_counts["crash"] += 1
            elif kind == "hang":
                counts["hang"] += 1
                raw_counts["hang"] += 1
                replay = item.get("replay")
                if (
                    isinstance(replay, dict)
                    and replay.get("status") == "reproduced"
                    and replay.get("result") == "target-hang"
                ):
                    validated_target_hangs += 1
            elif kind == "setup-timeout":
                counts["timeout"] += 1
                raw_counts["timeout"] += 1

        reported_groups = source_manifest.get("reported_groups", 0)
        groups_missing = source_manifest.get("groups_missing_reproducer", 0)
        if not isinstance(reported_groups, int) or not isinstance(groups_missing, int):
            raise ReplayValidationError(f"invalid cryptoTesting report-group accounting: {manifest_path}")
        if reported_groups and groups_missing:
            raise ReplayValidationError(
                f"cryptoTesting reports {groups_missing} group(s) without retained raw reproducers"
            )
        result_counts = {
            key: self.summary_count_value(source_manifest.get(key, 0), field=key)
            for key in (
                "semantic_finding_count",
                "malleability_count",
                "mismatch_count",
                "sanitizer_crash_count",
                "hang_count",
                "operation_diagnostic_count",
            )
        }

        self.retain_tree_files(raw_root)
        task_coverage = source_manifest.get("task_coverage")
        if not isinstance(task_coverage, dict):
            scheduled = source_manifest.get("scheduled_tasks", 0)
            if not isinstance(scheduled, int) or scheduled < 0:
                scheduled = 0
            terminal = scheduled if source_manifest.get("tasks_terminal") else 0
            task_coverage = {
                "scheduled": scheduled,
                "terminal": terminal,
                "incomplete": scheduled - terminal,
                "fraction": 1.0 if scheduled and terminal == scheduled else 0.0,
            }
        self.crypto_testing_campaigns[mode] = {
            "raw_root": raw_root,
            "source_manifest": source_manifest,
            "target": self.crypto_testing_target(),
            "raw_artifact_counts": raw_counts,
            "retained_artifact_counts_by_property": {
                prop: dict(counts) for prop, counts in sorted(property_counts.items())
            },
            "reported_groups": reported_groups,
            "groups_with_reproducer": source_manifest.get("groups_with_reproducer", 0),
            "groups_replayed": source_manifest.get("groups_replayed", 0),
            "groups_missing_reproducer": groups_missing,
            "validated_target_hangs": validated_target_hangs,
            "tasks_terminal": bool(source_manifest.get("tasks_terminal")),
            "full_matrix_complete": bool(source_manifest.get("full_matrix_complete")),
            "budget_exhausted": bool(source_manifest.get("budget_exhausted")),
            "task_coverage": task_coverage,
            "unvalidated_artifact_count": source_manifest.get("unvalidated_artifact_count", 0),
            "result_counts": result_counts,
        }

    def compact_crypto_testing(self) -> None:
        roots = self.crypto_testing_roots()
        if not roots:
            raise ReplayValidationError(
                f"cryptoTesting compaction requires mounted raw output under {self.run_root / 'raw'}"
            )
        for mode, raw_root in roots:
            self.compact_crypto_testing_campaign(mode, raw_root)
        self.retain_tree_files(self.run_root / "reports")
        self.retain_tree_files(self.run_root / "logs")
        self.remove_path(self.build_root)

    def crypto_testing_manifest_updates(self) -> dict[str, Any]:
        return {
            "cryptoTesting_campaigns": {
                mode: {
                    "raw_output_root": rel(info["raw_root"]),
                    "target": info["target"],
                    "raw_artifact_counts": dict(info["raw_artifact_counts"]),
                    "retained_artifact_counts_by_property": info["retained_artifact_counts_by_property"],
                    "retained_artifact_counts_by_target": {
                        info["target"]: info["retained_artifact_counts_by_property"]
                    },
                    "reported_groups": info["reported_groups"],
                    "groups_with_reproducer": info["groups_with_reproducer"],
                    "groups_replayed": info["groups_replayed"],
                    "groups_missing_reproducer": info["groups_missing_reproducer"],
                    "validated_target_hangs": info["validated_target_hangs"],
                    "tasks_terminal": info["tasks_terminal"],
                    "full_matrix_complete": info["full_matrix_complete"],
                    "budget_exhausted": info["budget_exhausted"],
                    "task_coverage": info["task_coverage"],
                    "unvalidated_artifact_count": info["unvalidated_artifact_count"],
                    **info["result_counts"],
                }
                for mode, info in sorted(self.crypto_testing_campaigns.items())
            },
        }

    def libfuzzer_artifact_counts_by_target(self) -> dict[str, dict[str, int]]:
        return {
            target: dict(counts)
            for target, counts in sorted(self.retained_artifact_counts_by_target.items())
        }

    def libfuzzer_artifact_counts_by_target_profile(self) -> dict[str, dict[str, dict[str, int]]]:
        return {
            target: {
                profile: dict(counts)
                for profile, counts in sorted(profiles.items())
            }
            for target, profiles in sorted(self.retained_artifact_counts_by_target_profile.items())
        }

    @staticmethod
    def sorted_scalar_counts(counts: dict[str, int]) -> dict[str, int]:
        return {name: counts[name] for name in sorted(counts)}

    def libfuzzer_scalar_counts_by_target_profile(
        self,
        counts: dict[str, dict[str, int]],
    ) -> dict[str, dict[str, int]]:
        return {
            target: self.sorted_scalar_counts(profiles)
            for target, profiles in sorted(counts.items())
        }

    def libfuzzer_manifest_updates(self) -> dict[str, Any]:
        return {
            "retained_artifact_counts_by_target": self.libfuzzer_artifact_counts_by_target(),
            "retained_artifact_counts_by_target_profile": self.libfuzzer_artifact_counts_by_target_profile(),
            "retained_semantic_finding_count": sum(self.retained_semantic_finding_counts_by_target.values()),
            "retained_semantic_finding_counts_by_target": self.sorted_scalar_counts(
                self.retained_semantic_finding_counts_by_target
            ),
            "retained_semantic_finding_counts_by_target_profile": self.libfuzzer_scalar_counts_by_target_profile(
                self.retained_semantic_finding_counts_by_target_profile
            ),
            "retained_operation_diagnostic_count": sum(self.retained_operation_diagnostic_counts_by_target.values()),
            "retained_operation_diagnostic_counts_by_target": self.sorted_scalar_counts(
                self.retained_operation_diagnostic_counts_by_target
            ),
            "retained_operation_diagnostic_counts_by_target_profile": self.libfuzzer_scalar_counts_by_target_profile(
                self.retained_operation_diagnostic_counts_by_target_profile
            ),
            "retained_artifact_validation": self.libfuzzer_validation,
        }

    def single_style_manifest_updates(self) -> dict[str, Any]:
        """Return target-root evidence accounting for cryptofuzz/CLFuzz.

        These campaigns currently have one liboqs root, but the explicit map
        makes the ownership clear and prevents a future second target from
        inheriting counts collected from the first one.
        """

        return {
            "retained_artifact_counts_by_target": {
                target: dict(counts)
                for target, counts in sorted(self.single_style_artifact_counts_by_target.items())
            },
            "retained_semantic_finding_count": sum(
                self.single_style_semantic_finding_counts_by_target.values()
            ),
            "retained_semantic_finding_counts_by_target": self.sorted_scalar_counts(
                self.single_style_semantic_finding_counts_by_target
            ),
            "retained_operation_diagnostic_count": sum(
                self.single_style_operation_diagnostic_counts_by_target.values()
            ),
            "retained_operation_diagnostic_counts_by_target": self.sorted_scalar_counts(
                self.single_style_operation_diagnostic_counts_by_target
            ),
            "retained_artifact_validation": self.single_style_validation,
        }

    def compact(self) -> dict[str, Any]:
        if self.baseline == "libFuzzer":
            self.compact_libfuzzer()
        elif self.baseline in {"cryptofuzz", "CLFuzz"}:
            self.compact_single_libfuzzer_style()
        elif self.baseline == "cryptoTesting":
            self.compact_crypto_testing()
        else:
            raise RuntimeError(f"unsupported baseline: {self.baseline}")

        manifest = {
            "baseline": self.baseline,
            "version": self.version,
            "mode": "compact",
            "generated_at": utc_now(),
            "status": "completed",
            "compacted": True,
            "workspace_root": rel(self.workspace_root),
            "baseline_root": rel(self.baseline_root),
            "retained_paths": [],
            "removed_paths": self.removed_paths,
            "retained_artifact_counts": dict(self.retained_artifact_counts),
            "removed_bytes_estimate": self.removed_bytes_estimate,
            "build_retained": self.build_root.exists(),
            "corpus_retained": any(path.name == "corpus" for path in self.run_root.rglob("corpus"))
            if self.run_root.is_dir()
            else False,
        }
        if self.baseline == "libFuzzer":
            manifest.update(self.libfuzzer_manifest_updates())
        elif self.baseline in {"cryptofuzz", "CLFuzz"}:
            manifest.update(self.single_style_manifest_updates())
        elif self.baseline == "cryptoTesting":
            manifest.update(self.crypto_testing_manifest_updates())
        self.update_summaries(manifest)
        self.retained_paths.add(rel(self.manifest_path))
        manifest["retained_paths"] = sorted(self.retained_paths)
        self.write_manifest(manifest)
        return manifest

    def write_manifest(self, manifest: dict[str, Any]) -> None:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with self.manifest_path.open("w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
            f.write("\n")

    def write_skipped_manifest(self, reason: str) -> dict[str, Any]:
        manifest = {
            "baseline": self.baseline,
            "version": self.version,
            "mode": "compact",
            "generated_at": utc_now(),
            "status": "skipped",
            "reason": reason,
            "compacted": False,
            "workspace_root": rel(self.workspace_root),
            "baseline_root": rel(self.baseline_root),
            "retained_paths": [rel(self.manifest_path)],
            "removed_paths": [],
            "retained_artifact_counts": dict(self.retained_artifact_counts),
            "removed_bytes_estimate": 0,
            "build_retained": self.build_root.exists(),
            "corpus_retained": any(path.name == "corpus" for path in self.run_root.rglob("corpus"))
            if self.run_root.is_dir()
            else False,
        }
        self.write_manifest(manifest)
        return manifest

    def write_failed_replay_manifest(self, reason: str) -> dict[str, Any]:
        """Document a replay validation failure without compacting anything."""

        manifest = {
            "baseline": self.baseline,
            "version": self.version,
            "mode": "compact",
            "generated_at": utc_now(),
            "status": "failed",
            "reason": reason,
            "compacted": False,
            "workspace_root": rel(self.workspace_root),
            "baseline_root": rel(self.baseline_root),
            "retained_paths": [rel(self.manifest_path)],
            "removed_paths": [],
            "retained_artifact_counts": dict(self.retained_artifact_counts),
            "removed_bytes_estimate": 0,
            "build_retained": self.build_root.exists(),
            "corpus_retained": any(path.name == "corpus" for path in self.run_root.rglob("corpus"))
            if self.run_root.is_dir()
            else False,
        }
        if self.baseline in {"cryptofuzz", "CLFuzz"}:
            manifest.update(self.single_style_manifest_updates())
        self.write_manifest(manifest)
        return manifest

    def summary_updates(self, manifest: dict[str, Any]) -> dict[str, Any]:
        return {
            "result_save_mode": "compact",
            "compacted": True,
            "compaction_manifest": rel(self.manifest_path),
            "build_retained": manifest["build_retained"],
            "corpus_retained": manifest["corpus_retained"],
            "retained_artifact_counts": manifest["retained_artifact_counts"],
        }

    def compaction_common_updates(self, manifest: dict[str, Any]) -> dict[str, Any]:
        return {
            "result_save_mode": "compact",
            "compacted": True,
            "compaction_manifest": rel(self.manifest_path),
            "build_retained": manifest["build_retained"],
            "corpus_retained": manifest["corpus_retained"],
        }

    def libfuzzer_profiles_for_target(self, target: str) -> list[str]:
        profiles = set(self._libfuzzer_target_profiles.get(target, set()))
        profiles.update(self.retained_artifact_counts_by_target_profile.get(target, {}))
        profiles.update(self.retained_semantic_finding_counts_by_target_profile.get(target, {}))
        profiles.update(self.retained_operation_diagnostic_counts_by_target_profile.get(target, {}))
        return sorted(profiles)

    def libfuzzer_profile_artifact_counts(self, target: str, profile: str) -> dict[str, int]:
        return dict(
            self.retained_artifact_counts_by_target_profile.get(target, {}).get(profile, empty_artifact_counts())
        )

    def libfuzzer_profile_semantic_finding_count(self, target: str, profile: str) -> int:
        return self.retained_semantic_finding_counts_by_target_profile.get(target, {}).get(profile, 0)

    def libfuzzer_profile_operation_diagnostic_count(self, target: str, profile: str) -> int:
        return self.retained_operation_diagnostic_counts_by_target_profile.get(target, {}).get(profile, 0)

    def libfuzzer_profile_validation(self, target: str, profile: str) -> dict[str, Any]:
        return {
            "status": "passed",
            "profile": profile,
            "retained_artifact_counts": self.libfuzzer_profile_artifact_counts(target, profile),
            "retained_semantic_finding_count": self.libfuzzer_profile_semantic_finding_count(target, profile),
            "retained_operation_diagnostic_count": self.libfuzzer_profile_operation_diagnostic_count(target, profile),
        }

    def libfuzzer_profile_summary_updates(
        self,
        manifest: dict[str, Any],
        target: str,
        profile: str,
    ) -> dict[str, Any]:
        updates = self.compaction_common_updates(manifest)
        updates.update(
            {
                "retained_artifact_counts": self.libfuzzer_profile_artifact_counts(target, profile),
                "retained_semantic_finding_count": self.libfuzzer_profile_semantic_finding_count(target, profile),
                "retained_operation_diagnostic_count": self.libfuzzer_profile_operation_diagnostic_count(
                    target, profile
                ),
                "compaction_validation": self.libfuzzer_profile_validation(target, profile),
            }
        )
        return updates

    def libfuzzer_target_index_updates(self, manifest: dict[str, Any], target: str) -> dict[str, Any]:
        profiles = self.libfuzzer_profiles_for_target(target)
        updates = self.compaction_common_updates(manifest)
        updates.update(
            {
                "retained_artifact_counts_by_profile": {
                    profile: self.libfuzzer_profile_artifact_counts(target, profile) for profile in profiles
                },
                "retained_semantic_finding_counts_by_profile": {
                    profile: self.libfuzzer_profile_semantic_finding_count(target, profile) for profile in profiles
                },
                "retained_operation_diagnostic_counts_by_profile": {
                    profile: self.libfuzzer_profile_operation_diagnostic_count(target, profile)
                    for profile in profiles
                },
                "compaction_validation": {
                    "status": "passed",
                    "profiles": {
                        profile: self.libfuzzer_profile_validation(target, profile) for profile in profiles
                    },
                },
            }
        )
        return updates

    def libfuzzer_target_legacy_updates(self, manifest: dict[str, Any], target: str) -> dict[str, Any]:
        updates = self.compaction_common_updates(manifest)
        updates.update(
            {
                "retained_artifact_counts": dict(
                    self.retained_artifact_counts_by_target.get(target, empty_artifact_counts())
                ),
                "retained_semantic_finding_count": self.retained_semantic_finding_counts_by_target.get(
                    target, 0
                ),
                "retained_operation_diagnostic_count": self.retained_operation_diagnostic_counts_by_target.get(
                    target, 0
                ),
                "compaction_validation": self.libfuzzer_validation["targets"].get(
                    target, {"status": "passed"}
                ),
            }
        )
        return updates

    def libfuzzer_aggregate_profile_updates(
        self,
        manifest: dict[str, Any],
        profile: str,
    ) -> dict[str, Any]:
        targets = [
            target
            for target in sorted(self.retained_artifact_counts_by_target)
            if profile in self.libfuzzer_profiles_for_target(target)
        ]
        updates = self.compaction_common_updates(manifest)
        updates.update(
            {
                "retained_artifact_counts_by_target": {
                    target: self.libfuzzer_profile_artifact_counts(target, profile) for target in targets
                },
                "retained_semantic_finding_counts_by_target": {
                    target: self.libfuzzer_profile_semantic_finding_count(target, profile) for target in targets
                },
                "retained_operation_diagnostic_counts_by_target": {
                    target: self.libfuzzer_profile_operation_diagnostic_count(target, profile)
                    for target in targets
                },
                "compaction_validation": {
                    "status": "passed",
                    "profile": profile,
                    "targets": {
                        target: self.libfuzzer_profile_validation(target, profile) for target in targets
                    },
                },
            }
        )
        return updates

    def libfuzzer_aggregate_index_updates(self, manifest: dict[str, Any]) -> dict[str, Any]:
        updates = self.compaction_common_updates(manifest)
        updates.update(
            {
                "retained_artifact_counts_by_target_profile": self.libfuzzer_artifact_counts_by_target_profile(),
                "retained_semantic_finding_counts_by_target_profile": self.libfuzzer_scalar_counts_by_target_profile(
                    self.retained_semantic_finding_counts_by_target_profile
                ),
                "retained_operation_diagnostic_counts_by_target_profile": self.libfuzzer_scalar_counts_by_target_profile(
                    self.retained_operation_diagnostic_counts_by_target_profile
                ),
                "compaction_validation": self.libfuzzer_validation,
            }
        )
        return updates

    @staticmethod
    def remove_flat_profile_counts(data: dict[str, Any]) -> None:
        for key in (
            "retained_artifact_counts",
            "retained_semantic_finding_count",
            "retained_operation_diagnostic_count",
        ):
            data.pop(key, None)

    def write_updated_summary(self, path: Path, data: dict[str, Any]) -> None:
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        self.retain(path)

    def update_libfuzzer_summary_file(
        self,
        path: Path,
        manifest: dict[str, Any],
        version_run_root: Path,
        target_roots: dict[str, Path],
    ) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return

        target = next((name for name, root in target_roots.items() if path.parent == root), None)
        profiles = data.get("profiles")
        is_profile_index = isinstance(profiles, dict)

        if target is not None:
            if is_profile_index:
                for profile, profile_data in profiles.items():
                    if isinstance(profile, str) and isinstance(profile_data, dict):
                        profile_data.update(self.libfuzzer_profile_summary_updates(manifest, target, profile))
                self.remove_flat_profile_counts(data)
                data.update(self.libfuzzer_target_index_updates(manifest, target))
            else:
                profile = data.get("profile")
                if not isinstance(profile, str):
                    profile = self.summary_profile_from_filename(path)
                if profile is None:
                    data.update(self.libfuzzer_target_legacy_updates(manifest, target))
                else:
                    data.update(self.libfuzzer_profile_summary_updates(manifest, target, profile))
            self.write_updated_summary(path, data)
            return

        # The version root is an aggregate.  A profile index and a profile
        # detail both retain target-keyed values instead of flattening KEM/SIG
        # or memory-safety/semantic counts into one number.
        if is_profile_index:
            for profile, profile_data in profiles.items():
                if isinstance(profile, str) and isinstance(profile_data, dict):
                    self.remove_flat_profile_counts(profile_data)
                    profile_data.update(self.libfuzzer_aggregate_profile_updates(manifest, profile))
            self.remove_flat_profile_counts(data)
            data.update(self.libfuzzer_aggregate_index_updates(manifest))
        else:
            profile = data.get("profile")
            if not isinstance(profile, str):
                profile = self.summary_profile_from_filename(path)
            if profile is None:
                updates = self.compaction_common_updates(manifest)
                updates.update(
                    {
                        "retained_artifact_counts": dict(manifest["retained_artifact_counts"]),
                        "retained_artifact_counts_by_target": self.libfuzzer_artifact_counts_by_target(),
                        "retained_semantic_finding_count": manifest["retained_semantic_finding_count"],
                        "retained_semantic_finding_counts_by_target": manifest[
                            "retained_semantic_finding_counts_by_target"
                        ],
                        "retained_operation_diagnostic_count": manifest[
                            "retained_operation_diagnostic_count"
                        ],
                        "retained_operation_diagnostic_counts_by_target": manifest[
                            "retained_operation_diagnostic_counts_by_target"
                        ],
                        "compaction_validation": self.libfuzzer_validation,
                    }
                )
                data.update(updates)
            else:
                self.remove_flat_profile_counts(data)
                data.update(self.libfuzzer_aggregate_profile_updates(manifest, profile))
        self.write_updated_summary(path, data)

    def update_libfuzzer_summaries(self, manifest: dict[str, Any]) -> None:
        version_run_root = self.run_root / f"liboqs-{self.version}"
        target_roots = dict(self.libfuzzer_target_roots(version_run_root))
        summary_paths = set(version_run_root.glob("summary*.json"))
        for target_root in target_roots.values():
            summary_paths.update(target_root.glob("summary*.json"))
        for path in sorted(summary_paths):
            self.update_libfuzzer_summary_file(path, manifest, version_run_root, target_roots)

    def update_summary_file(self, path: Path, updates: dict[str, Any]) -> None:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        data.update(updates)
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        self.retain(path)

    def update_crypto_testing_summaries(self, manifest: dict[str, Any]) -> None:
        """Write one isolated summary per workflow mode.

        Functional cryptoTesting and the vanilla AFL baseline exercise
        different properties.  Keeping their summaries under their respective
        mounted raw roots makes a later aggregate unable to double-count one
        mode as evidence for the other.
        """

        for mode, info in sorted(self.crypto_testing_campaigns.items()):
            raw_root = info["raw_root"]
            source = info["source_manifest"]
            summary_path = raw_root / "summary.json"
            finding_count = (
                info["result_counts"]["semantic_finding_count"]
                + info["result_counts"]["sanitizer_crash_count"]
                + info["result_counts"]["hang_count"]
                + info["result_counts"]["operation_diagnostic_count"]
            )
            data: dict[str, Any] = {
                "baseline": "cryptoTesting",
                "label": f"cryptoTesting-{mode}",
                "version": self.version,
                "target": self.crypto_testing_target(),
                "mode": mode,
                "status": (
                    "completed-with-findings" if info["tasks_terminal"] and finding_count else
                    "completed" if info["tasks_terminal"] else
                    "completed-at-budget-incomplete" if info["budget_exhausted"] else
                    "timed-out-partial"
                ),
                "normalized_outcome": "invariant_violation" if info["tasks_terminal"] and finding_count else (
                    "ok" if info["tasks_terminal"] else (
                    "coverage_incomplete" if info["budget_exhausted"] else "process_hang"
                    )
                ),
                "stop_reason": "fuzzing-time-budget" if info["budget_exhausted"] else (
                    "all-tasks-terminal" if info["tasks_terminal"] else "interrupted"
                ),
                "budget_exhausted": info["budget_exhausted"],
                "raw_output_root": rel(raw_root),
                "reports": source.get("report_files", []),
                "task_states": source.get("task_states", {}),
                "scheduled_tasks": source.get("scheduled_tasks", 0),
                "task_coverage": info["task_coverage"],
                "tasks_terminal": info["tasks_terminal"],
                "full_matrix_complete": info["full_matrix_complete"],
                "unvalidated_artifact_count": info["unvalidated_artifact_count"],
                "worker_count": source.get("resource_allocation", {}).get("effective_workers"),
                "requested_workers": source.get("resource_allocation", {}).get("requested_workers"),
                "cpu_allocation": source.get("resource_allocation", {}).get("cpu_allocation"),
                "schedule": source.get("schedule", {}),
                "algorithm_list": source.get("algorithm_list", []),
                "property_list": source.get("property_list", []),
                "skipped_tasks": [
                    task for task in source.get("schedule", {}).get("tasks", [])
                    if isinstance(task, dict) and not task.get("enabled", True)
                ] if isinstance(source.get("schedule"), dict) else [],
                "retained_raw_artifact_counts": dict(info["raw_artifact_counts"]),
                "retained_artifact_counts_by_property": info["retained_artifact_counts_by_property"],
                "retained_artifact_counts_by_target": {
                    info["target"]: info["retained_artifact_counts_by_property"]
                },
                "reported_groups": info["reported_groups"],
                "groups_with_reproducer": info["groups_with_reproducer"],
                "groups_replayed": info["groups_replayed"],
                "groups_missing_reproducer": info["groups_missing_reproducer"],
                "validated_target_hang_count": info["validated_target_hangs"],
                **info["result_counts"],
            }
            data.update(self.compaction_common_updates(manifest))
            with summary_path.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.write("\n")
            self.retain(summary_path)

    def single_style_summary_updates(self, manifest: dict[str, Any], target: str | None) -> dict[str, Any]:
        updates = self.compaction_common_updates(manifest)
        if target is None:
            # A summary that cannot be tied to one target may expose the map,
            # but must not receive a flattened count owned by another root.
            updates.update(
                {
                    "retained_artifact_counts_by_target": manifest[
                        "retained_artifact_counts_by_target"
                    ],
                    "retained_semantic_finding_counts_by_target": manifest[
                        "retained_semantic_finding_counts_by_target"
                    ],
                    "retained_operation_diagnostic_counts_by_target": manifest[
                        "retained_operation_diagnostic_counts_by_target"
                    ],
                    "compaction_validation": manifest["retained_artifact_validation"],
                }
            )
            return updates

        target_validation = manifest["retained_artifact_validation"]["targets"].get(
            target, {"status": "passed"}
        )
        updates.update(
            {
                "retained_artifact_counts": dict(
                    self.single_style_artifact_counts_by_target.get(target, empty_artifact_counts())
                ),
                "retained_semantic_finding_count": self.single_style_semantic_finding_counts_by_target.get(
                    target, 0
                ),
                "retained_operation_diagnostic_count": self.single_style_operation_diagnostic_counts_by_target.get(
                    target, 0
                ),
                "compaction_validation": target_validation,
            }
        )
        return updates

    def update_single_style_summaries(self, manifest: dict[str, Any]) -> None:
        version_run_root = self.run_root / f"liboqs-{self.version}"
        target_names = set(self.single_style_target_roots)
        only_target = next(iter(target_names)) if len(target_names) == 1 else None
        for summary in sorted(version_run_root.rglob("summary*.json")):
            data = self.read_json_object(summary)
            if data is None:
                continue
            target = data.get("target")
            profile = None
            try:
                relative_parent = summary.parent.relative_to(version_run_root)
                if len(relative_parent.parts) == 1:
                    profile = relative_parent.parts[0]
            except ValueError:
                pass
            target_key = (
                self.single_style_target_key(target, profile)
                if isinstance(target, str)
                else None
            )
            if target_key not in target_names:
                target_key = only_target if only_target is not None else None
            self.update_summary_file(summary, self.single_style_summary_updates(manifest, target_key))

    def update_summaries(self, manifest: dict[str, Any]) -> None:
        if self.baseline == "libFuzzer":
            self.update_libfuzzer_summaries(manifest)
            return
        if self.baseline in {"cryptofuzz", "CLFuzz"}:
            self.update_single_style_summaries(manifest)
            return
        if self.baseline == "cryptoTesting":
            self.update_crypto_testing_summaries(manifest)
            return
        updates = self.summary_updates(manifest)
        for summary in sorted(self.run_root.rglob("summary.json")):
            self.update_summary_file(summary, updates)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", required=True, type=Path)
    parser.add_argument("--baseline", required=True, choices=["libFuzzer", "cryptofuzz", "CLFuzz", "cryptoTesting"])
    parser.add_argument("--version", required=True)
    parser.add_argument("--mode", required=True, choices=["compact", "all"])
    parser.add_argument("--skip-reason", default="", help="write a skipped manifest without deleting files")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    workspace_root = args.workspace_root.resolve()
    baseline_root = workspace_root / args.baseline

    if args.mode == "all":
        print(f"[baseline-compact] mode=all; leaving {baseline_root} unchanged")
        return 0

    compactor = Compactor(workspace_root, args.baseline, args.version)
    if args.skip_reason:
        manifest = compactor.write_skipped_manifest(args.skip_reason)
        print(compactor.manifest_path)
        print(f"[baseline-compact] skipped: {manifest['reason']}")
        return 0

    try:
        manifest = compactor.compact()
    except ReplayValidationError as exc:
        manifest = compactor.write_failed_replay_manifest(str(exc))
        print(compactor.manifest_path)
        print(f"[baseline-compact] replay validation failed: {manifest['reason']}", file=sys.stderr)
        return 1
    print(compactor.manifest_path)
    print(
        "[baseline-compact] removed "
        f"{manifest['removed_bytes_estimate']} bytes from {len(manifest['removed_paths'])} paths"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
