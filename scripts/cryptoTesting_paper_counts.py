#!/usr/bin/env python3
"""Paper-style result normalizer for the vendored cryptoTesting baseline.

This tool reads cryptoTesting reports (SQLite DB, XLSX, LaTeX, or raw AFL
manifest metadata as a last-resort fallback) and produces paper-aligned,
deduplicated counts that are comparable to Table 3 of

    Fenzi, Gilcher, Virdia (2026).
    Finding Bugs and Features Using Cryptographically-Informed Functional
    Testing.  IACR Transactions on Cryptographic Hardware and Embedded
    Systems, 2026(1).

Paper counting rule (Section 2 of the reproduction plan):

    Count results independently by liboqs version and by algorithm parameter
    set.  Within the same liboqs version, algorithm parameter set, paper test,
    and outcome class, do not count multiple raw bit flips or multiple
    artifacts as separate paper-level results.

The deduplication key is therefore:

    paper_count_key = library + liboqs_version + algorithm +
                      paper_test_number + outcome_bucket + outcome_subtype
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Iterable


# --------------------------------------------------------------------------
# Source-of-truth mappings
# --------------------------------------------------------------------------

# Paper test number -> (paper description, report test name(s)).
# Report test names are the strings stored in the ``test`` column of the
# SQLite/XLSX reports and used as section headers in the LaTeX report.
PAPER_TEST_MAP = OrderedDict([
    (2,  ("Gen(; Maul(r))",            ["KEM/Keygen/badrng", "SIGN/Keygen/badrng"])),
    (3,  ("Encaps(Maul(pk); r)",       ["KEM/Encaps/pk-0"])),
    (4,  ("Decaps(sk, Encaps(Maul(pk); r))", ["KEM/Encaps/pk"])),
    (5,  ("Encaps(pk; Maul(r))",       ["KEM/Encaps/badrng"])),
    (6,  ("Decaps(Maul(sk), c)",       ["KEM/Decaps/sk"])),
    (7,  ("Decaps(sk, Maul(c))",       ["KEM/Decaps/c"])),
    (8,  ("Sign(Maul(sk), m; r)",      ["SIGN/Sign/sk"])),
    (9,  ("Sign(sk, Maul(m); r)",      ["SIGN/Sign/m"])),
    (10, ("Sign(sk, m; Maul(r))",      ["SIGN/Sign/badrng"])),
    (11, ("Verify(Maul(pk), m, sigma)", ["SIGN/Verify/pk"])),
    (12, ("Verify(pk, Maul(m), sigma)", ["SIGN/Verify/m"])),
    (13, ("Verify(pk, m, Maul(sigma))", ["SIGN/Verify/sig"])),
])

# Reverse lookup: report test name -> paper test number.
REPORT_TO_PAPER = {}
for _num, (_desc, _names) in PAPER_TEST_MAP.items():
    for _name in _names:
        REPORT_TO_PAPER[_name] = _num

# liboqs version -> upstream target name (README version-target mapping).
VERSION_TARGET_MAP = OrderedDict([
    ("0.14.0", "ches_liboqs"),
    ("0.8.0",  "cur_liboqs"),
    ("0.4.0",  "mid_liboqs"),
    ("2018-11", "old_liboqs"),
])
TARGET_TO_VERSION = {v: k for k, v in VERSION_TARGET_MAP.items()}

# Paper Table 3 expected deduplicated counts for the three supported versions.
# Each entry: (version, report_test_name, outcome_bucket, outcome_subtype, count, note).
PAPER_TABLE3 = [
    # liboqs 0.14.0 (ches_liboqs)
    ("0.14.0", "KEM/Encaps/badrng", "malleability", "maul", 1, ""),
    ("0.14.0", "KEM/Encaps/badrng", "crash_hang", "hang", 10, "10 hangs"),
    ("0.14.0", "KEM/Decaps/sk", "malleability", "maul", 26, ""),
    ("0.14.0", "SIGN/Sign/sk", "malleability", "maul", 11, ""),
    ("0.14.0", "SIGN/Verify/pk", "malleability", "maul", 10, ""),
    ("0.14.0", "SIGN/Verify/sig", "malleability", "maul", 25, ""),
    # liboqs 0.8.0 (cur_liboqs)
    ("0.8.0", "KEM/Encaps/pk-0", "malleability", "maul", 10, ""),
    ("0.8.0", "KEM/Encaps/pk", "malleability", "maul", 10, ""),
    ("0.8.0", "KEM/Encaps/badrng", "malleability", "maul", 1, ""),
    ("0.8.0", "KEM/Encaps/badrng", "crash_hang", "hang", 10, "10 hangs"),
    ("0.8.0", "KEM/Decaps/sk", "malleability", "maul", 23, ""),
    ("0.8.0", "SIGN/Sign/sk", "malleability", "maul", 3, ""),
    ("0.8.0", "SIGN/Verify/sig", "malleability", "maul", 2, ""),
    # liboqs 0.4.0 (mid_liboqs)
    ("0.4.0", "KEM/Encaps/pk-0", "malleability", "maul", 23, ""),
    ("0.4.0", "KEM/Encaps/pk-0", "crash_hang", "segfault", 8, "8 segfaults"),
    ("0.4.0", "KEM/Encaps/pk", "malleability", "maul", 31, ""),
    ("0.4.0", "KEM/Encaps/pk", "crash_hang", "segfault", 8, "8 segfaults"),
    ("0.4.0", "KEM/Encaps/badrng", "malleability", "maul", 1, ""),
    ("0.4.0", "KEM/Encaps/badrng", "crash_hang", "hang", 10, "10 hangs"),
    ("0.4.0", "KEM/Decaps/sk", "malleability", "maul", 51, ""),
    ("0.4.0", "KEM/Decaps/c", "malleability", "maul", 10, ""),
    ("0.4.0", "SIGN/Sign/sk", "malleability", "maul", 10, ""),
    ("0.4.0", "SIGN/Sign/sk", "crash_hang", "heapoverflow", 3, "3 heap overflows"),
    ("0.4.0", "SIGN/Sign/sk", "crash_hang", "hang", 1, "1 hang"),
    ("0.4.0", "SIGN/Sign/m", "crash_hang", "hang", 1, "1 hang"),
    ("0.4.0", "SIGN/Sign/badrng", "malleability", "maul", 22, ""),
    ("0.4.0", "SIGN/Sign/badrng", "crash_hang", "hang", 1, "1 hang"),
    ("0.4.0", "SIGN/Verify/pk", "malleability", "maul", 7, ""),
    ("0.4.0", "SIGN/Verify/pk", "crash_hang", "hang", 1, "1 hang"),
    ("0.4.0", "SIGN/Verify/m", "crash_hang", "hang", 1, "1 hang"),
    ("0.4.0", "SIGN/Verify/sig", "malleability", "maul", 9, ""),
    ("0.4.0", "SIGN/Verify/sig", "crash_hang", "hang", 1, "1 hang"),
]

OUTCOME_SUBTYPES = (
    "maul", "nonmaul", "segfault", "heapoverflow",
    "stackoverflow", "hang", "returnedbot", "other",
)


# --------------------------------------------------------------------------
# BLACKLIST / setup-timeout helpers (Phase C audit support)
# --------------------------------------------------------------------------

def detect_blacklist(source_path: Path) -> dict:
    """Inspect a ``fuzz_liboqs.py`` file and report BLACKLIST status.

    Returns a dict with keys:
      - ``blacklist``: list of (name, test) tuples parsed from the source.
      - ``is_full_run``: True when the BLACKLIST is empty (``BLACKLIST=()``).
      - ``coverage_limitation``: True when any entry is present.
    """
    text = source_path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"BLACKLIST\s*=\s*\(", text)
    entries: list[tuple[str, str]] = []
    if m:
        # Balance parentheses to capture the full BLACKLIST body, which itself
        # contains ("name", "test") tuples that the naive [^)]* regex misses.
        start = m.end()
        depth = 1
        end = start
        while end < len(text) and depth > 0:
            if text[end] == "(":
                depth += 1
            elif text[end] == ")":
                depth -= 1
            end += 1
        body = text[start:end - 1]
        for em in re.finditer(r'\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)', body):
            entries.append((em.group(1), em.group(2)))
    return {
        "blacklist": entries,
        "is_full_run": len(entries) == 0,
        "coverage_limitation": len(entries) > 0,
    }


def is_setup_timeout_record(record: dict) -> bool:
    """Return True if a task metadata record describes a setup-timeout.

    Setup-timeout records are created by ``fuzz_liboqs.experiment`` before the
    target executes (GenInput timeout) and must not be counted as target hangs.
    """
    state = str(record.get("state", "")).lower()
    reason = str(record.get("stop_reason", "")).lower()
    return state == "setup-timeout" or reason == "geninput-timeout"


class StrictPaperError(ValueError):
    """Raised when --strict-paper encounters an unmapped report test name."""


# --------------------------------------------------------------------------
# Classification (mirrors report.py guess_crash exactly)
# --------------------------------------------------------------------------

def guess_crash(rowdata: dict) -> str:
    """Classify a raw report row, replicating ``report.TexReport.guess_crash``.

    Returns one of the OUTCOME_SUBTYPES.  ``rowdata`` must contain either an
    ``error`` key (for crash/hang rows) or an ``expected`` key (for functional
    malleability / non-malleability rows).
    """
    error = rowdata.get("error")
    if error:
        line = str(error)
        if "SEGV" in line:
            return "segfault"
        if "stack-overflow" in line:
            return "stackoverflow"
        if "heap-buffer-overflow" in line:
            return "heapoverflow"
        if "ERROR:" in line and "failed!" in line:
            return "returnedbot"
        if line.strip().lower() == "hang":
            return "hang"
        return "other"
    expected = rowdata.get("expected")
    if expected == "unequal":
        return "maul"
    return "nonmaul"


def outcome_bucket(subtype: str) -> str:
    """Map an outcome subtype to a paper outcome bucket."""
    if subtype == "maul":
        return "malleability"
    if subtype == "nonmaul":
        return "non_malleability"
    return "crash_hang"


def primitive_of(report_test_name: str) -> str:
    if report_test_name.startswith("KEM"):
        return "KEM"
    if report_test_name.startswith("SIGN"):
        return "SIGN"
    if report_test_name.startswith("Hash") or "/crypto_hash" in report_test_name:
        return "Hash"
    return "unknown"


def paper_test_for(report_test_name: str, strict: bool = False) -> int | None:
    num = REPORT_TO_PAPER.get(report_test_name)
    if num is None and strict:
        raise StrictPaperError(f"unmapped report test name: {report_test_name!r}")
    return num


# --------------------------------------------------------------------------
# Report readers (priority: SQLite -> XLSX -> LaTeX -> raw manifest)
# --------------------------------------------------------------------------

def _version_from_target(target: str) -> str:
    return TARGET_TO_VERSION.get(target, target)


def read_sqlite(path: Path, library: str = "liboqs", version: str | None = None,
                strict: bool = False) -> list[dict]:
    """Read raw rows from a cryptoTesting SQLite report database.

    Returns a list of normalized row dicts with keys: name, test, error,
    expected, gotten, plus provenance fields (source_report_path, library,
    liboqs_version, liboqs_target_name).
    """
    rows: list[dict] = []
    if not path.is_file():
        return rows
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        if "crashes" not in tables:
            return rows
        cur.execute("SELECT * FROM crashes")
        db_rows = cur.fetchall()
        # Infer version from filename if not supplied: crash_report_<target>_python.db
        target = version_target_from_path(path) if version is None else VERSION_TARGET_MAP.get(version, version)
        ver = version if version else _version_from_target(target)
        for r in db_rows:
            d = {k: r[k] for k in r.keys()}
            test = d.get("test")
            if test and strict and test not in REPORT_TO_PAPER:
                raise StrictPaperError(f"unmapped report test name in {path}: {test!r}")
            d["source_report_path"] = str(path)
            d["library"] = library
            d["liboqs_version"] = ver
            d["liboqs_target_name"] = target
            rows.append(d)
    finally:
        con.close()
    return rows


def version_target_from_path(path: Path) -> str:
    """Extract the upstream target name (e.g. ``mid_liboqs``) from a report path."""
    name = path.name
    m = re.search(r"crash_report_([a-z]+_liboqs)", name)
    if m:
        return m.group(1)
    m = re.search(r"crash_report_([a-z]+_liboqs)_", name)
    if m:
        return m.group(1)
    return "unknown"


def read_xlsx(path: Path, library: str = "liboqs", version: str | None = None,
              strict: bool = False) -> list[dict]:
    """Read raw rows from a cryptoTesting XLSX report.

    The XLSX layout (see report.XLSXReport) interleaves section header rows of
    the form ``["path", "<report_test_name>"]`` with data rows whose first cell
    is the algorithm name.  Functional rows carry ``expected``/``gotten`` cells
    while crash/hang rows carry an ``error`` cell or repeated ``"hang"`` cells.
    """
    rows: list[dict] = []
    try:
        import openpyxl
    except ImportError:
        return rows
    if not path.is_file():
        return rows
    wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
    target = version_target_from_path(path) if version is None else VERSION_TARGET_MAP.get(version, version)
    ver = version if version else _version_from_target(target)
    for ws in wb.worksheets:
        cur_test = None
        header_keys: list[str] | None = None
        for raw in ws.iter_rows(values_only=True):
            if not raw or raw[0] is None:
                continue
            cells = [("" if c is None else str(c)) for c in raw]
            if raw[0] == "path" and len(raw) >= 2 and raw[1]:
                cur_test = str(raw[1])
                if strict and cur_test not in REPORT_TO_PAPER:
                    raise StrictPaperError(f"unmapped report test name in {path}: {cur_test!r}")
                header_keys = None
                continue
            if cur_test is None or raw[0] == "path":
                continue
            name = str(raw[0])
            if name == "DEFAULT":
                continue
            # Hang rows are encoded as [name, "hang", "hang", ...].
            lowered = [c.lower() for c in cells]
            if "hang" in lowered and not any(c in lowered for c in ("unequal", "equal", "segv", "overflow")):
                rows.append({
                    "name": name, "test": cur_test, "error": "hang",
                    "expected": None, "gotten": None,
                    "source_report_path": str(path), "library": library,
                    "liboqs_version": ver, "liboqs_target_name": target,
                })
                continue
            # Functional / crash rows: build a dict from a header row if present.
            if "name" in cells and "expected" in cells:
                header_keys = cells
                continue
            if header_keys is not None:
                d = {}
                for k, v in zip(header_keys, cells):
                    if k:
                        d[k] = v
                d.setdefault("name", name)
                d["test"] = cur_test
                d.setdefault("error", d.get("error"))
                d.setdefault("expected", d.get("expected"))
                d["source_report_path"] = str(path)
                d["library"] = library
                d["liboqs_version"] = ver
                d["liboqs_target_name"] = target
                rows.append(d)
                continue
            # Fallback: classify by scanning the row text.
            rowstr = " ".join(cells)
            d = {"name": name, "test": cur_test, "source_report_path": str(path),
                 "library": library, "liboqs_version": ver, "liboqs_target_name": target}
            if "SEGV" in rowstr:
                d["error"] = "SEGV"
            elif "heap-buffer-overflow" in rowstr:
                d["error"] = "heap-buffer-overflow"
            elif "stack-overflow" in rowstr:
                d["error"] = "stack-overflow"
            else:
                d["error"] = None
                d["expected"] = "unequal" if "unequal" in rowstr else ("equal" if "equal" in rowstr else None)
            rows.append(d)
    wb.close()
    return rows


def read_latex(path: Path, library: str = "liboqs", version: str | None = None,
               strict: bool = False) -> list[dict]:
    """Read aggregated counts from a cryptoTesting LaTeX table report.

    The LaTeX report (report.TexReport.savetodisk) only stores deduplicated
    counts per test, not per-algorithm rows.  This reader therefore emits one
    synthetic row per (test, subtype) with a placeholder algorithm name, so the
    downstream deduplication still yields the recorded count.
    """
    rows: list[dict] = []
    if not path.is_file():
        return rows
    text = path.read_text(encoding="utf-8", errors="replace")
    target = version_target_from_path(path) if version is None else VERSION_TARGET_MAP.get(version, version)
    ver = version if version else _version_from_target(target)
    # Lines look like: KEM/Decaps/sk & 26 &  0  & 0 \\
    pattern = re.compile(
        r"^(?P<test>[A-Za-z0-9/_-]+)\s*&\s*(?P<maul>\d+)\s*&\s*(?P<errs>.*?)\s*&\s*(?P<nonmaul>\d+)\s*\\\\",
        re.MULTILINE,
    )
    for m in pattern.finditer(text):
        test = m.group("test")
        if test in ("Test", "LIBRARY", ""):
            continue
        if test not in REPORT_TO_PAPER:
            if strict:
                raise StrictPaperError(f"unmapped report test name in {path}: {test!r}")
            continue
        maul = int(m.group("maul"))
        nonmaul = int(m.group("nonmaul"))
        errs = m.group("errs").strip()
        if maul:
            rows.append(_synth(test, "maul", maul, ver, target, path, library))
        if nonmaul:
            rows.append(_synth(test, "nonmaul", nonmaul, ver, target, path, library))
        if errs and errs != "0":
            for part in errs.split("+"):
                part = part.strip()
                km = re.match(r"(\d+)\s*\(([^)]+)\)", part)
                if km:
                    cnt = int(km.group(1))
                    label = km.group(2).strip().lower().replace(" ", "")
                    sub = {"segfault": "segfault", "stackoverflow": "stackoverflow",
                           "heapoverflow": "heapoverflow", "hang": "hang",
                           "returnsbot": "returnedbot", "returns$\\bot$": "returnedbot",
                           "other": "other"}.get(label, "other")
                    rows.append(_synth(test, sub, cnt, ver, target, path, library))
    return rows


def _synth(test, subtype, count, ver, target, path, library):
    return {
        "name": f"__latex__{subtype}__{count}", "test": test,
        "error": {"segfault": "SEGV", "stackoverflow": "stack-overflow",
                  "heapoverflow": "heap-buffer-overflow", "hang": "hang"}.get(subtype),
        "expected": "unequal" if subtype == "maul" else ("equal" if subtype == "nonmaul" else None),
        "gotten": None, "source_report_path": str(path), "library": library,
        "liboqs_version": ver, "liboqs_target_name": target, "_synthetic_count": count,
    }


def read_raw_manifest(result_root: Path, strict: bool = False) -> list[dict]:
    """Fallback reader: infer counts from raw AFL tree + task metadata.

    This walks the ``afl/<property>/<alg>/fuzzoutputs/default/{crashes,hangs}``
    tree and the durable task metadata, producing one row per discovered
    artifact.  This is the lowest-priority reader and is only used when no
    SQLite/XLSX/LaTeX report exists.
    """
    rows: list[dict] = []
    afl_root = result_root / "afl"
    if not afl_root.is_dir():
        return rows
    meta = _load_campaign_meta(result_root)
    ver = meta.get("version", "unknown")
    target = VERSION_TARGET_MAP.get(ver, ver)
    for prop_dir in sorted(afl_root.iterdir()):
        if not prop_dir.is_dir():
            continue
        test = prop_dir.name  # e.g. KEM/Decaps/c stored as directory name
        if test not in REPORT_TO_PAPER:
            if strict:
                raise StrictPaperError(f"unmapped report test name in raw tree: {test!r}")
            continue
        for alg_dir in sorted(prop_dir.iterdir()):
            if not alg_dir.is_dir():
                continue
            alg_name_path = alg_dir / "alg.txt"
            alg_name = alg_name_path.read_text().strip() if alg_name_path.is_file() else alg_dir.name
            if alg_name == "DEFAULT":
                continue
            base = alg_dir / "fuzzoutputs" / "default"
            for kind, subtype in (("crashes", "other"), ("hangs", "hang")):
                d = base / kind
                if d.is_dir():
                    files = [f for f in d.iterdir() if f.is_file() and f.name != "README.txt"]
                    if files:
                        rows.append({
                            "name": alg_name, "test": test,
                            "error": "hang" if subtype == "hang" else "other",
                            "expected": None, "gotten": None,
                            "source_report_path": str(result_root), "library": "liboqs",
                            "liboqs_version": ver, "liboqs_target_name": target,
                        })
    return rows


def _load_campaign_meta(result_root: Path) -> dict:
    for cand in ("metadata/campaign.json", "metadata/schedule.json"):
        p = result_root / cand
        if p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
    return {}


# --------------------------------------------------------------------------
# Discovery + normalization
# --------------------------------------------------------------------------

def discover_result_roots(result_root: Path) -> list[dict]:
    """Find cryptoTesting campaign report directories under ``result_root``.

    Returns a list of dicts with: result_root, version, target, report_dir,
    sqlite_db, xlsx, tex, raw_root.
    """
    found = []
    # Layout A: <root>/<target>/... or <root>/cryptoTesting-<ver>/...
    # Layout B (PQCFuzz campaigns): <root>/cryptoTesting-<version>/workspace/cryptoTesting/targets-run/reports/<...>
    for report_dir in sorted(result_root.rglob("reports")):
        if not report_dir.is_dir():
            continue
        for rep in sorted(report_dir.iterdir()):
            if not rep.is_dir():
                continue
            entry = {
                "result_root": str(result_root),
                "report_dir": str(rep),
                "sqlite_db": None, "xlsx": None, "tex": None,
                "version": None, "target": None, "raw_root": None,
            }
            for f in rep.iterdir():
                if f.suffix == ".db":
                    entry["sqlite_db"] = str(f)
                    entry["target"] = version_target_from_path(f)
                elif f.suffix == ".xlsx":
                    entry["xlsx"] = str(f)
                    if entry["target"] is None:
                        entry["target"] = version_target_from_path(f)
                elif f.suffix == ".tex":
                    entry["tex"] = str(f)
            if entry["target"]:
                entry["version"] = TARGET_TO_VERSION.get(entry["target"], entry["target"])
            # Look for a raw AFL root sibling.
            raw = rep.parent.parent / "raw"
            if raw.is_dir():
                entry["raw_root"] = str(raw)
            if entry["sqlite_db"] or entry["xlsx"] or entry["tex"]:
                found.append(entry)
    return found


def read_report_entry(entry: dict, strict: bool = False) -> list[dict]:
    """Read a single discovered report entry in priority order."""
    rows: list[dict] = []
    version = entry.get("version")
    target = entry.get("target")
    if entry.get("sqlite_db"):
        rows = read_sqlite(Path(entry["sqlite_db"]), version=version, strict=strict)
        if rows:
            return rows
    if entry.get("xlsx"):
        rows = read_xlsx(Path(entry["xlsx"]), version=version, strict=strict)
        if rows:
            return rows
    if entry.get("tex"):
        rows = read_latex(Path(entry["tex"]), version=version, strict=strict)
        if rows:
            return rows
    if entry.get("raw_root"):
        return read_raw_manifest(Path(entry["raw_root"]), strict=strict)
    return rows


def normalize_rows(rows: list[dict], strict: bool = False) -> list[dict]:
    """Classify and deduplicate raw rows into paper-level normalized rows."""
    # Group raw rows by paper_count_key, keeping representative evidence.
    groups: dict[tuple, list[dict]] = defaultdict(list)
    raw_to_paper: list[dict] = []
    for r in rows:
        test = r.get("test")
        if not test:
            continue
        ptn = paper_test_for(test, strict=strict)
        if ptn is None:
            continue
        subtype = guess_crash(r)
        bucket = outcome_bucket(subtype)
        alg = r.get("name") or "unknown"
        ver = r.get("liboqs_version") or "unknown"
        lib = r.get("library") or "liboqs"
        target = r.get("liboqs_target_name") or VERSION_TARGET_MAP.get(ver, ver)
        key = (lib, ver, alg, ptn, bucket, subtype)
        groups[key].append(r)
        raw_to_paper.append({
            "library": lib, "liboqs_version": ver, "liboqs_target_name": target,
            "paper_test_number": ptn, "report_test_name": test,
            "algorithm": alg, "outcome_bucket": bucket, "outcome_subtype": subtype,
            "paper_count_key": "|".join(str(x) for x in key),
            "source_report_path": r.get("source_report_path", ""),
        })
    normalized = []
    for key, evidence in groups.items():
        lib, ver, alg, ptn, bucket, subtype = key
        rep = evidence[0]
        test = rep.get("test")
        target = rep.get("liboqs_target_name") or VERSION_TARGET_MAP.get(ver, ver)
        count = rep.get("_synthetic_count")
        raw_count = count if count else len(evidence)
        notes = "synthetic-from-latex" if rep.get("_synthetic_count") else ""
        # Test 13 (SIGN/Verify/sig): record when evidence shows the signature
        # length field was part of the test input (variable-length signatures).
        if ptn == 13:
            sig_len_fields = [v for k, v in rep.items()
                              if v not in (None, "") and "sizeof_sig" in k.lower()]
            if sig_len_fields:
                notes = (notes + ";" if notes else "") + \
                    "variable-length-signature:length-field-in-input"
        normalized.append({
            "library": lib,
            "liboqs_version": ver,
            "liboqs_target_name": target,
            "paper_test_number": ptn,
            "report_test_name": test,
            "primitive": primitive_of(test) if test else "unknown",
            "algorithm": alg,
            "parameter_set": alg,
            "outcome_bucket": bucket,
            "outcome_subtype": subtype,
            "paper_count_key": "|".join(str(x) for x in key),
            "raw_evidence_count": raw_count,
            "representative_artifact": rep.get("source_report_path", ""),
            "representative_report_row": _row_summary(rep),
            "source_report_path": rep.get("source_report_path", ""),
            "classification_confidence": "high" if not rep.get("_synthetic_count") else "medium",
            "notes": notes,
        })
    normalized.sort(key=lambda d: (d["liboqs_version"], d["paper_test_number"],
                                   d["report_test_name"], d["outcome_bucket"],
                                   d["outcome_subtype"], d["algorithm"]))
    return normalized


def _row_summary(row: dict) -> str:
    parts = []
    for k in ("name", "test", "error", "expected", "gotten"):
        if k in row and row[k] not in (None, ""):
            parts.append(f"{k}={row[k]}")
    return ";".join(parts)


# --------------------------------------------------------------------------
# Paper Table 3 comparison
# --------------------------------------------------------------------------

def paper_counts_by_key(normalized: list[dict]) -> dict[tuple, int]:
    """Aggregate normalized rows into paper-level counts.

    Multiple algorithms under the same (version, test, bucket, subtype) collapse
    to a single paper count of distinct algorithms.
    """
    counts: dict[tuple, set] = defaultdict(set)
    for d in normalized:
        key = (d["liboqs_version"], d["report_test_name"],
               d["outcome_bucket"], d["outcome_subtype"])
        counts[key].add(d["algorithm"])
    return {k: len(v) for k, v in counts.items()}


def build_table3(normalized: list[dict]) -> list[dict]:
    """Build the observed-vs-expected Table 3 rows for the three versions."""
    observed = paper_counts_by_key(normalized)
    rows = []
    for (ver, test, bucket, subtype, exp, note) in PAPER_TABLE3:
        if ver not in ("0.14.0", "0.8.0", "0.4.0"):
            continue
        obs = observed.get((ver, test, bucket, subtype), 0)
        ptn = REPORT_TO_PAPER.get(test)
        rows.append({
            "liboqs_version": ver,
            "liboqs_target_name": VERSION_TARGET_MAP.get(ver, ver),
            "paper_test_number": ptn,
            "report_test_name": test,
            "outcome_bucket": bucket,
            "outcome_subtype": subtype,
            "paper_expected_count": exp,
            "observed_count": obs,
            "paper_note": note,
        })
    return rows


def table3_status(row: dict, has_results_for_version: bool) -> tuple[str, str]:
    """Return (status, reason) for a Table 3 alignment row."""
    exp = row["paper_expected_count"]
    obs = row["observed_count"]
    if not has_results_for_version:
        return "NOT_RUN", "raw_results_missing"
    if exp == 0 and obs == 0:
        return "MATCH", ""
    if obs == 0 and exp > 0:
        return "MISSING", "raw_results_missing_or_campaign_budget_exhausted"
    if obs == exp:
        return "MATCH", ""
    if obs < exp:
        return "PARTIAL", "campaign_budget_exhausted"
    return "EXTRA", "raw_count_not_paper_count"


# --------------------------------------------------------------------------
# Output writers
# --------------------------------------------------------------------------

def _write_tsv(path: Path, rows: list[dict], fieldnames: list[str] | None = None):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\t".join(fieldnames or []) + "\n", encoding="utf-8")
        return
    fn = fieldnames or list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fn, delimiter="\t",
                           extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


NORMALIZED_FIELDS = [
    "library", "liboqs_version", "liboqs_target_name", "paper_test_number",
    "report_test_name", "primitive", "algorithm", "parameter_set",
    "outcome_bucket", "outcome_subtype", "paper_count_key",
    "raw_evidence_count", "representative_artifact",
    "representative_report_row", "source_report_path",
    "classification_confidence", "notes",
]


def write_outputs(out_dir: Path, normalized: list[dict],
                  raw_to_paper: list[dict], table3: list[dict],
                  discovered: list[dict], strict: bool = False):
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_tsv(out_dir / "paper_count_key.tsv", normalized, NORMALIZED_FIELDS)
    _write_tsv(out_dir / "raw_to_paper_key.tsv", raw_to_paper)
    _write_tsv(out_dir / "paper_table3_three_versions.tsv", table3)

    # Deviation from paper: rows where observed != expected.
    versions_with_results = {d["liboqs_version"] for d in normalized}
    deviations = []
    for row in table3:
        status, reason = table3_status(row, row["liboqs_version"] in versions_with_results)
        if status != "MATCH":
            deviations.append({**row, "status": status, "reason": reason})
    _write_tsv(out_dir / "deviation_from_paper.tsv", deviations,
               ["liboqs_version", "liboqs_target_name", "paper_test_number",
                "report_test_name", "outcome_bucket", "outcome_subtype",
                "paper_expected_count", "observed_count", "status", "reason",
                "paper_note"])

    # Missing or extra results markdown.
    md = ["# Missing or extra results\n"]
    if not deviations:
        md.append("No deviations from paper Table 3 detected.\n")
    else:
        md.append("| version | test | bucket | subtype | expected | observed | status | reason |")
        md.append("|---|---|---|---|---:|---:|---|---|")
        for d in deviations:
            md.append(f"| {d['liboqs_version']} | {d['report_test_name']} | "
                      f"{d['outcome_bucket']} | {d['outcome_subtype']} | "
                      f"{d['paper_expected_count']} | {d['observed_count']} | "
                      f"{d['status']} | {d['reason']} |")
    (out_dir / "missing_or_extra_results.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    # Table 3 markdown.
    md = ["# Paper Table 3 alignment (three supported versions)\n",
          "| version | target | test | bucket | subtype | expected | observed |",
          "|---|---|---|---|---|---:|---:|"]
    for r in table3:
        md.append(f"| {r['liboqs_version']} | {r['liboqs_target_name']} | "
                  f"{r['report_test_name']} | {r['outcome_bucket']} | "
                  f"{r['outcome_subtype']} | {r['paper_expected_count']} | "
                  f"{r['observed_count']} |")
    (out_dir / "paper_table3_three_versions.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    # Discovery log.
    _write_tsv(out_dir / "discovered_reports.tsv", discovered)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Normalize cryptoTesting reports into paper-aligned counts.")
    p.add_argument("--result-root", action="append", default=[],
                   help="Local campaign result root to scan for reports.")
    p.add_argument("--paper-reports", default=None,
                   help="Path to baselines/cryptoTesting/paper_reports/ for reference.")
    p.add_argument("--output-dir", default=None,
                   help="Directory to write normalized outputs (default: stdout summary).")
    p.add_argument("--strict-paper", action="store_true",
                   help="Treat unmapped report test names as errors.")
    p.add_argument("--version", default=None,
                   help="Override liboqs version for a single result root.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out_dir = Path(args.output_dir) if args.output_dir else None

    discovered: list[dict] = []
    for root in args.result_root:
        discovered.extend(discover_result_roots(Path(root)))

    rows: list[dict] = []
    for entry in discovered:
        rows.extend(read_report_entry(entry, strict=args.strict_paper))

    # Optional paper-reports reference read.
    paper_rows: list[dict] = []
    if args.paper_reports:
        pr = Path(args.paper_reports)
        for xlsx in sorted(pr.glob("crash_report_*_python.xlsx")):
            paper_rows.extend(read_xlsx(xlsx, strict=args.strict_paper))

    normalized = normalize_rows(rows, strict=args.strict_paper)
    raw_to_paper = [{
        "library": r.get("library", "liboqs"),
        "liboqs_version": r.get("liboqs_version", "unknown"),
        "liboqs_target_name": r.get("liboqs_target_name", "unknown"),
        "paper_test_number": REPORT_TO_PAPER.get(r.get("test", ""), ""),
        "report_test_name": r.get("test", ""),
        "algorithm": r.get("name", ""),
        "outcome_bucket": outcome_bucket(guess_crash(r)),
        "outcome_subtype": guess_crash(r),
        "paper_count_key": "",
        "source_report_path": r.get("source_report_path", ""),
    } for r in rows if r.get("test") in REPORT_TO_PAPER]
    for rp in raw_to_paper:
        rp["paper_count_key"] = "|".join(str(x) for x in (
            rp["library"], rp["liboqs_version"], rp["algorithm"],
            rp["paper_test_number"], rp["outcome_bucket"], rp["outcome_subtype"]))

    table3 = build_table3(normalized)

    if out_dir:
        write_outputs(out_dir, normalized, raw_to_paper, table3, discovered,
                      strict=args.strict_paper)

    # Stdout summary.
    print(f"discovered_reports: {len(discovered)}")
    print(f"raw_rows: {len(rows)}")
    print(f"normalized_keys: {len(normalized)}")
    if paper_rows:
        paper_norm = normalize_rows(paper_rows, strict=args.strict_paper)
        print(f"paper_reports_raw_rows: {len(paper_rows)}")
        print(f"paper_reports_normalized_keys: {len(paper_norm)}")
    print("table3_observed:")
    for r in table3:
        print(f"  {r['liboqs_version']} {r['report_test_name']} "
              f"{r['outcome_bucket']}/{r['outcome_subtype']}: "
              f"expected={r['paper_expected_count']} observed={r['observed_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
