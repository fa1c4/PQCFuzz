"""Unit tests for the cryptoTesting paper-style result normalizer.

These tests use small in-memory fixtures and do not require Docker or long
fuzzing campaigns.
"""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "cryptoTesting_paper_counts.py"

SPEC = importlib.util.spec_from_file_location("cryptoTesting_paper_counts", MODULE_PATH)
assert SPEC and SPEC.loader
PC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PC
SPEC.loader.exec_module(PC)


# --------------------------------------------------------------------------
# Helpers to build fixture databases / xlsx / latex
# --------------------------------------------------------------------------

def make_sqlite_db(path: Path, rows: list[dict], table: str = "crashes") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    cur = con.cursor()
    if not rows:
        cur.execute(f"CREATE TABLE {table} (name TEXT)")
        con.commit()
        con.close()
        return path
    cols = list(rows[0].keys())
    col_def = ", ".join(f"{c} TEXT" for c in cols)
    cur.execute(f"CREATE TABLE {table} ({col_def})")
    for r in rows:
        placeholders = ", ".join("?" for _ in cols)
        cur.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})",
                    [str(r[c]) if r[c] is not None else None for c in cols])
    con.commit()
    con.close()
    return path


def row(name, test, error=None, expected="unequal", gotten="equal", **extra):
    d = {"name": name, "test": test, "error": error,
         "expected": expected, "gotten": gotten}
    d.update(extra)
    return d


# --------------------------------------------------------------------------
# Test 1: report-name to paper-test mapping covers all Tests 2-13
# --------------------------------------------------------------------------

def test_mapping_covers_tests_2_through_13():
    expected_numbers = set(range(2, 14))
    covered = set(PC.PAPER_TEST_MAP.keys())
    assert covered == expected_numbers
    # Every report name must round-trip to a paper number.
    for _num, (_desc, names) in PC.PAPER_TEST_MAP.items():
        for name in names:
            assert PC.REPORT_TO_PAPER[name] == _num


# --------------------------------------------------------------------------
# Test 5: KEM/Encaps/pk-0 -> Test 3 and KEM/Encaps/pk -> Test 4 (no swap)
# --------------------------------------------------------------------------

def test_pk0_is_test3_pk_is_test4():
    assert PC.REPORT_TO_PAPER["KEM/Encaps/pk-0"] == 3
    assert PC.REPORT_TO_PAPER["KEM/Encaps/pk"] == 4


# --------------------------------------------------------------------------
# Test 6: SIGN/Verify/sig -> Test 13 and signature length in input
# --------------------------------------------------------------------------

def test_verify_sig_is_test13_with_length_field():
    assert PC.REPORT_TO_PAPER["SIGN/Verify/sig"] == 13
    rows = [row("Falcon-512", "SIGN/Verify/sig", expected="unequal",
                gotten="equal", sizeof_sig__max_sizeof_sig__="512/4080")]
    norm = PC.normalize_rows(rows)
    assert norm
    assert norm[0]["paper_test_number"] == 13
    assert "variable-length-signature:length-field-in-input" in norm[0]["notes"]


# --------------------------------------------------------------------------
# Test 2: multiple raw rows for same version/alg/test/outcome collapse to one
# --------------------------------------------------------------------------

def test_multiple_raw_rows_collapse_to_one_paper_count():
    rows = [row("Kyber-512-90s", "KEM/Decaps/sk") for _ in range(7)]
    norm = PC.normalize_rows(rows)
    assert len(norm) == 1
    assert norm[0]["raw_evidence_count"] == 7
    # The paper count is the number of distinct algorithms = 1.
    counts = PC.paper_counts_by_key(norm)
    key = ("unknown", "KEM/Decaps/sk", "malleability", "maul")
    assert counts[key] == 1


# --------------------------------------------------------------------------
# Test 3: different versions of the same algorithm count independently
# --------------------------------------------------------------------------

def test_different_versions_count_independently():
    rows = [
        {"name": "Kyber-512", "test": "KEM/Decaps/sk", "expected": "unequal",
         "liboqs_version": "0.8.0", "liboqs_target_name": "cur_liboqs"},
        {"name": "Kyber-512", "test": "KEM/Decaps/sk", "expected": "unequal",
         "liboqs_version": "0.4.0", "liboqs_target_name": "mid_liboqs"},
    ]
    norm = PC.normalize_rows(rows)
    assert len(norm) == 2
    versions = {d["liboqs_version"] for d in norm}
    assert versions == {"0.8.0", "0.4.0"}
    counts = PC.paper_counts_by_key(norm)
    assert counts[("0.8.0", "KEM/Decaps/sk", "malleability", "maul")] == 1
    assert counts[("0.4.0", "KEM/Decaps/sk", "malleability", "maul")] == 1


# --------------------------------------------------------------------------
# Test 4: different parameter sets count independently
# --------------------------------------------------------------------------

def test_different_parameter_sets_count_independently():
    rows = [
        row("ML-KEM-512", "KEM/Decaps/sk"),
        row("ML-KEM-768", "KEM/Decaps/sk"),
        row("ML-KEM-1024", "KEM/Decaps/sk"),
    ]
    norm = PC.normalize_rows(rows)
    algs = {d["algorithm"] for d in norm}
    assert algs == {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
    counts = PC.paper_counts_by_key(norm)
    assert counts[("unknown", "KEM/Decaps/sk", "malleability", "maul")] == 3


# --------------------------------------------------------------------------
# Test 7: setup-timeout diagnostics do not become target hangs
# --------------------------------------------------------------------------

def test_setup_timeout_not_counted_as_target_hang():
    # A setup-timeout task metadata record must not be classified as a hang.
    record = {"state": "setup-timeout", "stop_reason": "GenInput-timeout"}
    assert PC.is_setup_timeout_record(record) is True
    # A genuine target hang has error == "hang" in the report row.
    hang_row = row("Picnic-L1-FS", "SIGN/Sign/sk", error="hang")
    assert PC.guess_crash(hang_row) == "hang"
    # The raw-manifest reader only walks crashes/hangs dirs, so a setup-timeout
    # record (which lives under setup-timeout/) is never emitted as a row.
    assert PC.guess_crash({"error": None, "expected": "unequal"}) == "maul"


# --------------------------------------------------------------------------
# Test 8: Paper Table 3 expected rows can be represented by the schema
# --------------------------------------------------------------------------

def test_paper_table3_rows_representable():
    rows = []
    for (ver, test, bucket, subtype, exp, note) in PC.PAPER_TABLE3:
        if ver not in ("0.14.0", "0.8.0", "0.4.0"):
            continue
        # Build one raw row per expected algorithm to exercise the full path.
        for i in range(exp):
            r = row(f"alg-{ver}-{test}-{i}", test,
                    error={"segfault": "SEGV", "heapoverflow": "heap-buffer-overflow",
                           "hang": "hang"}.get(subtype),
                    expected="unequal" if subtype == "maul" else "equal")
            r["liboqs_version"] = ver
            r["liboqs_target_name"] = PC.VERSION_TARGET_MAP[ver]
            rows.append(r)
    norm = PC.normalize_rows(rows)
    counts = PC.paper_counts_by_key(norm)
    matched = 0
    for (ver, test, bucket, subtype, exp, note) in PC.PAPER_TABLE3:
        if ver not in ("0.14.0", "0.8.0", "0.4.0"):
            continue
        obs = counts.get((ver, test, bucket, subtype), 0)
        assert obs == exp, f"{ver} {test} {bucket}/{subtype}: {obs} != {exp}"
        matched += 1
    assert matched >= 31  # all three-version rows


# --------------------------------------------------------------------------
# Test 9: LaTeX-only and XLSX-only fixtures produce the same normalized key
# --------------------------------------------------------------------------

def test_latex_and_xlsx_produce_same_normalized_key(tmp_path):
    # Build a SQLite fixture (the primary, highest-fidelity source).
    db_rows = [
        row("Kyber-512", "KEM/Decaps/sk"),
        row("Kyber-768", "KEM/Decaps/sk"),
        row("Falcon-512", "SIGN/Verify/sig"),
    ]
    db_path = make_sqlite_db(tmp_path / "sqlite" / "crash_report_mid_liboqs_python.db", db_rows)

    # Build a LaTeX fixture with the same deduplicated counts.
    tex = ("\\begin{tabular}{lc@{\\hskip 0em}c@{\\hskip 0em}c}\n"
           "Test & Malleabilities & Crashes/hangs & Non-malleabilities \\\\\n"
           "KEM/Decaps/sk & 2 & 0 & 0 \\\\\n"
           "SIGN/Verify/sig & 1 & 0 & 0 \\\\\n"
           "\\end{tabular}\n")
    tex_path = tmp_path / "tex" / "crash_report_mid_liboqs_python.tex"
    tex_path.parent.mkdir(parents=True, exist_ok=True)
    tex_path.write_text(tex, encoding="utf-8")

    sqlite_rows = PC.read_sqlite(db_path, version="0.4.0")
    latex_rows = PC.read_latex(tex_path, version="0.4.0")
    # SQLite yields per-algorithm rows; LaTeX yields synthetic count rows.
    norm_sql = PC.normalize_rows(sqlite_rows)
    norm_tex = PC.normalize_rows(latex_rows)
    keys_sql = {(d["liboqs_version"], d["report_test_name"],
                 d["outcome_bucket"], d["outcome_subtype"]): d["algorithm"]
                for d in norm_sql}
    # Both must produce the same set of (version, test, bucket, subtype) keys.
    assert keys_sql.keys() == {(d["liboqs_version"], d["report_test_name"],
                                d["outcome_bucket"], d["outcome_subtype"])
                               for d in norm_tex}


# --------------------------------------------------------------------------
# Test 10: BLACKLIST=() is full-run; non-empty blacklist is a limitation
# --------------------------------------------------------------------------

def test_blacklist_detection_full_run(tmp_path):
    src = tmp_path / "fuzz_liboqs.py"
    src.write_text("BLACKLIST=()\n", encoding="utf-8")
    info = PC.detect_blacklist(src)
    assert info["is_full_run"] is True
    assert info["coverage_limitation"] is False
    assert info["blacklist"] == []


def test_blacklist_detection_non_empty(tmp_path):
    src = tmp_path / "fuzz_liboqs.py"
    src.write_text(
        'BLACKLIST=(\n    ("McEliece", "Encaps/pk"),\n    ("BIKE", "Encaps/pk"),\n)\n',
        encoding="utf-8")
    info = PC.detect_blacklist(src)
    assert info["is_full_run"] is False
    assert info["coverage_limitation"] is True
    assert ("McEliece", "Encaps/pk") in info["blacklist"]
    assert ("BIKE", "Encaps/pk") in info["blacklist"]


def test_blacklist_detection_real_vendored_file():
    src = REPO_ROOT / "baselines" / "cryptoTesting" / "fuzz_liboqs.py"
    info = PC.detect_blacklist(src)
    # The vendored file is configured for full paper reproduction.
    assert info["is_full_run"] is True
    assert info["blacklist"] == []


# --------------------------------------------------------------------------
# Extra: strict-paper rejects unmapped report names
# --------------------------------------------------------------------------

def test_strict_paper_rejects_unmapped():
    with pytest.raises(PC.StrictPaperError):
        PC.paper_test_for("UNKNOWN/test", strict=True)


# --------------------------------------------------------------------------
# Extra: crash subtype classification mirrors report.py guess_crash
# --------------------------------------------------------------------------

@pytest.mark.parametrize("rowdata,expected", [
    ({"error": "SEGV"}, "segfault"),
    ({"error": "stack-overflow"}, "stackoverflow"),
    ({"error": "heap-buffer-overflow"}, "heapoverflow"),
    ({"error": "ERROR: ... failed!"}, "returnedbot"),
    ({"error": "hang"}, "hang"),
    ({"error": "something weird"}, "other"),
    ({"expected": "unequal"}, "maul"),
    ({"expected": "equal"}, "nonmaul"),
])
def test_guess_crash_classification(rowdata, expected):
    assert PC.guess_crash(rowdata) == expected
    if expected == "maul":
        assert PC.outcome_bucket(expected) == "malleability"
    elif expected == "nonmaul":
        assert PC.outcome_bucket(expected) == "non_malleability"
    else:
        assert PC.outcome_bucket(expected) == "crash_hang"
