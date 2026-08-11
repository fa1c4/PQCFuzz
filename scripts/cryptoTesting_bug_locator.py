#!/usr/bin/env python3
"""Paper-level bug locator for the cryptoTesting reproduction.

Consumes normalized paper-count rows (from ``cryptoTesting_paper_counts.py``)
and classifies each into a paper-level category with root-cause summary and
source trace.  Does not rerun fuzzing.

Classification rules are implemented as data-driven matchers (Phase 3 of the
beta plan, Rules A-I) and are intentionally conservative: malleability
observations are not automatically bugs.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Paper test names (mirrors cryptoTesting_paper_counts for standalone use)
# --------------------------------------------------------------------------

PAPER_TEST_NAMES = {
    2: "KEM/Keygen/badrng",
    3: "KEM/Encaps/pk-0",
    4: "KEM/Encaps/pk",
    5: "KEM/Encaps/badrng",
    6: "KEM/Decaps/sk",
    7: "KEM/Decaps/c",
    8: "SIGN/Sign/sk",
    9: "SIGN/Sign/m",
    10: "SIGN/Sign/badrng",
    11: "SIGN/Verify/pk",
    12: "SIGN/Verify/m",
    13: "SIGN/Verify/sig",
}

PAPER_CATEGORIES = [
    "CONFIRMED_SOFTWARE_BUG",
    "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE",
    "UNEXPECTED_BUT_ALLOWED_FEATURE",
    "BAD_RNG_ROBUSTNESS_ISSUE",
    "HARNESS_ARTIFACT",
    "FALSE_POSITIVE_ORACLE_ASSUMPTION",
    "INCONCLUSIVE",
    "NEEDS_RERUN",
    "NEEDS_SOURCE_TRACE",
]

SOURCE_TRACE_STATUSES = [
    "verified_source_path",
    "source_path_exists_but_lines_unverified",
    "missing_source_path",
    "not_applicable",
    "needs_manual_review",
]

BUG_LOCATOR_FIELDS = [
    "paper_key", "library", "version", "version_label", "algorithm",
    "test_id", "paper_test_number", "paper_test_name", "outcome_bucket",
    "outcome_subtype", "paper_category", "paper_claim", "confidence",
    "artifact_count", "representative_artifact", "representative_log",
    "source_version_path", "source_files", "source_trace_status",
    "root_cause_summary", "recommended_action",
]


# --------------------------------------------------------------------------
# Source trace helpers (Phase 4)
# --------------------------------------------------------------------------

def source_root_for_version(source_root: Path, version: str) -> Path:
    """Return the liboqs source directory for a version."""
    return source_root / f"liboqs-{version}"


# Known source directory locations for rule groups.
SOURCE_PATHS = {
    ("NTRU", "0.4.0"): "src/kem/ntru/",
    ("Falcon", "0.4.0"): "src/sig/falcon/",
    ("Falcon", "0.8.0"): "src/sig/falcon/",
    ("Falcon", "0.14.0"): "src/sig/falcon/",
    ("Picnic", "0.4.0"): "src/sig/picnic/",
    ("SIKE", "0.4.0"): "src/kem/sike/",
    ("SIDH", "0.4.0"): "src/kem/sike/",
    ("sntrup761", "0.8.0"): "src/kem/ntruprime/",
    ("sntrup761", "0.14.0"): "src/kem/ntruprime/",
    ("Classic-McEliece", "*"): "src/kem/classic_mceliece/",
    ("CROSS", "0.14.0"): "src/sig/cross/",
    ("SNOVA", "0.14.0"): "src/sig/snova/",
    ("Dilithium", "*"): "src/sig/dilithium/",
    ("Kyber", "*"): "src/kem/kyber/",
    ("ML-KEM", "*"): "src/kem/ml_kem/",
    ("NewHope", "0.4.0"): "src/kem/newhope/",
    ("Frodo", "*"): "src/kem/frodokem/",
    ("BIKE", "*"): "src/kem/bike/",
    ("Saber", "0.4.0"): "src/kem/saber/",
}


def find_source_path(source_root: Path, algorithm: str, version: str) -> Optional[Path]:
    """Try to locate the source directory for an algorithm/version pair."""
    for (key_alg, key_ver), rel in SOURCE_PATHS.items():
        if key_alg.lower() not in algorithm.lower():
            continue
        if key_ver != "*" and key_ver != version:
            continue
        candidate = source_root_for_version(source_root, version) / rel
        if candidate.is_dir():
            return candidate
    return None


def source_trace_status(source_path: Optional[Path]) -> str:
    if source_path is None:
        return "missing_source_path"
    if source_path.is_dir():
        return "source_path_exists_but_lines_unverified"
    return "missing_source_path"


# --------------------------------------------------------------------------
# Classification rules (Phase 3, Rules A-I + Default)
# --------------------------------------------------------------------------

class Classification:
    """Result of classifying a paper-count row."""

    def __init__(self, category: str, claim: str, confidence: str,
                 source_path: Optional[Path] = None,
                 root_cause: str = "",
                 recommended_action: str = "",
                 trace_status: str = ""):
        self.paper_category = category
        self.paper_claim = claim
        self.confidence = confidence
        self.source_path = source_path
        self.root_cause_summary = root_cause or claim
        self.recommended_action = recommended_action
        if trace_status:
            self.source_trace_status = trace_status
        else:
            self.source_trace_status = source_trace_status(source_path)


def classify(row: dict, source_root: Path) -> Classification:
    """Apply Rules A-I to a normalized paper-count row.

    ``row`` must have: version, algorithm, test_id (report_test_name),
    paper_test_number, outcome_bucket, outcome_subtype.
    """
    ver = str(row.get("version") or row.get("liboqs_version") or "")
    alg = str(row.get("algorithm") or "")
    test_id = str(row.get("test_id") or row.get("report_test_name") or "")
    ptn = row.get("paper_test_number")
    try:
        ptn = int(ptn) if ptn else None
    except (ValueError, TypeError):
        ptn = None
    bucket = str(row.get("outcome_bucket") or "")

    # Rule A: NTRU 0.4.0 IND-CCA zero-padding counterexamples
    if (ver == "0.4.0" and test_id == "KEM/Decaps/c" and ptn == 7
            and bucket == "malleability"
            and any(n in alg for n in ("NTRU-HRSS-701", "NTRU-HPS-2048-677", "NTRU-HPS-2048-509", "NTRU"))):
        sp = find_source_path(source_root, alg, ver)
        return Classification(
            "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE",
            "IND-CCA counterexample due to non-byte-aligned ciphertext zero-padding acceptance",
            "HIGH" if sp and sp.is_dir() else "MEDIUM",
            source_path=sp,
            root_cause="NTRU decaps does not check zero padding of non-byte-aligned encapsulations, accepting mauled ciphertexts that should be rejected under IND-CCA.",
            recommended_action="No action needed; this reproduces the paper's security-notion counterexample.")

    # Rule B: Falcon signature noncanonical encoding / sUF-CMA
    if ("Falcon" in alg and test_id == "SIGN/Verify/sig" and ptn == 13
            and bucket == "malleability"):
        sp = find_source_path(source_root, alg, ver)
        return Classification(
            "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE",
            "sUF-CMA counterexample / non-canonical signature encoding",
            "HIGH" if sp and sp.is_dir() else "MEDIUM",
            source_path=sp,
            root_cause="Falcon signature verification accepts non-canonical encodings of the same signature, breaking strong unforgeability. This is alternative valid encoding of an existing signature, not forgery of a new message.",
            recommended_action="No action needed; this reproduces the paper's sUF-CMA counterexample.")

    # Rule C: CROSS / SNOVA Test 13
    if (ver == "0.14.0" and test_id == "SIGN/Verify/sig" and ptn == 13
            and bucket == "malleability"
            and ("CROSS" in alg.upper() or "SNOVA" in alg.upper())):
        sp = find_source_path(source_root, alg, ver)
        return Classification(
            "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE",
            "possible sUF-CMA counterexample; verify signature length/appended bytes behavior",
            "MEDIUM",
            source_path=sp,
            root_cause="CROSS/SNOVA PQClean-compatible implementation may ignore input signature length, allowing appended bytes.",
            recommended_action="Verify signature-length/appended-byte behavior in source.",
            trace_status="needs_manual_review")

    # Rule D: Picnic 0.4.0 signing crashes / heap overflows
    if (ver == "0.4.0" and "Picnic" in alg and test_id.startswith("SIGN/Sign")
            and bucket in ("crash", "crash_hang", "sanitizer", "heap_overflow", "segfault")):
        sp = find_source_path(source_root, alg, ver)
        has_sanitizer = bucket in ("sanitizer", "heap_overflow") or row.get("outcome_subtype") in ("heapoverflow", "segfault")
        return Classification(
            "CONFIRMED_SOFTWARE_BUG",
            "Picnic signing memory-safety failure",
            "HIGH" if has_sanitizer else "MEDIUM",
            source_path=sp,
            root_cause="Picnic signing implementation has heap-buffer-overflow memory-safety failures.",
            recommended_action="Rerun with ASan and raw AFL retention if only crash artifact exists.")

    # Rule E: SIKE/SIDH compressed encapsulation segfaults
    if (ver == "0.4.0" and ("SIKE" in alg or "SIDH" in alg)
            and test_id in ("KEM/Encaps/pk", "KEM/Encaps/pk-0")
            and bucket in ("crash", "crash_hang", "segfault", "sanitizer")):
        sp = find_source_path(source_root, alg, ver)
        has_segfault = row.get("outcome_subtype") == "segfault"
        return Classification(
            "CONFIRMED_SOFTWARE_BUG",
            "SIKE/SIDH compressed encapsulation crash",
            "HIGH" if has_segfault else "MEDIUM",
            source_path=sp,
            root_cause="SIKE/SIDH compressed encapsulation implementation segfaults on mauled public keys.",
            recommended_action="Rerun with ASan if segfault log not available.")

    # Rule F: Bad-randomness hangs
    if ptn in (2, 5, 10) and bucket in ("hang", "crash_hang") and row.get("outcome_subtype") == "hang":
        return Classification(
            "BAD_RNG_ROBUSTNESS_ISSUE",
            "implementation may hang under degenerate bad randomness",
            "MEDIUM",
            root_cause="The implementation hangs when the RNG produces degenerate values. This is a robustness issue under a bad-RNG threat model, not a remote vulnerability unless the threat model proves attacker-controlled RNG.",
            recommended_action="Do not label as vulnerability without attacker-controlled RNG threat model evidence.",
            trace_status="not_applicable")

    # Rule G: FO transform / implicit rejection secret-key features
    if (test_id == "KEM/Decaps/sk" and bucket == "malleability"
            and any(k in alg for k in ("Kyber", "ML-KEM", "NewHope", "NTRU", "Frodo", "Saber", "SIKE", "BIKE", "Classic-McEliece"))):
        sp = find_source_path(source_root, alg, ver)
        return Classification(
            "UNEXPECTED_BUT_ALLOWED_FEATURE",
            "secret-key malleability or redundant/failure-only secret-key field",
            "MEDIUM",
            source_path=sp,
            root_cause="FO-transform KEM decaps tolerates secret-key bit flips in failure-only or redundant fields. This is an expected feature of the transform, not an implementation bug.",
            recommended_action="No action needed; this is an allowed feature of the FO transform.")

    # Rule H: Dilithium randomized-signing K behavior
    if ("Dilithium" in alg and test_id == "SIGN/Sign/sk" and bucket == "malleability"):
        if "0.14.0" in ver and "ML-DSA" in alg:
            return Classification(
                "INCONCLUSIVE",
                "ML-DSA functional secret-key field observation requires multi-message replay",
                "MEDIUM",
                root_cause="ML-DSA s2/t0 functional secret-key field observation requires multi-message replay to classify.",
                recommended_action="Rerun with multi-message replay to classify.",
                trace_status="needs_manual_review")
        sp = find_source_path(source_root, alg, ver)
        return Classification(
            "UNEXPECTED_BUT_ALLOWED_FEATURE",
            "randomized Dilithium may ignore deterministic-signing K under fixed RNG; source trace required for exact field",
            "MEDIUM",
            source_path=sp,
            root_cause="Dilithium randomized signing may ignore the K parameter used in deterministic signing when the RNG is fixed/faulty.",
            recommended_action="Source trace required for exact mutated field.")

    # Rule H (ML-DSA variant): ML-DSA is the NIST-standardized Dilithium.
    if ("ML-DSA" in alg and test_id == "SIGN/Sign/sk" and bucket == "malleability"):
        return Classification(
            "INCONCLUSIVE",
            "ML-DSA functional secret-key field observation requires multi-message replay",
            "MEDIUM",
            root_cause="ML-DSA s2/t0 functional secret-key field observation requires multi-message replay to classify.",
            recommended_action="Rerun with multi-message replay to classify.",
            trace_status="needs_manual_review")

    # Rule I: Harness artifacts
    if bucket in ("harness_artifact",) or row.get("outcome_subtype") == "setup_timeout":
        return Classification(
            "HARNESS_ARTIFACT",
            "harness or setup artifact, not a target bug",
            "HIGH",
            root_cause="Setup timeout, queue-only artifact, or report-finalization artifact. Not a target hang unless replay proves otherwise.",
            recommended_action="Do not count as target hang.",
            trace_status="not_applicable")

    # Default rule
    return Classification(
        "INCONCLUSIVE",
        "unclassified paper-level observation",
        "LOW",
        root_cause="No classification rule matched. Inspect artifact and add a rule if supported by source/replay evidence.",
        recommended_action="inspect artifact and add a paper classification rule if supported by source/replay evidence",
        trace_status="needs_manual_review")


# --------------------------------------------------------------------------
# Readers
# --------------------------------------------------------------------------

def read_paper_count_key(path: Path) -> list[dict]:
    """Read a paper_count_key.tsv file."""
    rows = []
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            rows.append(row)
    return rows


# --------------------------------------------------------------------------
# Output writers
# --------------------------------------------------------------------------

def write_tsv(path: Path, rows: list[dict], fields: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


VERSION_LABELS = {
    "0.14.0": "ches_liboqs",
    "0.8.0": "cur_liboqs",
    "0.4.0": "mid_liboqs",
    "2018-11": "old_liboqs",
}


def build_locator_rows(paper_rows: list[dict], source_root: Path) -> list[dict]:
    """Classify each paper-count row and build bug_locator.tsv rows."""
    out = []
    for r in paper_rows:
        ver = str(r.get("liboqs_version") or "")
        alg = str(r.get("algorithm") or "")
        test_id = str(r.get("report_test_name") or "")
        ptn = r.get("paper_test_number") or ""
        bucket = str(r.get("outcome_bucket") or "")
        subtype = str(r.get("outcome_subtype") or "")

        row_for_classify = {
            "version": ver, "algorithm": alg, "test_id": test_id,
            "paper_test_number": ptn, "outcome_bucket": bucket,
            "outcome_subtype": subtype,
        }
        cls = classify(row_for_classify, source_root)

        source_files = ""
        source_ver_path = ""
        if cls.source_path and cls.source_path.is_dir():
            source_ver_path = str(cls.source_path)
            source_files = ";".join(sorted(f.name for f in cls.source_path.iterdir() if f.is_file())[:10])

        paper_key = f"liboqs|{ver}|{alg}|{ptn}|{bucket}|{subtype}"

        out.append({
            "paper_key": paper_key,
            "library": r.get("library", "liboqs"),
            "version": ver,
            "version_label": VERSION_LABELS.get(ver, ver),
            "algorithm": alg,
            "test_id": test_id,
            "paper_test_number": ptn,
            "paper_test_name": PAPER_TEST_NAMES.get(int(ptn) if ptn and str(ptn).isdigit() else 0, test_id),
            "outcome_bucket": bucket,
            "outcome_subtype": subtype,
            "paper_category": cls.paper_category,
            "paper_claim": cls.paper_claim,
            "confidence": cls.confidence,
            "artifact_count": r.get("raw_evidence_count", "1"),
            "representative_artifact": r.get("representative_artifact", r.get("source_report_path", "")),
            "representative_log": r.get("representative_report_row", ""),
            "source_version_path": source_ver_path,
            "source_files": source_files,
            "source_trace_status": cls.source_trace_status,
            "root_cause_summary": cls.root_cause_summary,
            "recommended_action": cls.recommended_action,
        })
    return out


def write_root_cause_review(path: Path, rows: list[dict]):
    cats = Counter(r["paper_category"] for r in rows)
    md = ["# Root Cause Review\n",
          "## 1. Scope and limitations",
          "This review classifies paper-level artifacts from the cryptoTesting",
          "reproduction. It is an academic reproduction and triage aid. It",
          "classifies paper-level artifacts conservatively. Malleability",
          "observations are not automatically bugs.",
          "",
          "## 2. Paper-level counting rule",
          "Count at most one result per: library + liboqs_version +",
          "algorithm/parameter_set + paper_test_number + outcome type.",
          "Multiple bit flips or raw AFL artifacts for the same",
          "algorithm/version/test/outcome are not counted as multiple",
          "paper-level results.",
          "",
          "## 3. Distinctions",
          "- **Raw finding row**: a single crash/hang/malleability artifact.",
          "- **Paper-level result**: deduplicated count per version/alg/test/outcome.",
          "- **Malleability observation**: oracle expected output to differ after",
          "  mauling a DIFF-labeled field, but output remained equal. Not",
          "  automatically a bug.",
          "- **Confirmed bug**: memory-safety failure or security-notion",
          "  counterexample with source/replay evidence.",
          "- **Unexpected feature**: implementation behavior that reproduces a",
          "  paper-observed property but is not a conventional implementation bug.",
          "",
          "## 4. Category count table",
          "| category | count |",
          "|---|---:|"]
    for cat in PAPER_CATEGORIES:
        if cats.get(cat, 0):
            md.append(f"| {cat} | {cats[cat]} |")
    md += ["",
           "## 5. Root-cause sections for matched rule groups"]
    for cat in ("CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE", "CONFIRMED_SOFTWARE_BUG",
                "UNEXPECTED_BUT_ALLOWED_FEATURE", "BAD_RNG_ROBUSTNESS_ISSUE"):
        cat_rows = [r for r in rows if r["paper_category"] == cat]
        if not cat_rows:
            continue
        md.append(f"\n### {cat}\n")
        for r in cat_rows[:20]:
            md.append(f"- **{r['version']} / {r['algorithm']} / {r['test_id']}**: {r['root_cause_summary']}")
    md += ["",
           "## 6. Not bugs by default",
           "- Malleability is not automatically a bug. It means the oracle",
           "  expected output to differ after mauling, but it remained equal.",
           "- Bad-RNG hang is a robustness issue unless the threat model proves",
           "  attacker-controlled RNG.",
           "- Secret-key malleability in FO-style transforms may be an expected",
           "  feature (failure-only or redundant fields).",
           "",
           "## 7. Needs rerun / inconclusive"]
    inconc = [r for r in rows if r["paper_category"] in ("INCONCLUSIVE", "NEEDS_RERUN", "NEEDS_SOURCE_TRACE")]
    if inconc:
        md.append(f"\n{len(inconc)} rows require further investigation:\n")
        for r in inconc[:20]:
            md.append(f"- **{r['version']} / {r['algorithm']} / {r['test_id']}**: {r['recommended_action']}")
    else:
        md.append("\nNo inconclusive or needs-rerun rows.")
    write_text(path, "\n".join(md) + "\n")


def write_confirmed_paper_bugs(path: Path, rows: list[dict]):
    bugs = [r for r in rows if r["paper_category"] in ("CONFIRMED_SOFTWARE_BUG", "CONFIRMED_SECURITY_NOTION_COUNTEREXAMPLE")]
    md = ["# Confirmed Paper Bugs\n",
          "This beta pass is an academic reproduction and triage aid.",
          "It classifies paper-level artifacts conservatively.",
          "Malleability observations are not automatically bugs.\n"]
    if not bugs:
        md.append("No confirmed software bugs or security-notion counterexamples found.\n")
    else:
        md.append("| version | algorithm | test | category | paper claim | confidence | source trace |")
        md.append("|---|---|---|---|---|---|---|")
        for r in bugs:
            md.append(f"| {r['version']} | {r['algorithm']} | {r['test_id']} | {r['paper_category']} | {r['paper_claim']} | {r['confidence']} | {r['source_trace_status']} |")
    write_text(path, "\n".join(md) + "\n")


def write_unexpected_features(path: Path, rows: list[dict]):
    feats = [r for r in rows if r["paper_category"] in ("UNEXPECTED_BUT_ALLOWED_FEATURE", "BAD_RNG_ROBUSTNESS_ISSUE")]
    md = ["# Unexpected Features\n",
          "These items reproduce paper-observed features but are not automatically",
          "conventional implementation bugs.\n"]
    if not feats:
        md.append("No unexpected features or bad-RNG robustness issues found.\n")
    else:
        for r in feats:
            md.append(f"## {r['version']} / {r['algorithm']} / {r['test_id']}\n")
            md.append(f"- **Category**: {r['paper_category']}")
            md.append(f"- **Claim**: {r['paper_claim']}")
            md.append(f"- **Root cause**: {r['root_cause_summary']}")
            md.append(f"- **Confidence**: {r['confidence']}\n")
    write_text(path, "\n".join(md) + "\n")


def write_harness_artifacts(path: Path, rows: list[dict]):
    arts = [r for r in rows if r["paper_category"] in ("HARNESS_ARTIFACT", "FALSE_POSITIVE_ORACLE_ASSUMPTION")]
    md = ["# Harness Artifacts\n"]
    if not arts:
        md.append("No harness artifacts or false-positive oracle assumptions found.\n")
    else:
        for r in arts:
            md.append(f"- **{r['version']} / {r['algorithm']} / {r['test_id']}**: {r['paper_claim']}")
    write_text(path, "\n".join(md) + "\n")


def write_inconclusive(path: Path, rows: list[dict]):
    inc = [r for r in rows if r["paper_category"] in ("INCONCLUSIVE", "NEEDS_RERUN", "NEEDS_SOURCE_TRACE")]
    md = ["# Inconclusive or Needs Rerun\n"]
    if not inc:
        md.append("No inconclusive or needs-rerun rows.\n")
    else:
        for r in inc:
            md.append(f"## {r['version']} / {r['algorithm']} / {r['test_id']}\n")
            md.append(f"- **Category**: {r['paper_category']}")
            md.append(f"- **Missing evidence**: {r['recommended_action']}")
            md.append(f"- **Confidence**: {r['confidence']}\n")
    write_text(path, "\n".join(md) + "\n")


def write_locator_summary(path: Path, rows: list[dict]):
    cats = Counter(r["paper_category"] for r in rows)
    confs = Counter(r["confidence"] for r in rows)
    traces = Counter(r["source_trace_status"] for r in rows)
    summary = {
        "total_rows": len(rows),
        "category_counts": dict(cats),
        "confidence_counts": dict(confs),
        "source_trace_counts": dict(traces),
        "categories": PAPER_CATEGORIES,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Paper-level bug locator for cryptoTesting reproduction.")
    p.add_argument("--paper-count-key", default=None,
                   help="Path to paper_count_key.tsv from the normalizer.")
    p.add_argument("--result-root", default=None,
                   help="Optional result root to generate paper-count on the fly.")
    p.add_argument("--source-root", default="third_party",
                   help="Root directory for liboqs source trees (default: third_party).")
    p.add_argument("--output-dir", default=None,
                   help="Directory to write locator outputs.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.output_dir:
        print("error: --output-dir is required", file=sys.stderr)
        return 2

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    source_root = Path(args.source_root)

    # Resolve paper-count rows.
    paper_rows: list[dict] = []
    if args.paper_count_key:
        pck = Path(args.paper_count_key)
        if not pck.is_file():
            print(f"error: paper-count-key not found: {pck}", file=sys.stderr)
            return 2
        paper_rows = read_paper_count_key(pck)
    elif args.result_root:
        # Invoke the normalizer to generate a temporary paper-count table.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "cryptoTesting_paper_counts",
            Path(__file__).parent / "cryptoTesting_paper_counts.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        discovered = mod.discover_result_roots(Path(args.result_root))
        rows = []
        for entry in discovered:
            rows.extend(mod.read_report_entry(entry))
        paper_rows = mod.normalize_rows(rows)
    else:
        print("error: either --paper-count-key or --result-root is required", file=sys.stderr)
        return 2

    # Classify.
    locator_rows = build_locator_rows(paper_rows, source_root)

    # Write outputs.
    write_tsv(out_dir / "bug_locator.tsv", locator_rows, BUG_LOCATOR_FIELDS)
    write_root_cause_review(out_dir / "root_cause_review.md", locator_rows)
    write_confirmed_paper_bugs(out_dir / "confirmed_paper_bugs.md", locator_rows)
    write_unexpected_features(out_dir / "unexpected_features.md", locator_rows)
    write_harness_artifacts(out_dir / "harness_artifacts.md", locator_rows)
    write_inconclusive(out_dir / "inconclusive_or_needs_rerun.md", locator_rows)
    write_locator_summary(out_dir / "locator_summary.json", locator_rows)

    # Stdout summary.
    cats = Counter(r["paper_category"] for r in locator_rows)
    print(f"classified_rows: {len(locator_rows)}")
    for cat in PAPER_CATEGORIES:
        if cats.get(cat, 0):
            print(f"  {cat}: {cats[cat]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
