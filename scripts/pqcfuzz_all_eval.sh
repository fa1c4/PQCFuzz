#!/usr/bin/env bash
# Master PQCFuzz evaluation driver for every algorithm lane.
#
# Runs, with one command interface, the liboqs ML-KEM/ML-DSA/SLH-DSA campaign,
# the PQMagic Aigis (SM3-vs-SHAKE) campaign, and the CROSS, Falcon, NTRU,
# SIKE/SIDH and SNOVA family lanes.
#
# Usage:
#   scripts/pqcfuzz_all_eval.sh build      # build every selected lane
#   scripts/pqcfuzz_all_eval.sh preflight  # seeded integrity check per lane
#   scripts/pqcfuzz_all_eval.sh smoke      # short sanitizer campaign per lane
#   scripts/pqcfuzz_all_eval.sh run        # full campaign per lane
#   scripts/pqcfuzz_all_eval.sh report     # per-lane reports + aggregate
#   scripts/pqcfuzz_all_eval.sh all        # build + preflight + smoke + run + report
#
# Environment:
#   SUITES=liboqs,aigis,cross,falcon,ntru,sike_sidh,snova   lanes to drive (default all)
#   MAX_TOTAL_TIME=seconds      per-job campaign budget, default 120
#   SMOKE_FUZZ_SECONDS=seconds  smoke budget, default 30
#   BUILD_WORKERS=N             parallel build workers, default 8
#   JOB_FILTER=<substring>      restrict a lane to matching jobs
#   PQCFUZZ_INCLUDE_P2=1        schedule the opt-in P2 oracles
#   FAMILY=all|SIKE|SIDH        sub-lane for sike_sidh
#   VERSIONS=0.14.0,...         liboqs versions
#   ORACLE_SUITE=fips|metamorphic   Aigis oracle suite
#   ORACLE_SET=all|security     Aigis oracle subset
#   LIBOQS_ORACLE_SUITE=fips|metamorphic  liboqs oracle suite
#   LIBOQS_ORACLE_SET=all|security        liboqs metamorphic subset
#   SESSION_PREFIX=<name>       tmux session prefix for the liboqs campaigns
#   OUTPUT_ROOT=workspace/pqcfuzz_eval  liboqs output root
#   ALL_ROOT=workspace/all      aggregate output root
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

SUITES="${SUITES:-liboqs,aigis,cross,falcon,ntru,sike_sidh,snova}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-120}"
SMOKE_FUZZ_SECONDS="${SMOKE_FUZZ_SECONDS:-30}"
BUILD_WORKERS="${BUILD_WORKERS:-8}"
JOB_FILTER="${JOB_FILTER:-}"
FAMILY="${FAMILY:-all}"
VERSIONS="${VERSIONS:-0.14.0,0.8.0,0.4.0}"
ORACLE_SUITE="${ORACLE_SUITE:-fips}"
ORACLE_SET="${ORACLE_SET:-all}"
LIBOQS_ORACLE_SUITE="${LIBOQS_ORACLE_SUITE:-metamorphic}"
LIBOQS_ORACLE_SET="${LIBOQS_ORACLE_SET:-all}"
SESSION_PREFIX="${SESSION_PREFIX:-pqcfuzz-all}"
OUTPUT_ROOT="${OUTPUT_ROOT:-workspace/pqcfuzz_eval}"
ALL_ROOT="${ALL_ROOT:-workspace/all}"

usage() {
  awk '/^set -euo/{exit} NR > 1 {sub(/^# ?/, ""); print}' "$0"
}

die() {
  echo "[all] error: $*" >&2
  exit 2
}

known_suite() {
  case "$1" in
    liboqs|aigis|cross|falcon|ntru|sike_sidh|snova) return 0 ;;
    *) return 1 ;;
  esac
}

parse_suites() {
  local raw="${1:-$SUITES}" suite
  PARSED_SUITES=()
  IFS=',' read -r -a PARSED_SUITES <<< "$raw"
  for suite in "${PARSED_SUITES[@]}"; do
    suite="${suite// /}"
    [ -n "$suite" ] || continue
    known_suite "$suite" || die "unknown suite '$suite' (known: liboqs,aigis,cross,falcon,ntru,sike_sidh,snova)"
  done
  [ "${#PARSED_SUITES[@]}" -gt 0 ] || die "no suites selected"
}

run_family_suite() {
  local suite="$1" command="$2"
  local script="scripts/pqcfuzz_${suite}_eval.sh"
  [ -f "$script" ] || die "missing lane script $script"
  echo "[all] ${suite}: ${command}"
  env \
    MAX_TOTAL_TIME="$MAX_TOTAL_TIME" \
    SMOKE_FUZZ_SECONDS="$SMOKE_FUZZ_SECONDS" \
    BUILD_WORKERS="$BUILD_WORKERS" \
    JOB_FILTER="$JOB_FILTER" \
    PQCFUZZ_INCLUDE_P2="${PQCFUZZ_INCLUDE_P2:-}" \
    FAMILY="$FAMILY" \
    bash "$script" "$command"
}

run_liboqs_suite() {
  local command="$1"
  local duration
  case "$command" in
    build|preflight)
      echo "[all] liboqs: ${command} (build + seeded oracle corpus via --preflight-only)"
      bash scripts/pqcfuzz_eval.sh \
        --preflight-only \
        --versions "$VERSIONS" \
        --oracle-suite "$LIBOQS_ORACLE_SUITE" \
        --oracle-set "$LIBOQS_ORACLE_SET" \
        --session-prefix "${SESSION_PREFIX}-liboqs" \
        --output-root "$OUTPUT_ROOT"
      ;;
    smoke)
      duration="${SMOKE_FUZZ_SECONDS}s"
      echo "[all] liboqs: smoke (${duration})"
      bash scripts/pqcfuzz_eval.sh \
        --fuzzing-time "$duration" \
        --versions "$VERSIONS" \
        --oracle-suite "$LIBOQS_ORACLE_SUITE" \
        --oracle-set "$LIBOQS_ORACLE_SET" \
        --session-prefix "${SESSION_PREFIX}-liboqs-smoke" \
        --output-root "$OUTPUT_ROOT"
      ;;
    run)
      duration="${MAX_TOTAL_TIME}s"
      echo "[all] liboqs: run (${duration})"
      bash scripts/pqcfuzz_eval.sh \
        --fuzzing-time "$duration" \
        --versions "$VERSIONS" \
        --oracle-suite "$LIBOQS_ORACLE_SUITE" \
        --oracle-set "$LIBOQS_ORACLE_SET" \
        --session-prefix "${SESSION_PREFIX}-liboqs" \
        --output-root "$OUTPUT_ROOT"
      ;;
    report)
      echo "[all] liboqs: report"
      mkdir -p "$ALL_ROOT/report"
      local -a inputs=()
      local results
      while IFS= read -r results; do
        inputs+=(--input-root "$results")
      done < <(find "$OUTPUT_ROOT" -maxdepth 3 -type d -name results 2>/dev/null | sort)
      if [ "${#inputs[@]}" -eq 0 ]; then
        echo "[all] liboqs: no result directories under $OUTPUT_ROOT; nothing to report"
        return 0
      fi
      python3 src/reporting/write_report.py \
        "${inputs[@]}" \
        --output-root "$OUTPUT_ROOT" \
        --formats json,tsv \
        --trace-mode exemplar \
        --findings-mode fast-summary
      ;;
    *)
      die "unsupported liboqs command $command"
      ;;
  esac
}

run_aigis_suite() {
  local command="$1"
  case "$command" in
    build)
      run_aigis_env build
      ;;
    preflight)
      run_aigis_env preflight
      ;;
    smoke)
      echo "[all] aigis: smoke (${SMOKE_FUZZ_SECONDS}s)"
      MAX_TOTAL_TIME="$SMOKE_FUZZ_SECONDS" run_aigis_env run
      ;;
    run)
      run_aigis_env run
      ;;
    report)
      echo "[all] aigis: report"
      mkdir -p "$ALL_ROOT/report"
      if ! compgen -G "workspace/results/job_aigis*" > /dev/null; then
        echo "[all] aigis: no aigis results yet; skipping report"
        return 0
      fi
      if [ -f scripts/pqcfuzz_aigis_report.py ]; then
        python3 scripts/pqcfuzz_aigis_report.py --out "$ALL_ROOT/report/aigis_summary.md"
      else
        echo "[all] aigis: report script missing; skipping"
      fi
      ;;
    *)
      die "unsupported aigis command $command"
      ;;
  esac
}

run_aigis_env() {
  echo "[all] aigis: $1"
  env \
    ORACLE_SUITE="$ORACLE_SUITE" \
    ORACLE_SET="$ORACLE_SET" \
    MAX_TOTAL_TIME="$MAX_TOTAL_TIME" \
    bash scripts/pqcfuzz_aigis_eval.sh "$1"
}

write_aggregate_report() {
  mkdir -p "$ALL_ROOT/report"
  python3 - "$ALL_ROOT/report/summary.json" "$OUTPUT_ROOT" "$ALL_ROOT" "${PARSED_SUITES[@]}" <<'PY'
import json
import os
import sys
from pathlib import Path

out_path, liboqs_root, all_root = sys.argv[1:4]
suites = sys.argv[4:]
family_roots = {
    "cross": "workspace/cross",
    "falcon": "workspace/falcon",
    "ntru": "workspace/ntru",
    "sike_sidh": "workspace/sike_sidh",
    "snova": "workspace/snova",
}
aggregate = {
    "driver": "scripts/pqcfuzz_all_eval.sh",
    "suites": suites,
    "claims": "conformance, differential and counterexample search only; no security proof is claimed",
    "lanes": {},
}
total_findings = 0
for suite in suites:
    entry = {"report": None, "findings": None, "status": "no_report"}
    candidates = []
    if suite in family_roots:
        candidates.append(Path(family_roots[suite]) / "report" / "summary.json")
    elif suite == "liboqs":
        candidates.append(Path(liboqs_root) / "summary.json")
    elif suite == "aigis":
        aggregate["lanes"][suite] = {
            "report": str(Path(all_root) / "report" / "aigis_summary.md"),
            "findings": None,
            "status": "markdown",
        }
        continue
    for candidate in candidates:
        if candidate.is_file():
            entry["report"] = str(candidate)
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                entry["status"] = "unreadable"
                break
            findings = payload.get("total_finding_records")
            if findings is None:
                by_oracle = payload.get("findings_by_oracle")
                if isinstance(by_oracle, dict):
                    findings = sum(
                        value for value in by_oracle.values() if isinstance(value, int)
                    )
            if findings is not None:
                entry["findings"] = findings
                total_findings += findings
            entry["status"] = "ok"
            break
    aggregate["lanes"][suite] = entry
aggregate["total_findings"] = total_findings
Path(out_path).parent.mkdir(parents=True, exist_ok=True)
Path(out_path).write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"[all] aggregate report: {out_path}")
PY
}

command_is_valid() {
  case "$1" in
    build|preflight|smoke|run|report|all) return 0 ;;
    *) return 1 ;;
  esac
}

main() {
  local command="${1:-all}"
  shift 2>/dev/null || true
  case "$command" in
    -h|--help|help)
      usage
      exit 0
      ;;
  esac
  command_is_valid "$command" || die "unknown command '$command' (use build|preflight|smoke|run|report|all)"
  parse_suites "${1:-}"

  local -a steps
  case "$command" in
    all) steps=(build preflight smoke run report) ;;
    *) steps=("$command") ;;
  esac

  local step suite status=0
  for step in "${steps[@]}"; do
    for suite in "${PARSED_SUITES[@]}"; do
      set +e
      case "$suite" in
        liboqs) run_liboqs_suite "$step" ;;
        aigis) run_aigis_suite "$step" ;;
        *) run_family_suite "$suite" "$step" ;;
      esac
      local rc=$?
      set -e
      if [ "$rc" -ne 0 ]; then
        echo "[all] ${suite} ${step} failed with status ${rc}" >&2
        status=1
        if [ "${ALL_CONTINUE_ON_ERROR:-0}" != "1" ]; then
          echo "[all] stopping (set ALL_CONTINUE_ON_ERROR=1 to continue)" >&2
          exit "$status"
        fi
      fi
    done
    if [ "$step" = "report" ]; then
      write_aggregate_report
    fi
  done
  exit "$status"
}

main "$@"
