#!/usr/bin/env bash
set -euo pipefail

if [ -z "${PQCDF_EVAL_BASELINES_SNAPSHOT_ACTIVE:-}" ]; then
  ORIGINAL_SCRIPT="${BASH_SOURCE[0]}"
  ORIGINAL_ROOT="${PQCDF_ROOT_DIR:-$(cd "$(dirname "$ORIGINAL_SCRIPT")/.." && pwd)}"
  SNAPSHOT_PARENT="${TMPDIR:-/tmp}/pqcdf-eval-baselines-${USER:-user}-$$"
  SNAPSHOT_SCRIPT="${SNAPSHOT_PARENT}/eval_baselines_fuzzing.sh"
  mkdir -p "$SNAPSHOT_PARENT"
  cp "$ORIGINAL_SCRIPT" "$SNAPSHOT_SCRIPT"
  chmod +x "$SNAPSHOT_SCRIPT"
  export PQCDF_EVAL_BASELINES_SNAPSHOT_ACTIVE=1
  export PQCDF_EVAL_BASELINES_SNAPSHOT_FILE="$SNAPSHOT_SCRIPT"
  export PQCDF_ROOT_DIR="$ORIGINAL_ROOT"
  exec bash "$SNAPSHOT_SCRIPT" "$@"
fi

usage() {
  cat <<'EOF'
Usage:
  scripts/eval_baselines_fuzzing.sh [options]

Options:
  --fuzzing-time DURATION       Wall-clock budget for each campaign. Default: 24h.
                                Accepts seconds or s/m/h/d suffixes, e.g. 86400, 60m, 24h.
  --progress-interval SECONDS   Seconds between progress reports. Default: 3600.
  --session-prefix NAME         Prefix for tmux session names. Default: pqcdf.
  --result-save-mode compact|all
                                Result retention policy. Default: compact.
  --campaign BASELINE-VERSION   Run only one campaign. May be repeated.
                                Example: --campaign libFuzzer-0.14.0
  --summarize-only              Regenerate summaries from existing campaign status files.
  --dry-run                     Print the sessions and commands without starting tmux.
  -h, --help                    Show this help.

This launches and waits for 12 tmux sessions:
  baselines: libFuzzer, cryptofuzz, CLFuzz, cryptoTesting
  versions:  0.14.0, 0.8.0, 0.4.0

Outputs are written under:
  workspace/baselines_eval/
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

parse_duration_seconds() {
  local raw="$1"
  local value multiplier

  raw="${raw,,}"

  if [[ "$raw" =~ ^([0-9]+)[[:space:]]*$ ]]; then
    value="${BASH_REMATCH[1]}"
    multiplier=1
  elif [[ "$raw" =~ ^([0-9]+)[[:space:]]*(s|sec|secs|second|seconds)[[:space:]]*$ ]]; then
    value="${BASH_REMATCH[1]}"
    multiplier=1
  elif [[ "$raw" =~ ^([0-9]+)[[:space:]]*(m|min|mins|minute|minutes)[[:space:]]*$ ]]; then
    value="${BASH_REMATCH[1]}"
    multiplier=60
  elif [[ "$raw" =~ ^([0-9]+)[[:space:]]*(h|hr|hrs|hour|hours)[[:space:]]*$ ]]; then
    value="${BASH_REMATCH[1]}"
    multiplier=3600
  elif [[ "$raw" =~ ^([0-9]+)[[:space:]]*(d|day|days)[[:space:]]*$ ]]; then
    value="${BASH_REMATCH[1]}"
    multiplier=86400
  else
    die "invalid duration '$1'"
  fi

  if [ "$value" -le 0 ]; then
    die "duration must be positive"
  fi

  echo $((value * multiplier))
}

validate_session_prefix() {
  local prefix="$1"
  if [[ ! "$prefix" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
    die "--session-prefix must match [A-Za-z0-9][A-Za-z0-9_.-]*"
  fi
}

format_elapsed() {
  local seconds="$1"
  local hours minutes
  hours=$((seconds / 3600))
  minutes=$(((seconds % 3600) / 60))
  seconds=$((seconds % 60))
  printf "%02d:%02d:%02d" "$hours" "$minutes" "$seconds"
}

print_campaign_commands() {
  local baseline="$1"
  local version="$2"
  local seconds="$3"
  local kem_seconds="$4"
  local sig_seconds="$5"
  local result_save_mode="$6"

  echo "scripts/run_baseline.sh $baseline docker-build"
  case "$baseline" in
    libFuzzer)
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> scripts/run_baseline.sh libFuzzer build --version $version"
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> scripts/run_baseline.sh libFuzzer run --profile semantic --version $version --target kem --mode full --max-total-time $kem_seconds"
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> scripts/run_baseline.sh libFuzzer run --profile semantic --version $version --target sig --mode full --max-total-time $sig_seconds"
      ;;
    cryptofuzz|CLFuzz)
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> scripts/run_baseline.sh $baseline build --version $version"
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> scripts/run_baseline.sh $baseline run --version $version --mode full --max-total-time $seconds"
      ;;
    cryptoTesting)
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> CRYPTO_TESTING_WORKERS=1 scripts/run_baseline.sh cryptoTesting run --version $version --mode functional --workers 1 --max-total-time $seconds --skip-core-pattern-check"
      ;;
    *)
      die "unknown baseline '$baseline'"
      ;;
  esac

  if [ "$result_save_mode" = "compact" ]; then
    echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> python3 scripts/compact_baseline_results.py --workspace-root <campaign-workspace> --baseline $baseline --version $version --mode compact"
  fi
}

hash_file() {
  python3 - "$1" <<'PY'
import hashlib
import sys
from pathlib import Path

path = Path(sys.argv[1])
h = hashlib.sha256()
with path.open("rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
print(h.hexdigest())
PY
}

write_parent_status() {
  local status_file="$1"
  local campaign="$2"
  local baseline="$3"
  local version="$4"
  local session_name="$5"
  local workspace_root_rel="$6"
  local workspace_root_abs="$7"
  local log_file="$8"
  local launcher_file="$9"
  local phase="${10}"
  local state="${11}"
  local result="${12}"
  local final_status="${13}"

  EVAL_STATUS_FILE="$status_file" \
  EVAL_CAMPAIGN="$campaign" \
  EVAL_BASELINE="$baseline" \
  EVAL_VERSION="$version" \
  EVAL_SESSION_NAME="$session_name" \
  EVAL_WORKSPACE_ROOT="$workspace_root_rel" \
  EVAL_WORKSPACE_ROOT_ABS="$workspace_root_abs" \
  EVAL_LOG_FILE="$log_file" \
  EVAL_LAUNCHER_FILE="$launcher_file" \
  EVAL_PHASE="$phase" \
  EVAL_STATE="$state" \
  EVAL_RESULT="$result" \
  EVAL_FINAL_STATUS="$final_status" \
  EVAL_REPO_COMMIT="$REPO_COMMIT" \
  EVAL_SCRIPT_SNAPSHOT="$RUNNER_SNAPSHOT_DIR_REL" \
  EVAL_SCRIPT_SNAPSHOT_HASH="$RUNNER_SNAPSHOT_HASH" \
  EVAL_RESULT_SAVE_MODE="$RESULT_SAVE_MODE" \
  python3 - <<'PY'
import json
import os
import tempfile
import time
from datetime import datetime, timezone

def int_or_none(value):
    if value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return value

path = os.environ["EVAL_STATUS_FILE"]
os.makedirs(os.path.dirname(path), exist_ok=True)
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
now_epoch = int(time.time())

doc = {}
if os.path.exists(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except json.JSONDecodeError:
        doc = {}

if "queued_at" not in doc:
    doc["queued_at"] = now
if "start_epoch" not in doc:
    doc["start_epoch"] = now_epoch

doc.update({
    "campaign": os.environ["EVAL_CAMPAIGN"],
    "baseline": os.environ["EVAL_BASELINE"],
    "fuzzer_mode": "functional" if os.environ["EVAL_BASELINE"] == "cryptoTesting" else None,
    "baseline_label": "cryptoTesting-functional" if os.environ["EVAL_BASELINE"] == "cryptoTesting" else os.environ["EVAL_BASELINE"],
    "version": os.environ["EVAL_VERSION"],
    "session_name": os.environ["EVAL_SESSION_NAME"],
    "workspace_root": os.environ["EVAL_WORKSPACE_ROOT"],
    "workspace_root_abs": os.environ["EVAL_WORKSPACE_ROOT_ABS"],
    "log": os.environ["EVAL_LOG_FILE"],
    "launcher": os.environ["EVAL_LAUNCHER_FILE"],
    "phase": os.environ["EVAL_PHASE"],
    "state": os.environ["EVAL_STATE"],
    "updated_at": now,
    "repo_commit": os.environ["EVAL_REPO_COMMIT"],
    "script_snapshot": os.environ["EVAL_SCRIPT_SNAPSHOT"],
    "script_snapshot_hash": os.environ["EVAL_SCRIPT_SNAPSHOT_HASH"],
    "result": os.environ["EVAL_RESULT"] or None,
    "final_status": int_or_none(os.environ["EVAL_FINAL_STATUS"]),
    "result_save_mode": os.environ["EVAL_RESULT_SAVE_MODE"],
})

if os.environ["EVAL_STATE"] == "finished" and "ended_at" not in doc:
    doc["ended_at"] = now
if doc.get("start_epoch") is not None:
    doc["elapsed_seconds"] = now_epoch - int(doc["start_epoch"])

fd, tmp = tempfile.mkstemp(prefix=".status.", dir=os.path.dirname(path))
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
os.replace(tmp, path)
PY
}

create_runner_snapshot() {
  RUNNER_SNAPSHOT_DIR_REL="${EVAL_ROOT_REL}/script_snapshot"
  RUNNER_SNAPSHOT_DIR="${ROOT_DIR}/${RUNNER_SNAPSHOT_DIR_REL}"
  RUNNER_SNAPSHOT_SCRIPTS_DIR="${RUNNER_SNAPSHOT_DIR}/scripts"
  RUNNER_SNAPSHOT_BASELINES_DIR="${RUNNER_SNAPSHOT_SCRIPTS_DIR}/baselines"
  RUNNER_SNAPSHOT_RUN_BASELINE="${RUNNER_SNAPSHOT_SCRIPTS_DIR}/run_baseline.sh"
  RUNNER_SNAPSHOT_COMPACTOR="${RUNNER_SNAPSHOT_SCRIPTS_DIR}/compact_baseline_results.py"
  RUNNER_SNAPSHOT_EVAL="${RUNNER_SNAPSHOT_SCRIPTS_DIR}/eval_baselines_fuzzing.sh"
  RUNNER_SNAPSHOT_BASELINES_DIR_REL="${RUNNER_SNAPSHOT_DIR_REL}/scripts/baselines"
  RUNNER_SNAPSHOT_RUN_BASELINE_REL="${RUNNER_SNAPSHOT_DIR_REL}/scripts/run_baseline.sh"
  RUNNER_SNAPSHOT_COMPACTOR_REL="${RUNNER_SNAPSHOT_DIR_REL}/scripts/compact_baseline_results.py"

  mkdir -p "$RUNNER_SNAPSHOT_BASELINES_DIR"
  cp -p "${PQCDF_EVAL_BASELINES_SNAPSHOT_FILE:-${ROOT_DIR}/scripts/eval_baselines_fuzzing.sh}" "$RUNNER_SNAPSHOT_EVAL"
  cp -p "${ROOT_DIR}/scripts/run_baseline.sh" "$RUNNER_SNAPSHOT_RUN_BASELINE"
  if [ -f "${ROOT_DIR}/scripts/compact_baseline_results.py" ]; then
    cp -p "${ROOT_DIR}/scripts/compact_baseline_results.py" "$RUNNER_SNAPSHOT_COMPACTOR"
  fi

  local baseline wrapper
  for baseline in "${BASELINES[@]}"; do
    mkdir -p "${RUNNER_SNAPSHOT_BASELINES_DIR}/${baseline}"
    for wrapper in build run; do
      if [ -f "${ROOT_DIR}/scripts/baselines/${baseline}/${wrapper}.sh" ]; then
        cp -p "${ROOT_DIR}/scripts/baselines/${baseline}/${wrapper}.sh" \
          "${RUNNER_SNAPSHOT_BASELINES_DIR}/${baseline}/${wrapper}.sh"
      fi
    done
  done

  find "$RUNNER_SNAPSHOT_SCRIPTS_DIR" -type f -name '*.sh' -exec chmod +x {} +
  RUNNER_SNAPSHOT_HASH="$(hash_file "$RUNNER_SNAPSHOT_EVAL")"
}

write_launcher() {
  local launcher_file="$1"
  local baseline="$2"
  local version="$3"
  local campaign="$4"
  local session_name="$5"
  local workspace_root_rel="$6"
  local workspace_root_abs="$7"
  local log_file="$8"
  local status_file="$9"
  local seconds="${10}"
  local kem_seconds="${11}"
  local sig_seconds="${12}"
  local result_save_mode="${13}"
  local run_baseline_script="${14}"
  local compactor_script="${15}"
  local baseline_wrapper_root="${16}"
  local script_snapshot_dir="${17}"
  local script_snapshot_hash="${18}"
  local repo_commit="${19}"

  {
    printf '#!/usr/bin/env bash\n'
    printf 'set +e +u +o pipefail\n\n'
    printf 'cd %q || exit 1\n\n' "$ROOT_DIR"
    printf 'BASELINE=%q\n' "$baseline"
    printf 'VERSION=%q\n' "$version"
    printf 'CAMPAIGN=%q\n' "$campaign"
    printf 'SESSION_NAME=%q\n' "$session_name"
    printf 'WORKSPACE_ROOT_REL=%q\n' "$workspace_root_rel"
    printf 'WORKSPACE_ROOT_ABS=%q\n' "$workspace_root_abs"
    printf 'LOG_FILE=%q\n' "$log_file"
    printf 'STATUS_FILE=%q\n' "$status_file"
    printf 'FUZZING_SECONDS=%q\n' "$seconds"
    printf 'KEM_SECONDS=%q\n' "$kem_seconds"
    printf 'SIG_SECONDS=%q\n' "$sig_seconds"
    printf 'RESULT_SAVE_MODE=%q\n' "$result_save_mode"
    printf 'RUN_BASELINE_SCRIPT=%q\n' "$run_baseline_script"
    printf 'COMPACTOR_SCRIPT=%q\n' "$compactor_script"
    printf 'BASELINE_WRAPPER_ROOT=%q\n' "$baseline_wrapper_root"
    printf 'SCRIPT_SNAPSHOT_DIR=%q\n' "$script_snapshot_dir"
    printf 'SCRIPT_SNAPSHOT_HASH=%q\n' "$script_snapshot_hash"
    printf 'REPO_COMMIT=%q\n' "$repo_commit"
    printf 'LAUNCHER_FILE=%q\n\n' "$launcher_file"
    cat <<'EOF'
mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$STATUS_FILE")" "$WORKSPACE_ROOT_REL"
: > "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

START_EPOCH="$(date +%s)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DOCKER_BUILD_STATUS=""
TARGET_BUILD_STATUS=""
FUZZ_STATUS=""
KEM_STATUS=""
SIG_STATUS=""
COMPACTION_STATUS=""
COMPACTION_MANIFEST=""
COMPACTION_ELIGIBLE=0
FINAL_STATUS=""
RESULT=""
ENDED_AT=""
FINISHED=0

write_status() {
  local phase="$1"
  local state="$2"

  EVAL_STATUS_FILE="$STATUS_FILE" \
  EVAL_CAMPAIGN="$CAMPAIGN" \
  EVAL_BASELINE="$BASELINE" \
  EVAL_VERSION="$VERSION" \
  EVAL_SESSION_NAME="$SESSION_NAME" \
  EVAL_WORKSPACE_ROOT="$WORKSPACE_ROOT_REL" \
  EVAL_WORKSPACE_ROOT_ABS="$WORKSPACE_ROOT_ABS" \
  EVAL_LOG_FILE="$LOG_FILE" \
  EVAL_LAUNCHER_FILE="$LAUNCHER_FILE" \
  EVAL_PHASE="$phase" \
  EVAL_STATE="$state" \
  EVAL_STARTED_AT="$STARTED_AT" \
  EVAL_START_EPOCH="$START_EPOCH" \
  EVAL_ENDED_AT="$ENDED_AT" \
  EVAL_DOCKER_BUILD_STATUS="$DOCKER_BUILD_STATUS" \
  EVAL_TARGET_BUILD_STATUS="$TARGET_BUILD_STATUS" \
  EVAL_FUZZ_STATUS="$FUZZ_STATUS" \
  EVAL_KEM_STATUS="$KEM_STATUS" \
  EVAL_SIG_STATUS="$SIG_STATUS" \
  EVAL_COMPACTION_STATUS="$COMPACTION_STATUS" \
  EVAL_COMPACTION_MANIFEST="$COMPACTION_MANIFEST" \
  EVAL_FINAL_STATUS="$FINAL_STATUS" \
  EVAL_RESULT="$RESULT" \
  EVAL_RESULT_SAVE_MODE="$RESULT_SAVE_MODE" \
  EVAL_REPO_COMMIT="$REPO_COMMIT" \
  EVAL_SCRIPT_SNAPSHOT="$SCRIPT_SNAPSHOT_DIR" \
  EVAL_SCRIPT_SNAPSHOT_HASH="$SCRIPT_SNAPSHOT_HASH" \
  python3 - <<'PY'
import json
import os
import tempfile
import time
from datetime import datetime, timezone

def int_or_none(value):
    if value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return value

path = os.environ["EVAL_STATUS_FILE"]
os.makedirs(os.path.dirname(path), exist_ok=True)
start_epoch = int(os.environ["EVAL_START_EPOCH"])
now = int(time.time())

doc = {}
if os.path.exists(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except json.JSONDecodeError:
        doc = {}

doc.update({
    "campaign": os.environ["EVAL_CAMPAIGN"],
    "baseline": os.environ["EVAL_BASELINE"],
    "fuzzer_mode": "functional" if os.environ["EVAL_BASELINE"] == "cryptoTesting" else None,
    "baseline_label": "cryptoTesting-functional" if os.environ["EVAL_BASELINE"] == "cryptoTesting" else os.environ["EVAL_BASELINE"],
    "version": os.environ["EVAL_VERSION"],
    "session_name": os.environ["EVAL_SESSION_NAME"],
    "workspace_root": os.environ["EVAL_WORKSPACE_ROOT"],
    "workspace_root_abs": os.environ["EVAL_WORKSPACE_ROOT_ABS"],
    "log": os.environ["EVAL_LOG_FILE"],
    "launcher": os.environ["EVAL_LAUNCHER_FILE"],
    "phase": os.environ["EVAL_PHASE"],
    "state": os.environ["EVAL_STATE"],
    "started_at": os.environ["EVAL_STARTED_AT"],
    "start_epoch": start_epoch,
    "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "elapsed_seconds": now - start_epoch,
    "docker_build_status": int_or_none(os.environ["EVAL_DOCKER_BUILD_STATUS"]),
    "target_build_status": int_or_none(os.environ["EVAL_TARGET_BUILD_STATUS"]),
    "fuzz_status": int_or_none(os.environ["EVAL_FUZZ_STATUS"]),
    "kem_status": int_or_none(os.environ["EVAL_KEM_STATUS"]),
    "sig_status": int_or_none(os.environ["EVAL_SIG_STATUS"]),
    "compaction_status": int_or_none(os.environ["EVAL_COMPACTION_STATUS"]),
    "compaction_manifest": os.environ["EVAL_COMPACTION_MANIFEST"] or None,
    "final_status": int_or_none(os.environ["EVAL_FINAL_STATUS"]),
    "result": os.environ["EVAL_RESULT"] or None,
    "result_save_mode": os.environ["EVAL_RESULT_SAVE_MODE"],
    "repo_commit": os.environ["EVAL_REPO_COMMIT"],
    "script_snapshot": os.environ["EVAL_SCRIPT_SNAPSHOT"],
    "script_snapshot_hash": os.environ["EVAL_SCRIPT_SNAPSHOT_HASH"],
})
if os.environ["EVAL_ENDED_AT"]:
    doc["ended_at"] = os.environ["EVAL_ENDED_AT"]

fd, tmp = tempfile.mkstemp(prefix=".status.", dir=os.path.dirname(path))
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
os.replace(tmp, path)
PY
}

unexpected_exit() {
  local status="$?"
  if [ "$FINISHED" != "1" ]; then
    if [ "$status" -eq 0 ]; then
      status=1
    fi
    RESULT="launcher-exited-unexpectedly"
    FINAL_STATUS="$status"
    ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    write_status "finished" "finished" || true
  fi
}
trap unexpected_exit EXIT

finish_campaign() {
  RESULT="$1"
  FINAL_STATUS="$2"

  # Do not turn a pre-run cryptoTesting failure into a second compaction
  # failure: no raw result tree means there is nothing to retain yet.
  if [ "$BASELINE" = "cryptoTesting" ] && [ "$COMPACTION_ELIGIBLE" = "1" ] && \
     [ ! -f "${WORKSPACE_ROOT_REL}/cryptoTesting/targets-run/raw/cryptoTesting-${VERSION}/functional/manifest.json" ]; then
    COMPACTION_ELIGIBLE=0
  fi

  if [ "$RESULT_SAVE_MODE" = "compact" ]; then
    COMPACTION_MANIFEST="${WORKSPACE_ROOT_REL}/${BASELINE}/compaction_manifest.json"
    if [ "$COMPACTION_ELIGIBLE" = "1" ]; then
      write_status "compact-results" "running"
      run_step python3 "$COMPACTOR_SCRIPT" \
        --workspace-root "$WORKSPACE_ROOT_REL" \
        --baseline "$BASELINE" \
        --version "$VERSION" \
        --mode compact
    else
      write_status "compact-results" "skipped"
      run_step python3 "$COMPACTOR_SCRIPT" \
        --workspace-root "$WORKSPACE_ROOT_REL" \
        --baseline "$BASELINE" \
        --version "$VERSION" \
        --mode compact \
        --skip-reason "campaign did not reach result-producing phase"
    fi
    COMPACTION_STATUS="$?"
    echo "[eval] compaction exited with status $COMPACTION_STATUS"
    if [ "$COMPACTION_STATUS" -ne 0 ] && [ "$FINAL_STATUS" -eq 0 ]; then
      RESULT="compaction-failed"
      FINAL_STATUS="$COMPACTION_STATUS"
    fi
  fi

  ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  write_status "finished" "finished"
  echo
  echo "[eval] ended: $ENDED_AT"
  echo "[eval] elapsed: $(( $(date +%s) - START_EPOCH ))s"
  echo "[eval] result: $RESULT"
  echo "[eval] final status: $FINAL_STATUS"
  FINISHED=1
  exit "$FINAL_STATUS"
}

run_step() {
  echo "[eval] command: $*"
  "$@"
  return $?
}

single_style_campaign_outcome() {
  local baseline="$1"
  local summary_file="${WORKSPACE_ROOT_REL}/${baseline}/targets-run/liboqs-${VERSION}/summary.json"
  if [ "$baseline" = "CLFuzz" ]; then
    summary_file="${WORKSPACE_ROOT_REL}/${baseline}/targets-run/liboqs-${VERSION}/full/summary.json"
  fi

  python3 - "$summary_file" <<'PY'
import json
import sys
from pathlib import Path


def count(value, paths):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return len(paths) if isinstance(paths, list) else 0


def outcome(document):
    for key in ("outcome", "status"):
        value = document.get(key)
        if value in {
            "completed", "completed-with-findings", "target-crash", "timed-out",
            "harness-error", "infrastructure-failed", "sanitizer-report", "completed-with-coverage-gap",
        }:
            return value
    if count(document.get("semantic_finding_count"), document.get("semantic_findings")) > 0:
        return "completed-with-findings"
    normalized = document.get("normalized_outcome")
    return {
        "ok": "completed",
        "invariant_violation": "completed-with-findings",
        "coverage_incomplete": "completed-with-coverage-gap",
        "process_crash": "target-crash",
        "process_hang": "timed-out",
        "operation_error": "harness-error",
    }.get(normalized, "unknown")


try:
    with Path(sys.argv[1]).open(encoding="utf-8") as f:
        document = json.load(f)
except (OSError, json.JSONDecodeError):
    document = {}

print(outcome(document) if isinstance(document, dict) else "unknown")
PY
}

crypto_testing_campaign_outcome() {
  local summary_file="${WORKSPACE_ROOT_REL}/cryptoTesting/targets-run/raw/cryptoTesting-${VERSION}/functional/summary.json"

  python3 - "$summary_file" <<'PY'
import json
import sys
from pathlib import Path

try:
    document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    document = {}

status = document.get("status") if isinstance(document, dict) else None
print(status if status in {"completed", "completed-at-budget-incomplete", "timed-out-partial", "harness-error"} else "unknown")
PY
}

export PQCDF_WORKSPACE_ROOT="$WORKSPACE_ROOT_REL"
export PQCDF_BASELINE_WRAPPER_ROOT="$BASELINE_WRAPPER_ROOT"

echo "[eval] session: $SESSION_NAME"
echo "[eval] campaign: $CAMPAIGN"
echo "[eval] baseline: $BASELINE"
echo "[eval] liboqs version: $VERSION"
echo "[eval] fuzzing time: ${FUZZING_SECONDS}s"
echo "[eval] result save mode: $RESULT_SAVE_MODE"
echo "[eval] workspace root: $WORKSPACE_ROOT_REL"
echo "[eval] started: $STARTED_AT"
echo "[eval] log: $LOG_FILE"
echo "[eval] status: $STATUS_FILE"
echo
write_status "launcher-started" "running"

write_status "docker-build" "running"
run_step "$RUN_BASELINE_SCRIPT" "$BASELINE" docker-build
DOCKER_BUILD_STATUS="$?"
echo "[eval] docker-build exited with status $DOCKER_BUILD_STATUS"
if [ "$DOCKER_BUILD_STATUS" -ne 0 ]; then
  finish_campaign "docker-build-failed" "$DOCKER_BUILD_STATUS"
fi

case "$BASELINE" in
  libFuzzer|cryptofuzz|CLFuzz)
    write_status "target-build" "running"
    run_step "$RUN_BASELINE_SCRIPT" "$BASELINE" build --version "$VERSION"
    TARGET_BUILD_STATUS="$?"
    echo "[eval] target-build exited with status $TARGET_BUILD_STATUS"
    if [ "$TARGET_BUILD_STATUS" -ne 0 ]; then
      finish_campaign "target-build-failed" "$TARGET_BUILD_STATUS"
    fi
    ;;
  cryptoTesting)
    TARGET_BUILD_STATUS=""
    ;;
  *)
    finish_campaign "unknown-baseline" 2
    ;;
esac

case "$BASELINE" in
  libFuzzer)
    COMPACTION_ELIGIBLE=1
    write_status "run-kem" "running"
    run_step "$RUN_BASELINE_SCRIPT" libFuzzer run --profile semantic --version "$VERSION" --target kem --mode full --max-total-time "$KEM_SECONDS"
    KEM_STATUS="$?"
    echo "[eval] libFuzzer kem exited with status $KEM_STATUS"
    echo

    write_status "run-sig" "running"
    run_step "$RUN_BASELINE_SCRIPT" libFuzzer run --profile semantic --version "$VERSION" --target sig --mode full --max-total-time "$SIG_SECONDS"
    SIG_STATUS="$?"
    echo "[eval] libFuzzer sig exited with status $SIG_STATUS"

    if [ "$KEM_STATUS" -ne 0 ]; then
      FUZZ_STATUS="$KEM_STATUS"
    else
      FUZZ_STATUS="$SIG_STATUS"
    fi
    ;;

  cryptofuzz)
    COMPACTION_ELIGIBLE=1
    write_status "run" "running"
    run_step "$RUN_BASELINE_SCRIPT" cryptofuzz run --version "$VERSION" --mode full --max-total-time "$FUZZING_SECONDS"
    FUZZ_STATUS="$?"
    ;;

  CLFuzz)
    COMPACTION_ELIGIBLE=1
    write_status "run" "running"
    run_step "$RUN_BASELINE_SCRIPT" CLFuzz run --version "$VERSION" --mode full --profile full --max-total-time "$FUZZING_SECONDS"
    FUZZ_STATUS="$?"
    ;;

  cryptoTesting)
    COMPACTION_ELIGIBLE=1
    write_status "run" "running"
    echo "[eval] command: CRYPTO_TESTING_WORKERS=1 $RUN_BASELINE_SCRIPT cryptoTesting run --version $VERSION --mode functional --workers 1 --max-total-time $FUZZING_SECONDS --skip-core-pattern-check"
    CRYPTO_TESTING_WORKERS=1 "$RUN_BASELINE_SCRIPT" cryptoTesting run --version "$VERSION" --mode functional --workers 1 --max-total-time "$FUZZING_SECONDS" --skip-core-pattern-check
    FUZZ_STATUS="$?"
    ;;
esac

echo "[eval] fuzzing exited with status $FUZZ_STATUS"
CAMPAIGN_OUTCOME=""
if [ "$BASELINE" = "cryptofuzz" ] || [ "$BASELINE" = "CLFuzz" ]; then
  CAMPAIGN_OUTCOME="$(single_style_campaign_outcome "$BASELINE")"
  echo "[eval] ${BASELINE} outcome: $CAMPAIGN_OUTCOME"
elif [ "$BASELINE" = "cryptoTesting" ]; then
  CAMPAIGN_OUTCOME="$(crypto_testing_campaign_outcome)"
  echo "[eval] cryptoTesting outcome: $CAMPAIGN_OUTCOME"
fi
if [ "$FUZZ_STATUS" -ne 0 ]; then
  case "$CAMPAIGN_OUTCOME" in
    target-crash|timed-out|harness-error|infrastructure-failed|sanitizer-report)
      finish_campaign "$CAMPAIGN_OUTCOME" "$FUZZ_STATUS"
      ;;
  esac
  finish_campaign "fuzzing-failed" "$FUZZ_STATUS"
fi

if [ "$CAMPAIGN_OUTCOME" = "completed-with-findings" ]; then
  finish_campaign "completed-with-findings" 0
fi
if [ "$CAMPAIGN_OUTCOME" = "completed-with-coverage-gap" ]; then
  finish_campaign "completed-with-coverage-gap" 0
fi
if [ "$CAMPAIGN_OUTCOME" = "completed-at-budget-incomplete" ]; then
  finish_campaign "completed-at-budget-incomplete" 0
fi

finish_campaign "completed" 0
EOF
  } > "$launcher_file"

  chmod +x "$launcher_file"
}

read_status_fields() {
  local status_file="$1"
  if [ ! -f "$status_file" ]; then
    printf 'pending\tpending\t0\t-\n'
    return
  fi

  python3 - "$status_file" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print("unknown\tunknown\t0\t-")
    raise SystemExit

print(
    f"{data.get('phase') or '-'}\t"
    f"{data.get('state') or '-'}\t"
    f"{data.get('elapsed_seconds') or 0}\t"
    f"{data.get('result') or '-'}"
)
PY
}

print_progress() {
  local now="$1"
  local id status_file session phase state elapsed result tmux_state fields

  echo
  echo "[eval] progress: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%-24s %-14s %-10s %-6s %-18s\n' "campaign" "phase" "elapsed" "tmux" "status"
  printf '%-24s %-14s %-10s %-6s %-18s\n' "--------" "-----" "-------" "----" "------"

  for id in "${CAMPAIGN_IDS[@]}"; do
    status_file="${STATUS_FILE_BY_ID[$id]}"
    session="${SESSION_BY_ID[$id]}"
    fields="$(read_status_fields "$status_file")"
    IFS=$'\t' read -r phase state elapsed result <<<"$fields"

    if tmux has-session -t "=${session}" 2>/dev/null; then
      tmux_state="alive"
    else
      tmux_state="dead"
    fi

    if { [ "$state" = "pending" ] || [ "$state" = "queued" ]; } && [ "$tmux_state" = "alive" ]; then
      phase="starting"
      state="running"
      elapsed=0
    elif [ "$state" != "finished" ] && [ "$tmux_state" = "dead" ]; then
      if [ "$result" != "-" ]; then
        state="$result"
      else
        state="launcher-exited-no-status"
      fi
    elif [ "$state" = "finished" ]; then
      state="$result"
    fi

    printf '%-24s %-14s %-10s %-6s %-18s\n' \
      "$id" "$phase" "$(format_elapsed "$elapsed")" "$tmux_state" "$state"
  done
  echo "[eval] next progress report in ${PROGRESS_INTERVAL}s"
}

write_final_summary() {
  python3 - "$INDEX_FILE" "$SUMMARY_JSON" "$SUMMARY_TSV" "$FUZZING_SECONDS" "$RESULT_SAVE_MODE" <<'PY'
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

index_file = Path(sys.argv[1])
summary_json = Path(sys.argv[2])
summary_tsv = Path(sys.argv[3])
fuzzing_seconds = int(sys.argv[4])
result_save_mode = sys.argv[5]

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def rel(path):
    try:
        return os.path.relpath(path)
    except ValueError:
        return str(path)

def artifact_counts(run_root):
    counts = {"crash": 0, "timeout": 0, "leak": 0, "oom": 0, "hang": 0}
    if not run_root.is_dir():
        return counts
    for path in run_root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name
        for prefix in counts:
            if name.startswith(prefix + "-"):
                counts[prefix] += 1
                break
        else:
            parts = set(path.parts)
            if "artifacts" in parts and "crashes" in parts and name != "README.txt":
                counts["crash"] += 1
            elif "artifacts" in parts and "hangs" in parts and name != "README.txt":
                counts["hang"] += 1
    return counts

def nonnegative_int(value):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None

def evidence_count(document, count_keys, path_keys):
    if not isinstance(document, dict):
        return 0
    for key in count_keys:
        value = nonnegative_int(document.get(key))
        if value is not None:
            return value
    for key in path_keys:
        value = document.get(key)
        if isinstance(value, list):
            return len(value)
    return 0

def selected_summary(document):
    """Return one campaign-level record without double-counting nested profiles."""
    if not isinstance(document, dict):
        return {}
    profiles = document.get("profiles")
    if isinstance(profiles, dict):
        for name in ("semantic", document.get("latest_profile")):
            record = profiles.get(name)
            if isinstance(record, dict):
                return record
        if len(profiles) == 1:
            record = next(iter(profiles.values()))
            if isinstance(record, dict):
                return record
    return document

def summary_metrics(document):
    document = selected_summary(document)
    return {
        "outcome": document.get("outcome") or document.get("status"),
        "normalized_outcome": document.get("normalized_outcome"),
        "stop_reason": document.get("stop_reason"),
        "semantic_finding_count": evidence_count(
            document,
            ("semantic_finding_count", "structured_finding_count", "finding_count"),
            ("semantic_findings", "structured_findings", "findings"),
        ),
        "operation_diagnostic_count": evidence_count(
            document,
            ("operation_diagnostic_count", "diagnostic_count"),
            ("operation_diagnostics", "diagnostics"),
        ),
        "sanitizer_crash_count": evidence_count(
            document,
            ("sanitizer_crash_count", "crash_count"),
            ("sanitizer_crashes", "crashes"),
        ),
        "hang_count": evidence_count(document, ("hang_count", "timeout_count"), ("hangs", "timeouts")),
        "sanitizer_artifact_count": evidence_count(
            document,
            ("sanitizer_artifact_count",),
            ("sanitizer_artifacts",),
        ),
        "worker_count": document.get("worker_count"),
        "jobs": document.get("jobs"),
        "cpu_allocation": document.get("cpu_allocation"),
        "wall_time_seconds": document.get("wall_time_seconds"),
        "cpu_time_seconds": document.get("cpu_time_seconds"),
        "operations": document.get("operations"),
        "algorithm_list": document.get("algorithm_list"),
        "property_list": document.get("property_list"),
        "module_version": document.get("module_version"),
    }

campaigns = []
with open(index_file, "r", encoding="utf-8", newline="") as f:
    reader = csv.DictReader(f, delimiter="\t")
    for row in reader:
        campaigns.append(row)

rows = []
overall_status = 0

for campaign in campaigns:
    baseline = campaign["baseline"]
    status_path = Path(campaign["status_file"])
    workspace_root = Path(campaign["workspace_root_abs"])
    run_root = workspace_root / baseline / "targets-run"
    status = load_json(status_path) or {}

    baseline_summary_paths = sorted(run_root.rglob("summary.json")) if run_root.is_dir() else []
    baseline_summaries = []
    for path in baseline_summary_paths:
        parsed = load_json(path)
        parsed_metrics = summary_metrics(parsed)
        baseline_summaries.append({
            "path": rel(path),
            "status": parsed.get("status") if isinstance(parsed, dict) else None,
            "outcome": parsed_metrics["outcome"],
            "target": parsed.get("target") if isinstance(parsed, dict) else None,
            "mode": parsed.get("mode") if isinstance(parsed, dict) else None,
            "semantic_finding_count": parsed_metrics["semantic_finding_count"],
            "operation_diagnostic_count": parsed_metrics["operation_diagnostic_count"],
            "sanitizer_crash_count": parsed_metrics["sanitizer_crash_count"],
            "hang_count": parsed_metrics["hang_count"],
        })

    version_root = run_root / f"liboqs-{campaign['version']}"
    profile_summary_path = version_root / "full" / "summary.json"
    version_summary_path = version_root / "summary.json"
    if baseline == "cryptoTesting":
        root_summary = load_json(
            run_root / "raw" / f"cryptoTesting-{campaign['version']}" / "functional" / "summary.json"
        )
    elif profile_summary_path.is_file():
        root_summary = load_json(profile_summary_path)
    else:
        root_summary = load_json(version_summary_path if version_summary_path.is_file() else run_root / "summary.json")
    metrics = summary_metrics(root_summary)

    reports_dir = run_root / "reports"
    logs_dir = run_root / "logs"
    reports = sorted(rel(path) for path in reports_dir.rglob("*") if path.is_file()) if reports_dir.is_dir() else []
    logs = sorted(rel(path) for path in logs_dir.rglob("*") if path.is_file()) if logs_dir.is_dir() else []
    counts = artifact_counts(run_root)
    manifest_path = workspace_root / baseline / "compaction_manifest.json"
    manifest = load_json(manifest_path) if manifest_path.is_file() else None
    retained_counts = manifest.get("retained_artifact_counts", {}) if isinstance(manifest, dict) else {}
    if not isinstance(retained_counts, dict):
        retained_counts = {}
    row_result_save_mode = (
        campaign.get("result_save_mode")
        or status.get("result_save_mode")
        or result_save_mode
    )

    final_status = status.get("final_status")
    if not status:
        result = "missing-status"
        aggregate_status = 1
    elif final_status is None:
        result = status.get("result") or "launcher-exited-no-status"
        aggregate_status = 1
    else:
        result = status.get("result") or "unknown"
        aggregate_status = int(final_status)

    missing_expected_summary = False
    if aggregate_status == 0 and not baseline_summaries:
        missing_expected_summary = True
        aggregate_status = 1
        result = "missing-summary"

    if aggregate_status != 0:
        overall_status = 1

    row = {
        "campaign": campaign["campaign"],
        "baseline": baseline,
        "baseline_label": status.get("baseline_label") or baseline,
        "fuzzer_mode": status.get("fuzzer_mode"),
        "version": campaign["version"],
        "session_name": campaign["session_name"],
        "workspace_root": campaign["workspace_root"],
        "started_at": status.get("started_at"),
        "ended_at": status.get("ended_at"),
        "elapsed_seconds": status.get("elapsed_seconds"),
        "docker_build_status": status.get("docker_build_status"),
        "target_build_status": status.get("target_build_status"),
        "fuzz_run_status": status.get("fuzz_status"),
        "kem_status": status.get("kem_status"),
        "sig_status": status.get("sig_status"),
        "final_status": final_status,
        "aggregate_status": aggregate_status,
        "result": result,
        "log": campaign["log_file"],
        "launcher": campaign.get("launcher_file"),
        "status_file": campaign["status_file"],
        "script_snapshot": campaign.get("script_snapshot") or status.get("script_snapshot"),
        "script_snapshot_hash": campaign.get("script_snapshot_hash") or status.get("script_snapshot_hash"),
        "baseline_summaries": baseline_summaries,
        "summary_outcome": metrics["outcome"],
        "normalized_outcome": metrics["normalized_outcome"],
        "stop_reason": metrics["stop_reason"],
        "semantic_finding_count": metrics["semantic_finding_count"],
        "operation_diagnostic_count": metrics["operation_diagnostic_count"],
        "sanitizer_crash_count": max(
            metrics["sanitizer_crash_count"],
            counts["crash"] + counts["leak"] + counts["oom"],
        ),
        "sanitizer_artifact_count": max(
            metrics["sanitizer_artifact_count"],
            counts["crash"] + counts["leak"] + counts["oom"] + counts["timeout"],
        ),
        "worker_count": metrics["worker_count"],
        "jobs": metrics["jobs"],
        "cpu_allocation": metrics["cpu_allocation"],
        "wall_time_seconds": metrics["wall_time_seconds"],
        "cpu_time_seconds": metrics["cpu_time_seconds"],
        "operations": metrics["operations"],
        "algorithm_list": metrics["algorithm_list"],
        "property_list": metrics["property_list"],
        "module_version": metrics["module_version"],
        "missing_expected_summary": missing_expected_summary,
        "crash_count": counts["crash"],
        "timeout_count": counts["timeout"],
        "leak_count": counts["leak"],
        "oom_count": counts["oom"],
        "cryptoTesting_reports": reports,
        "cryptoTesting_logs": logs,
        "result_save_mode": row_result_save_mode,
        "compacted": bool(manifest.get("compacted")) if isinstance(manifest, dict) else False,
        "compaction_status": status.get("compaction_status"),
        "compaction_manifest": rel(manifest_path) if manifest_path.is_file() else status.get("compaction_manifest"),
        "removed_bytes_estimate": manifest.get("removed_bytes_estimate", 0) if isinstance(manifest, dict) else 0,
        "build_retained": manifest.get("build_retained") if isinstance(manifest, dict) else row_result_save_mode == "all",
        "corpus_retained": manifest.get("corpus_retained") if isinstance(manifest, dict) else row_result_save_mode == "all",
        "retained_artifact_counts": retained_counts,
        "hang_count": max(
            metrics["hang_count"],
            counts["hang"],
            counts["timeout"],
            nonnegative_int(retained_counts.get("hang")) or 0,
        ),
    }
    rows.append(row)

totals = {
    "semantic_finding_count": sum(row["semantic_finding_count"] for row in rows),
    "operation_diagnostic_count": sum(row["operation_diagnostic_count"] for row in rows),
    "sanitizer_crash_count": sum(row["sanitizer_crash_count"] for row in rows),
    "hang_count": sum(row["hang_count"] for row in rows),
}

coverage_by_version = {}
for version in sorted({row["version"] for row in rows}):
    version_rows = [row for row in rows if row["version"] == version]
    algorithm_sets = [set(row["algorithm_list"] or []) for row in version_rows if row["algorithm_list"]]
    property_sets = [set(row["property_list"] or []) for row in version_rows if row["property_list"]]
    coverage_by_version[version] = {
        "shared_algorithms": sorted(set.intersection(*algorithm_sets)) if algorithm_sets else [],
        "shared_properties": sorted(set.intersection(*property_sets)) if property_sets else [],
        # Keep each campaign's complete scheduled matrix alongside the shared
        # intersection; consumers must not confuse the latter with full-run
        # totals when baselines exercise different properties.
        "full_matrix_campaigns": [
            {
                "campaign": row["campaign"],
                "baseline_label": row.get("baseline_label", row["baseline"]),
                "algorithms": row["algorithm_list"] or [],
                "properties": row["property_list"] or [],
            }
            for row in version_rows
        ],
    }

summary = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "fuzzing_seconds": fuzzing_seconds,
    "result_save_mode": result_save_mode,
    "overall_status": overall_status,
    "totals": totals,
    "coverage_matrix": coverage_by_version,
    "campaigns": rows,
}

summary_json.parent.mkdir(parents=True, exist_ok=True)
with open(summary_json, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")

columns = [
    "campaign",
    "baseline",
    "baseline_label",
    "fuzzer_mode",
    "version",
    "result",
    "aggregate_status",
    "docker_build_status",
    "target_build_status",
    "fuzz_run_status",
    "kem_status",
    "sig_status",
    "elapsed_seconds",
    "summary_outcome",
    "normalized_outcome",
    "stop_reason",
    "semantic_finding_count",
    "operation_diagnostic_count",
    "sanitizer_crash_count",
    "sanitizer_artifact_count",
    "crash_count",
    "timeout_count",
    "leak_count",
    "oom_count",
    "hang_count",
    "worker_count",
    "jobs",
    "cpu_allocation",
    "wall_time_seconds",
    "cpu_time_seconds",
    "module_version",
    "log",
    "launcher",
    "result_save_mode",
    "compacted",
    "compaction_status",
    "compaction_manifest",
    "script_snapshot",
    "script_snapshot_hash",
    "removed_bytes_estimate",
    "build_retained",
    "corpus_retained",
]
with open(summary_tsv, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, delimiter="\t", fieldnames=columns)
    writer.writeheader()
    for row in rows:
        writer.writerow({column: row.get(column) for column in columns})

print(summary_json)
print(summary_tsv)
raise SystemExit(overall_status)
PY
}

archive_existing_eval_root() {
  if [ ! -e "$EVAL_ROOT" ]; then
    return
  fi

  if [ -d "$EVAL_ROOT" ] && [ -z "$(find "$EVAL_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    return
  fi

  local archive_date archive_root archive_rel suffix
  archive_date="$(date +%Y%m%d)"
  archive_rel="workspace/baselines_eval_${archive_date}"
  archive_root="${ROOT_DIR}/${archive_rel}"
  suffix=1

  while [ -e "$archive_root" ]; do
    archive_rel="workspace/baselines_eval_${archive_date}_${suffix}"
    archive_root="${ROOT_DIR}/${archive_rel}"
    suffix=$((suffix + 1))
  done

  mkdir -p "$(dirname "$archive_root")"
  mv "$EVAL_ROOT" "$archive_root"
  echo "[eval] archived previous results: $EVAL_ROOT -> $archive_root"
}

ROOT_DIR="${PQCDF_ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
FUZZING_TIME="24h"
PROGRESS_INTERVAL="3600"
SESSION_PREFIX="pqcdf"
RESULT_SAVE_MODE="compact"
DRY_RUN=0
SUMMARIZE_ONLY=0
declare -a REQUESTED_CAMPAIGNS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --fuzzing-time)
      if [ "$#" -lt 2 ]; then
        die "missing value for --fuzzing-time"
      fi
      FUZZING_TIME="$2"
      shift 2
      ;;
    --fuzzing-time=*)
      FUZZING_TIME="${1#--fuzzing-time=}"
      shift
      ;;
    --progress-interval)
      if [ "$#" -lt 2 ]; then
        die "missing value for --progress-interval"
      fi
      PROGRESS_INTERVAL="$2"
      shift 2
      ;;
    --progress-interval=*)
      PROGRESS_INTERVAL="${1#--progress-interval=}"
      shift
      ;;
    --session-prefix)
      if [ "$#" -lt 2 ]; then
        die "missing value for --session-prefix"
      fi
      SESSION_PREFIX="$2"
      shift 2
      ;;
    --session-prefix=*)
      SESSION_PREFIX="${1#--session-prefix=}"
      shift
      ;;
    --result-save-mode)
      if [ "$#" -lt 2 ]; then
        die "missing value for --result-save-mode"
      fi
      RESULT_SAVE_MODE="$2"
      shift 2
      ;;
    --result-save-mode=*)
      RESULT_SAVE_MODE="${1#--result-save-mode=}"
      shift
      ;;
    --campaign)
      if [ "$#" -lt 2 ]; then
        die "missing value for --campaign"
      fi
      REQUESTED_CAMPAIGNS+=("$2")
      shift 2
      ;;
    --campaign=*)
      REQUESTED_CAMPAIGNS+=("${1#--campaign=}")
      shift
      ;;
    --summarize-only)
      SUMMARIZE_ONLY=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option '$1'"
      ;;
  esac
done

validate_session_prefix "$SESSION_PREFIX"
case "$RESULT_SAVE_MODE" in
  compact|all) ;;
  *)
    die "--result-save-mode must be 'compact' or 'all'"
    ;;
esac
FUZZING_SECONDS="$(parse_duration_seconds "$FUZZING_TIME")"
if [[ ! "$PROGRESS_INTERVAL" =~ ^[0-9]+$ ]] || [ "$PROGRESS_INTERVAL" -le 0 ]; then
  die "--progress-interval must be a positive integer number of seconds"
fi

KEM_SECONDS=$(((FUZZING_SECONDS + 1) / 2))
SIG_SECONDS=$((FUZZING_SECONDS / 2))
if [ "$SIG_SECONDS" -le 0 ]; then
  SIG_SECONDS=1
fi

BASELINES=(libFuzzer cryptofuzz CLFuzz cryptoTesting)
VERSIONS=(0.14.0 0.8.0 0.4.0)

declare -A VALID_CAMPAIGN_BY_ID
for baseline in "${BASELINES[@]}"; do
  for version in "${VERSIONS[@]}"; do
    VALID_CAMPAIGN_BY_ID["${baseline}-${version}"]=1
  done
done

declare -A REQUESTED_CAMPAIGN_BY_ID
for campaign in "${REQUESTED_CAMPAIGNS[@]}"; do
  if [ -z "${VALID_CAMPAIGN_BY_ID[$campaign]+x}" ]; then
    die "unknown campaign '$campaign' (expected BASELINE-VERSION, e.g. libFuzzer-0.14.0)"
  fi
  REQUESTED_CAMPAIGN_BY_ID["$campaign"]=1
done

EVAL_ROOT_REL="workspace/baselines_eval"
EVAL_ROOT="${ROOT_DIR}/${EVAL_ROOT_REL}"
CAMPAIGN_ROOT="${EVAL_ROOT}/campaigns"
LOG_DIR="${EVAL_ROOT}/logs"
LAUNCHER_DIR="${EVAL_ROOT}/launchers"
STATUS_DIR="${EVAL_ROOT}/status"
INDEX_FILE="${STATUS_DIR}/campaigns.tsv"
SUMMARY_JSON="${EVAL_ROOT}/summary.json"
SUMMARY_TSV="${EVAL_ROOT}/summary.tsv"

declare -a CAMPAIGN_IDS=()
declare -A BASELINE_BY_ID
declare -A VERSION_BY_ID
declare -A SESSION_BY_ID
declare -A WORKSPACE_REL_BY_ID
declare -A WORKSPACE_ABS_BY_ID
declare -A LOG_FILE_BY_ID
declare -A LAUNCHER_FILE_BY_ID
declare -A STATUS_FILE_BY_ID

for baseline in "${BASELINES[@]}"; do
  for version in "${VERSIONS[@]}"; do
    campaign="${baseline}-${version}"
    if [ "${#REQUESTED_CAMPAIGNS[@]}" -gt 0 ] && [ -z "${REQUESTED_CAMPAIGN_BY_ID[$campaign]+x}" ]; then
      continue
    fi
    safe_version="${version//./_}"
    session_name="${SESSION_PREFIX}-${baseline}-${safe_version}"
    workspace_root_rel="${EVAL_ROOT_REL}/campaigns/${campaign}/workspace"
    workspace_root_abs="${ROOT_DIR}/${workspace_root_rel}"
    log_file="${LOG_DIR}/${campaign}.log"
    launcher_file="${LAUNCHER_DIR}/${campaign}.sh"
    status_file="${STATUS_DIR}/${campaign}.json"

    CAMPAIGN_IDS+=("$campaign")
    BASELINE_BY_ID["$campaign"]="$baseline"
    VERSION_BY_ID["$campaign"]="$version"
    SESSION_BY_ID["$campaign"]="$session_name"
    WORKSPACE_REL_BY_ID["$campaign"]="$workspace_root_rel"
    WORKSPACE_ABS_BY_ID["$campaign"]="$workspace_root_abs"
    LOG_FILE_BY_ID["$campaign"]="$log_file"
    LAUNCHER_FILE_BY_ID["$campaign"]="$launcher_file"
    STATUS_FILE_BY_ID["$campaign"]="$status_file"
  done
done

if [ "${#CAMPAIGN_IDS[@]}" -eq 0 ]; then
  die "no campaigns selected"
fi
if [ "$SUMMARIZE_ONLY" -eq 1 ] && [ "${#REQUESTED_CAMPAIGNS[@]}" -gt 0 ]; then
  die "--summarize-only cannot be combined with --campaign"
fi

echo "[eval] repository: $ROOT_DIR"
echo "[eval] output root: $EVAL_ROOT"
echo "[eval] fuzzing time: ${FUZZING_SECONDS}s"
echo "[eval] progress interval: ${PROGRESS_INTERVAL}s"
echo "[eval] session prefix: $SESSION_PREFIX"
echo "[eval] result save mode: $RESULT_SAVE_MODE"
if [ "${#REQUESTED_CAMPAIGNS[@]}" -gt 0 ]; then
  echo "[eval] selected campaigns: ${REQUESTED_CAMPAIGNS[*]}"
else
  echo "[eval] selected campaigns: all"
fi
echo "[eval] dry run: $DRY_RUN"
echo

if [ "$SUMMARIZE_ONLY" -eq 1 ]; then
  [ -f "$INDEX_FILE" ] || die "cannot summarize: missing campaign index $INDEX_FILE"
  SUMMARY_OUTPUT="$(write_final_summary)"
  SUMMARY_STATUS="$?"
  printf '%s\n' "$SUMMARY_OUTPUT"
  exit "$SUMMARY_STATUS"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  for campaign in "${CAMPAIGN_IDS[@]}"; do
    baseline="${BASELINE_BY_ID[$campaign]}"
    version="${VERSION_BY_ID[$campaign]}"
    echo "[dry-run] campaign: $campaign"
    echo "[dry-run] session: ${SESSION_BY_ID[$campaign]}"
    echo "[dry-run] workspace: ${WORKSPACE_REL_BY_ID[$campaign]}"
    echo "[dry-run] log: ${LOG_FILE_BY_ID[$campaign]}"
    echo "[dry-run] status: ${STATUS_FILE_BY_ID[$campaign]}"
    print_campaign_commands "$baseline" "$version" "$FUZZING_SECONDS" "$KEM_SECONDS" "$SIG_SECONDS" "$RESULT_SAVE_MODE" |
      sed "s#<campaign-workspace>#${WORKSPACE_REL_BY_ID[$campaign]}#g; s/^/[dry-run] command: /"
    echo
  done
  exit 0
fi

command -v tmux >/dev/null 2>&1 || die "tmux is required"
command -v timeout >/dev/null 2>&1 || die "timeout is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"

if [ ! -x "${ROOT_DIR}/scripts/run_baseline.sh" ]; then
  die "missing executable dispatcher: scripts/run_baseline.sh"
fi
if [ "$RESULT_SAVE_MODE" = "compact" ] && [ ! -f "${ROOT_DIR}/scripts/compact_baseline_results.py" ]; then
  die "missing compaction helper: scripts/compact_baseline_results.py"
fi

CONFLICTS=0
for campaign in "${CAMPAIGN_IDS[@]}"; do
  if tmux has-session -t "=${SESSION_BY_ID[$campaign]}" 2>/dev/null; then
    echo "[eval] session already exists: ${SESSION_BY_ID[$campaign]}" >&2
    echo "[eval] stop it first with: tmux kill-session -t ${SESSION_BY_ID[$campaign]}" >&2
    CONFLICTS=1
  fi
done
if [ "$CONFLICTS" -ne 0 ]; then
  exit 2
fi

archive_existing_eval_root
mkdir -p "$CAMPAIGN_ROOT" "$LOG_DIR" "$LAUNCHER_DIR" "$STATUS_DIR"
REPO_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
create_runner_snapshot

{
  printf 'campaign\tbaseline\tversion\tsession_name\tworkspace_root\tworkspace_root_abs\tlog_file\tlauncher_file\tstatus_file\tresult_save_mode\tscript_snapshot\tscript_snapshot_hash\n'
  for campaign in "${CAMPAIGN_IDS[@]}"; do
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$campaign" \
      "${BASELINE_BY_ID[$campaign]}" \
      "${VERSION_BY_ID[$campaign]}" \
      "${SESSION_BY_ID[$campaign]}" \
      "${WORKSPACE_REL_BY_ID[$campaign]}" \
      "${WORKSPACE_ABS_BY_ID[$campaign]}" \
      "${LOG_FILE_BY_ID[$campaign]}" \
      "${LAUNCHER_FILE_BY_ID[$campaign]}" \
      "${STATUS_FILE_BY_ID[$campaign]}" \
      "$RESULT_SAVE_MODE" \
      "$RUNNER_SNAPSHOT_DIR_REL" \
      "$RUNNER_SNAPSHOT_HASH"
  done
} > "$INDEX_FILE"

START_FAILURE=0
for campaign in "${CAMPAIGN_IDS[@]}"; do
  write_launcher \
    "${LAUNCHER_FILE_BY_ID[$campaign]}" \
    "${BASELINE_BY_ID[$campaign]}" \
    "${VERSION_BY_ID[$campaign]}" \
    "$campaign" \
    "${SESSION_BY_ID[$campaign]}" \
    "${WORKSPACE_REL_BY_ID[$campaign]}" \
    "${WORKSPACE_ABS_BY_ID[$campaign]}" \
    "${LOG_FILE_BY_ID[$campaign]}" \
    "${STATUS_FILE_BY_ID[$campaign]}" \
    "$FUZZING_SECONDS" \
    "$KEM_SECONDS" \
    "$SIG_SECONDS" \
    "$RESULT_SAVE_MODE" \
    "$RUNNER_SNAPSHOT_RUN_BASELINE_REL" \
    "$RUNNER_SNAPSHOT_COMPACTOR_REL" \
    "$RUNNER_SNAPSHOT_BASELINES_DIR_REL" \
    "$RUNNER_SNAPSHOT_DIR_REL" \
    "$RUNNER_SNAPSHOT_HASH" \
    "$REPO_COMMIT"

  write_parent_status \
    "${STATUS_FILE_BY_ID[$campaign]}" \
    "$campaign" \
    "${BASELINE_BY_ID[$campaign]}" \
    "${VERSION_BY_ID[$campaign]}" \
    "${SESSION_BY_ID[$campaign]}" \
    "${WORKSPACE_REL_BY_ID[$campaign]}" \
    "${WORKSPACE_ABS_BY_ID[$campaign]}" \
    "${LOG_FILE_BY_ID[$campaign]}" \
    "${LAUNCHER_FILE_BY_ID[$campaign]}" \
    "queued" \
    "queued" \
    "" \
    ""

  if ! bash -n "${LAUNCHER_FILE_BY_ID[$campaign]}"; then
    echo "[eval] generated launcher failed syntax check: ${LAUNCHER_FILE_BY_ID[$campaign]}" >&2
    write_parent_status \
      "${STATUS_FILE_BY_ID[$campaign]}" \
      "$campaign" \
      "${BASELINE_BY_ID[$campaign]}" \
      "${VERSION_BY_ID[$campaign]}" \
      "${SESSION_BY_ID[$campaign]}" \
      "${WORKSPACE_REL_BY_ID[$campaign]}" \
      "${WORKSPACE_ABS_BY_ID[$campaign]}" \
      "${LOG_FILE_BY_ID[$campaign]}" \
      "${LAUNCHER_FILE_BY_ID[$campaign]}" \
      "finished" \
      "finished" \
      "launch-failed" \
      "1"
    START_FAILURE=1
    continue
  fi

  if tmux new-session -d -s "${SESSION_BY_ID[$campaign]}" -c "$ROOT_DIR" "${LAUNCHER_FILE_BY_ID[$campaign]}"; then
    echo "[eval] started: ${SESSION_BY_ID[$campaign]}"
    echo "[eval] campaign: $campaign"
    echo "[eval] log: ${LOG_FILE_BY_ID[$campaign]}"
    echo
  else
    echo "[eval] failed to start tmux session: ${SESSION_BY_ID[$campaign]}" >&2
    write_parent_status \
      "${STATUS_FILE_BY_ID[$campaign]}" \
      "$campaign" \
      "${BASELINE_BY_ID[$campaign]}" \
      "${VERSION_BY_ID[$campaign]}" \
      "${SESSION_BY_ID[$campaign]}" \
      "${WORKSPACE_REL_BY_ID[$campaign]}" \
      "${WORKSPACE_ABS_BY_ID[$campaign]}" \
      "${LOG_FILE_BY_ID[$campaign]}" \
      "${LAUNCHER_FILE_BY_ID[$campaign]}" \
      "finished" \
      "finished" \
      "launch-failed" \
      "1"
    START_FAILURE=1
  fi
done

LAST_PROGRESS=0
SLEEP_SECONDS=5
if [ "$PROGRESS_INTERVAL" -lt "$SLEEP_SECONDS" ]; then
  SLEEP_SECONDS="$PROGRESS_INTERVAL"
fi

while :; do
  now="$(date +%s)"
  if [ $((now - LAST_PROGRESS)) -ge "$PROGRESS_INTERVAL" ]; then
    print_progress "$now"
    LAST_PROGRESS="$now"
  fi

  remaining=0
  for campaign in "${CAMPAIGN_IDS[@]}"; do
    session="${SESSION_BY_ID[$campaign]}"
    status_file="${STATUS_FILE_BY_ID[$campaign]}"
    fields="$(read_status_fields "$status_file")"
    IFS=$'\t' read -r phase state elapsed result <<<"$fields"

    if [ "$state" = "finished" ]; then
      if tmux has-session -t "=${session}" 2>/dev/null; then
        tmux kill-session -t "=${session}" 2>/dev/null || true
      fi
      continue
    fi

    if tmux has-session -t "=${session}" 2>/dev/null; then
      remaining=$((remaining + 1))
    fi
  done

  if [ "$remaining" -eq 0 ]; then
    break
  fi

  sleep "$SLEEP_SECONDS"
done

print_progress "$(date +%s)"

echo
echo "[eval] writing final summaries"
set +e
SUMMARY_OUTPUT="$(write_final_summary)"
SUMMARY_STATUS="$?"
set -e
echo "$SUMMARY_OUTPUT"

if [ "$START_FAILURE" -ne 0 ] && [ "$SUMMARY_STATUS" -eq 0 ]; then
  SUMMARY_STATUS=1
fi

if [ "$SUMMARY_STATUS" -eq 0 ]; then
  echo "[eval] all campaigns completed successfully"
else
  echo "[eval] one or more campaigns failed; see $SUMMARY_JSON" >&2
fi

exit "$SUMMARY_STATUS"
