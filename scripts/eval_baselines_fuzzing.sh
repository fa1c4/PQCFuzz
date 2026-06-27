#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/eval_baselines_fuzzing.sh [options]

Options:
  --fuzzing-time DURATION       Wall-clock budget for each campaign. Default: 24h.
                                Accepts seconds or s/m/h/d suffixes, e.g. 86400, 60m, 24h.
  --progress-interval SECONDS   Seconds between progress reports. Default: 3600.
  --session-prefix NAME         Prefix for tmux session names. Default: pqcdf.
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

  echo "scripts/run_baseline.sh $baseline docker-build"
  case "$baseline" in
    libFuzzer)
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> scripts/run_baseline.sh libFuzzer build --version $version"
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> scripts/run_baseline.sh libFuzzer run --version $version --target kem --mode full --max-total-time $kem_seconds"
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> scripts/run_baseline.sh libFuzzer run --version $version --target sig --mode full --max-total-time $sig_seconds"
      ;;
    cryptofuzz|CLFuzz)
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> scripts/run_baseline.sh $baseline build --version $version"
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> scripts/run_baseline.sh $baseline run --version $version --mode full --max-total-time $seconds"
      ;;
    cryptoTesting)
      echo "PQCDF_WORKSPACE_ROOT=<campaign-workspace> timeout ${seconds}s scripts/run_baseline.sh cryptoTesting run --version $version --skip-core-pattern-check"
      ;;
    *)
      die "unknown baseline '$baseline'"
      ;;
  esac
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
    printf 'SIG_SECONDS=%q\n\n' "$sig_seconds"
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
FINAL_STATUS=""
RESULT=""
ENDED_AT=""

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
  EVAL_FINAL_STATUS="$FINAL_STATUS" \
  EVAL_RESULT="$RESULT" \
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
    "version": os.environ["EVAL_VERSION"],
    "session_name": os.environ["EVAL_SESSION_NAME"],
    "workspace_root": os.environ["EVAL_WORKSPACE_ROOT"],
    "workspace_root_abs": os.environ["EVAL_WORKSPACE_ROOT_ABS"],
    "log": os.environ["EVAL_LOG_FILE"],
    "phase": os.environ["EVAL_PHASE"],
    "state": os.environ["EVAL_STATE"],
    "started_at": os.environ["EVAL_STARTED_AT"],
    "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "elapsed_seconds": now - start_epoch,
    "docker_build_status": int_or_none(os.environ["EVAL_DOCKER_BUILD_STATUS"]),
    "target_build_status": int_or_none(os.environ["EVAL_TARGET_BUILD_STATUS"]),
    "fuzz_status": int_or_none(os.environ["EVAL_FUZZ_STATUS"]),
    "kem_status": int_or_none(os.environ["EVAL_KEM_STATUS"]),
    "sig_status": int_or_none(os.environ["EVAL_SIG_STATUS"]),
    "final_status": int_or_none(os.environ["EVAL_FINAL_STATUS"]),
    "result": os.environ["EVAL_RESULT"] or None,
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

finish_campaign() {
  RESULT="$1"
  FINAL_STATUS="$2"
  ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  write_status "finished" "finished"
  echo
  echo "[eval] ended: $ENDED_AT"
  echo "[eval] elapsed: $(( $(date +%s) - START_EPOCH ))s"
  echo "[eval] result: $RESULT"
  echo "[eval] final status: $FINAL_STATUS"
  exit "$FINAL_STATUS"
}

run_step() {
  echo "[eval] command: $*"
  "$@"
  return $?
}

export PQCDF_WORKSPACE_ROOT="$WORKSPACE_ROOT_REL"

echo "[eval] session: $SESSION_NAME"
echo "[eval] campaign: $CAMPAIGN"
echo "[eval] baseline: $BASELINE"
echo "[eval] liboqs version: $VERSION"
echo "[eval] fuzzing time: ${FUZZING_SECONDS}s"
echo "[eval] workspace root: $WORKSPACE_ROOT_REL"
echo "[eval] started: $STARTED_AT"
echo "[eval] log: $LOG_FILE"
echo "[eval] status: $STATUS_FILE"
echo

write_status "docker-build" "running"
run_step scripts/run_baseline.sh "$BASELINE" docker-build
DOCKER_BUILD_STATUS="$?"
echo "[eval] docker-build exited with status $DOCKER_BUILD_STATUS"
if [ "$DOCKER_BUILD_STATUS" -ne 0 ]; then
  finish_campaign "docker-build-failed" "$DOCKER_BUILD_STATUS"
fi

case "$BASELINE" in
  libFuzzer|cryptofuzz|CLFuzz)
    write_status "target-build" "running"
    run_step scripts/run_baseline.sh "$BASELINE" build --version "$VERSION"
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
    write_status "run-kem" "running"
    run_step scripts/run_baseline.sh libFuzzer run --version "$VERSION" --target kem --mode full --max-total-time "$KEM_SECONDS"
    KEM_STATUS="$?"
    echo "[eval] libFuzzer kem exited with status $KEM_STATUS"
    echo

    write_status "run-sig" "running"
    run_step scripts/run_baseline.sh libFuzzer run --version "$VERSION" --target sig --mode full --max-total-time "$SIG_SECONDS"
    SIG_STATUS="$?"
    echo "[eval] libFuzzer sig exited with status $SIG_STATUS"

    if [ "$KEM_STATUS" -ne 0 ]; then
      FUZZ_STATUS="$KEM_STATUS"
    else
      FUZZ_STATUS="$SIG_STATUS"
    fi
    ;;

  cryptofuzz)
    write_status "run" "running"
    run_step scripts/run_baseline.sh cryptofuzz run --version "$VERSION" --mode full --max-total-time "$FUZZING_SECONDS"
    FUZZ_STATUS="$?"
    ;;

  CLFuzz)
    write_status "run" "running"
    run_step scripts/run_baseline.sh CLFuzz run --version "$VERSION" --mode full --max-total-time "$FUZZING_SECONDS"
    FUZZ_STATUS="$?"
    ;;

  cryptoTesting)
    write_status "run" "running"
    echo "[eval] command: timeout ${FUZZING_SECONDS}s scripts/run_baseline.sh cryptoTesting run --version $VERSION --skip-core-pattern-check"
    timeout "${FUZZING_SECONDS}s" scripts/run_baseline.sh cryptoTesting run --version "$VERSION" --skip-core-pattern-check
    FUZZ_STATUS="$?"
    if [ "$FUZZ_STATUS" -eq 124 ]; then
      echo "[eval] cryptoTesting reached the configured fuzzing-time limit"
      finish_campaign "timed-out" 0
    fi
    ;;
esac

echo "[eval] fuzzing exited with status $FUZZ_STATUS"
if [ "$FUZZ_STATUS" -ne 0 ]; then
  finish_campaign "fuzzing-failed" "$FUZZ_STATUS"
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

    if [ "$state" = "pending" ] && [ "$tmux_state" = "alive" ]; then
      phase="starting"
      state="running"
      elapsed=0
    elif [ "$state" != "finished" ] && [ "$tmux_state" = "dead" ]; then
      state="exited-no-status"
    elif [ "$state" = "finished" ]; then
      state="$result"
    fi

    printf '%-24s %-14s %-10s %-6s %-18s\n' \
      "$id" "$phase" "$(format_elapsed "$elapsed")" "$tmux_state" "$state"
  done
  echo "[eval] next progress report in ${PROGRESS_INTERVAL}s"
}

write_final_summary() {
  python3 - "$INDEX_FILE" "$SUMMARY_JSON" "$SUMMARY_TSV" "$FUZZING_SECONDS" <<'PY'
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
    counts = {"crash": 0, "timeout": 0, "leak": 0, "oom": 0}
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
    return counts

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
        baseline_summaries.append({
            "path": rel(path),
            "status": parsed.get("status") if isinstance(parsed, dict) else None,
            "target": parsed.get("target") if isinstance(parsed, dict) else None,
            "mode": parsed.get("mode") if isinstance(parsed, dict) else None,
        })

    reports_dir = run_root / "reports"
    logs_dir = run_root / "logs"
    reports = sorted(rel(path) for path in reports_dir.glob("*") if path.is_file()) if reports_dir.is_dir() else []
    logs = sorted(rel(path) for path in logs_dir.glob("*") if path.is_file()) if logs_dir.is_dir() else []
    counts = artifact_counts(run_root)

    final_status = status.get("final_status")
    result = status.get("result") or "missing-status"
    aggregate_status = 1 if final_status is None else int(final_status)

    missing_expected_summary = False
    if baseline != "cryptoTesting" and aggregate_status == 0 and not baseline_summaries:
        missing_expected_summary = True
        aggregate_status = 1
        result = "missing-summary"

    if aggregate_status != 0:
        overall_status = 1

    row = {
        "campaign": campaign["campaign"],
        "baseline": baseline,
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
        "status_file": campaign["status_file"],
        "baseline_summaries": baseline_summaries,
        "missing_expected_summary": missing_expected_summary,
        "crash_count": counts["crash"],
        "timeout_count": counts["timeout"],
        "leak_count": counts["leak"],
        "oom_count": counts["oom"],
        "cryptoTesting_reports": reports,
        "cryptoTesting_logs": logs,
    }
    rows.append(row)

summary = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "fuzzing_seconds": fuzzing_seconds,
    "overall_status": overall_status,
    "campaigns": rows,
}

summary_json.parent.mkdir(parents=True, exist_ok=True)
with open(summary_json, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")

columns = [
    "campaign",
    "baseline",
    "version",
    "result",
    "aggregate_status",
    "docker_build_status",
    "target_build_status",
    "fuzz_run_status",
    "kem_status",
    "sig_status",
    "elapsed_seconds",
    "crash_count",
    "timeout_count",
    "leak_count",
    "oom_count",
    "log",
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

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZING_TIME="24h"
PROGRESS_INTERVAL="3600"
SESSION_PREFIX="pqcdf"
DRY_RUN=0

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

echo "[eval] repository: $ROOT_DIR"
echo "[eval] output root: $EVAL_ROOT"
echo "[eval] fuzzing time: ${FUZZING_SECONDS}s"
echo "[eval] progress interval: ${PROGRESS_INTERVAL}s"
echo "[eval] session prefix: $SESSION_PREFIX"
echo "[eval] dry run: $DRY_RUN"
echo

if [ "$DRY_RUN" -eq 1 ]; then
  for campaign in "${CAMPAIGN_IDS[@]}"; do
    baseline="${BASELINE_BY_ID[$campaign]}"
    version="${VERSION_BY_ID[$campaign]}"
    echo "[dry-run] campaign: $campaign"
    echo "[dry-run] session: ${SESSION_BY_ID[$campaign]}"
    echo "[dry-run] workspace: ${WORKSPACE_REL_BY_ID[$campaign]}"
    echo "[dry-run] log: ${LOG_FILE_BY_ID[$campaign]}"
    echo "[dry-run] status: ${STATUS_FILE_BY_ID[$campaign]}"
    print_campaign_commands "$baseline" "$version" "$FUZZING_SECONDS" "$KEM_SECONDS" "$SIG_SECONDS" |
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

{
  printf 'campaign\tbaseline\tversion\tsession_name\tworkspace_root\tworkspace_root_abs\tlog_file\tstatus_file\n'
  for campaign in "${CAMPAIGN_IDS[@]}"; do
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$campaign" \
      "${BASELINE_BY_ID[$campaign]}" \
      "${VERSION_BY_ID[$campaign]}" \
      "${SESSION_BY_ID[$campaign]}" \
      "${WORKSPACE_REL_BY_ID[$campaign]}" \
      "${WORKSPACE_ABS_BY_ID[$campaign]}" \
      "${LOG_FILE_BY_ID[$campaign]}" \
      "${STATUS_FILE_BY_ID[$campaign]}"
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
    "$SIG_SECONDS"

  if tmux new-session -d -s "${SESSION_BY_ID[$campaign]}" -c "$ROOT_DIR" "${LAUNCHER_FILE_BY_ID[$campaign]}"; then
    echo "[eval] started: ${SESSION_BY_ID[$campaign]}"
    echo "[eval] campaign: $campaign"
    echo "[eval] log: ${LOG_FILE_BY_ID[$campaign]}"
    echo
  else
    echo "[eval] failed to start tmux session: ${SESSION_BY_ID[$campaign]}" >&2
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
