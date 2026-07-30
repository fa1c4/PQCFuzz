#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  clone_with_retry.sh [options] DEST

Options:
  --repo URL          Git repository URL. Default: LIBOQS_REPO or upstream liboqs.
  --ref REF           Optional branch, tag, or commit to checkout after cloning.
  --cache PATH        Optional bare or working-tree cache to clone from first.
  --retries N         Network clone/fetch attempts. Default: LIBOQS_CLONE_RETRIES or 5.
  --sleep SECONDS     Sleep between network attempts. Default: LIBOQS_CLONE_SLEEP or 5.
  -h, --help          Show this help.
EOF
}

repo="${LIBOQS_REPO:-https://github.com/open-quantum-safe/liboqs.git}"
ref=""
cache="${LIBOQS_CACHE:-}"
retries="${LIBOQS_CLONE_RETRIES:-5}"
sleep_seconds="${LIBOQS_CLONE_SLEEP:-5}"
dest=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --repo" >&2
        exit 2
      fi
      repo="$2"
      shift 2
      ;;
    --repo=*)
      repo="${1#--repo=}"
      shift
      ;;
    --ref)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --ref" >&2
        exit 2
      fi
      ref="$2"
      shift 2
      ;;
    --ref=*)
      ref="${1#--ref=}"
      shift
      ;;
    --cache)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --cache" >&2
        exit 2
      fi
      cache="$2"
      shift 2
      ;;
    --cache=*)
      cache="${1#--cache=}"
      shift
      ;;
    --retries)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --retries" >&2
        exit 2
      fi
      retries="$2"
      shift 2
      ;;
    --retries=*)
      retries="${1#--retries=}"
      shift
      ;;
    --sleep)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --sleep" >&2
        exit 2
      fi
      sleep_seconds="$2"
      shift 2
      ;;
    --sleep=*)
      sleep_seconds="${1#--sleep=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [ -n "$dest" ]; then
        echo "Unexpected extra argument: $1" >&2
        usage >&2
        exit 2
      fi
      dest="$1"
      shift
      ;;
  esac
done

if [ -z "$dest" ] && [ "$#" -gt 0 ]; then
  dest="$1"
  shift
fi
if [ -z "$dest" ] || [ "$#" -gt 0 ]; then
  usage >&2
  exit 2
fi
if ! [[ "$retries" =~ ^[1-9][0-9]*$ ]]; then
  echo "--retries must be a positive integer" >&2
  exit 2
fi
if ! [[ "$sleep_seconds" =~ ^[0-9]+$ ]]; then
  echo "--sleep must be a non-negative integer" >&2
  exit 2
fi
case "$dest" in
  ""|"/"|".")
    echo "Refusing unsafe destination: $dest" >&2
    exit 2
    ;;
esac
if [ -n "$cache" ]; then
  case "$cache" in
    "/"|"."|"..")
      echo "Refusing unsafe cache path: $cache" >&2
      exit 2
      ;;
  esac
fi
if [ -e "$dest" ]; then
  echo "Destination already exists: $dest" >&2
  exit 2
fi

remove_dest() {
  if [ -e "$dest" ]; then
    rm -rf -- "$dest"
  fi
}

checkout_ref() {
  if [ -n "$ref" ]; then
    git -C "$dest" checkout "$ref"
  fi
}

clone_from_cache() {
  if [ -z "$cache" ] || [ ! -e "$cache" ]; then
    return 1
  fi
  if ! git -C "$cache" rev-parse --git-dir >/dev/null 2>&1; then
    echo "[clone] cache is not a git repository: $cache" >&2
    return 1
  fi
  echo "[clone] trying cache: $cache -> $dest"
  if git clone "$cache" "$dest" && checkout_ref; then
    return 0
  fi
  remove_dest
  return 1
}

network_attempt() {
  local description="$1"
  shift
  local attempt=1
  local status=1

  while [ "$attempt" -le "$retries" ]; do
    echo "[clone] ${description} attempt ${attempt}/${retries}"
    if "$@"; then
      return 0
    fi
    status="$?"
    attempt=$((attempt + 1))
    if [ "$attempt" -le "$retries" ] && [ "$sleep_seconds" -gt 0 ]; then
      sleep "$sleep_seconds"
    fi
  done
  return "$status"
}

populate_or_update_cache() {
  if [ -z "$cache" ]; then
    return 1
  fi

  if [ -e "$cache" ]; then
    if ! git -C "$cache" rev-parse --git-dir >/dev/null 2>&1; then
      echo "[clone] cache path exists but is not a git repository: $cache" >&2
      return 1
    fi
    network_attempt "fetch cache" git -C "$cache" fetch --all --tags --prune
    return $?
  fi

  mkdir -p "$(dirname "$cache")"
  populate_cache() {
    remove_path "$cache"
    git clone --mirror "$repo" "$cache"
  }
  network_attempt "populate cache" populate_cache
}

remove_path() {
  local path="$1"
  if [ -e "$path" ]; then
    rm -rf -- "$path"
  fi
}

direct_clone() {
  remove_dest
  git clone "$repo" "$dest"
  checkout_ref
}

if clone_from_cache; then
  exit 0
fi

if populate_or_update_cache && clone_from_cache; then
  exit 0
fi

network_attempt "clone" direct_clone || {
  remove_dest
  exit 1
}
