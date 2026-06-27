#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/run_baseline.sh libFuzzer build [options]

Options:
  --version VERSION             Build libFuzzer harnesses against a supported liboqs version. Default: 0.14.0.
  -h, --help                    Show this help.

Supported versions:
  0.14.0
  0.8.0
  0.4.0
EOF
}

BASELINE_DIR="$1"
BUILD_DIR="$2"
RUN_DIR="$3"
shift 3

VERSION="0.14.0"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --version." >&2
        exit 2
      fi
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#--version=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown libFuzzer build option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

case "$VERSION" in
  0.14.0|0.8.0|0.4.0) ;;
  *)
    echo "Unsupported libFuzzer liboqs version: $VERSION" >&2
    echo "Supported versions: 0.14.0, 0.8.0, 0.4.0" >&2
    exit 2
    ;;
esac

mkdir -p "$BUILD_DIR" "$RUN_DIR"

IMAGE_NAME="pqcdf-baseline-libfuzzer"

if [ "${PQCDF_LIBFUZZER_IN_DOCKER:-0}" != "1" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to build libFuzzer/liboqs through this wrapper." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed, but the Docker daemon is not available to this user." >&2
    exit 1
  fi
  if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Docker image not found: $IMAGE_NAME" >&2
    echo "Run: scripts/run_baseline.sh libFuzzer docker-build" >&2
    exit 1
  fi

  HOST_UID="$(id -u)"
  HOST_GID="$(id -g)"
  docker run --rm \
    -e PQCDF_LIBFUZZER_IN_DOCKER=1 \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    -e PQCDF_CHOWN_BUILD_DIR="$BUILD_DIR" \
    -e PQCDF_CHOWN_RUN_DIR="$RUN_DIR" \
    -v "$(pwd)":/workspace/PQC-DF \
    -w /workspace/PQC-DF \
    "$IMAGE_NAME" \
    bash -lc 'trap "chown -R ${HOST_UID}:${HOST_GID} \"${PQCDF_CHOWN_BUILD_DIR}\" \"${PQCDF_CHOWN_RUN_DIR}\" 2>/dev/null || true" EXIT; "$@"' \
    bash scripts/baselines/libFuzzer/build.sh "$BASELINE_DIR" "$BUILD_DIR" "$RUN_DIR" --version "$VERSION"
  exit $?
fi

BUILD_DIR_ABS="$(realpath "$BUILD_DIR")"
BASELINE_DIR_ABS="$(realpath "$BASELINE_DIR")"
VERSION_BUILD_DIR="${BUILD_DIR_ABS}/liboqs-${VERSION}"
LIBOQS_SRC_DIR="${VERSION_BUILD_DIR}/liboqs-src"
LIBOQS_BUILD_DIR="${VERSION_BUILD_DIR}/liboqs-build"
FUZZER_BUILD_DIR="${VERSION_BUILD_DIR}/libFuzzer"

mkdir -p "$VERSION_BUILD_DIR" "$FUZZER_BUILD_DIR"

echo "[libFuzzer] build directory: $BUILD_DIR"
echo "[libFuzzer] run directory: $RUN_DIR"
echo "[libFuzzer] liboqs version: $VERSION"
echo "[libFuzzer] version build directory: $VERSION_BUILD_DIR"

if [ ! -d "${LIBOQS_SRC_DIR}/.git" ]; then
  rm -rf "$LIBOQS_SRC_DIR"
  git clone --branch "$VERSION" --depth 1 https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_SRC_DIR"
else
  git config --global --add safe.directory "$LIBOQS_SRC_DIR"
  if ! git -C "$LIBOQS_SRC_DIR" rev-parse -q --verify "refs/tags/${VERSION}" >/dev/null; then
    git -C "$LIBOQS_SRC_DIR" fetch --depth 1 origin "refs/tags/${VERSION}:refs/tags/${VERSION}"
  fi
  CURRENT_COMMIT="$(git -C "$LIBOQS_SRC_DIR" rev-parse HEAD)"
  TARGET_COMMIT="$(git -C "$LIBOQS_SRC_DIR" rev-list -n 1 "$VERSION")"
  if [ "$CURRENT_COMMIT" != "$TARGET_COMMIT" ]; then
    git -C "$LIBOQS_SRC_DIR" checkout --force "$VERSION"
  fi
fi

CC_BIN="${CC:-clang}"
CXX_BIN="${CXX:-clang++}"
PARALLEL_JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
SAN_CFLAGS=(-std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined)
LIBOQS_CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined"
LINK_FLAGS=(-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined)

cmake -S "$LIBOQS_SRC_DIR" -B "$LIBOQS_BUILD_DIR" -GNinja \
  -DCMAKE_C_COMPILER="$CC_BIN" \
  -DCMAKE_CXX_COMPILER="$CXX_BIN" \
  -DCMAKE_ASM_COMPILER="$CC_BIN" \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="$LIBOQS_CFLAGS" \
  -DCMAKE_CXX_FLAGS="$LIBOQS_CFLAGS" \
  -DCMAKE_ASM_FLAGS="-fno-omit-frame-pointer"

cmake --build "$LIBOQS_BUILD_DIR" --target oqs --parallel "$PARALLEL_JOBS"

LIBOQS_ARCHIVE="${LIBOQS_BUILD_DIR}/lib/liboqs.a"
if [ ! -f "$LIBOQS_ARCHIVE" ]; then
  echo "Expected liboqs archive not found: $LIBOQS_ARCHIVE" >&2
  exit 1
fi

for TARGET in kem sig; do
  SRC="${BASELINE_DIR_ABS}/fuzz_${TARGET}.c"
  OBJ="${FUZZER_BUILD_DIR}/fuzz_${TARGET}.o"
  BIN="${FUZZER_BUILD_DIR}/fuzz_${TARGET}"

  "$CC_BIN" "${SAN_CFLAGS[@]}" \
    -I"$BASELINE_DIR_ABS" \
    -I"${LIBOQS_BUILD_DIR}/include" \
    -c "$SRC" -o "$OBJ"

  "$CXX_BIN" "${LINK_FLAGS[@]}" -o "$BIN" \
    "$OBJ" \
    "$LIBOQS_ARCHIVE" \
    -lcrypto -ldl -lpthread -lm

  echo "[libFuzzer] built binary: $BIN"
done
