#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/run_baseline.sh cryptofuzz build [options]

Options:
  --version VERSION             Build cryptofuzz against a supported liboqs version. Default: 0.14.0.
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
MAKE_ARGS=()

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
      MAKE_ARGS+=("$1")
      shift
      ;;
  esac
done

case "$VERSION" in
  0.14.0|0.8.0|0.4.0) ;;
  *)
    echo "Unsupported cryptofuzz liboqs version: $VERSION" >&2
    echo "Supported versions: 0.14.0, 0.8.0, 0.4.0" >&2
    exit 2
    ;;
esac

mkdir -p "$BUILD_DIR" "$RUN_DIR"

IMAGE_NAME="pqcdf-baseline-cryptofuzz"

if [ "${PQCDF_CRYPTOFUZZ_IN_DOCKER:-0}" != "1" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to build cryptofuzz/liboqs through this wrapper." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed, but the Docker daemon is not available to this user." >&2
    exit 1
  fi
  if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Docker image not found: $IMAGE_NAME" >&2
    echo "Run: scripts/run_baseline.sh cryptofuzz docker-build" >&2
    exit 1
  fi

  HOST_UID="$(id -u)"
  HOST_GID="$(id -g)"
  FORWARDED_ARGS=(
    scripts/baselines/cryptofuzz/build.sh
    "$BASELINE_DIR"
    "$BUILD_DIR"
    "$RUN_DIR"
    --version "$VERSION"
  )
  FORWARDED_ARGS+=("${MAKE_ARGS[@]}")

  docker run --rm \
    -e PQCDF_CRYPTOFUZZ_IN_DOCKER=1 \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    -e PQCDF_CHOWN_BUILD_DIR="$BUILD_DIR" \
    -e PQCDF_CHOWN_RUN_DIR="$RUN_DIR" \
    -v "$(pwd)":/workspace/PQC-DF \
    -w /workspace/PQC-DF \
    "$IMAGE_NAME" \
    bash -lc 'trap "chown -R ${HOST_UID}:${HOST_GID} \"${PQCDF_CHOWN_BUILD_DIR}\" \"${PQCDF_CHOWN_RUN_DIR}\" 2>/dev/null || true" EXIT; "$@"' \
    bash "${FORWARDED_ARGS[@]}"
  exit $?
fi

BUILD_DIR_ABS="$(realpath "$BUILD_DIR")"
BASELINE_DIR_ABS="$(realpath "$BASELINE_DIR")"
VERSION_BUILD_DIR="${BUILD_DIR_ABS}/liboqs-${VERSION}"
LIBOQS_SRC_DIR="${VERSION_BUILD_DIR}/liboqs-src"
LIBOQS_BUILD_DIR="${VERSION_BUILD_DIR}/liboqs-build"
CRYPTOFUZZ_BUILD_DIR="${VERSION_BUILD_DIR}/cryptofuzz"
LIBOQS_MODULE_BUILD_DIR="${VERSION_BUILD_DIR}/modules/liboqs"

mkdir -p "$VERSION_BUILD_DIR" "$LIBOQS_MODULE_BUILD_DIR" "$CRYPTOFUZZ_BUILD_DIR"

echo "[cryptofuzz] build directory: $BUILD_DIR"
echo "[cryptofuzz] run directory: $RUN_DIR"
echo "[cryptofuzz] liboqs version: $VERSION"
echo "[cryptofuzz] version build directory: $VERSION_BUILD_DIR"

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
SAN_CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined"
SAN_CXXFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined"

cmake -S "$LIBOQS_SRC_DIR" -B "$LIBOQS_BUILD_DIR" -GNinja \
  -DCMAKE_C_COMPILER="$CC_BIN" \
  -DCMAKE_CXX_COMPILER="$CXX_BIN" \
  -DCMAKE_ASM_COMPILER="$CC_BIN" \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="$SAN_CFLAGS" \
  -DCMAKE_CXX_FLAGS="$SAN_CXXFLAGS" \
  -DCMAKE_ASM_FLAGS="-fno-omit-frame-pointer"

cmake --build "$LIBOQS_BUILD_DIR" --target oqs --parallel "$PARALLEL_JOBS"

LIBOQS_ARCHIVE="${LIBOQS_BUILD_DIR}/lib/liboqs.a"
if [ ! -f "$LIBOQS_ARCHIVE" ]; then
  echo "Expected liboqs archive not found: $LIBOQS_ARCHIVE" >&2
  exit 1
fi

(
  cd "$CRYPTOFUZZ_BUILD_DIR"
  python3 "${BASELINE_DIR_ABS}/gen_repository.py"
)

CC="$CC_BIN" \
CXX="$CXX_BIN" \
CXXFLAGS="$SAN_CXXFLAGS" \
make -C "${BASELINE_DIR}/modules/liboqs" \
  BUILD_DIR="$LIBOQS_MODULE_BUILD_DIR" \
  REPOSITORY_INCLUDE_PATH="$CRYPTOFUZZ_BUILD_DIR" \
  OQS_INCLUDE_PATH="${LIBOQS_BUILD_DIR}/include"

CC="$CC_BIN" \
CXX="$CXX_BIN" \
CFLAGS="$SAN_CFLAGS" \
CXXFLAGS="$SAN_CXXFLAGS -DCRYPTOFUZZ_LIBOQS" \
make -C "$BASELINE_DIR" \
  BUILD_DIR="$CRYPTOFUZZ_BUILD_DIR" \
  EXTRA_MODULE_ARCHIVES="${LIBOQS_MODULE_BUILD_DIR}/module.a" \
  LINK_FLAGS="$LIBOQS_ARCHIVE -lcrypto -ldl -lpthread -lm" \
  LIBFUZZER_LINK="-fsanitize=fuzzer" \
  "${MAKE_ARGS[@]}"

echo "[cryptofuzz] built binary: ${CRYPTOFUZZ_BUILD_DIR}/cryptofuzz"
