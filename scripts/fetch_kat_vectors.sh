#!/usr/bin/env bash
# Fetch the pinned NIST ACVP test-vector files used by the KAT oracle.
#
# Vectors are stored under third_party/kat/ (gitignored).  The parser reads
# them to emit the checked-in src/oracles/kat/generated_kat_vectors.inc.
#
# Usage: scripts/fetch_kat_vectors.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

acvp_commit="${ACVP_COMMIT:-975de31eb83d87039ec88934fdc47d8c312b892d}"
base="https://raw.githubusercontent.com/usnistgov/ACVP-Server/${acvp_commit}/gen-val/json-files"
out_root="third_party/kat/acvp-${acvp_commit}"
mkdir -p "$out_root"

files=(
  "ML-KEM-keyGen-FIPS203/prompt.json"
  "ML-KEM-keyGen-FIPS203/expectedResults.json"
  "ML-KEM-encapDecap-FIPS203/prompt.json"
  "ML-KEM-encapDecap-FIPS203/expectedResults.json"
  "SLH-DSA-keyGen-FIPS205/prompt.json"
  "SLH-DSA-keyGen-FIPS205/expectedResults.json"
)

manifest="$out_root/manifest.json"
{
  echo "{"
  echo "  \"source\": \"usnistgov/ACVP-Server\","
  echo "  \"commit\": \"$acvp_commit\","
  echo "  \"files\": {"
} > "$manifest"

first=1
for file in "${files[@]}"; do
  target="$out_root/$file"
  mkdir -p "$(dirname "$target")"
  if [[ ! -f "$target" ]]; then
    curl -sfL "$base/$file" -o "$target"
  fi
  digest="$(sha256sum "$target" | awk '{print $1}')"
  if [[ $first -eq 0 ]]; then
    echo "," >> "$manifest"
  fi
  first=0
  printf '    "%s": "%s"' "$file" "$digest" >> "$manifest"
done
{
  echo ""
  echo "  }"
  echo "}"
} >> "$manifest"

echo "fetched ACVP vectors into $out_root"
