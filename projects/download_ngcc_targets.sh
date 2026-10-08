#!/usr/bin/env bash
# Download all 119 NGCC Round 1 candidate submission archives and design PDFs.
# The submissions are proposals, not promulgated GB/T or GM/T standards.
# Usage:
#   projects/download_ngcc_targets.sh                 # download all 119
#   projects/download_ngcc_targets.sh --target kem-29 # one candidate
#   projects/download_ngcc_targets.sh --dry-run       # validate all 119 mappings
#   projects/download_ngcc_targets.sh --verify-only --target kem-29
# Requires Python 3.10+ and HTTPS access to NICCS and raw.githubusercontent.com.
# Original ZIPs, extracted trees, matching specification PDFs and receipts are
# stored in third_party/<candidate-id>/. Nested RAR source packages are
# expanded under source/_nested/ with bsdtar and recorded in download.json.
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
if command -v cygpath >/dev/null 2>&1; then
  repo_root=$(cygpath -w "$repo_root")
fi
export PQCFUZZ_NGCC_ROOT="$repo_root"

python_bin=""
if [ -n "${PQCFUZZ_PYTHON:-}" ]; then
  python_bin="$PQCFUZZ_PYTHON"
else
  for candidate in python3 python; do
    if "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
      python_bin="$candidate"
      break
    fi
  done
fi
if [ -z "$python_bin" ]; then
  echo "error: Python 3.10+ is required (set PQCFUZZ_PYTHON)" >&2
  exit 2
fi

"$python_bin" - "$@" <<'PY'
import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(os.environ["PQCFUZZ_NGCC_ROOT"]).resolve()
THIRD_PARTY = (ROOT / "third_party").resolve()
CATALOG = ROOT / "projects" / "ngcc_targets.json"
EXPECTED_COUNTS = {"sign": 34, "kem": 41, "kex": 9, "hash": 35}
USER_AGENT = "PQCFuzz-NGCC-downloader/1.0 (+https://ngcc.dev/reports/index.html)"


class DownloadError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise DownloadError(message)



def io_path(path):
    path = Path(path)
    if os.name == "nt":
        raw = str(path.absolute())
        prefix = chr(92) * 2 + "?" + chr(92)
        if not raw.startswith(prefix):
            raw = prefix + raw
        return Path(raw)
    return path


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_tree_sha256(root):
    root = io_path(root)
    digest = hashlib.sha256()
    require(not any(p.is_symlink() for p in root.rglob("*")), "symlink in extracted source")
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(bytes.fromhex(file_sha256(path)))
    return digest.hexdigest()


def validate_catalog():
    require(CATALOG.is_file(), "missing projects/ngcc_targets.json")
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    require(catalog.get("schema_version") == 1, "unsupported target catalog schema")
    targets = catalog.get("targets")
    require(isinstance(targets, list) and len(targets) == 119, "catalog must contain 119 targets")
    commit = catalog.get("source_catalog_commit", "")
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit),
            "invalid source catalog commit")
    ids = set()
    counts = {category: 0 for category in EXPECTED_COUNTS}
    for item in targets:
        identifier = item.get("id")
        require(isinstance(identifier, str) and re.fullmatch(r"(sign|kem|kex|hash)-[0-9]{2}", identifier),
                "invalid candidate ID")
        require(identifier not in ids, "duplicate candidate ID: " + identifier)
        ids.add(identifier)
        category = item.get("category")
        require(category == identifier.split("-")[0], "category/ID mismatch: " + identifier)
        counts[category] += 1
        require(re.fullmatch("[0-9a-f]{64}", item.get("official_archive_sha256", "")),
                "missing archive SHA-256: " + identifier)
        for key, hosts in (("official_archive_url", {"www.niccs.org.cn", "niccs.org.cn"}),
                           ("spec_pdf_url", {"raw.githubusercontent.com"})):
            parsed = urllib.parse.urlparse(item.get(key, ""))
            require(parsed.scheme == "https" and parsed.hostname in hosts and not parsed.username,
                    "untrusted " + key + " for " + identifier)
        require("/" + commit + "/" in item["spec_pdf_url"], "unversioned spec PDF URL")
        require(item["spec_pdf_url"].endswith("/" + identifier + "/" + identifier + "-spec.pdf"),
                "spec PDF identity mismatch: " + identifier)
        require(item["report_url"] == "https://ngcc.dev/reports/" + identifier + ".html",
                "report identity mismatch: " + identifier)
    require(counts == EXPECTED_COUNTS, "candidate category count mismatch: " + repr(counts))
    for category, count in EXPECTED_COUNTS.items():
        expected = {f"{category}-{number:02d}" for number in range(1, count + 1)}
        require(expected.issubset(ids), "missing IDs in " + category)
    return catalog, targets


def download(url, destination, max_bytes, attempts):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_error = None
    for attempt in range(1, attempts + 1):
        digest = hashlib.sha256()
        received = 0
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                final = urllib.parse.urlparse(response.url)
                require(final.scheme == "https", "download redirected off HTTPS: " + url)
                with destination.open("xb") as output:
                    while True:
                        block = response.read(1024 * 1024)
                        if not block:
                            break
                        received += len(block)
                        require(received <= max_bytes, "download exceeds byte limit: " + url)
                        digest.update(block)
                        output.write(block)
            return received, digest.hexdigest(), response.url
        except (OSError, urllib.error.URLError, TimeoutError, DownloadError) as exc:
            last_error = exc
            destination.unlink(missing_ok=True)
            if attempt < attempts:
                time.sleep(min(2 ** attempt, 8))
    raise DownloadError("download failed after " + str(attempts) + " attempts: " +
                        url + " (" + str(last_error) + ")")


def safe_parts(name):
    require(name and not name.startswith(("/", "\\")) and "\\" not in name and "\x00" not in name,
            "unsafe ZIP member name")
    parts = name.rstrip("/").split("/")
    require(parts and all(part not in ("", ".", "..") for part in parts), "ZIP path traversal")
    for part in parts:
        require(":" not in part and not part.endswith((" ", ".")), "invalid Windows ZIP name")
        stem = part.split(".")[0].upper()
        require(stem not in {"CON", "PRN", "AUX", "NUL"} and
                not re.fullmatch(r"(COM|LPT)[1-9]", stem), "reserved Windows ZIP name")
    return parts


def extract_archive(archive_path, source_root, max_unpacked):
    source_root = io_path(source_root)
    source_root.mkdir()
    seen = set()
    member_count = 0
    unpacked = 0
    nested = []
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            parts = safe_parts(info.filename)
            relative = "/".join(parts)
            mode = info.external_attr >> 16
            require(not stat.S_ISLNK(mode), "ZIP symlink rejected: " + relative)
            destination = source_root.joinpath(*parts)
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            folded = relative.casefold()
            require(folded not in seen, "duplicate ZIP member: " + relative)
            seen.add(folded)
            member_count += 1
            require(member_count <= 200000, "too many ZIP members")
            unpacked += info.file_size
            require(unpacked <= max_unpacked, "unpacked source exceeds byte limit")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, destination.open("xb") as output:
                copied = shutil.copyfileobj(source, output, length=1024 * 1024)
            require(destination.stat().st_size == info.file_size,
                    "ZIP extracted size mismatch: " + relative)
            if mode & 0o111:
                destination.chmod(0o755)
            if relative.lower().endswith((".rar", ".7z")):
                nested.append(relative)
    require(member_count > 0, "empty submission archive")
    return member_count, unpacked, nested



def find_bsdtar():
    if os.name == "nt":
        candidate = Path(os.environ.get("SystemRoot", "C:" + chr(92) + "Windows")) / "System32/tar.exe"
        if candidate.is_file():
            result = subprocess.run([str(candidate), "--version"], capture_output=True, timeout=10)
            if b"bsdtar" in result.stdout.lower():
                return str(candidate)
    candidate = shutil.which("bsdtar")
    require(candidate is not None, "nested RAR source requires bsdtar (7-Zip alone is not used)")
    return candidate


def expand_nested_rars(source_root, nested, max_unpacked):
    if not nested:
        return []
    bsdtar = find_bsdtar()
    expanded = []
    nested_root = io_path(source_root) / "_nested"
    require(not nested_root.exists(), "nested extraction directory already exists")
    for number, relative in enumerate(nested, 1):
        require(relative.lower().endswith(".rar"), "unsupported nested archive: " + relative)
        archive = io_path(source_root).joinpath(*relative.split("/"))
        listing = subprocess.run([bsdtar, "-tf", str(archive)],
                                 capture_output=True, timeout=300)
        require(listing.returncode == 0, "cannot list nested RAR: " + relative)
        names = listing.stdout.decode("utf-8", "replace").splitlines()
        require(names, "empty nested RAR: " + relative)
        for name in names:
            safe_parts(name)
        verbose = subprocess.run([bsdtar, "-tvf", str(archive)],
                                 capture_output=True, timeout=300)
        require(verbose.returncode == 0 and not any(
            line[:1] in (b"l", b"h") for line in verbose.stdout.splitlines()),
            "nested RAR contains link entries: " + relative)
        output = nested_root / (str(number) + "-" + Path(relative).stem)
        output.mkdir(parents=True)
        result = subprocess.run([bsdtar, "-xf", str(archive), "-C", str(output)],
                                capture_output=True, timeout=1200)
        require(result.returncode == 0, "nested RAR extraction failed: " +
                relative + " (" + result.stderr.decode("utf-8", "replace")[-500:] + ")")
        require(not any(p.is_symlink() for p in output.rglob("*")),
                "nested RAR produced symlink: " + relative)
        files = [p for p in output.rglob("*") if p.is_file()]
        require(files, "nested RAR produced no source files: " + relative)
        expanded.append(output.relative_to(io_path(source_root)).as_posix())
    total = sum(p.stat().st_size for p in io_path(source_root).rglob("*") if p.is_file())
    require(total <= max_unpacked, "nested extraction exceeds byte limit")
    return expanded


def embedded_spec_paths(source_root, pdf_hash):
    source_root = io_path(source_root)
    matches = []
    for path in source_root.rglob("*"):
        if path.is_file() and path.suffix.lower() == ".pdf" and file_sha256(path) == pdf_hash:
            matches.append(path.relative_to(source_root).as_posix())
    return matches


def select_official_spec(source_root):
    source_root = io_path(source_root)
    choices = []
    for path in source_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() != ".pdf":
            continue
        relative = path.relative_to(source_root).as_posix()
        lower = relative.lower()
        if "algorithm specifications" in lower or "algorithm_text" in lower or "algorithm text" in lower:
            choices.append((relative, path))
    require(len(choices) == 1, "mirror mismatch and official algorithm PDF is not unique: " +
            repr([name for name, _ in choices]))
    return choices[0]

def verify_existing(item, directory):
    identifier = item["id"]
    receipt_path = directory / "download.json"
    require(receipt_path.is_file(), identifier + ": existing directory lacks download.json")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    require(receipt.get("candidate_id") == identifier, identifier + ": receipt ID mismatch")
    require(receipt.get("archive_url") == item["official_archive_url"], identifier + ": archive URL changed")
    require(receipt.get("archive_sha256") == item["official_archive_sha256"],
            identifier + ": catalog archive SHA changed")
    archive_path = directory / "original" / "submission.zip"
    pdf_path = directory / "specification.pdf"
    source_root = directory / "source"
    require(archive_path.is_file() and pdf_path.is_file() and source_root.is_dir(),
            identifier + ": incomplete target directory")
    require(file_sha256(archive_path) == item["official_archive_sha256"],
            identifier + ": original archive digest mismatch")
    require(pdf_path.open("rb").read(5) == b"%PDF-", identifier + ": invalid PDF")
    require(file_sha256(pdf_path) == receipt.get("spec_pdf_sha256"),
            identifier + ": specification digest mismatch")
    require(source_tree_sha256(source_root) == receipt.get("source_tree_sha256"),
            identifier + ": source tree changed")
    require(not receipt.get("nested_archives_needing_separate_extraction"),
            identifier + ": nested source archives are not expanded")
    for relative in receipt.get("nested_archives_extracted", []):
        require((io_path(source_root) / relative).is_dir(),
                identifier + ": nested source tree missing")
    matches = embedded_spec_paths(source_root, receipt["spec_pdf_sha256"])
    require(matches, identifier + ": PDF no longer matches official archive")
    if receipt.get("spec_pdf_source_archive_member"):
        require(receipt["spec_pdf_source_archive_member"] in matches,
                identifier + ": official spec member changed")
    else:
        require(receipt.get("spec_pdf_url") == item["spec_pdf_url"],
                identifier + ": mirror PDF URL changed")
    recorded = receipt.get("official_embedded_spec_paths")
    require(recorded is None or sorted(recorded) == sorted(matches),
            identifier + ": embedded specification path changed")
    return "verified-existing"


def process_target(item, args, catalog):
    identifier = item["id"]
    destination = THIRD_PARTY / identifier
    require(destination.parent.resolve() == THIRD_PARTY, "invalid target directory")
    require(not destination.is_symlink(), "target directory is a symlink: " + identifier)
    if args.dry_run:
        return identifier, "planned", item["official_archive_url"]
    if destination.exists():
        return identifier, verify_existing(item, destination), str(destination)
    if args.verify_only:
        raise DownloadError(identifier + ": not downloaded")
    stage = Path(tempfile.mkdtemp(prefix=".ngcc-stage-" + identifier + "-", dir=THIRD_PARTY))
    require(stage.resolve().parent == THIRD_PARTY, "temporary directory outside third_party")
    try:
        (stage / "original").mkdir()
        archive_path = stage / "original" / "submission.zip"
        archive_bytes, archive_hash, archive_final = download(
            item["official_archive_url"], archive_path, args.max_archive_gb * (1024 ** 3), args.retries)
        require(archive_hash == item["official_archive_sha256"],
                identifier + ": official archive SHA-256 mismatch; received " + archive_hash)
        known_size = item.get("official_archive_size")
        require(known_size is None or known_size == archive_bytes,
                identifier + ": official archive size mismatch")
        pdf_path = stage / "specification.pdf"
        pdf_bytes, pdf_hash, pdf_final = download(
            item["spec_pdf_url"], pdf_path, args.max_pdf_mb * (1024 ** 2), args.retries)
        with pdf_path.open("rb") as stream:
            require(stream.read(5) == b"%PDF-", identifier + ": specification is not a PDF")
        member_count, unpacked_bytes, nested = extract_archive(
            archive_path, stage / "source", args.max_unpacked_gb * (1024 ** 3))
        expanded_nested = expand_nested_rars(
            stage / "source", nested, args.max_unpacked_gb * (1024 ** 3))
        all_source_files = [p for p in io_path(stage / "source").rglob("*") if p.is_file()]
        unpacked_bytes = sum(p.stat().st_size for p in all_source_files)
        embedded_specs = embedded_spec_paths(stage / "source", pdf_hash)
        source_member = None
        mirror_hash = None
        if not embedded_specs:
            source_member, official_pdf = select_official_spec(stage / "source")
            mirror_hash = pdf_hash
            shutil.copy2(official_pdf, pdf_path)
            pdf_hash = file_sha256(pdf_path)
            pdf_bytes = pdf_path.stat().st_size
            embedded_specs = embedded_spec_paths(stage / "source", pdf_hash)
            require(source_member in embedded_specs, identifier + ": official spec copy mismatch")
        receipt = {
            "schema_version": 1,
            "candidate_id": identifier,
            "target_name": identifier,
            "algorithm": item["algorithm"],
            "category": item["category"],
            "material_status": "candidate_proposal_not_promulgated_standard",
            "source_identity_kind": "non_git_official_submission_zip",
            "source_commit": None,
            "archive_url": item["official_archive_url"],
            "archive_final_url": archive_final,
            "archive_name": item["archive_name"],
            "archive_sha256": archive_hash,
            "archive_bytes": archive_bytes,
            "official_page_url": item["official_page_url"],
            "spec_pdf_url": item["official_archive_url"] if source_member else item["spec_pdf_url"],
            "spec_pdf_final_url": archive_final if source_member else pdf_final,
            "spec_pdf_source_archive_member": source_member,
            "mirror_spec_pdf_url": item["spec_pdf_url"] if source_member else None,
            "mirror_spec_pdf_sha256": mirror_hash,
            "spec_pdf_sha256": pdf_hash,
            "spec_pdf_bytes": pdf_bytes,
            "spec_pdf_provenance": ("official ZIP; pinned mirror differs" if source_member else
                                    "ngcc-harness mirror at pinned commit; bytes matched official ZIP"),
            "official_embedded_spec_paths": embedded_specs,
            "source_catalog_commit": catalog["source_catalog_commit"],
            "source_catalog_downloads_sha256": catalog["downloads_csv_sha256"],
            "source_catalog_hashes_sha256": catalog["source_archives_md_sha256"],
            "source_tree_sha256": source_tree_sha256(stage / "source"),
            "source_members": member_count,
            "source_total_files": len(all_source_files),
            "source_unpacked_bytes": unpacked_bytes,
            "nested_archives_extracted": expanded_nested,
            "nested_archives_needing_separate_extraction": [],
            "downloaded_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        (stage / "download.json").write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            stage.rename(destination)
        except FileExistsError:
            return identifier, verify_existing(item, destination), str(destination)
        return identifier, "downloaded", str(destination)
    finally:
        if stage.exists():
            require(stage.resolve().parent == THIRD_PARTY and
                    stage.name.startswith(".ngcc-stage-" + identifier + "-"),
                    "unsafe cleanup target")
            shutil.rmtree(io_path(stage))


def main():
    parser = argparse.ArgumentParser(
        description="Download 119 NGCC Round 1 candidate source ZIPs and specification PDFs")
    parser.add_argument("--target", action="append", help="candidate ID; repeatable, default: all 119")
    parser.add_argument("--jobs", type=int, default=4, help="parallel targets (1-16)")
    parser.add_argument("--dry-run", action="store_true", help="show planned official ZIP URLs")
    parser.add_argument("--verify-only", action="store_true", help="verify existing targets without downloads")
    parser.add_argument("--list", action="store_true", help="list IDs and algorithm names")
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--max-archive-gb", type=int, default=4)
    parser.add_argument("--max-unpacked-gb", type=int, default=20)
    parser.add_argument("--max-pdf-mb", type=int, default=100)
    args = parser.parse_args()
    require(1 <= args.jobs <= 16 and 1 <= args.retries <= 10, "invalid jobs/retries")
    require(args.max_archive_gb > 0 and args.max_unpacked_gb > 0 and args.max_pdf_mb > 0,
            "invalid size limit")
    catalog, all_targets = validate_catalog()
    by_id = {item["id"]: item for item in all_targets}
    selected_ids = args.target or [item["id"] for item in all_targets]
    require(len(selected_ids) == len(set(selected_ids)), "duplicate --target")
    unknown = sorted(set(selected_ids) - by_id.keys())
    require(not unknown, "unknown candidate IDs: " + ", ".join(unknown))
    selected = [by_id[identifier] for identifier in selected_ids]
    if args.list:
        for item in selected:
            print(item["id"] + "\t" + item["algorithm"])
        return 0
    THIRD_PARTY.mkdir(parents=True, exist_ok=True)
    require(THIRD_PARTY.is_relative_to(ROOT), "third_party outside repository")
    successes = 0
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {executor.submit(process_target, item, args, catalog): item["id"] for item in selected}
        for future in concurrent.futures.as_completed(futures):
            identifier = futures[future]
            try:
                target, status, detail = future.result()
                print(target + "\t" + status + "\t" + detail, flush=True)
                successes += 1
            except Exception as exc:
                print(identifier + "\tFAILED\t" + str(exc), file=sys.stderr, flush=True)
                failures.append(identifier)
    print(json.dumps({"selected": len(selected), "succeeded": successes,
                      "failed": len(failures), "failed_ids": sorted(failures),
                      "known_archive_bytes": sum(item.get("official_archive_size") or 0 for item in selected),
                      "unknown_archive_sizes": sum(item.get("official_archive_size") is None for item in selected)}),
          flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DownloadError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
PY
