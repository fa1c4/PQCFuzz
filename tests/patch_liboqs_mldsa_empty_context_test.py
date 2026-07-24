from __future__ import annotations

import importlib.util
import json
import sys
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "patch_liboqs_mldsa_empty_context.py"
SPEC = importlib.util.spec_from_file_location("patch_liboqs_mldsa_empty_context", MODULE_PATH)
assert SPEC and SPEC.loader
PATCHER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PATCHER
SPEC.loader.exec_module(PATCHER)


def write_sign_source(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "int sign(const unsigned char *ctx, unsigned long ctxlen) {\n"
        "  unsigned char pre[257];\n"
        "  memcpy(&pre[2], ctx, ctxlen);\n"
        "}\n"
        "int verify(const unsigned char *ctx, unsigned long ctxlen) {\n"
        "  unsigned char pre[257];\n"
        "  memcpy(&pre[2], ctx, ctxlen);\n"
        "}\n",
        encoding="utf-8",
    )


def write_safe_loop_source(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "int sign(const unsigned char *ctx, unsigned long ctxlen) {\n"
        "  unsigned char pre[257];\n"
        "  for (unsigned long i = 0; i < ctxlen; i++)\n"
        "    pre[2 + i] = ctx[i];\n"
        "}\n"
        "int verify(const unsigned char *ctx, unsigned long ctxlen) {\n"
        "  unsigned char pre[257];\n"
        "  for (unsigned long i = 0; i < ctxlen; ++i) {\n"
        "    pre[2 + i] = ctx[i];\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )


def test_mldsa_empty_context_patch_covers_ref_and_avx2_variants(tmp_path: Path) -> None:
    source_root = tmp_path / "liboqs"
    for implementation in PATCHER.IMPLEMENTATIONS:
        for parameter in ("44", "65", "87"):
            write_sign_source(
                source_root
                / "src"
                / "sig"
                / "ml_dsa"
                / f"pqcrystals-dilithium-standard_ml-dsa-{parameter}_{implementation}"
                / "sign.c"
            )

    manifest = PATCHER.apply_patch(source_root)

    assert manifest["state"] == "applied"
    assert manifest["replacements"] == 12
    for path in PATCHER.source_files(source_root):
        text = path.read_text(encoding="utf-8")
        assert "if (ctxlen > 0)" in text
        assert all(line != PATCHER.OLD for line in text.splitlines())

    assert PATCHER.apply_patch(source_root)["state"] == "already-applied"


def test_patch_cli_writes_a_manifest(tmp_path: Path) -> None:
    source_root = tmp_path / "liboqs"
    for implementation in PATCHER.IMPLEMENTATIONS:
        for parameter in ("44", "65", "87"):
            write_sign_source(
                source_root
                / "src"
                / "sig"
                / "ml_dsa"
                / f"pqcrystals-dilithium-standard_ml-dsa-{parameter}_{implementation}"
                / "sign.c"
            )

    manifest_path = tmp_path / "manifest.json"
    subprocess.run(
        [sys.executable, str(MODULE_PATH), "--source-root", str(source_root), "--manifest", str(manifest_path)],
        check=True,
        text=True,
        capture_output=True,
    )
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["patch_id"] == PATCHER.PATCH_ID


def test_safe_loop_layout_is_recorded_without_modifying_liboqs(tmp_path: Path) -> None:
    source_root = tmp_path / "liboqs"
    for implementation in PATCHER.IMPLEMENTATIONS:
        for parameter in ("44", "65", "87"):
            write_safe_loop_source(
                source_root
                / "src"
                / "sig"
                / "ml_dsa"
                / f"pqcrystals-dilithium-standard_ml-dsa-{parameter}_{implementation}"
                / "sign.c"
            )

    before = {path: path.read_text(encoding="utf-8") for path in PATCHER.source_files(source_root)}
    manifest = PATCHER.apply_patch(source_root)

    assert manifest["state"] == "not-required"
    assert manifest["replacements"] == 0
    assert len(manifest["already_safe"]) == PATCHER.EXPECTED_FILES
    assert {path: path.read_text(encoding="utf-8") for path in PATCHER.source_files(source_root)} == before
