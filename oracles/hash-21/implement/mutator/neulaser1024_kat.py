"""Bind one exact hash instance to its source-pinned P1 KAT corpus."""
import importlib.util
import json
from pathlib import Path
_PACKAGE = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("a_hash_common", _PACKAGE / "implement/common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)
_CORPUS = json.loads((_PACKAGE / "data/kat_neulaser1024.json").read_text())

def generate(seed, iteration):
    return _COMMON.kat_generate(seed, iteration, _CORPUS, 1024, ("reference",))

def smoke_cases():
    return _COMMON.kat_smoke(_CORPUS, 1024, ("reference",))
