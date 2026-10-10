"""Bind one exact hash instance to its source-pinned P1 KAT corpus."""
import importlib.util
import json
from pathlib import Path
_PACKAGE = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("a_hash_common", _PACKAGE / "implement/common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)
_CORPUS = json.loads((_PACKAGE / "data/kat_mastercube768.json").read_text())

def evaluate(case, baseline, mutated):
    return _COMMON.kat_evaluate(case, baseline, mutated, _CORPUS, 768, ("reference",), True)

def fault_observation(mutated):
    return _COMMON.fault_observation(mutated)
