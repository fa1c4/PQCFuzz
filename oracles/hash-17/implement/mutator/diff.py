import importlib.util
import json
from pathlib import Path
_PACKAGE = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("a_hash_common", _PACKAGE / "implement/common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)
_CORPUS = json.loads((_PACKAGE / "data/kat_512_subset.json").read_text())
_BACKENDS = ("reference", "optimized")

def generate(seed, iteration):
    return _COMMON.diff_generate(seed, iteration, _CORPUS, 512, _BACKENDS)

def smoke_cases():
    return _COMMON.diff_smoke(_CORPUS, 512, _BACKENDS)
