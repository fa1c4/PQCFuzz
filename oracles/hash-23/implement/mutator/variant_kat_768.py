import importlib.util
import json
from pathlib import Path

_PACKAGE = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location('variant_common', _PACKAGE / 'implement/variant_common.py')
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)
_CORPUS = json.loads((_PACKAGE / 'data/kat_qilin768_subset.json').read_text(encoding='utf-8'))
_BITS = 768
_BACKENDS = ('reference', 'optimized')
_CANARY = False

def generate(seed, iteration):
    return _COMMON.kat_generate(seed, iteration, _CORPUS, _BITS, _BACKENDS)

def smoke_cases():
    return _COMMON.kat_smoke(_CORPUS, _BITS, _BACKENDS)
