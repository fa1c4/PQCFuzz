import importlib.util
import json
from pathlib import Path

_PACKAGE = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location('variant_common', _PACKAGE / 'implement/variant_common.py')
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)
_CORPUS = json.loads((_PACKAGE / 'data/kat_llh768_subset.json').read_text(encoding='utf-8'))
_BITS = 768
_BACKENDS = ('reference', 'optimized')
_CANARY = False

def evaluate(case, baseline, mutated):
    return _COMMON.kat_evaluate(case, baseline, mutated, _CORPUS, _BITS, _BACKENDS, _CANARY)

def fault_observation(mutated):
    return _COMMON.fault_observation(mutated)
