"""Bind one exact parameter set and public API to the shared relation."""
import importlib.util
from pathlib import Path

INSTANCE = 'SHUTTLE-512'
API = 'sig_keygen'
_PATH = Path(__file__).resolve().parents[1] / 'implement/full_api_common.py'
_SPEC = importlib.util.spec_from_file_location('a_full_api_common', _PATH)
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

def evaluate(case, baseline, mutated):
    return _COMMON.evaluate(INSTANCE, API, case, baseline, mutated)

def fault_observation(mutated):
    return _COMMON.fault_observation(API, mutated)
