"""Bind one exact parameter set and public API to the shared relation."""
import importlib.util
from pathlib import Path

INSTANCE = 'NTRE-512'
API = 'kem_get_ss_len_bytes'
_PATH = Path(__file__).resolve().parents[2] / 'implement/full_api_common.py'
_SPEC = importlib.util.spec_from_file_location('a_full_api_common', _PATH)
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

def generate(seed, iteration):
    return _COMMON.generate(INSTANCE, API, seed, iteration)

def smoke_cases():
    return _COMMON.smoke_cases(INSTANCE, API)
