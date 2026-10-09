"""Reproducible XRH-2-512 bitstring corpus with one backend intervention."""
import json
import random
from pathlib import Path


_CORPUS = json.loads((Path(__file__).resolve().parents[2] / "data" / "kat_512_subset.json").read_text())
_RATE_BITS = 704
_BOUNDARY_LENGTHS = (0, 1, 7, 8, 63, 64, 65,
                     _RATE_BITS - 1, _RATE_BITS, _RATE_BITS + 1,
                     2 * _RATE_BITS - 1, 2 * _RATE_BITS, 2 * _RATE_BITS + 1)


def _pair(message_hex, message_bits, expected=None, vector_index=None):
    baseline = {"backend": "reference", "message_hex": message_hex,
                "message_bits": message_bits, "digest_bits": 512}
    mutated = dict(baseline, backend="optimized")
    case = {"baseline": baseline, "mutated": mutated,
            "changed_fields": ["backend"],
            "intervention": "switch submitted XRH-2-512 backend while preserving the bitstring",
            "effective": baseline["backend"] != mutated["backend"] and
                         all(baseline[key] == mutated[key] for key in
                             ("message_hex", "message_bits", "digest_bits")),
            "effectiveness_evidence": {"same_message": True,
                                       "same_bit_length": True,
                                       "baseline_backend": "reference",
                                       "mutated_backend": "optimized"}}
    if expected is not None:
        case["submitted_kat_digest"] = expected
        case["submitted_kat_provenance"] = {
            "path": _CORPUS["source_path"], "sha256": _CORPUS["source_sha256"],
            "record_index": vector_index}
    return case


def _random_message(seed, iteration):
    rng = random.Random((seed << 32) ^ iteration)
    length = (_BOUNDARY_LENGTHS[iteration % len(_BOUNDARY_LENGTHS)]
              if iteration % 3 != 2 else rng.randrange(0, 4097))
    data = bytearray(rng.randbytes((length + 7) // 8))
    if length % 8:
        data[-1] &= 0xff << (8 - length % 8)
    return data.hex(), length


def generate(seed, iteration):
    if iteration % 4 == 0:
        index = (seed + iteration // 4) % len(_CORPUS["records"])
        vector = _CORPUS["records"][index]
        return _pair(vector["message_hex"], vector["message_bits"],
                     vector["digest_hex"], vector["source_record_index"])
    message_hex, length = _random_message(seed, iteration)
    return _pair(message_hex, length)


def smoke_cases():
    vector = next(item for item in _CORPUS["records"] if item["message_bits"] == _RATE_BITS)
    positive = _pair(vector["message_hex"], vector["message_bits"],
                     vector["digest_hex"], vector["source_record_index"])
    repeated = {"backend": "reference", "message_hex": vector["message_hex"],
                "message_bits": vector["message_bits"], "digest_bits": 512}
    negative = {"baseline": repeated, "mutated": dict(repeated),
                "changed_fields": [], "intervention": "none",
                "effective": False,
                "effectiveness_evidence": {"identical_structured_input": True}}
    return {"positive": positive, "negative": negative}
