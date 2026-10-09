"""Reproducible Litchi-XOF core-to-wrapper intervention."""
import json
import random
from pathlib import Path


_CORPUS = json.loads((Path(__file__).resolve().parents[2] / "data/kat_1024_subset.json").read_text())
_RATE_BITS = 576
_BOUNDARY_LENGTHS = (0, 1, 7, 8, 63, 64, 65,
                     _RATE_BITS - 1, _RATE_BITS, _RATE_BITS + 1,
                     1023, 1024, 1025)


def _pair(message_hex, message_bits, out_bits, expected=None, record_index=None):
    baseline = {"backend": "core", "message_hex": message_hex,
                "message_bits": message_bits, "out_bits": out_bits}
    mutated = dict(baseline, backend="wrapper")
    case = {"baseline": baseline, "mutated": mutated,
            "changed_fields": ["backend"],
            "intervention": "switch from submitted XOF core to CryptHash wrapper at the same requested bit length",
            "effective": baseline["backend"] != mutated["backend"] and
                         all(baseline[key] == mutated[key] for key in
                             ("message_hex", "message_bits", "out_bits")),
            "effectiveness_evidence": {"same_message": True,
                                       "same_bit_length": True,
                                       "same_requested_output_bits": True,
                                       "baseline_backend": "core",
                                       "mutated_backend": "wrapper"}}
    if expected is not None:
        case["submitted_kat_digest"] = expected
        case["submitted_kat_provenance"] = {
            "path": _CORPUS["source_path"], "sha256": _CORPUS["source_sha256"],
            "record_index": record_index}
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
        vector = _CORPUS["records"][(seed + iteration // 4) % len(_CORPUS["records"])]
        return _pair(vector["message_hex"], vector["message_bits"], 1024,
                     vector["digest_hex"], vector["source_record_index"])
    message_hex, length = _random_message(seed, iteration)
    return _pair(message_hex, length, (512, 768, 1024)[iteration % 3])


def smoke_cases():
    vector = next(item for item in _CORPUS["records"] if item["message_bits"] == _RATE_BITS)
    positive = _pair(vector["message_hex"], vector["message_bits"], 1024,
                     vector["digest_hex"], vector["source_record_index"])
    repeated = dict(positive["baseline"])
    negative = {"baseline": repeated, "mutated": dict(repeated),
                "changed_fields": [], "intervention": "none", "effective": False,
                "effectiveness_evidence": {"identical_structured_input": True}}
    return {"positive": positive, "negative": negative}
