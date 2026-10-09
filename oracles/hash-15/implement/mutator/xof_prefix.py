"""P4: request two XOF output lengths for one exact bitstring."""
import json
import random
from pathlib import Path


_CORPUS = json.loads((Path(__file__).resolve().parents[2] / "data/kat_1024_subset.json").read_text())
_LENGTHS = ((512, 768), (512, 1024), (768, 1024))


def _pair(message_hex, message_bits, short, long, backend, row=None):
    baseline = {"backend": backend, "message_hex": message_hex,
                "message_bits": message_bits, "out_bits": short}
    mutated = dict(baseline, out_bits=long)
    case = {"baseline": baseline, "mutated": mutated,
            "changed_fields": ["out_bits"] if short != long else [],
            "intervention": "extend requested XOF output length" if short != long else "none",
            "effective": short != long,
            "effectiveness_evidence": {"same_message": True, "same_backend": True,
                                       "requested_bits_changed": short != long}}
    if row is not None and long == 1024:
        case["submitted_kat_digest"] = row["digest_hex"]
        case["submitted_kat_provenance"] = {
            "path": _CORPUS["source_path"], "sha256": _CORPUS["source_sha256"],
            "record_index": row["source_record_index"]}
    return case


def generate(seed, iteration):
    short, long = _LENGTHS[iteration % len(_LENGTHS)]
    backend = "core" if iteration % 2 == 0 else "wrapper"
    if iteration % 4 == 0:
        row = _CORPUS["records"][(seed + iteration // 4) % len(_CORPUS["records"])]
        return _pair(row["message_hex"], row["message_bits"], short, long, backend, row)
    rng = random.Random((seed << 32) ^ iteration)
    message_bits = (0, 1, 7, 8, 575, 576, 577, 1024, 4096)[iteration % 9]
    message = bytearray(rng.randbytes((message_bits + 7) // 8))
    if message_bits % 8:
        message[-1] &= 0xff << (8 - message_bits % 8)
    return _pair(message.hex(), message_bits, short, long, backend)


def smoke_cases():
    row = next(item for item in _CORPUS["records"] if item["message_bits"] == 576)
    positive = _pair(row["message_hex"], 576, 512, 1024, "core", row)
    negative = _pair(row["message_hex"], 576, 512, 512, "core")
    return {"positive": positive, "negative": negative}
