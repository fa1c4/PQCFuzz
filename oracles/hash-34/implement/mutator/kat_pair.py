"""Pair exact submitted WChain-V1-512 KAT rows with preserved provenance."""
import json
from pathlib import Path


_CORPUS = json.loads((Path(__file__).resolve().parents[2] / "data/kat_512_subset.json").read_text())
_BACKENDS = ('reference', 'optimized')
_RATE_BITS = 1152


def _structured(vector, backend):
    return {"backend": backend, "message_hex": vector["message_hex"],
            "message_bits": vector["message_bits"], "digest_bits": 512}


def _pair(first, second, backend):
    baseline = _structured(first, backend)
    mutated = _structured(second, backend)
    changed = [key for key in ("message_hex", "message_bits") if baseline[key] != mutated[key]]
    return {"baseline": baseline, "mutated": mutated,
            "baseline_expected": first["digest_hex"],
            "mutated_expected": second["digest_hex"],
            "kat_provenance": {"path": _CORPUS["source_path"],
                               "sha256": _CORPUS["source_sha256"],
                               "baseline_record_index": first["source_record_index"],
                               "mutated_record_index": second["source_record_index"]},
            "changed_fields": changed,
            "intervention": "switch between exact submitted KAT records on the same backend" if changed else "none",
            "effective": bool(changed) and baseline["backend"] == mutated["backend"] and
                         baseline["digest_bits"] == mutated["digest_bits"],
            "effectiveness_evidence": {"source_record_changed":
                                       first["source_record_index"] != second["source_record_index"],
                                       "same_backend": baseline["backend"] == mutated["backend"],
                                       "same_output_profile": baseline["digest_bits"] == mutated["digest_bits"]}}


def generate(seed, iteration):
    records = _CORPUS["records"]
    index = (seed + iteration) % len(records)
    return _pair(records[index], records[(index + 1) % len(records)],
                 _BACKENDS[iteration % len(_BACKENDS)])


def smoke_cases():
    records = _CORPUS["records"]
    first = next(item for item in records if item["message_bits"] == _RATE_BITS)
    second = next(item for item in records if item["message_bits"] == _RATE_BITS + 1)
    return {"positive": _pair(first, second, _BACKENDS[0]),
            "negative": _pair(first, first, _BACKENDS[0])}
