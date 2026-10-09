"""Shared, run-local X05/P1 and X05/P3 relations for one pinned hash instance.

Thin instance modules bind an exact submitted KAT corpus, digest size and
backend pair. No target is selected from process-global state.
"""
import random


def _input(record, backend, digest_bits):
    return {"backend": backend, "message_hex": record["message_hex"],
            "message_bits": record["message_bits"], "digest_bits": digest_bits}


def _record_by_index(corpus):
    return {row["source_record_index"]: row for row in corpus["records"]}


def _provenance(corpus, **indexes):
    return {"path": corpus["source_path"], "sha256": corpus["source_sha256"], **indexes}


def _random_message(seed, iteration):
    rng = random.Random((seed << 32) ^ iteration)
    boundaries = (0, 1, 7, 8, 63, 64, 65, 511, 512, 513,
                  1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096)
    bits = boundaries[iteration % len(boundaries)] if iteration % 3 != 2 else rng.randrange(0, 4097)
    data = bytearray(rng.randbytes((bits + 7) // 8))
    if bits % 8:
        data[-1] &= 0xff << (8 - bits % 8)
    return {"message_hex": data.hex(), "message_bits": bits}


def _diff_pair(record, digest_bits, backends, corpus=None, index=None):
    baseline = _input(record, backends[0], digest_bits)
    mutated = dict(baseline, backend=backends[1])
    case = {"baseline": baseline, "mutated": mutated,
            "changed_fields": ["backend"],
            "intervention": "switch submitted implementation for the exact same bitstring",
            "effective": baseline["backend"] != mutated["backend"],
            "effectiveness_evidence": {"same_message": True, "same_bit_length": True,
                                       "same_digest_length": True,
                                       "baseline_backend": backends[0],
                                       "mutated_backend": backends[1]}}
    if corpus is not None:
        case["submitted_kat_digest"] = record["digest_hex"]
        case["submitted_kat_provenance"] = _provenance(corpus, record_index=index)
    return case


def diff_generate(seed, iteration, corpus, digest_bits, backends):
    if iteration % 4 == 0:
        rows = corpus["records"]
        row = rows[(seed + iteration // 4) % len(rows)]
        return _diff_pair(row, digest_bits, backends, corpus, row["source_record_index"])
    return _diff_pair(_random_message(seed, iteration), digest_bits, backends)


def diff_smoke(corpus, digest_bits, backends):
    rows = _record_by_index(corpus)
    first = next(row for row in rows.values() if row["message_bits"] == 512)
    positive = _diff_pair(first, digest_bits, backends, corpus, first["source_record_index"])
    repeated = dict(positive["baseline"])
    negative = {"baseline": repeated, "mutated": dict(repeated),
                "changed_fields": [], "intervention": "none", "effective": False,
                "effectiveness_evidence": {"identical_structured_input": True}}
    return {"positive": positive, "negative": negative}


def _kat_pair(first, second, digest_bits, backend, corpus):
    baseline = _input(first, backend, digest_bits)
    mutated = _input(second, backend, digest_bits)
    changed = [key for key in ("message_hex", "message_bits") if baseline[key] != mutated[key]]
    return {"baseline": baseline, "mutated": mutated,
            "baseline_expected": first["digest_hex"],
            "mutated_expected": second["digest_hex"],
            "kat_provenance": _provenance(corpus,
                                          baseline_record_index=first["source_record_index"],
                                          mutated_record_index=second["source_record_index"]),
            "changed_fields": changed,
            "intervention": "switch between exact submitted KAT records on one backend" if changed else "none",
            "effective": bool(changed) and first["source_record_index"] != second["source_record_index"],
            "effectiveness_evidence": {"source_record_changed":
                                       first["source_record_index"] != second["source_record_index"],
                                       "same_backend": True, "same_digest_length": True}}


def kat_generate(seed, iteration, corpus, digest_bits, backends):
    rows = corpus["records"]
    index = (seed + iteration) % len(rows)
    return _kat_pair(rows[index], rows[(index + 1) % len(rows)], digest_bits,
                     backends[iteration % len(backends)], corpus)


def kat_smoke(corpus, digest_bits, backends):
    rows = _record_by_index(corpus)
    first = next(row for row in rows.values() if row["message_bits"] == 512)
    second = next(row for row in rows.values() if row["message_bits"] == 513)
    return {"positive": _kat_pair(first, second, digest_bits, backends[0], corpus),
            "negative": _kat_pair(first, first, digest_bits, backends[0], corpus)}


def _observation(observation, digest_bytes, canary):
    return (isinstance(observation, dict) and observation.get("reached") is True and
            observation.get("status") == "ok" and
            observation.get("output_length") == digest_bytes and
            isinstance(observation.get("output"), str) and
            len(observation["output"]) == 2 * digest_bytes and
            (not canary or observation.get("guard_modified") is False))


def _exact_kat_input(value, expected, index, corpus, digest_bits):
    rows = _record_by_index(corpus)
    if not isinstance(value, dict) or not isinstance(index, int) or index not in rows:
        return False
    row = rows[index]
    return (value.get("message_hex") == row["message_hex"] and
            value.get("message_bits") == row["message_bits"] and
            value.get("digest_bits") == digest_bits and expected == row["digest_hex"])


def diff_evaluate(case, baseline, mutated, corpus, digest_bits, backends, canary=False):
    left, right = case.get("baseline"), case.get("mutated")
    if not isinstance(left, dict) or not isinstance(right, dict):
        left, right = {}, {}
    provenance = case.get("submitted_kat_provenance")
    kat = case.get("submitted_kat_digest")
    kat_valid = kat is None
    if kat is not None and isinstance(provenance, dict):
        kat_valid = (provenance.get("path") == corpus["source_path"] and
                     provenance.get("sha256") == corpus["source_sha256"] and
                     _exact_kat_input(left, kat, provenance.get("record_index"), corpus, digest_bits))
    applicable = (left.get("backend") == backends[0] and right.get("backend") == backends[1] and
                  left.get("message_hex") == right.get("message_hex") and
                  left.get("message_bits") == right.get("message_bits") and
                  left.get("digest_bits") == right.get("digest_bits") == digest_bits and kat_valid)
    observable = (_observation(baseline, digest_bits // 8, canary) and
                  _observation(mutated, digest_bits // 8, canary))
    holds = (baseline.get("output") == mutated.get("output") and
             (kat is None or baseline.get("output") == mutated.get("output") == kat))
    return {"applicable": bool(applicable), "observable": bool(observable), "holds": bool(holds),
            "expected": "identical submitted implementations on the same valid input" +
                        (" and exact KAT digest" if kat is not None else ""),
            "actual": {backends[0]: baseline.get("output"), backends[1]: mutated.get("output"),
                       "submitted_kat": kat},
            "explanation": "source-pinned same-instance differential comparison"}


def kat_evaluate(case, baseline, mutated, corpus, digest_bits, backends, canary=False):
    left, right = case.get("baseline"), case.get("mutated")
    provenance = case.get("kat_provenance")
    if not isinstance(left, dict) or not isinstance(right, dict):
        left, right = {}, {}
    if not isinstance(provenance, dict):
        provenance = {}
    applicable = (left.get("backend") == right.get("backend") and
                  left.get("backend") in backends and
                  left.get("digest_bits") == right.get("digest_bits") == digest_bits and
                  provenance.get("path") == corpus["source_path"] and
                  provenance.get("sha256") == corpus["source_sha256"] and
                  _exact_kat_input(left, case.get("baseline_expected"),
                                   provenance.get("baseline_record_index"), corpus, digest_bits) and
                  _exact_kat_input(right, case.get("mutated_expected"),
                                   provenance.get("mutated_record_index"), corpus, digest_bits))
    observable = (_observation(baseline, digest_bits // 8, canary) and
                  _observation(mutated, digest_bits // 8, canary))
    holds = (baseline.get("output") == case.get("baseline_expected") and
             mutated.get("output") == case.get("mutated_expected"))
    return {"applicable": bool(applicable), "observable": bool(observable), "holds": bool(holds),
            "expected": "each exact submitted KAT row matches its own digest",
            "actual": {"baseline": baseline.get("output"), "mutated": mutated.get("output"),
                       "baseline_kat": case.get("baseline_expected"),
                       "mutated_kat": case.get("mutated_expected")},
            "explanation": "two source-pinned submitted KAT records on one backend"}


def fault_observation(mutated):
    altered = dict(mutated)
    output = altered.get("output")
    if isinstance(output, str) and len(output) >= 2:
        altered["output"] = f"{int(output[:2], 16) ^ 1:02x}" + output[2:]
    return altered
