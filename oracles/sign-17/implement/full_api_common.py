"""Exact source-KAT selection and public API relations for one A-tier instance."""
import json
from pathlib import Path


DATA = json.loads((Path(__file__).resolve().parents[1] / "data/instances.json").read_text())


def pair(instance, api, a, b):
    cfg = DATA[instance]
    left = {"instance": instance, "operation": api, "record_index": a}
    right = {"instance": instance, "operation": api, "record_index": b}
    distinct = a != b
    seed_distinct = (cfg["record_seed_sha256"][a] != cfg["record_seed_sha256"][b]
                     if distinct else False)
    return {"baseline": left, "mutated": right,
            "kat_provenance": {"path": cfg["kat"], "sha256": cfg["kat_sha256"]},
            "changed_fields": ["record_index"] if distinct else [],
            "intervention": "select a different public KAT record" if distinct else "none",
            "effective": distinct and seed_distinct,
            "effectiveness_evidence": {"distinct_record_indices": distinct,
                                       "distinct_public_seed_hashes": seed_distinct,
                                       "same_instance_and_api": True}}


def generate(instance, api, seed, iteration):
    a = (seed + iteration) % 10
    return pair(instance, api, a, (a + 1) % 10)


def smoke_cases(instance, api):
    return {"positive": pair(instance, api, 0, 1),
            "negative": pair(instance, api, 0, 0)}


def expected_length(cfg, api, index):
    kind = api.split("_get_", 1)[1].split("_len_bytes", 1)[0]
    key = ("Sn" if kind == "sn" else kind.upper()) + "_Len"
    return cfg["records"][index][key]


def evaluate(instance, api, case, baseline, mutated):
    cfg = DATA[instance]
    left, right = case.get("baseline"), case.get("mutated")
    provenance = case.get("kat_provenance")
    applicable = (isinstance(left, dict) and isinstance(right, dict) and
                  isinstance(provenance, dict) and
                  left.get("instance") == right.get("instance") == instance and
                  left.get("operation") == right.get("operation") == api and
                  provenance.get("path") == cfg["kat"] and
                  provenance.get("sha256") == cfg["kat_sha256"] and
                  all(isinstance(row.get("record_index"), int) and
                      not isinstance(row.get("record_index"), bool) and
                      0 <= row["record_index"] < 10 for row in (left, right)))
    getter = "_get_" in api
    expected = ([expected_length(cfg, api, row["record_index"])
                 for row in (left, right)] if applicable and getter else
                [True, True] if applicable else [None, None])
    observations = (baseline, mutated)
    observable = all(isinstance(obs, dict) and obs.get("reached") is True and
                     obs.get("api") == api and obs.get("parameter_set") == instance and
                     obs.get("record_index") == row["record_index"] and
                     api in obs.get("called", []) and
                     obs.get("output_length") == (8 if getter else 1) and
                     (isinstance(obs.get("output"), int) and
                      not isinstance(obs.get("output"), bool) if getter else
                      isinstance(obs.get("output"), bool))
                     for obs, row in zip(observations, (left, right))) if applicable else False
    if getter and api == "sig_get_sn_len_bytes" and cfg.get("variable_signature_length"):
        holds = observable and all(obs.get("output") >= value and obs.get("status") == "ok"
                                   for obs, value in zip(observations, expected))
    else:
        holds = observable and all(obs.get("output") == value and obs.get("status") == "ok"
                                   for obs, value in zip(observations, expected))
    return {"applicable": bool(applicable), "observable": bool(observable),
            "holds": bool(holds), "expected": expected,
            "actual": [obs.get("output") if isinstance(obs, dict) else None
                       for obs in observations],
            "explanation": ("submitted public length contract" if getter else
                            "honest public API roundtrip with source-pinned seed")}


def fault_observation(api, mutated):
    changed = dict(mutated)
    value = changed.get("output")
    changed["output"] = 0 if "_get_" in api and isinstance(value, int) else False
    return changed
