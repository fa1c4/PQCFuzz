"""X05/P3 comparison of LLH-512 reference and optimized observations."""


def evaluate(case, baseline, mutated):
    left = case.get("baseline", {})
    right = case.get("mutated", {})
    applicable = (isinstance(left, dict) and isinstance(right, dict) and
                  left.get("backend") == "reference" and
                  right.get("backend") == "optimized" and
                  left.get("message_hex") == right.get("message_hex") and
                  left.get("message_bits") == right.get("message_bits") and
                  left.get("digest_bits") == right.get("digest_bits") == 512)
    observable = (baseline.get("reached") is True and mutated.get("reached") is True and
                  baseline.get("status") == "ok" and mutated.get("status") == "ok" and
                  baseline.get("output_length") == mutated.get("output_length") == 64 and
                  isinstance(baseline.get("output"), str) and
                  isinstance(mutated.get("output"), str))
    expected_kat = case.get("submitted_kat_digest")
    if expected_kat is not None and (not isinstance(expected_kat, str) or len(expected_kat) != 128):
        applicable = False
    holds = (baseline.get("output") == mutated.get("output") and
             (expected_kat is None or
              (baseline.get("output") == expected_kat and mutated.get("output") == expected_kat)))
    return {"applicable": bool(applicable), "observable": bool(observable),
            "holds": bool(holds),
            "expected": "equal 64-byte LLH-512 digests" +
                        (" matching the submitted KAT" if expected_kat is not None else ""),
            "actual": {"reference": baseline.get("output"),
                       "optimized": mutated.get("output"),
                       "submitted_kat": expected_kat},
            "explanation": "same valid bitstring under two submitted LLH-512 backends"}


def fault_observation(mutated):
    altered = dict(mutated)
    output = altered.get("output")
    if isinstance(output, str) and len(output) == 128:
        altered["output"] = f"{int(output[:2], 16) ^ 1:02x}" + output[2:]
    return altered
