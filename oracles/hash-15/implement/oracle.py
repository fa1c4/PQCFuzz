"""X05/P3 relation for Litchi-XOF core versus CryptHash output bounds."""


def evaluate(case, baseline, mutated):
    left = case.get("baseline", {})
    right = case.get("mutated", {})
    applicable = (isinstance(left, dict) and isinstance(right, dict) and
                  left.get("backend") == "core" and right.get("backend") == "wrapper" and
                  left.get("message_hex") == right.get("message_hex") and
                  left.get("message_bits") == right.get("message_bits") and
                  left.get("out_bits") == right.get("out_bits") and
                  left.get("out_bits") in (512, 768, 1024))
    requested = left.get("out_bits", 0) // 8 if isinstance(left.get("out_bits"), int) else 0
    observable = (baseline.get("reached") is True and mutated.get("reached") is True and
                  baseline.get("status") == mutated.get("status") == "ok" and
                  baseline.get("output_length") == mutated.get("output_length") == requested and
                  isinstance(baseline.get("guard_modified"), bool) and
                  isinstance(mutated.get("guard_modified"), bool) and
                  isinstance(baseline.get("output"), str) and
                  isinstance(mutated.get("output"), str))
    expected_kat = case.get("submitted_kat_digest")
    if expected_kat is not None and (left.get("out_bits") != 1024 or
                                    not isinstance(expected_kat, str) or len(expected_kat) != 256):
        applicable = False
    holds = (baseline.get("output") == mutated.get("output") and
             baseline.get("guard_modified") is False and
             mutated.get("guard_modified") is False and
             (expected_kat is None or
              (baseline.get("output") == expected_kat and
               mutated.get("output") == expected_kat)))
    return {"applicable": bool(applicable), "observable": bool(observable),
            "holds": bool(holds),
            "expected": "equal requested XOF bytes and unchanged canaries after requested length",
            "actual": {"core_output": baseline.get("output"),
                       "wrapper_output": mutated.get("output"),
                       "core_guard_modified": baseline.get("guard_modified"),
                       "wrapper_guard_modified": mutated.get("guard_modified"),
                       "wrapper_first_changed_offset": mutated.get("guard_first_changed_offset"),
                       "submitted_kat": expected_kat},
            "explanation": "same Litchi-XOF input and requested digest bits through core and wrapper"}


def fault_observation(mutated):
    altered = dict(mutated)
    if altered.get("reached") is True and altered.get("status") == "ok":
        altered["guard_modified"] = True
        altered["guard_first_changed_offset"] = 128
        altered["guard_after_maximum_modified"] = True
    return altered
