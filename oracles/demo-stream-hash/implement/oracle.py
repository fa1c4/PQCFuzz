"""H07/P4 streaming consistency relation."""
def evaluate(case, baseline, mutated):
    applicable = isinstance(case.get("baseline"), dict) and isinstance(case.get("mutated"), dict)
    observable = baseline.get("status") == "ok" and mutated.get("status") == "ok"
    holds = (baseline.get("output") == mutated.get("output") and
             baseline.get("output_length") == 32 and mutated.get("output_length") == 32)
    return {"applicable": applicable, "observable": observable, "holds": bool(holds),
            "expected": "equal 32-byte digest for same message", "actual": {
                "baseline": baseline.get("output"), "mutated": mutated.get("output")},
            "explanation": "chunk boundaries must not alter digest"}


def fault_observation(mutated):
    result = dict(mutated)
    original = result["output"]
    result["output"] = ("00" if original[:2] != "00" else "ff") + original[2:]
    return result
