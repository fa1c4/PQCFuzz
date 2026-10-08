"""Isolated worker for a registered target package. No repository state is mutated."""
import argparse
import importlib.util
import json
from pathlib import Path


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load " + str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    adapter = load(payload["adapter"], "pqcfuzz_adapter")
    oracle = load(payload["oracle"], "pqcfuzz_oracle")
    mutator = load(payload["mutator"], "pqcfuzz_mutator")
    if payload["mode"] == "smoke":
        controls = mutator.smoke_cases()
        cases = [("positive", controls["positive"]), ("negative", controls["negative"])]
    else:
        cases = [("campaign", mutator.generate(payload["seed"], payload["iteration"]))]
    traces = []
    for kind, case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("baseline"), dict) or not isinstance(case.get("mutated"), dict):
            raise ValueError("invalid structured case")
        if not isinstance(case.get("changed_fields"), list) or not isinstance(case.get("effective"), bool):
            raise ValueError("missing mutation evidence")
        if case["effective"] and (case["baseline"] == case["mutated"] or not case["changed_fields"]):
            raise ValueError("claimed effective mutation did not change structured input")
        baseline = adapter.invoke(case["baseline"], payload["source_root"], payload["profile"])
        mutated = adapter.invoke(case["mutated"], payload["source_root"], payload["profile"])
        relation = oracle.evaluate(case, baseline, mutated)
        record = {"kind": kind, "case": case, "baseline_observation": baseline,
                  "mutated_observation": mutated, "relation": relation}
        if kind == "positive":
            fault_observation = oracle.fault_observation(mutated)
            record["fault_observation"] = fault_observation
            record["fault_relation"] = oracle.evaluate(case, baseline, fault_observation)
        traces.append(record)
    Path(args.result).write_text(json.dumps(traces, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
