#!/usr/bin/env python3
"""Map submitted B-tier reference API declarations and vector formats as data."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "workspace/b_targets_sop/inventory.json"
OUT = ROOT / "workspace/b_targets_sop/api_matrix.json"
FUNCTION = re.compile(r"\b((?:CryptHash|(?:kem|sig|kex)_[A-Za-z0-9_]+))\s*\(")
INSTANCE = re.compile(r'#define\s+ALGORITHM_INSTANCE\s+"([^"]+)"')
FIELD = re.compile(rb"^([A-Za-z_][A-Za-z_0-9]*)\s*=", re.MULTILINE)


def main():
    matrix = []
    for item in json.loads(INVENTORY.read_text()):
        source = ROOT / "third_party" / item["target"] / "source"
        candidates = [path for path in item["api_headers"]
                      if "Reference_Implementation" in path and
                      not any(x in path.lower() for x in ("/others/", "self_assess", "self-assess"))]
        primary = [path for path in candidates if "Optimized_Implementation" not in path]
        if not primary:
            primary = candidates
        headers = []
        for relative in primary:
            data = (source / relative).read_text(errors="replace")
            instance = INSTANCE.search(data)
            headers.append({"path": relative, "parameter_label": Path(relative).parent.name,
                            "instance_macro": instance.group(1) if instance else None,
                            "functions": sorted(set(FUNCTION.findall(data)))})
        vectors = []
        for relative in item["kat_texts"]:
            with (source / relative).open("rb") as stream:
                prefix = stream.read(1 << 20)
            fields = list(dict.fromkeys(match.decode("ascii", errors="ignore")
                                        for match in FIELD.findall(prefix)))
            vectors.append({"path": relative, "assignment_fields_in_first_mib": fields,
                            "prefix_only": (source / relative).stat().st_size > len(prefix)})
        matrix.append({"target": item["target"], "name": item["name"],
                       "primitive": item["primitive"],
                       "source_sha256": item["source_sha256"],
                       "document_sha256": item["document_sha256"],
                       "primary_reference_headers": headers,
                       "submitted_vector_files": vectors,
                       "missing_standard_primary_header": not bool(primary),
                       "stage": "api_and_vector_inventory", "sop_completion": False})
        print(item["target"], len(headers), len(vectors), flush=True)
    OUT.write_text(json.dumps(matrix, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"targets": len(matrix),
                      "with_primary_standard_header": sum(not x["missing_standard_primary_header"] for x in matrix),
                      "without": sum(x["missing_standard_primary_header"] for x in matrix)}))


if __name__ == "__main__":
    main()
