"""Adapter to the run-local copy of the demo implementation."""
import importlib.util
from pathlib import Path


def invoke(structured_input, source_root, profile):
    chunks = structured_input.get("chunks")
    if not isinstance(chunks, list) or not chunks or any(not isinstance(x, str) for x in chunks):
        return {"reached": False, "status": "invalid_input", "output": None, "output_length": 0}
    try:
        decoded = [bytes.fromhex(x) for x in chunks]
    except ValueError:
        return {"reached": False, "status": "invalid_input", "output": None, "output_length": 0}
    path = Path(source_root) / "stream_hash.py"
    spec = importlib.util.spec_from_file_location("demo_stream_hash", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = module.digest_chunks(decoded, bool(profile.get("injected_fault", False)))
    return {"reached": True, "status": "ok", "output": output.hex(), "output_length": len(output)}
