"""Build only pinned submitted source files in the run-local tree."""
import json
import pathlib
import subprocess
import sys

TARGET = "hash-21"

def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: build.py SOURCE RUN")
    source, run = pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve()
    if source != run / "source" or run.parent.parent.name != TARGET or sys.byteorder != "little":
        raise SystemExit("wrong run-local source, target, or byte order")
    spec = json.loads((pathlib.Path(__file__).resolve().parents[1] / "data/build_sources.json").read_text())
    build_dir = run / "build"
    build_dir.mkdir(exist_ok=True)
    for backend in ("reference", "optimized"):
        paths = [(source / item).resolve() for item in spec[backend]]
        if not paths or any(not p.is_file() or not p.is_relative_to(source) for p in paths):
            raise SystemExit("missing or escaping submitted source")
        flags = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs"]
        if backend == "optimized":
            flags.append("-march=native")
        output = build_dir / ("hash512-" + backend + ".so")
        subprocess.run(flags + ["-o", str(output), *(str(p) for p in paths)], check=True)
        print(backend + ": " + ", ".join(str(p.relative_to(source)) for p in paths), flush=True)

if __name__ == "__main__":
    main()
