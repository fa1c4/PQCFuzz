"""Build only pinned submitted source files in the run-local tree."""
import json
import pathlib
import subprocess
import sys

TARGET = "hash-26"

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
        if TARGET == "hash-01" and backend == "optimized":
            flags.extend(["-DAFS_TREDM_BENCH_IMPL_AVX2=1", "-DAFS_TREDM_USE_AVX2=1",
                          "-DAFS_TREDM_S6_CANONICAL_AVX2=1", "-mavx2"])
        if TARGET == "hash-26" and backend == "optimized":
            flags[0] = "g++"
            flags.append("-std=c++17")
        output = build_dir / ("hash512-" + backend + ".so")
        command = flags + ["-o", str(output), *(str(p) for p in paths)]
        if TARGET == "hash-26" and backend == "optimized":
            command.append("-lcrypto")
        subprocess.run(command, check=True)
        print(backend + ": " + ", ".join(str(p.relative_to(source)) for p in paths), flush=True)

if __name__ == "__main__":
    main()
