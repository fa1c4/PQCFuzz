"""Compile exact run-local Pavelor reference and AES/SSE submitted paths."""
import pathlib
import subprocess
import sys

def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: variant_build.py SOURCE RUN INSTANCE")
    source, run = pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve()
    instance = sys.argv[3]
    if source != run / "source" or run.parent.parent.name != "hash-22" or \
            instance not in ("Pavelor-512", "Pavelor-768", "Pavelor-1024") or sys.byteorder != "little":
        raise SystemExit("wrong source, run or instance")
    cpu = pathlib.Path("/proc/cpuinfo").read_text().lower()
    if " aes " not in cpu or "sse4_1" not in cpu:
        raise SystemExit("optimized Pavelor requires AES-NI and SSE4.1")
    root = source / "Pavelor/Implementations and Test_Vectors/API_CryptHash/Implementations"
    output = run / "build"
    output.mkdir(exist_ok=True)
    prefix = instance.lower().replace("-", "")
    for backend, subdirectory in (("reference", "Reference_Implementation"),
                                  ("optimized", "Optimized_Implementation")):
        file = root / subdirectory / instance / "CryptHash_AlgorithmInstance.c"
        if not file.is_file():
            raise SystemExit("missing submitted source " + str(file))
        flags = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs"]
        if backend == "optimized":
            flags += ["-maes", "-msse4.1"]
        subprocess.run(flags + ["-o", str(output / f"{prefix}-{backend}.so"), str(file)], check=True)
        print(backend + ": " + str(file.relative_to(source)), flush=True)

if __name__ == "__main__":
    main()
