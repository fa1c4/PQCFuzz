"""Build the archived LLH-512 CryptHash backends in one isolated run."""
import pathlib
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: build.py SOURCE_ROOT RUN_ROOT")
    source = pathlib.Path(sys.argv[1]).resolve()
    run = pathlib.Path(sys.argv[2]).resolve()
    if source != run / "source" or sys.byteorder != "little":
        raise SystemExit("build requires run-local source and little-endian host")
    if "avx2" not in pathlib.Path("/proc/cpuinfo").read_text().lower():
        raise SystemExit("optimized backend requires AVX2")
    output_dir = run / "build"
    output_dir.mkdir(exist_ok=True)
    root = source / 'LLH/Implementations and Test_Vectors/LLH_C/API_CryptHash/Implementations'
    for backend, tree in (("reference", "Reference_Implementation"),
                          ("optimized", "Optimized_Implementation")):
        instance = root / tree / 'LLH-512'
        implementation = instance / "CryptHash_AlgorithmInstance.c"
        if not implementation.is_file():
            raise SystemExit("missing submitted source: " + str(implementation))
        sources = [implementation]
        output = output_dir / ("llh512-" + backend + ".so")
        command = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs"]
        if backend == "optimized":
            command.append("-mavx2")
        if backend == "optimized":
            command.append("-DLLH_FORCE_AVX2=1")
        command.extend(["-o", str(output), *(str(path) for path in sources)])
        subprocess.run(command, check=True)
        print(backend + " built from " + str(implementation.relative_to(source)), flush=True)


if __name__ == "__main__":
    main()
