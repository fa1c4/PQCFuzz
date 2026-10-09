"""Build the archived QILIN-512 backends inside one isolated run."""
import pathlib
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: build.py SOURCE_ROOT RUN_ROOT")
    source = pathlib.Path(sys.argv[1]).resolve()
    run = pathlib.Path(sys.argv[2]).resolve()
    if source != run / "source" or sys.byteorder != "little":
        raise SystemExit("QILIN-512 build requires the run-local source and a little-endian host")
    build = run / "build"
    build.mkdir(exist_ok=True)
    root = source / "QILIN" / "Implementations"
    for backend, tree, flags in (
        ("reference", "Reference_Implementation", []),
        ("optimized", "Optimized_Implementation", ["-O2"]),
    ):
        implementation = root / tree / "QILIN-512" / "CryptHash_AlgorithmInstance.c"
        if not implementation.is_file():
            raise SystemExit("missing submitted source: " + str(implementation))
        output = build / ("qilin512-" + backend + ".so")
        command = ["gcc", "-std=c99", "-fPIC", "-shared", *flags,
                   "-o", str(output), str(implementation)]
        subprocess.run(command, check=True)
        print(backend + " built from " + str(implementation.relative_to(source)), flush=True)


if __name__ == "__main__":
    main()
