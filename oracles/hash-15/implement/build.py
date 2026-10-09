"""Build the submitted Litchi-XOF core and CryptHash wrapper in one run."""
import pathlib
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: build.py SOURCE_ROOT RUN_ROOT")
    source = pathlib.Path(sys.argv[1]).resolve()
    run = pathlib.Path(sys.argv[2]).resolve()
    if source != run / "source" or sys.byteorder != "little":
        raise SystemExit("Litchi-XOF build requires run-local source and little-endian host")
    directory = source / "Litchi/Implementations/Reference_Implementation/Litchi-XOF"
    files = [directory / "litchi_xof.c", directory / "CryptHash_AlgorithmInstance.c"]
    if not all(file.is_file() for file in files):
        raise SystemExit("missing submitted Litchi-XOF C source")
    build = run / "build"
    build.mkdir(exist_ok=True)
    subprocess.run(["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs",
                    "-o", str(build / "litchi_xof.so"), *(str(file) for file in files)],
                   check=True)
    print("Litchi-XOF core and wrapper built from submitted source", flush=True)


if __name__ == "__main__":
    main()
