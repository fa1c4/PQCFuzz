"""Build one exact submitted reference hash parameter set in the run tree."""
import json
import pathlib
import subprocess
import sys

TARGET = "hash-09"


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: secondary_build.py SOURCE RUN INSTANCE")
    source, run = pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve()
    instance = sys.argv[3]
    if source != run / "source" or run.parent.parent.name != TARGET or sys.byteorder != "little":
        raise SystemExit("wrong run-local source, target or byte order")
    config = json.loads((pathlib.Path(__file__).resolve().parents[1] /
                         "data/secondary_instances.json").read_text())
    if instance not in config:
        raise SystemExit("unknown parameter set")
    cfg = config[instance]
    paths = [(source / p).resolve() for p in cfg["sources"]]
    if not paths or any(not p.is_file() or not p.is_relative_to(source) for p in paths):
        raise SystemExit("missing or escaping submitted source")
    build = run / "build"
    build.mkdir(exist_ok=True)
    command = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs",
               "-o", str(build / "hash-secondary.so"), *(str(p) for p in paths)]
    subprocess.run(command, check=True)
    print(instance + ": compiled " + str(len(paths)) + " submitted reference files", flush=True)


if __name__ == "__main__":
    main()
