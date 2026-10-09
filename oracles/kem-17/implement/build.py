"""Compile one exact submitted instance and index its public KAT records."""
import hashlib
import json
import pathlib
import subprocess
import sys

TARGET = "kem-17"

def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: build.py SOURCE RUN INSTANCE")
    source, run = pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve()
    instance = sys.argv[3]
    if source != run / "source" or run.parent.parent.name != TARGET:
        raise SystemExit("wrong run-local source")
    data = json.loads((pathlib.Path(__file__).resolve().parents[1] / "data/instances.json").read_text())
    if instance not in data:
        raise SystemExit("unknown instance")
    cfg = data[instance]
    kat = (source / cfg["kat"]).resolve()
    if not kat.is_file() or not kat.is_relative_to(source):
        raise SystemExit("missing or escaping KAT path")
    h = hashlib.sha256()
    offsets = []
    with kat.open("rb") as stream:
        while True:
            position = stream.tell()
            line = stream.readline()
            if not line:
                break
            h.update(line)
            if line.startswith(b"Count ="):
                offsets.append(position)
        offsets.append(stream.tell())
    if h.hexdigest() != cfg["kat_sha256"] or len(offsets) != 11:
        raise SystemExit("submitted KAT digest or row count changed")
    build = run / "build"
    build.mkdir(exist_ok=True)
    (build / f"{instance}-offsets.json").write_text(json.dumps(offsets))
    files = [(source / item).resolve() for item in cfg["sources"]]
    includes = [(source / item).resolve() for item in cfg["includes"]]
    if any(not p.is_file() or not p.is_relative_to(source) for p in files) or \
            any(not p.is_dir() or not p.is_relative_to(source) for p in includes):
        raise SystemExit("invalid pinned build paths")
    command = ["gcc", "-std=c99" if TARGET == "sign-33" else "-std=c11", "-O2", "-fPIC",
               "-shared", "-Wl,-z,defs", *cfg["flags"],
               *(flag for p in includes for flag in ("-I", str(p))),
               "-o", str(build / f"{instance}.so"), *(str(p) for p in files)]
    subprocess.run(command, check=True)
    print(instance + ": compiled " + str(len(files)) + " pinned source files", flush=True)

if __name__ == "__main__":
    main()
