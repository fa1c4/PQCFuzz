"""Compile exact run-local ADKEX/DKEX submitted reference implementation."""
import hashlib
import json
import pathlib
import subprocess
import sys

TARGET = "kex-04"
ALG = "DKEX"

def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: build.py SOURCE RUN INSTANCE")
    source, run = pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve()
    instance = sys.argv[3]
    if source != run / "source" or run.parent.parent.name != TARGET:
        raise SystemExit("wrong run-local source")
    config = json.loads((pathlib.Path(__file__).resolve().parents[1] / "data/instances.json").read_text())
    if instance not in config:
        raise SystemExit("unknown instance")
    cfg = config[instance]
    kat = (source / cfg["kat"]).resolve()
    if not kat.is_file() or not kat.is_relative_to(source):
        raise SystemExit("invalid KAT path")
    digest = hashlib.sha256()
    offsets = []
    with kat.open("rb") as stream:
        while True:
            position = stream.tell()
            line = stream.readline()
            if not line:
                break
            digest.update(line)
            if line.startswith(b"Count ="):
                offsets.append(position)
        offsets.append(stream.tell())
    if digest.hexdigest() != cfg["kat_sha256"] or len(offsets) != 11:
        raise SystemExit("KAT digest/count mismatch")
    build = run / "build"
    build.mkdir(exist_ok=True)
    (build / f"{instance}-offsets.json").write_text(json.dumps(offsets))
    directory = (source / cfg["implementation_dir"]).resolve()
    if not directory.is_dir() or not directory.is_relative_to(source):
        raise SystemExit("invalid implementation directory")
    level = int(instance.split("-")[-1])
    flags = ["-std=c99", "-O2", "-fcommon", "-fPIC", "-DDKE_FORCE_SCALAR",
             f"-DADKEX_MODE={level}", f"-DDKE_MODE={level}", "-DDKE_HASH=0", "-DDKE_RANDOM=0"]
    output = build / f"{instance}.so"
    if ALG == "ADKEX":
        names = "sm3 dke_sm3 dke_hash reduce ntt poly polyvec random_sampling dke_utils packing verify dkecpa dkecca randombytes drng auxfunc adkex_derand KEX_AlgorithmInstance KAT_KEX".split()
        files = [directory / (name + ".c") for name in names]
        if any(not file.is_file() for file in files):
            raise SystemExit("missing submitted reference source")
        command = ["gcc", *flags, "-shared", "-Wl,-z,defs", "-I", str(directory),
                   "-o", str(output), *(str(file) for file in files), "-lm"]
        subprocess.run(command, check=True)
    else:
        dil_level = 2 if level == 128 else 5
        flags += ["-DADKEX_SIG_BACKEND_MLDSA", f"-DADKEX_SIG_MLDSA_LEVEL={dil_level}",
                  f"-DDILITHIUM_MODE={dil_level}"]
        groups = (("core", "sm3 dke_sm3 dke_hash reduce ntt poly polyvec random_sampling dke_utils packing verify dkecpa drng auxfunc".split(), directory, []),
                  ("dil", "fips202 ntt packing poly polyvec reduce rounding sign symmetric-shake".split(), directory / "dilithium", ["-I", str(directory / "dilithium")]),
                  ("lay", "adkex_derand adkex_sig_mldsa KEX_AlgorithmInstance KAT_KEX randombytes".split(), directory, ["-I", str(directory), "-I", str(directory / "dilithium")]))
        objects = []
        objdir = build / f"{instance}-objects"
        objdir.mkdir(exist_ok=True)
        for prefix, names, root, includes in groups:
            for name in names:
                file = root / (name + ".c")
                if not file.is_file() or not file.resolve().is_relative_to(source):
                    raise SystemExit("missing or escaping submitted source")
                obj = objdir / f"{prefix}_{name}.o"
                subprocess.run(["gcc", *flags, *includes, "-c", str(file), "-o", str(obj)], check=True)
                objects.append(obj)
        subprocess.run(["gcc", "-shared", "-Wl,-z,defs", "-o", str(output),
                        *(str(obj) for obj in objects), "-lm"], check=True)
    print(instance + ": reference KEX library ready", flush=True)

if __name__ == "__main__":
    main()
