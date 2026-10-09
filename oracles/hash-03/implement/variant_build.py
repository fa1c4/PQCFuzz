"""Build exact submitted CryptHash paths for one selected instance."""
import pathlib
import re
import subprocess
import sys


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: variant_build.py SOURCE_ROOT RUN_ROOT INSTANCE")
    source = pathlib.Path(sys.argv[1]).resolve()
    run = pathlib.Path(sys.argv[2]).resolve()
    instance = sys.argv[3]
    if source != run / "source" or sys.byteorder != "little":
        raise SystemExit("requires run-local source and little-endian host")
    target = run.parent.parent.name
    names = {"hash-03": "C-Hash", "hash-15": "Litchi", "hash-16": "LLH",
             "hash-23": "QILIN", "hash-28": "XRH-1", "hash-29": "XRH-2", "hash-34": "WChain"}
    if target not in names or not re.fullmatch(r"[A-Za-z0-9-]+", instance):
        raise SystemExit("invalid target or instance")
    prefix = re.sub(r"[^a-z0-9]", "", instance.lower())
    if not instance.startswith(names[target] + "-"):
        raise SystemExit("instance does not belong to target")
    if target in ("hash-03", "hash-16", "hash-28", "hash-29"):
        if "avx2" not in pathlib.Path("/proc/cpuinfo").read_text().lower():
            raise SystemExit("optimized path requires AVX2")
    roots = {
        "hash-03": "C Hash/Implementations",
        "hash-15": "Litchi/Implementations",
        "hash-16": "LLH/Implementations and Test_Vectors/LLH_C/API_CryptHash/Implementations",
        "hash-23": "QILIN/Implementations",
        "hash-28": "XRH-1/Implementations",
        "hash-29": "XRH-2/Implementations",
        "hash-34": "WChain/Implementations and Test_Vectors/Implementations",
    }
    source_instance = instance.replace("C-Hash-", "CHash_") if target == "hash-03" else instance
    build = run / "build"
    build.mkdir(exist_ok=True)
    for backend, tree in (("reference", "Reference_Implementation"),
                          ("optimized", "Optimized_Implementation")):
        if backend == "optimized" and target == "hash-15":
            continue
        directory = source / roots[target] / tree / source_instance
        files = [directory / "CryptHash_AlgorithmInstance.c"]
        if target == "hash-15":
            files.append(directory / (instance.lower().replace("-", "_") + ".c"))
        if target == "hash-34":
            files.append(directory / "wchain_c.c")
        if backend == "optimized" and target in ("hash-28", "hash-29"):
            files.append(directory / "CryptHash_AlgorithmInstance_AVX2.s")
        if not all(path.is_file() for path in files):
            raise SystemExit("missing submitted source: " + str(directory))
        output = build / f"{prefix}-{backend}.so"
        command = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs"]
        if backend == "optimized" and target in ("hash-03", "hash-16", "hash-28", "hash-29"):
            command.append("-mavx2")
        if backend == "optimized" and target == "hash-16":
            command.append("-DLLH_FORCE_AVX2=1")
        subprocess.run(command + ["-o", str(output), *(str(path) for path in files)], check=True)
        print(f"{backend}: {', '.join(str(path.relative_to(source)) for path in files)}", flush=True)


if __name__ == "__main__":
    main()
