#!/usr/bin/env python3
"""Collect real R6 executions. oracle/audit.py independently assigns verdicts."""
import argparse
import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import traceback
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from common import ROOT, R6, read, write
from driver import Case
from plans import causal, date_case, regression, reserve, call


def source_identity(options):
    if options.source_receipt:
        return read(options.source_receipt)
    def git(*args):
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "git_status": git("status", "--porcelain"),
            "input_sha256": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in R6.rglob("*") if p.is_file() and "__pycache__" not in p.parts}}


async def vector_runs(options, corpus):
    directory = options.output_dir / "vectors"
    directory.mkdir()
    vectors = corpus["binding_vectors"]
    inputs = options.private_root / "binding-vectors.json"
    write(inputs, vectors)
    auxiliary = corpus.get("binding_diagnostics", [])
    sets = [("vectors", vectors, inputs)]
    if auxiliary:
        auxfile = options.private_root / "auxiliary-binding-vectors.json"
        write(auxfile, auxiliary)
        sets.append(("binding_auxiliary", auxiliary, auxfile))
    results = []
    identity_code = "import sys,json,pathlib,hashlib,importlib.metadata; import zti_r6_demo.client as c; import zti_r6_demo.binding as b; print(json.dumps({'python':sys.version,'entry':{'path':c.__file__,'sha256':hashlib.sha256(pathlib.Path(c.__file__).read_bytes()).hexdigest()},'binding':{'path':b.__file__,'sha256':hashlib.sha256(pathlib.Path(b.__file__).read_bytes()).hexdigest()},'versions':{n:importlib.metadata.version(n) for n in ['zti-r6-demo','mcp','mcp-types']}}))"
    identity_process = await asyncio.create_subprocess_exec(str(options.python), "-I", "-c", identity_code,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=options.private_root)
    py_stdout, py_stderr = await asyncio.wait_for(identity_process.communicate(), 30)
    if identity_process.returncode:
        raise RuntimeError("Installed Python client identity failed: " + py_stderr.decode("utf-8", "replace"))
    python_identity = json.loads(py_stdout)
    node_process = await asyncio.create_subprocess_exec(str(options.node), "--version", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    node_stdout, node_stderr = await asyncio.wait_for(node_process.communicate(), 15)
    if node_process.returncode:
        raise RuntimeError("Node identity failed")
    typescript_identity = {"node": node_stdout.decode("ascii").strip(),
        "files": {name: {"path": str(options.client_dir / name), "sha256": hashlib.sha256((options.client_dir / name).read_bytes()).hexdigest()}
                  for name in ("client.ts", "binding.ts", "runtime-lock.json")},
        "sdk_version": read(options.client_dir / "node_modules" / "@modelcontextprotocol" / "client" / "package.json")["version"]}
    for category, rows, path in sets:
        target = options.output_dir / category
        target.mkdir(exist_ok=True)
        for client in ("P", "T"):
            command = ([str(options.python), "-I", "-m", "zti_r6_demo.client"] if client == "P"
                       else [str(options.node), str(options.client_dir / "client.ts")])
            process = await asyncio.create_subprocess_exec(*command, "--vectors", str(path), stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, cwd=options.private_root)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 40)
            (target / (client + ".stdout.txt")).write_bytes(stdout)
            (target / (client + ".stderr.txt")).write_bytes(stderr)
            if process.returncode:
                raise RuntimeError("Client vector process failed " + client + ": " + stderr.decode("utf-8", "replace"))
            raw = json.loads(stdout)
            converted = [{"id": r["id"], **({"result": r["binding"]} if "binding" in r else {"error": {"reason": r["error"]}}),
                **({"domain_error": r["domain_error"]} if "domain_error" in r else {}),
                **({"domain_accepted": r["domain_accepted"]} if "domain_accepted" in r else {})} for r in raw]
            write(target / (client + ".json"), {"client": client, "category": category, "rows": converted,
                "process_returncode": process.returncode, "source": options.source,
                "runtime": typescript_identity if client == "T" else python_identity})
            results.append({"category": category, "client": client, "rows": len(converted)})
    # A deliberately defective real TS binder, compared later to unchanged V16.
    target = options.output_dir / "vectors" / "M01.json"
    process = await asyncio.create_subprocess_exec(str(options.node), str(options.client_dir / "client.ts"),
        "--vectors", str(inputs), "--mutant", "M01", stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, cwd=options.private_root)
    stdout, stderr = await asyncio.wait_for(process.communicate(), 40)
    (options.output_dir / "vectors" / "M01.stdout.txt").write_bytes(stdout)
    (options.output_dir / "vectors" / "M01.stderr.txt").write_bytes(stderr)
    if process.returncode:
        raise RuntimeError("M01 vector process failed: " + stderr.decode("utf-8", "replace"))
    raw = json.loads(stdout)
    write(target, {"client": "T", "mutant_id": "M01", "rows": [{"id": r["id"],
        **({"result": r["binding"]} if "binding" in r else {"error": {"reason": r["error"]}})} for r in raw],
        "activation": {"site": "bind", "conversion": "String(Number(quantity))", "witness_vector": "V16"},
        "process_returncode": process.returncode, "source": options.source, "runtime": typescript_identity})
    return results


async def execute(options):
    corpus = read(R6 / "fixtures" / "scenarios.json")
    options.output_dir = options.output_dir.resolve()
    options.output_dir.mkdir(parents=True, exist_ok=False)
    if options.private_root is None:
        options.private_root = Path(tempfile.mkdtemp(prefix="zti-r6-campaign-private-"))
    else:
        options.private_root = options.private_root.resolve()
        if options.private_root.is_relative_to(ROOT) or options.private_root.is_relative_to(options.output_dir):
            raise ValueError("Private runtime must be outside checkout and public evidence directory")
        options.private_root.mkdir(parents=True, exist_ok=False)
    options.source = source_identity(options)
    options.runtime_receipt_sha256 = None
    if options.runtime_receipt:
        raw = options.runtime_receipt.read_bytes()
        json.loads(raw)
        (options.output_dir / "RUNTIME.json").write_bytes(raw)
        options.runtime_receipt_sha256 = hashlib.sha256(raw).hexdigest()
    for argument, output_name, hash_name in (
            ("distribution_guard", "DISTRIBUTION_GUARD.json", "distribution_guard_sha256"),
            ("build_receipt", "BUILD.json", "build_receipt_sha256")):
        setattr(options, hash_name, None)
        supplied = getattr(options, argument)
        if supplied:
            raw = supplied.read_bytes()
            json.loads(raw)
            (options.output_dir / output_name).write_bytes(raw)
            setattr(options, hash_name, hashlib.sha256(raw).hexdigest())
    options.distributions = read(options.distribution_manifest) if options.distribution_manifest else {}
    write(options.output_dir / "SOURCE.json", options.source)
    write(options.output_dir / "DISTRIBUTIONS.json", options.distributions)
    summary = {"format": "zti-r6-run/1", "status": "RUNNING", "verdict_owner": "separate oracle/audit.py",
        "source": options.source, "runtime": {"python": sys.version, "platform": platform.platform()},
        "cases": [], "vectors": [], "infrastructure_errors": [], "selection": options.select,
        "full_campaign": options.select is None, "categories_are_not_a_security_score": True}
    summary["runtime_receipt_sha256"] = options.runtime_receipt_sha256
    summary["distribution_guard_sha256"] = options.distribution_guard_sha256
    summary["build_receipt_sha256"] = options.build_receipt_sha256
    def selected(category, name):
        return options.select is None or options.select in (name, category + ":" + name)
    async def run_case(category, spec, sdk="P", pair=None, mutant=None, suffix=None, mode="history"):
        label = suffix or (mutant + "__P" if mutant else spec["id"] + "__" + (pair or sdk))
        if not selected(category, label):
            return None
        directory = options.output_dir / "cases" / category / label
        directory.parent.mkdir(parents=True, exist_ok=True)
        case = Case(options, corpus, directory, category, spec, sdk, pair, mutant)
        case.manifest["distributions"] = options.distributions
        case.persist()
        print(json.dumps({"type": "case_start", "category": category, "case": label}), flush=True)
        if mode == "causal":
            await causal(case)
        elif mode == "date":
            await date_case(case)
        elif mode == "regression":
            await regression(case)
        else:
            await case.execute_history()
        summary["cases"].append({"category": category, "case_id": label,
            "directory": directory.relative_to(options.output_dir).as_posix(),
            "history_id": spec["id"], "client": sdk, "pair": pair, "mutant_id": mutant,
            "execution_completed": True, "infrastructure_errors": len(case.observation["infrastructure_errors"])})
        write(options.output_dir / "SUMMARY.json", summary)
        print(json.dumps({"type": "case_collected", "case": label, "steps": len(case.observation["steps"])}), flush=True)
        return case
    try:
        if options.select is None or options.select == "vectors":
            summary["vectors"] = await vector_runs(options, corpus)
        for spec in corpus["histories"]:
            for sdk in ("P", "T"):
                case = await run_case("base", spec, sdk)
                if case is not None and spec["id"] == "I12":
                    for tag, alias, actor in (("red", "red", "A"), ("blue", "blue", "B")):
                        positive = {"id": "I12", "fixture_overrides": {},
                            "steps": [reserve("reserve", alias, actor), call("call", alias, actor)]}
                        label = "I12__" + sdk + "__" + tag + "-alone"
                        subdir = options.output_dir / "cases" / "positive_subrun" / label
                        subdir.parent.mkdir(parents=True, exist_ok=True)
                        subcase = Case(options, corpus, subdir, "positive_subrun", positive, sdk)
                        subcase.manifest.update(parent_case_id=case.directory.name, isolated_fact=tag,
                                               distributions=options.distributions)
                        subcase.persist()
                        await subcase.execute_history()
                        summary["cases"].append({"category": "positive_subrun", "case_id": label,
                            "parent_case_id": case.directory.name, "execution_completed": True})
        for spec in corpus["causal_plans"]:
            for pair in ("PP", "PT", "TP", "TT"):
                await run_case("causal", spec, pair=pair, mode="causal")
        for spec in corpus["date_diagnostics"]:
            for sdk in ("P", "T"):
                await run_case("date", spec, sdk, mode="date")
        for spec in corpus["malformed_regressions"]["cases"]:
            for sdk in ("P", "T"):
                await run_case("regression", spec, sdk, mode="regression")
        histories = {item["id"]: item for item in corpus["histories"]}
        causal_plans = {item["id"]: item for item in corpus["causal_plans"]}
        for mutant in corpus["mutants"]:
            if mutant["id"] == "M01":
                continue
            witness = mutant["witness"]
            spec = histories[witness] if witness.startswith("I") else causal_plans[witness]
            await run_case("mutant", spec, mutant=mutant["id"],
                pair="PP" if witness.startswith("C") else None, mode="causal" if witness.startswith("C") else "history")
        if options.select is None or options.select == "synthetic":
            from synthetics import make_synthetics
            summary["synthetic_copies"] = make_synthetics(options.output_dir, corpus)
        if options.select is None:
            command = [str(options.python), "-I", str(R6 / "issuer" / "raw_jws.py"),
                "--output-dir", str(options.output_dir / "raw_jws"),
                "--private-dir", str(options.private_root / "raw-jws-keys")]
            process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, cwd=options.private_root)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 40)
            (options.output_dir / "raw-jws.stdout.txt").write_bytes(stdout)
            (options.output_dir / "raw-jws.stderr.txt").write_bytes(stderr)
            if process.returncode:
                raise RuntimeError("Raw JWS diagnostic generator failed: " + stderr.decode("utf-8", "replace"))
            summary["raw_jws_generated"] = True
        if options.select is not None and not summary["cases"] and not summary["vectors"] and not summary.get("synthetic_copies"):
            raise ValueError("Selection matched no declared run")
        summary["status"] = "EXECUTION_COMPLETE_PENDING_INDEPENDENT_AUDIT"
    except BaseException as exc:
        summary["status"] = "FAIL"
        summary["infrastructure_errors"].append({"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()})
        raise
    finally:
        write(options.output_dir / "SUMMARY.json", summary)
    print(json.dumps({"status": summary["status"], "actual_case_count": len(summary["cases"]),
        "full_campaign": summary["full_campaign"]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--client-dir", type=Path, required=True)
    parser.add_argument("--consumer-package", default="zti_r6_demo")
    parser.add_argument("--distribution-manifest", type=Path)
    parser.add_argument("--source-receipt", type=Path)
    parser.add_argument("--runtime-receipt", type=Path, help="Portable installed-runtime receipt copied byte-for-byte; mandatory in final qualification")
    parser.add_argument("--distribution-guard", type=Path, help="Verified distribution guard copied byte-for-byte")
    parser.add_argument("--build-receipt", type=Path, help="Exact reused-distribution build receipt copied byte-for-byte")
    parser.add_argument("--private-root", type=Path, help="Fresh private runtime outside checkout and evidence; defaults to system temporary directory")
    parser.add_argument("--select", help="Development-only exact caseID, category:caseID, vectors or synthetic; not full qualification")
    args = parser.parse_args()
    args.python, args.client_dir = args.python.resolve(), args.client_dir.resolve()
    asyncio.run(execute(args))


if __name__ == "__main__":
    main()
