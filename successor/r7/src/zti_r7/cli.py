"""Entry point for the finite local R7 research program."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import package_evidence
from .runner import HERE, campaign, digest, evaluate_one, read, source_identity
from .worker import durable_json


def verify_source_and_capture(manifest, data):
    captured_source = read(data / "SOURCE.json")["loaded_package_files"]
    if captured_source != source_identity()["loaded_package_files"]:
        raise ValueError("Captured source map differs from closed installed package source set")
    for relative, metadata in manifest["files"].items():
        if digest(data / relative) != metadata["sha256"]:
            raise ValueError("Captured evidence changed during data-only audit")


def audit_archive(archive, output):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError("Fresh audit output required")
    manifest = package_evidence.extract(archive, output / "data")
    verify_source_and_capture(manifest, output / "data")
    if (output / "data" / "INSTRUMENT.json").exists():
        from .instrument import audit_instrument
        if read(output / "data" / "SUMMARY.json")["mode"] != "instrument":
            raise ValueError("Instrument archive scope mismatch")
        reviewed = audit_instrument(output / "data", review_output=output / "review")
        verify_source_and_capture(manifest, output / "data")
        receipt = {"status": reviewed["status"], "instrument_audits": reviewed["results"],
                   "manifest_members": len(manifest["files"]), "full_24_pair_qualification_scope": False,
                   "captured_code_executed": False, "new_provider_executions": 0}
        durable_json(output / "AUDIT_RECEIPT.json", receipt)
        return receipt
    source_cases = {case["case_id"]: case for case in read(HERE / "data" / "public_cases.json")["cases"]}
    source_expected = read(HERE / "data" / "oracle_expectations.json")["cases"]
    results = []
    identities = set()
    trace_fingerprints = set()
    for file in sorted((output / "data").glob("cases/*/*/audit_case.json")):
        case = read(file)
        identity = (case["case_id"], file.parent.name)
        if file.parent.name not in {"Z", "C"} or file.parent.parent.name != case["case_id"] or identity in identities:
            raise ValueError("Duplicate/misbound case or backend identity")
        identities.add(identity)
        fingerprint = (digest(file.parent / "state.sqlite"), digest(file.parent / "requests.jsonl"))
        if fingerprint in trace_fingerprints:
            raise ValueError("A captured SQL/request trace was reused under another case or arm")
        trace_fingerprints.add(fingerprint)
        if source_cases.get(case["case_id"]) != case or read(file.with_name("audit_expected.json")) != source_expected.get(case["case_id"]):
            raise ValueError("Captured labels/case differ from trusted installed corpus")
        expected = source_expected[case["case_id"]]
        audit = evaluate_one(case, expected, file.parent,
                             review_output=output / "review" / case["case_id"] / file.parent.name)
        results.append({"case_id": case["case_id"], "backend": file.parent.name, "status": audit["status"]})
    if not results:
        raise ValueError("No comparative data in archive")
    captured_summary = read(output / "data" / "SUMMARY.json")
    declared = {(item["case_id"], item["backend"]) for item in captured_summary["results"]}
    if declared != identities or len(captured_summary["results"]) != len(identities) or captured_summary["controller_executions"] != len(identities):
        raise ValueError("Campaign summary and closed case identities differ")
    full_set = {(case_id, backend) for case_id in source_cases for backend in ("Z", "C")}
    full_qualification = captured_summary["mode"] == "qualify"
    if full_qualification and (identities != full_set or captured_summary["paired_cases"] != 24):
        raise ValueError("Full qualification does not contain exactly the frozen24pairs")
    verify_source_and_capture(manifest, output / "data")
    receipt = {"status": "PASS" if all(item["status"] == "PASS" for item in results) else "FAIL",
               "case_audits": results, "manifest_members": len(manifest["files"]),
               "full_24_pair_qualification_scope": full_qualification,
               "captured_code_executed": False, "new_provider_executions": 0}
    durable_json(output / "AUDIT_RECEIPT.json", receipt)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description="R7 bounded local simulation; no real mail/model/network.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("develop", "qualify", "smoke"):
        command = commands.add_parser(name)
        command.add_argument("--output", required=True)
        command.add_argument("--cases", nargs="*")
        command.add_argument("--backend", choices=("Z", "C", "both"), default="both")
    command = commands.add_parser("export")
    command.add_argument("--run", required=True)
    command.add_argument("--archive", required=True)
    command = commands.add_parser("audit")
    command.add_argument("--archive", required=True)
    command.add_argument("--output", required=True)
    command = commands.add_parser("instrument")
    command.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.command == "instrument":
        from .instrument import instrument
        result = instrument(args.output)
        print(json.dumps({key: result[key] for key in ("status", "instrument_control_categories", "positive_witness_cases")}))
        return 0 if result["status"] == "PASS" else 1
    if args.command in {"develop", "qualify", "smoke"}:
        backends = ("Z", "C") if args.backend == "both" else (args.backend,)
        selected = args.cases if args.cases else (["T11A", "T12B"] if args.command == "smoke" else None)
        result = campaign(args.output, mode=args.command, selected=selected, backends=backends)
        print(json.dumps({key: result[key] for key in ("status", "mode", "paired_cases", "controller_executions")}))
        return 0 if result["status"] == "PASS" else 1
    if args.command == "export":
        result = package_evidence.export(args.run, args.archive)
        print(json.dumps(result))
        return 0
    result = audit_archive(args.archive, args.output)
    print(json.dumps({"status": result["status"], "case_audits": len(result.get("case_audits", [])), "instrument_audits": len(result.get("instrument_audits", []))}))
    return 0 if result["status"] == "PASS" else 1
