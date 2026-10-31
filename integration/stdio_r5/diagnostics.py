"""Separate wire regressions for Boolean signed-mandate body dates.

These eight diagnostics are not additions to the frozen twenty R5 variants or
the two integration mutants. Every attempt uses a fresh provider database and
actual official-SDK stdio registration, with genuine integer JWT NumericDates.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import secrets
import sqlite3
import subprocess
import sys
import traceback

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

from mcp import Client, StdioServerParameters, types
from mcp.client.extension import advertise
from mcp.shared.exceptions import MCPError
from crypto import sign
from fixtures import build_fixture
from models import CAPABILITY, EXT_ID, PROTOCOL, RegisterParams, ControlResult

EXECUTED_PROVIDER_FILES = ("core.py", "crypto.py", "endpoint.py", "models.py", "relay.py")
CASES = [
    {"id": "integer_root_positive", "target": "root", "field": None, "value": None, "clock": 2},
    {"id": "integer_child_positive", "target": "child", "field": None, "value": None, "clock": 2},
    {"id": "root_valid_from_true", "target": "root", "field": "valid_from", "value": True, "clock": 2},
    {"id": "child_valid_from_true", "target": "child", "field": "valid_from", "value": True, "clock": 2},
    {"id": "root_valid_from_false", "target": "root", "field": "valid_from", "value": False, "clock": 0},
    {"id": "child_valid_from_false", "target": "child", "field": "valid_from", "value": False, "clock": 0},
    {"id": "root_valid_until_true", "target": "root", "field": "valid_until", "value": True, "clock": 0},
    {"id": "child_valid_until_true", "target": "child", "field": "valid_until", "value": True, "clock": 0},
]


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def lines(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def snapshot(path):
    """Direct read-only base-table measurement, never provider decision code."""
    tables = ("roots", "mandates", "reservations", "business_effects", "receipts", "transitions")
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        records = {name: [dict(row) for row in connection.execute("SELECT * FROM " + name + " ORDER BY rowid")] for name in tables}
    return {"counts": {name: len(rows) for name, rows in records.items()}, "tables": records}


def setup_case(contract, case):
    source = copy.deepcopy(contract)
    source["fixture_contract"].update({"initial_test_clock": case["clock"], "mandate_valid_from": 0, "mandate_valid_until": 1000})
    fixture = build_fixture(source, {})
    target = fixture["mandates"]["root" if case["target"] == "root" else "agent_a"]
    # The child positive also exercises a nonzero genuine integer body date.
    if case["id"] == "integer_child_positive":
        target["valid_from"] = 1
    if case["field"]:
        target[case["field"]] = case["value"]
    for alias, body in fixture["mandates"].items():
        claims = fixture["mandate_claims"][alias]
        claims.update({"iat": 0, "nbf": int(body["valid_from"]), "exp": int(body["valid_until"]), "zti_mandate": body})
        # This assertion prevents a refusal caused merely by malformed JWT dates.
        assert all(type(claims[key]) is int for key in ("iat", "nbf", "exp"))
        assert 0 <= claims["iat"] <= claims["nbf"] < claims["exp"]
        assert claims["nbf"] <= case["clock"] < claims["exp"]
        fixture["signed_mandates"][alias] = sign(claims, "zti-mandate+jwt")
    fixture["diagnostic_case"] = case
    return fixture


async def register(client, token):
    try:
        result = await client.session.send_request(types.Request(method=EXT_ID + ".register", params=RegisterParams(mandate=token)), ControlResult)
        return {"sdk_result": result.model_dump(by_alias=True, mode="json", exclude_none=True)}
    except MCPError as exc:
        if exc.code != -31001:
            raise
        return {"error": exc.error.model_dump(by_alias=True, mode="json", exclude_none=True)}


async def execute_case(directory, provider_source, contract, case):
    directory.mkdir()
    fixture = setup_case(contract, case)
    dump(directory / "fixtures.json", fixture)
    database = directory / "provider.sqlite"
    clock = directory / "clock.txt"
    clock.write_text(str(case["clock"]), encoding="ascii")
    instance = "diagnostic-admin-" + secrets.token_hex(16)
    controls = directory / "control"
    controls.mkdir()
    config = {"db_path": str(database), "principal": fixture["endpoint_principals"]["admin"], "role": "admin", "clock_path": str(clock), "control_dir": str(controls), "endpoint_instance_id": instance, "advertise_extension": True, "mutant": None}
    dump(directory / "config.json", config)
    wire = directory / "wire.jsonl"
    lifecycle = directory / "lifecycle.jsonl"
    observation = {"case": case, "endpoint_instance_id": instance, "client_pid": os.getpid(), "attempts": [], "infrastructure_errors": [], "semantic_failures": []}
    target_alias = "root" if case["target"] == "root" else "agent_a"
    try:
        client = Client(StdioServerParameters(command=sys.executable, args=["-I", str(provider_source / "relay.py"), "--config", str(directory / "config.json"), "--wire", str(wire), "--lifecycle", str(lifecycle)]), mode="auto", extensions=[advertise(EXT_ID, settings=CAPABILITY)], cache=None, read_timeout_seconds=25)
        async with client:
            discovery = client.session.discover_result
            assert client.protocol_version == PROTOCOL and discovery is not None
            observation["discovery"] = discovery.model_dump(by_alias=True, mode="json", exclude_none=True)
            assert observation["discovery"]["capabilities"]["extensions"][EXT_ID] == CAPABILITY
            observation["initial_database"] = snapshot(database)
            if target_alias != "root":
                bootstrap = await register(client, fixture["signed_mandates"]["root"])
                if bootstrap.get("sdk_result", {}).get("status") != "ACTIVE":
                    raise RuntimeError("Genuine integer root failed prerequisite registration")
                observation["bootstrap"] = bootstrap
            observation["before_attempt"] = snapshot(database)
            attempt = await register(client, fixture["signed_mandates"][target_alias])
            observation["attempts"].append(attempt)
            observation["after_attempt"] = snapshot(database)
        observation["final_database"] = snapshot(database)
        if observation["after_attempt"] != observation["final_database"]:
            raise RuntimeError("Provider state changed after its acknowledged result")
        capture = lines(wire)
        lifecycle_rows = lines(lifecycle)
        ready = [r for r in lines(controls / "events.jsonl") if r.get("event") == "endpoint_ready"]
        starts = [r for r in lifecycle_rows if r.get("type") == "provider_start"]
        exits = [r for r in lifecycle_rows if r.get("type") == "provider_exit"]
        assert len(ready) == len(starts) == len(exits) == 1 and exits[0]["returncode"] == 0
        actual_pid = ready[0]["provider_pid"]
        assert starts[0]["provider_pid"] == actual_pid
        requests, responses = {}, {}
        for record in capture:
            assert record["provider_pid"] == actual_pid
            assert json.loads(base64.b64decode(record["raw_base64"], validate=True)) == record["frame"]
            frame = record["frame"]
            if "id" in frame:
                target = requests if record["direction"] == "client_to_server" else responses
                assert frame["id"] not in target
                target[frame["id"]] = frame
        assert any(frame.get("method") == "server/discover" for frame in requests.values())
        target_requests = [frame for frame in requests.values() if frame.get("method") == EXT_ID + ".register" and frame.get("params", {}).get("mandate") == fixture["signed_mandates"][target_alias]]
        assert len(target_requests) == 1
        request = target_requests[0]
        assert request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == PROTOCOL
        response = responses[request["id"]]
        observation["target_wire_request"] = request
        observation["target_wire_response"] = response
        observation["provider_pid"] = actual_pid
        observation["captured_frame_count"] = len(capture)
        before = observation["before_attempt"]
        after = observation["after_attempt"]
        if case["field"] is not None:
            error = response.get("error", {})
            expected = {"profile": "zti-mcp/0.1", "reason": "INVALID_TOKEN", "status": "REFUSED"}
            if error.get("code") != -31001 or error.get("data") != expected or "result" in response:
                observation["semantic_failures"].append("Boolean body date was not rejected with exact INVALID_TOKEN")
            if after != before:
                observation["semantic_failures"].append("Rejected Boolean-body attempt changed provider state")
            wanted_roots, wanted_mandates, wanted_revision = (0, 0, None) if target_alias == "root" else (1, 1, "1")
        else:
            if response.get("result", {}).get("status") != "ACTIVE" or "error" in response:
                observation["semantic_failures"].append("Genuine integer positive was not admitted")
            wanted_roots, wanted_mandates, wanted_revision = (1, 1, "1") if target_alias == "root" else (1, 2, "2")
        if after["counts"]["roots"] != wanted_roots or after["counts"]["mandates"] != wanted_mandates:
            observation["semantic_failures"].append("Root/mandate row counts differ from the diagnostic expectation")
        if wanted_revision is not None and [r["state_revision"] for r in after["tables"]["roots"]] != [wanted_revision]:
            observation["semantic_failures"].append("Root revision changed unexpectedly")
        if any(after["counts"][table] for table in ("reservations", "business_effects", "receipts")):
            observation["semantic_failures"].append("Registration diagnostic created an operation or business effect")
        # The actual signed segments remain in both fixture and raw request.
        payload = fixture["mandate_claims"][target_alias]
        assert all(type(payload[key]) is int for key in ("iat", "nbf", "exp"))
        assert 0 <= payload["iat"] <= payload["nbf"] < payload["exp"]
        if case["field"]:
            assert type(payload["zti_mandate"][case["field"]]) is bool
    except Exception as exc:
        observation["infrastructure_errors"].append({"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()})
    observation["matches_diagnostic"] = not observation["infrastructure_errors"] and not observation["semantic_failures"]
    dump(directory / "OBSERVATION.json", observation)
    return {"case_id": case["id"], "matches_diagnostic": observation["matches_diagnostic"], "semantic_failures": observation["semantic_failures"], "infrastructure_errors": observation["infrastructure_errors"]}


def source_identity(provider_source, provider_commit):
    def git(*arguments):
        return subprocess.run(["git", "-C", str(REPO), *arguments], check=True, capture_output=True).stdout
    hashes = {name: hashlib.sha256((provider_source / name).read_bytes()).hexdigest() for name in EXECUTED_PROVIDER_FILES}
    if provider_commit:
        for name, sha in hashes.items():
            assert hashlib.sha256(git("show", provider_commit + ":integration/stdio_r5/" + name)).hexdigest() == sha, name
    return {"driver_git_commit": git("rev-parse", "HEAD").decode().strip(), "driver_git_status": git("status", "--porcelain").decode(), "provider_commit": provider_commit or git("rev-parse", "HEAD").decode().strip(), "provider_source_kind": "verified_git_archive" if provider_commit else "working_checkout", "provider_files_sha256": hashes, "diagnostic_driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "runtime": {"platform": platform.platform(), "python": sys.version, "sqlite": sqlite3.sqlite_version, "mcp": importlib.metadata.version("mcp"), "mcp_types": importlib.metadata.version("mcp-types"), "cryptography": importlib.metadata.version("cryptography")}}


async def campaign(args):
    directory = Path(args.output_dir).resolve()
    if directory.exists() and any(directory.iterdir()):
        raise RuntimeError("Use a fresh output directory to preserve prior evidence")
    directory.mkdir(parents=True, exist_ok=True)
    provider_source = Path(args.provider_source).resolve() if args.provider_source else HERE
    source = source_identity(provider_source, args.provider_commit)
    contract = load(HERE / "scenarios.json")
    dump(directory / "SOURCE.json", source)
    dump(directory / "DIAGNOSTIC_CASES.json", CASES)
    cases = []
    for case in CASES:
        result = await execute_case(directory / case["id"], provider_source, contract, case)
        cases.append(result)
        print(json.dumps({"case": case["id"], "matches_diagnostic": result["matches_diagnostic"], "infrastructure_errors": len(result["infrastructure_errors"])}), flush=True)
    semantic = sum(len(case["semantic_failures"]) for case in cases)
    infrastructure = sum(len(case["infrastructure_errors"]) for case in cases)
    summary = {"diagnostic_id": "SIGNED_MANDATE_BODY_DATES_STRICT_INTEGER", "status": "PASS" if all(case["matches_diagnostic"] for case in cases) else "FAIL", "diagnostic_case_count": len(cases), "diagnostic_cases_matched": sum(case["matches_diagnostic"] for case in cases), "semantic_failure_count": semantic, "infrastructure_error_count": infrastructure, "counts_separate_from_frozen_r5_variants_and_mutants": True, "cases": cases, "source": source, "limitations": ["Local laboratory identities and public signing material only.", "No business tool is invoked; this is signed registration validation, not a new security-coverage rate.", "False valid_until cannot isolate this bug under genuine nonnegative JWT NumericDates with nbf<exp; the true valid_until case supplies the valid exp=1 boundary."]}
    dump(directory / "SUMMARY.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--provider-source", help="Preserved alternate stdio_r5 source directory")
    parser.add_argument("--provider-commit", help="Verify alternate executed source hashes against this immutable Git commit")
    args = parser.parse_args()
    if bool(args.provider_source) != bool(args.provider_commit):
        parser.error("--provider-source and --provider-commit must be used together")
    summary = asyncio.run(campaign(args))
    print(json.dumps({key: value for key, value in summary.items() if key not in {"cases", "source"}}, indent=2))
    raise SystemExit(0 if summary["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
