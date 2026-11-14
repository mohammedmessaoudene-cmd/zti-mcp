"""Finite process-based R7 runner and explicit, separate data-only evaluation.

Apache-2.0, Mohammed Messaoudene; prepared with AI assistance.
No models, real accounts, external effects or network are used by this runner.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import time

from .worker import durable_json

HERE = Path(__file__).resolve().parent


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_identity():
    hashes = {file.relative_to(HERE).as_posix(): digest(file) for file in sorted(HERE.rglob("*.py")) if "__pycache__" not in file.parts}
    try:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], text=True, stderr=subprocess.DEVNULL).strip())
    except (OSError, subprocess.CalledProcessError):
        head = None
        dirty = None
    return {"git_worktree_head": head, "git_worktree_dirty": dirty, "loaded_package_files": hashes,
            "python": platform.python_version(), "platform": platform.system(),
            "interpretation": "Package bytes measured here; source attribution additionally requires build/Git identity checks. A declared head alone is not proof."}


def backup_sqlite(source, target):
    source = Path(source).resolve()
    origin = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
    destination = sqlite3.connect(str(target))
    try:
        origin.backup(destination)
        destination.commit()
    finally:
        destination.close()
        origin.close()


def run_one(case, backend, output, *, control_extra=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    public = {key: case[key] for key in ("seed", "policy", "task")}
    durable_json(output / "input.json", public)
    control = {"interventions": case["interventions"], **(control_extra or {})}
    durable_json(output / "control.json", control)
    processes = []
    for attempt in range(3):
        prior_ids = {path.name for pattern in ("guard_*.json", "error_*.json") for path in output.glob(pattern)}
        command = [sys.executable, "-I", str(HERE / "worker.py"), "--backend", backend,
                   "--input", str(output / "input.json"), "--control", str(output / "control.json"),
                   "--output", str(output)]
        if attempt:
            command.append("--resume")
        start = time.monotonic()
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        timed_out = False
        try:
            console, _ = child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
            child.kill()
            console, _ = child.communicate()
        (output / ("worker_" + str(attempt) + ".log")).write_text(console, encoding="utf-8")
        identities = [read(path) for pattern in ("guard_*.json", "error_*.json") for path in output.glob(pattern) if path.name not in prior_ids]
        actual_pids = {value["pid"] for value in identities if "pid" in value}
        actual_pid = next(iter(actual_pids)) if len(actual_pids) == 1 else None
        processes.append({"pid": actual_pid, "launcher_pid": child.pid, "attempt": attempt, "exit_code": child.returncode,
                          "timed_out": timed_out, "elapsed_seconds": time.monotonic() - start,
                          "service_principal": case["policy"]["principal_id"]})
        durable_json(output / "PROCESSES.json", processes)
        if child.returncode != 86 or timed_out:
            break
    identity_file = output / "BACKEND_IDENTITY.json"
    if identity_file.exists():
        relative = Path(read(identity_file)["db_relative"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Backend DB path is outside case evidence")
        database = output / relative
        if database.exists():
            backup_sqlite(database, output / "state.sqlite")
    return processes


def evaluate_one(case, expected, evidence, *, review_output=None, expected_backend=None):
    evidence = Path(evidence)
    work = evidence if review_output is None else Path(review_output)
    if review_output is not None:
        work.mkdir(parents=True, exist_ok=False)
    # These oracle inputs are written only AFTER the controller processes end.
    durable_json(work / "audit_case.json", case)
    durable_json(work / "audit_expected.json", expected)
    command = [sys.executable, "-I", str(HERE / "oracle.py"),
               "--backend", expected_backend or evidence.name,
               "--case", str(work / "audit_case.json"),
               "--expected", str(work / "audit_expected.json"),
               "--evidence", str(evidence), "--output", str(work / "AUDIT.json")]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", timeout=30)
    (work / "oracle_console.log").write_text(result.stdout, encoding="utf-8")
    if not (work / "AUDIT.json").exists():
        return {"status": "ERROR", "reason": "ORACLE_PROCESS_FAILED", "exit_code": result.returncode}
    audit = read(work / "AUDIT.json")
    if result.returncode not in (0, 1):
        raise ValueError("Unexpected oracle process exit")
    return audit


def campaign(output, *, mode, selected=None, backends=("Z", "C")):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    data = read(HERE / "data" / "public_cases.json")
    expectations = read(HERE / "data" / "oracle_expectations.json")["cases"]
    cases = [case for case in data["cases"] if selected is None or case["case_id"] in selected]
    if selected is not None and set(selected) != {case["case_id"] for case in cases}:
        raise ValueError("Unknown selected case")
    if mode == "qualify":
        if selected is not None or tuple(backends) != ("Z", "C"):
            raise ValueError("Qualification must retain all24pairs and both arms")
        freeze = read(HERE / "data" / "FREEZE.json")
        for name, wanted in freeze["files"].items():
            if digest(HERE / name) != wanted:
                raise ValueError("Frozen input changed: " + name)
    durable_json(output / "SOURCE.json", source_identity())
    results = []
    for case in cases:
        for backend in backends:
            directory = output / "cases" / case["case_id"] / backend
            try:
                run_one(case, backend, directory)
                audit = evaluate_one(case, expectations[case["case_id"]], directory)
            except Exception as error:
                audit = {"status": "ERROR", "reason": type(error).__name__, "message": str(error)}
            results.append({"case_id": case["case_id"], "backend": backend, "audit": audit})
    summary = {"format": "zti-r7-campaign/1", "mode": mode,
               "status": "PASS" if all(item["audit"]["status"] == "PASS" for item in results) else "FAIL",
               "paired_cases": len(cases) if len(backends) == 2 else 0,
               "controller_executions": len(results), "template_count": len({case["template"] for case in cases}),
               "same_templates_reused": True, "independent_human_validation": False,
               "behavioral_LLM_experiment": False, "new_MCP_wire_qualification": False,
               "results": results}
    if len(backends) == 2:
        paired = []
        for case in cases:
            arms = {item["backend"]: item["audit"] for item in results if item["case_id"] == case["case_id"]}
            keys = ("goal_complete", "unauthorized_effects", "missing_required_outboxes", "extra_outboxes",
                    "semantic_duplicates", "factual_false_DONE", "unsupported_DONE", "justified_UNKNOWN", "claim_status",
                    "unnecessary_UNKNOWN", "false_refusals", "read_changes", "outbox_count", "delivery_count", "consumed", "reserved")
            paired.append({"case_id": case["case_id"], "equal_observed_outcomes": all(arms["Z"].get(key) == arms["C"].get(key) for key in keys)})
        summary["pairs"] = paired
        summary["comparison"] = ("NOT_ESTABLISHED_INVALID_RUN" if summary["status"] != "PASS" else
                                 "EQUALITY_OBSERVED" if all(item["equal_observed_outcomes"] for item in paired) else "DIFFERENCE_REQUIRES_ATTRIBUTION")
    durable_json(output / "SUMMARY.json", summary)
    return summary
