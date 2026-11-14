"""Trusted experiment worker; the adaptive pilot receives no oracle or schedule.

Apache-2.0, Mohammed Messaoudene. AI-assisted research implementation.
Process/import guards prevent accidental leakage, not a hostile-OS sandbox.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import traceback

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "zti_r7"


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def durable_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded(value) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def append(path, value):
    with Path(path).open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded(value) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def guard(public):
    if set(public) != {"seed", "policy", "task"}:
        raise ValueError("Closed public input required; oracle/schedule is not pilot input")
    forbidden = ("oracle", "expectation", "scoring", "fixture_builder")
    loaded = sorted(name for name in sys.modules if any(part in name.lower() for part in forbidden))
    if loaded:
        raise ValueError("Oracle module loaded into controller process: " + ",".join(loaded))
    return {"oracle_module_loaded": False, "pid": os.getpid(),
            "loaded_project_modules": sorted(name for name in sys.modules if name.startswith("zti_r7")),
            "input_keys": sorted(public), "hostile_os_isolation": False}


class FaultHooks:
    """The harness owns injections. No schedule is passed into run_pilot."""

    def __init__(self, output, schedule):
        self.output = Path(output)
        self.schedule = schedule
        self.backend = None

    def __call__(self, event, detail):
        append(self.output / "provider_events.jsonl", {"pid": os.getpid(), "event": event, "detail": detail})
        for index, item in enumerate(self.schedule):
            if item["boundary"] != event or item["action"] == "withhold":
                continue
            marker = self.output / ("injection_" + str(index) + ".json")
            if marker.exists():
                continue
            durable_json(marker, {"index": index, "boundary": event, "pid": os.getpid(), "action": item["action"]})
            if item["action"] == "environment":
                result = self.backend.inject_environment(item["change"])
                append(self.output / "provider_events.jsonl", {"pid": os.getpid(), "event": "environment_change_committed", "detail": result})
            elif item["action"] == "revoke":
                result = self.backend.revoke()
                append(self.output / "provider_events.jsonl", {"pid": os.getpid(), "event": "revocation_committed", "detail": result})
            elif item["action"] == "exit":
                append(self.output / "provider_events.jsonl", {"pid": os.getpid(), "event": "harness_process_exit", "detail": {"code": item["exit_code"], "boundary": event}})
                os._exit(item["exit_code"])
            else:
                raise ValueError("Unknown closed harness injection")

    def withhold_lookup(self):
        for index, item in enumerate(self.schedule):
            if item["boundary"] != "lookup_response" or item["action"] != "withhold":
                continue
            marker = self.output / ("injection_" + str(index) + ".json")
            count = json.loads(marker.read_text(encoding="utf-8"))["count"] if marker.exists() else 0
            if count < item["limit"]:
                durable_json(marker, {"index": index, "boundary": "lookup_response", "count": count + 1})
                return True
        return False


class VisibleBackend:
    def __init__(self, backend, output, hooks):
        self._backend = backend
        self._output = Path(output)
        self._hooks = hooks

    def prepare(self, arguments, operation_id):
        return self._backend.prepare(arguments, operation_id)

    def _call(self, method, *args):
        path = self._output / "observations.jsonl"
        request_path = self._output / "requests.jsonl"
        call_id = sum(1 for _ in request_path.open(encoding="utf-8")) + 1 if request_path.exists() else 1
        retained = json.loads((self._output / "journal.json").read_text(encoding="utf-8"))
        pending = retained["pending_call"]
        if pending["number"] != call_id or pending["method"] != method or pending["args"] != json.loads(encoded(args)):
            raise ValueError("Durable pre-dispatch journal does not bind actual call")
        records = {key: {name: value[name] for name in ("operation_id", "arguments", "action_hash", "phase") if name in value}
                   for key, value in retained["records"].items()}
        append(self._output / "dispatch_journal.jsonl", {"call_id": call_id, "pid": os.getpid(),
               "pending_call": pending, "records": records, "provider_calls": retained["provider_calls"],
               "lookup_calls": retained["lookup_calls"]})
        append(request_path, {"call_id": call_id, "pid": os.getpid(), "method": method, "args": args})
        result = getattr(self._backend, method)(*args)
        if result.get("status") == "REFUSED" and method in {"reserve", "execute"}:
            # Trusted auditor-only raw snapshot; never returned to the pilot.
            connection = sqlite3.connect(Path(self._backend.db_path).resolve().as_uri() + "?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("BEGIN")
                names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
                if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names):
                    raise ValueError("Unexpected auditor table")
                tables = {name: [dict(row) for row in connection.execute('SELECT * FROM "' + name + '"')] for name in names}
            finally:
                connection.close()
            append(self._output / "refusal_snapshots.jsonl", {"call_id": call_id, "tables": tables})
        withheld = method == "lookup" and self._hooks.withhold_lookup()
        if withheld:
            append(self._output / "provider_events.jsonl", {"pid": os.getpid(), "event": "lookup_response_not_delivered", "detail": {"operation_id": args[0], "actual_status": result.get("status")}})
            visible = {"status": "SUSPENDED", "reason": "OBSERVATION_UNAVAILABLE"}
        else:
            visible = result
        append(path, {"call_id": call_id, "pid": os.getpid(), "method": method,
                      "response": visible, "response_delivered": not withheld})
        return visible

    def observe(self):
        return self._call("observe")

    def reserve(self, arguments, operation_id):
        return self._call("reserve", arguments, operation_id)

    def execute(self, arguments, operation_id, reservation):
        return self._call("execute", arguments, operation_id, reservation)

    def lookup(self, operation_id):
        return self._call("lookup", operation_id)

    def cancel(self, operation_id, reservation):
        return self._call("cancel", operation_id, reservation)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", required=True, choices=("Z", "C"))
    parser.add_argument("--input", required=True)
    parser.add_argument("--control", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    public = json.loads(Path(args.input).read_text(encoding="utf-8"))
    control = json.loads(Path(args.control).read_text(encoding="utf-8"))
    try:
        if control.get("inject_oracle_module"):
            from . import oracle  # Deliberate separate instrumentation control.
        from .pilot import run_pilot
        if args.backend == "Z":
            from .zti_backend import ZtiBackend as Backend
        else:
            from .classic_backend import ClassicBackend as Backend
        module_guard = guard(public)
        durable_json(output / ("guard_" + str(os.getpid()) + ".json"), module_guard)
        hooks = FaultHooks(output, control.get("interventions", []))
        backend = Backend(output / "private", public["seed"], public["policy"], hook=hooks, initialize=not args.resume)
        hooks.backend = backend
        durable_json(output / "BACKEND_IDENTITY.json", {"backend": args.backend,
                    "db_relative": str(Path(backend.db_path).relative_to(output)), "service_principal": public["policy"]["principal_id"]})
        view = VisibleBackend(backend, output, hooks)
        claim = run_pilot(view, public["task"], public["policy"], output / "journal.json")
        guard(public)
        durable_json(output / "claim.json", claim)
        print(encoded({"status": "WORKER_COMPLETED", "pid": os.getpid(), "claim": claim.get("status")}))
        return 0
    except Exception as error:
        durable_json(output / ("error_" + str(os.getpid()) + ".json"),
                     {"status": "OPERATIONAL_ERROR", "pid": os.getpid(), "type": type(error).__name__, "message": str(error)})
        traceback.print_exc()
        return 88 if "Oracle module loaded" in str(error) else 1


if __name__ == "__main__":
    raise SystemExit(main())
