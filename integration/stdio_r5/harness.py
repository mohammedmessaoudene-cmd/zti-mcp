"""Frozen R5 campaign through real official-SDK stdio processes.

This driver selects inputs and trusted scheduling controls. readback.py owns
the independent expected/observed comparisons against SQLite base tables and
recorded pipe frames. It never treats a transport failure as a policy refusal.
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
import time
import traceback
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

from mcp import Client, StdioServerParameters, types
from mcp.client.extension import advertise
from mcp.shared.exceptions import MCPError
from crypto import verify_jws
from fixtures import build_fixture
from models import CAPABILITY, EXT_ID, PARAM_TYPES, PROTOCOL, ControlResult

TIMEOUT = 35


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def atomic_text(path: Path, value: str) -> None:
    temp = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    temp.write_text(value, encoding="utf-8", newline="\n")
    os.replace(temp, path)


def jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    # A live writer may be midway through its last append; the final independent
    # reader still rejects malformed/incomplete persisted records after shutdown.
    lines = raw.splitlines()
    if raw and not raw.endswith("\n"):
        lines = lines[:-1]
    return [json.loads(line) for line in lines if line]


def revision(db: Path) -> str | None:
    if not db.exists():
        return None
    with sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True) as connection:
        rows = connection.execute("SELECT state_revision FROM roots").fetchall()
    return rows[0][0] if rows else None


def independent_digest(value: Any) -> str:
    """Independent JSON subset digest for the recorded transformation evidence."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


class Endpoint:
    def __init__(self, run: "VariantRun", alias: str, generation: int = 1):
        self.run = run
        self.alias = alias
        self.instance = alias + "-" + str(generation) + "-" + secrets.token_hex(8)
        self.generation = generation
        self.wire = run.directory / "wire" / (self.instance + ".jsonl")
        self.lifecycle = run.directory / "wire" / (self.instance + ".lifecycle.jsonl")
        self.control = run.directory / "control" / self.instance
        self.control.mkdir(parents=True)
        self.config_path = run.directory / "config" / (self.instance + ".json")
        config = {
            "db_path": str(run.db),
            "principal": run.fixture["endpoint_principals"][alias],
            "role": "admin" if alias == "admin" else ("intruder" if alias == "intruder" else "agent"),
            "clock_path": str(run.clock),
            "control_dir": str(self.control),
            "endpoint_instance_id": self.instance,
            "advertise_extension": not (alias == "agent_a" and not run.fixture["agent_a_server_advertises_extension"]),
            "mutant": run.mutant,
        }
        write_json(self.config_path, config)
        self.client = Client(
            StdioServerParameters(command=sys.executable, args=["-I", str(HERE / "relay.py"), "--config", str(self.config_path), "--wire", str(self.wire), "--lifecycle", str(self.lifecycle)]),
            mode="auto", extensions=[advertise(EXT_ID, settings=CAPABILITY)], cache=None,
            read_timeout_seconds=TIMEOUT,
        )
        self.started = False
        self.tools_listed = False
        self.fault_armed = False
        self.discovery: dict[str, Any] | None = None

    async def start(self) -> None:
        await self.client.__aenter__()
        self.started = True
        if self.client.protocol_version != PROTOCOL:
            raise RuntimeError("SDK selected an incompatible protocol version")
        discover = self.client.session.discover_result
        if discover is None:
            raise RuntimeError("No actual SDK discovery result")
        self.discovery = discover.model_dump(by_alias=True, mode="json", exclude_none=True)
        if not any(r.get("frame", {}).get("method") == "server/discover" for r in jsonl(self.wire) if isinstance(r.get("frame"), dict)):
            raise RuntimeError("The pipe transcript contains no actual discovery request")
        self.run.event("endpoint_started", endpoint=self.alias, endpoint_instance_id=self.instance)

    def crash_records(self) -> list[dict[str, Any]]:
        return [r for r in jsonl(self.control / "events.jsonl") if r.get("stage") == "process_exit" and r.get("exitcode") == 86]

    async def close(self) -> None:
        if self.started:
            try:
                await self.client.__aexit__(None, None, None)
            except Exception:
                if not (self.fault_armed and self.crash_records()):
                    raise
            self.started = False

    async def wait_exit(self) -> dict[str, Any]:
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            exits = [r for r in jsonl(self.lifecycle) if r.get("type") == "provider_exit"]
            if exits:
                return exits[-1]
            await asyncio.sleep(0.02)
        raise TimeoutError("Provider exit was not recorded")


class VariantRun:
    def __init__(self, directory: Path, contract: dict[str, Any], scenario: dict[str, Any], variant: dict[str, Any], mutant: str | None = None):
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True)
        self.contract, self.scenario, self.variant, self.mutant = contract, scenario, variant, mutant
        self.db = self.directory / "provider.sqlite"
        self.clock = self.directory / "clock.txt"
        self.fixture = build_fixture(contract, variant)
        atomic_text(self.clock, str(self.fixture["initial_clock"]))
        write_json(self.directory / "fixtures.json", self.fixture)
        self.endpoints: dict[str, Endpoint] = {}
        self.all_endpoints: list[Endpoint] = []
        self.pending: dict[str, asyncio.Task] = {}
        self.group_specs: dict[str, list[dict[str, Any]]] = {}
        self.hooks: dict[str, list[dict[str, Any]]] = {}
        self.observation: dict[str, Any] = {"scenario_id": scenario["id"], "variant_id": variant["id"], "mutant_id": mutant, "steps": {}, "groups": {}, "events": [], "endpoints": [], "infra_errors": [], "expected_faults": []}

    def event(self, kind: str, **values: Any) -> None:
        self.observation["events"].append({"sequence": len(self.observation["events"]) + 1, "timestamp_ns": time.monotonic_ns(), "kind": kind, "source": "harness", **values})

    async def launch(self, alias: str, generation: int = 1) -> Endpoint:
        endpoint = Endpoint(self, alias, generation)
        self.endpoints[alias] = endpoint
        self.all_endpoints.append(endpoint)
        await endpoint.start()
        return endpoint

    def operation_ref(self, alias: str) -> dict[str, str]:
        action = self.fixture["actions"][alias]
        return {k: action[k] for k in ("tenant_id", "root_mandate_id", "operation_id")}

    def request_values(self, spec: dict[str, Any]) -> dict[str, Any]:
        method = spec["method"]
        if method.endswith(".register"):
            return {"mandate": self.fixture["signed_mandates"][spec["mandate_ref"]]}
        if method.endswith(".reserve"):
            action = copy.deepcopy(self.fixture["actions"][spec["action_ref"]])
            for field, value in spec.get("action_mutation", {}).items():
                if field == "arguments.payload":
                    action["arguments"]["payload"] = value
                elif field != "preserve_operation_id":
                    raise ValueError("Undeclared action mutation: " + field)
            return {"action": action}
        if method.endswith(".lookup") or method.endswith(".cancel"):
            params = self.operation_ref(spec["operation_ref"])
            if method.endswith(".cancel"):
                params["reservation_id"] = self.observation["steps"][spec["reservation_from"]]["result"]["reservation_id"]
            return params
        if method.endswith(".revoke"):
            mandate = self.fixture["mandates"][spec["mandate_ref"]]
            return {k: mandate[k] for k in ("tenant_id", "root_mandate_id", "mandate_id")}
        if method == "tools/call":
            action = self.fixture["actions"][spec["action_ref"]]
            prior = self.observation["steps"][spec["ict_from"]]["result"]
            metadata = {"revision": "0.1", "operation_id": action["operation_id"], "ict": prior["ict"]}
            mutation = spec.get("request_mutation", {})
            if "omit_action_metadata_member" in mutation:
                metadata.pop(mutation["omit_action_metadata_member"])
            if "action_metadata_revision" in mutation:
                metadata["revision"] = mutation["action_metadata_revision"]
            if "decoded_jws_signature_xor" in mutation:
                h, p, sig = metadata["ict"].split(".")
                raw = bytearray(base64.urlsafe_b64decode(sig + "=" * ((-len(sig)) % 4)))
                change = mutation["decoded_jws_signature_xor"]
                raw[change["byte_offset"]] ^= change["mask"]
                metadata["ict"] = h + "." + p + "." + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
            return {"name": action["tool_name"], "arguments": copy.deepcopy(action["arguments"]), "_meta": {EXT_ID: metadata}}
        if method == "server/discover":
            return {}
        raise ValueError("Undeclared method " + method)

    async def request(self, spec: dict[str, Any]) -> dict[str, Any]:
        endpoint = self.endpoints[spec["endpoint"]]
        method = spec["method"]
        step_id = spec["id"]
        params = self.request_values(spec)
        if method in {"tools/call", EXT_ID + ".reserve"}:
            advertised = (endpoint.discovery or {}).get("capabilities", {}).get("extensions", {}).get(EXT_ID)
            if advertised != CAPABILITY:
                raise RuntimeError("Client profile gate blocks unsupported server settings before protected transmission")
        if method == "tools/call" and not endpoint.tools_listed:
            await endpoint.client.session.list_tools()
            endpoint.tools_listed = True
        before = revision(self.db)
        first_sequence = max((r.get("sequence", 0) for r in jsonl(endpoint.wire)), default=0)
        first_hook = len(jsonl(endpoint.control / "events.jsonl"))
        observed = {"method": method, "endpoint": endpoint.alias, "endpoint_instance_id": endpoint.instance, "action_ref": spec.get("action_ref"), "request": params, "before_revision": before}
        self.event(step_id + ":request_sent", step=step_id, endpoint=endpoint.alias, endpoint_instance_id=endpoint.instance)
        try:
            if method == "server/discover":
                # discover() may return its already adopted cache. The public
                # send_discover() path always emits the required actual probe.
                response = await endpoint.client.session.send_discover(PROTOCOL)
            elif method == "tools/call":
                response = await endpoint.client.session.call_tool(params["name"], params["arguments"], meta=params["_meta"])
            else:
                short = method.rsplit(".", 1)[-1]
                model = PARAM_TYPES[short].model_validate(params)
                response = await endpoint.client.session.send_request(types.Request(method=method, params=model), ControlResult)
            observed["sdk_result"] = response if isinstance(response, dict) else response.model_dump(by_alias=True, mode="json", exclude_none=True)
            if method == "server/discover":
                endpoint.discovery = observed["sdk_result"]
        except MCPError as exc:
            if exc.code == -31001:
                observed["error"] = exc.error.model_dump(by_alias=True, mode="json", exclude_none=True)
            elif endpoint.fault_armed and endpoint.crash_records():
                observed["transport_outcome"] = "CONNECTION_CLOSED_WITHOUT_VALID_RESULT"
                observed["policy_refusal_claimed"] = False
                observed["transport_exception"] = {"type": type(exc).__name__, "code": exc.code, "message": exc.message}
            else:
                self.observation["infra_errors"].append({"step": step_id, "type": type(exc).__name__, "code": exc.code, "message": exc.message})
                raise
        except Exception as exc:
            if endpoint.fault_armed and endpoint.crash_records():
                observed["transport_outcome"] = "CONNECTION_CLOSED_WITHOUT_VALID_RESULT"
                observed["policy_refusal_claimed"] = False
                observed["transport_exception"] = {"type": type(exc).__name__, "message": str(exc)}
            else:
                self.observation["infra_errors"].append({"step": step_id, "type": type(exc).__name__, "message": str(exc)})
                raise
        frames = [r for r in jsonl(endpoint.wire) if r.get("sequence", 0) > first_sequence and isinstance(r.get("frame"), dict)]
        requests = [r for r in frames if r["direction"] == "client_to_server" and r["frame"].get("method") == method]
        if not requests:
            raise RuntimeError("No captured request for " + step_id)
        observed["request_id"] = requests[-1]["frame"]["id"]
        observed["request_ids"] = [r["frame"]["id"] for r in requests]
        observed["wire_request_sequence"] = requests[-1]["sequence"]
        replies = [r for r in frames if r["direction"] == "server_to_client" and r["frame"].get("id") == observed["request_id"]]
        if replies:
            raw = replies[-1]["frame"]
            if "result" in raw:
                observed["result"] = raw["result"]
                if "sdk_result" not in observed:
                    raise RuntimeError("A raw success was not accepted by the SDK")
                if method.endswith(".reserve") and "ict" in raw["result"]:
                    observed["verified_ict_claims"] = verify_jws(raw["result"]["ict"], "zti-ict+jwt")
            elif "error" in raw:
                observed["error"] = raw["error"]
        elif "transport_outcome" not in observed:
            raise RuntimeError("No captured response for " + step_id)
        observed["after_revision"] = revision(self.db)
        self.observation["steps"][step_id] = observed
        # Record observed provider milestones before their received response.
        # This is an explicit causal relation; timestamp ties between separate
        # processes cannot reorder the barrier/revoke/consume schedules.
        relevant = {"tools/call": "call:commit", EXT_ID + ".revoke": "revoke:commit", EXT_ID + ".cancel": "cancel:commit"}.get(method)
        if relevant:
            for record in jsonl(endpoint.control / "events.jsonl")[first_hook:]:
                if record.get("event") == relevant and not record.get("stage"):
                    self.event("call:effect_commit" if self.mutant == "M02" and relevant == "call:commit" else relevant,
                               step=step_id, source="observed_provider_hook", provider_hook=record)
        self.event(step_id + (":refusal" if "error" in observed else ":response_received") if "transport_outcome" not in observed else step_id + ":connection_closed", step=step_id, endpoint=endpoint.alias)
        return observed

    def add_rule(self, step: dict[str, Any], endpoint_alias: str, event: str, behavior: str) -> dict[str, Any]:
        endpoint = self.endpoints[endpoint_alias]
        rule_id = step["id"] + "-" + endpoint.instance
        rule = {"id": rule_id, "event": event, "behavior": behavior, "release_file": rule_id + ".release"}
        if "operation_ref" in step:
            rule["operation_id"] = self.fixture["actions"][step["operation_ref"]]["operation_id"]
        if behavior == "transform":
            rule["payload"] = step["transform"]["to"]
        path = endpoint.control / "rules.json"
        current = read_json(path) if path.exists() else []
        atomic_text(path, json.dumps(current + [rule]))
        item = {"endpoint": endpoint_alias, "instance": endpoint.instance, "control_dir": str(endpoint.control), "rule": rule}
        self.hooks.setdefault(step["id"], []).append(item)
        if behavior == "crash":
            endpoint.fault_armed = True
        self.event("rule_armed", step=step["id"], endpoint=endpoint_alias, event=event, behavior=behavior)
        return item

    async def await_rules(self, reference: str, distinct_pids: int = 1) -> list[dict[str, Any]]:
        rules = self.hooks[reference]
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            arrivals = []
            for item in rules:
                rows = [r for r in jsonl(Path(item["control_dir"]) / "events.jsonl") if r.get("rule_id") == item["rule"]["id"] and r.get("stage") == "arrived"]
                if rows:
                    arrivals.append(rows[-1])
            if len(arrivals) == len(rules):
                if len({r["pid"] for r in arrivals}) != distinct_pids:
                    raise RuntimeError("Required distinct provider PIDs were not observed")
                for arrival in arrivals:
                    if arrival["event"] == "call:pause_after_validation":
                        records = jsonl(Path(next(item["control_dir"] for item in rules if item["instance"] == arrival["endpoint_instance_id"])) / "events.jsonl")
                        validations = [r for r in records if r.get("event") == "call:validation_transaction_finished" and r.get("operation_id") == arrival.get("operation_id")]
                        if not validations:
                            raise RuntimeError("M02 pause lacks observed earlier validation transaction")
                        self.event("call:validation_transaction_finished", source="observed_provider_hook", provider_hook=validations[-1])
                        self.event("call:pause_after_validation", source="observed_provider_hook", provider_hook=arrival)
                    elif arrival["event"] == "call:before_transaction":
                        self.event("call:pause_before_transaction", source="observed_provider_hook", provider_hook=arrival)
                self.event("barrier_arrivals_observed", step=reference, arrivals=arrivals)
                return arrivals
            for task in self.pending.values():
                if task.done() and task.exception() is not None:
                    raise task.exception()
            await asyncio.sleep(0.01)
        raise TimeoutError("Trusted hook/barrier arrival was not observed: " + reference)

    def release(self, reference: str) -> None:
        for item in self.hooks[reference]:
            path = Path(item["control_dir"]) / item["rule"]["release_file"]
            atomic_text(path, "release\n")
        self.event("call:pause_released" if len(self.hooks[reference]) == 1 else "reservation_barrier:released", step=reference)

    def checkpoint(self, step_id: str) -> None:
        if any(not task.done() for task in self.pending.values()):
            raise RuntimeError("Cannot read checkpoint while a request is pending")
        dest = self.directory / "checkpoints" / (step_id + ".sqlite")
        dest.parent.mkdir(exist_ok=True)
        if dest.exists():
            raise RuntimeError("Checkpoint already exists")
        with sqlite3.connect(self.db.as_uri() + "?mode=ro", uri=True) as source:
            with sqlite3.connect(dest) as target:
                source.backup(target)
        self.event("checkpoint_saved", step=step_id, file=str(dest.relative_to(self.directory)))

    async def execute_step(self, step: dict[str, Any]) -> None:
        kind = step["kind"]
        if kind == "mcp_request":
            if step.get("async_start"):
                self.pending[step["id"]] = asyncio.create_task(self.request(step))
                await asyncio.sleep(0)
            else:
                await self.request(step)
        elif kind == "client_profile_gate":
            discovered = self.endpoints["agent_a"].discovery
            capability = (discovered or {}).get("capabilities", {}).get("extensions", {}).get(EXT_ID)
            self.observation["steps"][step["id"]] = {"client_outcome": "PROFILE_UNSUPPORTED" if capability != CAPABILITY else "SUPPORTED", "is_wire_error": False}
        elif kind == "trusted_test_hook":
            event = {"after_sdk_validation_before_final_action": "after_sdk_validation_before_final_action", "before_atomic_effect_transaction": "call:pause_after_validation" if self.mutant == "M02" else "call:before_transaction"}[step["hook"]]
            self.add_rule(step, step["endpoint"], event, "transform" if "transform" in step else "pause")
        elif kind == "trusted_reservation_barrier":
            for endpoint in step["endpoints"]:
                self.add_rule(step, endpoint, "reserve:before_transaction", "pause")
        elif kind in {"await_hook_arrival", "await_barrier"}:
            await self.await_rules(step.get("hook_ref", step.get("barrier_ref")), step.get("distinct_provider_pids", 1))
        elif kind in {"release_hook", "release_barrier"}:
            self.release(step.get("hook_ref", step.get("barrier_ref")))
        elif kind == "await_request":
            await self.pending[step["request_ref"]]
        elif kind == "concurrent_mcp_requests":
            self.group_specs[step["id"]] = step["requests"]
            self.observation["groups"][step["id"]] = [r["id"] for r in step["requests"]]
            for request in step["requests"]:
                self.pending[request["id"]] = asyncio.create_task(self.request(request))
            await asyncio.sleep(0)
        elif kind == "await_requests":
            await asyncio.gather(*(self.pending[r["id"]] for r in self.group_specs[step["request_group_ref"]]))
        elif kind == "mcp_call_each_admitted_once":
            ids = []
            for request in self.group_specs[step["admission_group_ref"]]:
                result = self.observation["steps"][request["id"]].get("result", {})
                if result.get("status") == "RESERVED":
                    spec = {"id": step["id"] + ":" + request["id"], "method": "tools/call", "endpoint": request["endpoint"], "action_ref": request["action_ref"], "ict_from": request["id"]}
                    await self.request(spec)
                    ids.append(spec["id"])
            self.observation["groups"][step["id"]] = ids
        elif kind == "independent_readback_checkpoint":
            self.checkpoint(step["id"])
        elif kind == "trusted_clock_set":
            parts = step["value_ref"].split(".")
            value: Any = self.observation["steps"][parts[0]]
            for key in parts[1:]:
                value = value[key]
            if type(value) is not int:
                raise TypeError("Fixture clock is not an integer")
            atomic_text(self.clock, str(value))
            self.event("clock_set", step=step["id"], value=value, source_ref=step["value_ref"])
        elif kind == "trusted_fault":
            event = {"after_commit_return_before_response_write": "call:after_commit", "after_effect_consumption_receipt_staged_before_commit": "call:staged_before_commit"}[step["point"]]
            self.add_rule(step, step["endpoint"], event, "crash")
        elif kind == "await_endpoint_exit":
            endpoint = self.endpoints[step["endpoint"]]
            record = await endpoint.wait_exit()
            if record["returncode"] != 86 or not endpoint.crash_records():
                raise RuntimeError("Expected injected crash not observed")
            self.observation["expected_faults"].append({"step": step["id"], **record})
        elif kind == "restart_endpoint":
            old = self.endpoints[step["endpoint"]]
            await old.close()
            await self.launch(step["endpoint"], old.generation + 1)
        else:
            raise ValueError("Unknown frozen step kind: " + kind)

    def collect_events(self) -> None:
        provider_events = []
        for endpoint in self.all_endpoints:
            lifecycle = jsonl(endpoint.lifecycle)
            starts = [r for r in lifecycle if r.get("type") == "provider_start"]
            exits = [r for r in lifecycle if r.get("type") == "provider_exit"]
            self.observation["endpoints"].append({"endpoint": endpoint.alias, "endpoint_instance_id": endpoint.instance, "provider_pid": starts[0]["provider_pid"] if starts else None, "lifecycle": lifecycle, "returncode": exits[-1]["returncode"] if exits else None})
            for item in jsonl(endpoint.control / "events.jsonl"):
                event = item["event"]
                if event == "call:before_transaction" and item.get("stage") == "arrived":
                    label = "call:pause_before_transaction"
                elif event == "call:pause_after_validation":
                    label = event
                elif self.mutant == "M02" and event == "call:commit":
                    label = "call:effect_commit"
                else:
                    label = event
                provider_events.append({**item, "kind": label, "source": "provider_hook"})
                if item.get("stage") == "transformed":
                    action = next(copy.deepcopy(a) for a in self.fixture["actions"].values() if a["operation_id"] == item["operation_id"])
                    before = copy.deepcopy(action)
                    before["arguments"] = item["before"]
                    action["arguments"] = item["after"]
                    self.observation.setdefault("transformed_actions", []).append({"before_action": before, "after_action": action, "before_action_hash": independent_digest(before), "after_action_hash": independent_digest(action), "source_hook": item})
        self.observation["provider_events"] = provider_events
        self.observation["event_order_basis"] = "Causal harness sequence of actual observed hook arrivals, received responses and release writes; raw per-provider event logs retained separately. Cross-process timestamp ties do not impose an order."

    async def run(self) -> dict[str, Any]:
        try:
            # Admin creates schema first; bootstrap writes only through real RPC.
            await self.launch("admin")
            for alias in ["root", *self.fixture["registered_leaves"]]:
                await self.request({"id": "bootstrap_register_" + alias, "method": EXT_ID + ".register", "endpoint": "admin", "mandate_ref": alias})
            for alias in self.fixture["endpoint_aliases"]:
                if alias != "admin":
                    await self.launch(alias)
            for step in self.variant["steps"]:
                await self.execute_step(step)
        except Exception as exc:
            self.observation["infra_errors"].append({"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()})
        finally:
            for task in self.pending.values():
                if not task.done():
                    task.cancel()
            if self.pending:
                await asyncio.gather(*self.pending.values(), return_exceptions=True)
            for endpoint in reversed(self.all_endpoints):
                try:
                    await endpoint.close()
                except Exception as exc:
                    self.observation["infra_errors"].append({"type": type(exc).__name__, "message": str(exc), "stage": "endpoint_close"})
            self.collect_events()
            write_json(self.directory / "observation.json", self.observation)
        from readback import verify_variant
        report = verify_variant(self.directory, self.scenario["id"], self.variant["id"], self.mutant)
        write_json(self.directory / "readback.json", report)
        return report


def source_identity() -> dict[str, Any]:
    repo = HERE.parents[1]
    def git(*args: str) -> str:
        return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout.decode("utf-8")
    files = [p for p in HERE.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    return {"commit": git("rev-parse", "HEAD").strip(), "git_status_porcelain": git("status", "--porcelain"), "diff_sha256": hashlib.sha256(git("diff", "HEAD").encode()).hexdigest(), "inputs": {p.relative_to(repo).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}, "runtime": {"os": platform.platform(), "python": sys.version, "sqlite": sqlite3.sqlite_version, "sdk": importlib.metadata.version("mcp"), "mcp_types": importlib.metadata.version("mcp-types"), "cryptography": importlib.metadata.version("cryptography")}, "client_pid": os.getpid()}


async def campaign(args: argparse.Namespace) -> dict[str, Any]:
    output = Path(args.output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("Use a fresh output directory; preserved evidence is never overwritten")
    output.mkdir(parents=True, exist_ok=True)
    contract = read_json(HERE / "scenarios.json")
    source = source_identity()
    write_json(output / "SOURCE.json", source)
    normal, mutants = [], []
    selected = {args.select} if args.select else None
    specs = [(s, v) for s in contract["scenarios"] for v in s["variants"]]
    allowed_variants = {s["id"] + "/" + v["id"] for s, v in specs}
    if args.select and args.select not in allowed_variants:
        raise ValueError("Unknown frozen scenario/variant: " + args.select)
    for scenario, variant in specs:
        if args.mutant or (selected and scenario["id"] + "/" + variant["id"] not in selected):
            continue
        name = scenario["id"] + "_" + variant["id"]
        result = await VariantRun(output / name, contract, scenario, variant).run()
        normal.append({"scenario": scenario["id"], "variant": variant["id"], "directory": name, "matches_oracle": result["matches_oracle"], "infrastructure_errors": result.get("infrastructure_errors", []), "errors": result.get("errors", [])})
        print(json.dumps({"variant": name, "matches_oracle": result["matches_oracle"], "infrastructure_errors": len(result.get("infrastructure_errors", []))}), flush=True)
        if not result["matches_oracle"]:
            break
    if args.mutant or (not selected and len(normal) == 20 and all(r["matches_oracle"] for r in normal)):
        for mutation in contract["integration_mutants"]:
            if args.mutant and args.mutant != mutation["id"]:
                continue
            scenario, variant = next((s, v) for s, v in specs if s["id"] == mutation["base_scenario"] and v["id"] == mutation["base_variant"])
            name = mutation["id"] + "_" + variant["id"]
            result = await VariantRun(output / name, contract, scenario, variant, mutation["id"]).run()
            mutants.append({"mutant": mutation["id"], "directory": name, "matches_normal_oracle": result["matches_oracle"], "mutation_detected": result["mutation_detected"], "infrastructure_errors": result.get("infrastructure_errors", []), "errors": result.get("errors", [])})
            print(json.dumps({"mutant": mutation["id"], "mutation_detected": result["mutation_detected"], "infrastructure_errors": len(result.get("infrastructure_errors", []))}), flush=True)
    infrastructure = sum(len(r["infrastructure_errors"]) for r in normal + mutants)
    matched = sum(r["matches_oracle"] for r in normal)
    detected = sum(r["mutation_detected"] for r in mutants)
    full = not args.select and not args.mutant
    passed = infrastructure == 0 and matched == len(normal) and detected == len(mutants) and (not full or (len(normal) == 20 and len(mutants) == 2))
    summary = {"status": "PASS" if passed else "FAIL", "full_campaign": full, "source_commit": source["commit"], "source_git_status": source["git_status_porcelain"], "scenario_count": len({r["scenario"] for r in normal}), "normal_variant_count": len(normal), "normal_variants_matched": matched, "integration_mutant_count": len(mutants), "integration_mutants_detected": detected, "infrastructure_error_count": infrastructure, "normal": normal, "mutants": mutants, "runtime": source["runtime"], "contract_sha256": hashlib.sha256((HERE / "contract.md").read_bytes()).hexdigest(), "scenarios_sha256": hashlib.sha256((HERE / "scenarios.json").read_bytes()).hexdigest(), "limits": contract["limitations"]}
    write_json(output / "SUMMARY.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--select", help="One frozen scenario/variant, e.g. S01/nominal")
    selection.add_argument("--mutant", choices=["M01", "M02"])
    args = parser.parse_args()
    summary = asyncio.run(campaign(args))
    print(json.dumps({k: v for k, v in summary.items() if k not in {"normal", "mutants"}}, indent=2))
    raise SystemExit(0 if summary["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
