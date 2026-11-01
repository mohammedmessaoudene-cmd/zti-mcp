"""Real-process R6 campaign machinery. Independent oracle owns all verdicts."""
import asyncio
import base64
import copy
import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import sys
import time

from common import EXT, R6, atomic, backup, digest, jsonl, read, revision, tables, write, quiesce
from fixtures import claims_of, issuer, resolve, signed_variant


class Bridge:
    def __init__(self, case, alias, sdk, generation):
        self.case, self.alias, self.sdk = case, alias, sdk
        self.instance = alias + "-" + str(generation) + "-" + secrets.token_hex(8)
        self.wire = case.directory / "wire" / (self.instance + ".jsonl")
        self.lifecycle = self.wire.with_name(self.instance + ".lifecycle.jsonl")
        self.control = case.directory / "control" / self.instance
        self.control.mkdir(parents=True)
        private = case.private / self.instance
        private.mkdir(parents=True)
        self.settings_path = private / "settings.json"
        self.config_path = private / "config.json"
        principal = case.principal(alias)
        context = case.corpus["context"]["key_contexts"]
        config = {**context, "db_path": str(case.db), "principal": principal,
                  "role": "admin" if alias == "admin" else ("intruder" if alias == "intruder" else "agent"),
                  "clock_path": str(case.clock), "control_dir": str(self.control),
                  "endpoint_instance_id": self.instance, "tools": ["zti_r6_demo.tools:tools"],
                  "mandate_public_key_path": case.keys["KI"]["public"],
                  "permit_private_key_path": case.keys["KP"]["private"], "mutant": case.mutant}
        write(self.config_path, config)
        info = case.spec.get("fixture_overrides", {}).get("client_info_by_channel", {}).get(alias)
        announced = case.spec.get("fixture_overrides", {}).get("announced_client_name_by_channel", {}).get(alias)
        if announced is not None:
            info = {"name": announced, "version": "0.3.0"}
        settings = {"python": str(case.options.python), "relay": str(R6 / "campaign" / "relay.py"),
                    "config": str(self.config_path), "wire": str(self.wire), "lifecycle": str(self.lifecycle),
                    "stderr": str(private / "endpoint.stderr.txt"), "client_events": str(private / "client-events.json"),
                    "principal": principal, "context": context,
                    "public_keys": {role: item["jwk"] for role, item in case.keys.items()}}
        if info:
            settings["client_info"] = info
        write(self.settings_path, settings)
        self.pending, self.process, self.reader_task, self.closed = {}, None, None, False
        self.ready = asyncio.get_running_loop().create_future()

    async def start(self):
        command = ([str(self.case.options.python), "-I", "-m", "zti_r6_demo.client"] if self.sdk == "P"
                   else [str(self.case.options.node), str(self.case.options.client_dir / "client.ts")])
        self.stderr = (self.settings_path.parent / "bridge.stderr.txt").open("wb")
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.process = await asyncio.create_subprocess_exec(*command, "--settings", str(self.settings_path),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=self.stderr,
            cwd=self.case.private, env=env)
        self.reader_task = asyncio.create_task(self._read())
        startup = await asyncio.wait_for(asyncio.shield(self.ready), 40)
        item = {"connection": self.alias, "client": self.sdk, "endpoint_instance_id": self.instance,
                "wire": self.wire.relative_to(self.case.directory).as_posix(),
                "lifecycle": self.lifecycle.relative_to(self.case.directory).as_posix(),
                "provider_events": (self.control / "events.jsonl").relative_to(self.case.directory).as_posix(),
                "principal": self.case.principal(self.alias), "bridge_pid": self.process.pid,
                "discovery": startup["discovery"], "loaded": startup.get("loaded", {})}
        self.case.observation["connections"].append(item)
        self.case.event("connection_ready", connection=self.alias, endpoint_instance_id=self.instance, client=self.sdk)

    async def _read(self):
        try:
            while line := await self.process.stdout.readline():
                item = json.loads(line)
                if item.get("type") == "ready":
                    if self.ready.done():
                        raise RuntimeError("Duplicate bridge ready")
                    self.ready.set_result(item)
                elif item.get("id") in self.pending:
                    self.pending.pop(item["id"]).set_result(item)
                else:
                    raise RuntimeError("Uncorrelated client bridge output")
            error = RuntimeError("SDK bridge closed its command channel")
            if not self.ready.done():
                self.ready.set_exception(error)
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(error)
        except Exception as exc:
            if not self.ready.done():
                self.ready.set_exception(exc)
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(exc)

    async def request(self, command):
        future = asyncio.get_running_loop().create_future()
        if command["id"] in self.pending:
            raise ValueError("Duplicate bridge command identifier")
        self.pending[command["id"]] = future
        self.process.stdin.write((json.dumps(command, ensure_ascii=True) + "\n").encode("utf-8"))
        await self.process.stdin.drain()
        return await asyncio.wait_for(future, 40)

    def expected_crashes(self):
        return [item for item in jsonl(self.control / "events.jsonl") if item.get("stage") == "process_exit" and item.get("exitcode") == 86]

    async def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process:
            if self.process.returncode is None:
                try:
                    self.process.stdin.write(b'{"id":"close","method":"close"}\n')
                    await self.process.stdin.drain()
                    self.process.stdin.close()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                try:
                    await asyncio.wait_for(self.process.wait(), 20)
                except asyncio.TimeoutError:
                    self.process.kill()
                    await self.process.wait()
                    raise RuntimeError("SDK bridge required unexpected termination")
            if self.reader_task:
                await self.reader_task
            code = self.process.returncode
            self.case.event("bridge_exit", connection=self.alias, endpoint_instance_id=self.instance, returncode=code)
            if code != 0 and not self.expected_crashes():
                raise RuntimeError("SDK bridge exited unexpectedly: " + str(code))
            event_path = self.settings_path.parent / "client-events.json"
            if self.sdk == "T":
                if not event_path.exists():
                    raise RuntimeError("Missing TypeScript SDK error/loaded-source receipt")
                actual = read(event_path)
                self.case.observation.setdefault("client_events", {})[self.instance] = actual
                unexpected = [item for item in actual.get("asyncErrors", [])
                              if not (self.expected_crashes() and item.get("code") == "CONNECTION_CLOSED")]
                if unexpected:
                    self.case.observation["infrastructure_errors"].append({"connection": self.alias,
                        "type": "SDKAsyncError", "errors": unexpected})
                    raise RuntimeError("Unexpected asynchronous SDK errors")
        if hasattr(self, "stderr"):
            self.stderr.close()
        exits = [item for item in jsonl(self.lifecycle) if item.get("type") == "provider_exit"]
        if not exits or exits[-1].get("returncode") not in (0, 86):
            raise RuntimeError("Provider did not record a normal or selected crash exit")
        if exits[-1]["returncode"] == 86 and not self.expected_crashes():
            raise RuntimeError("Unexplained provider crash")


class Case:
    def __init__(self, options, corpus, directory, category, spec, sdk="P", pair=None, mutant=None):
        self.options, self.corpus, self.spec = options, corpus, copy.deepcopy(spec)
        self.directory, self.category = Path(directory).resolve(), category
        self.directory.mkdir(parents=True, exist_ok=False)
        self.private = options.private_root / self.directory.name
        self.private.mkdir(parents=True, exist_ok=False)
        self.keys = issuer.make_keys(self.private / "keys")
        self.db, self.clock = self.directory / "provider.sqlite", self.private / "clock.txt"
        atomic(self.clock, str(corpus["context"]["clock"]))
        self.mutant, self.sdk, self.pair = mutant, sdk, pair
        self.fixture = resolve(corpus, self.keys, spec.get("fixture_overrides", spec.get("overrides", {})))
        self.channels, self.all_channels, self.generations = {}, [], {}
        self.tokens, self.pending, self.rules, self.rule_specs = {}, {}, {}, {}
        self.observation = {"format": "zti-r6-evidence/1", "steps": {}, "groups": {}, "events": [],
                            "connections": [], "checkpoints": [], "infrastructure_errors": [], "expected_faults": []}
        self.manifest = {"format": "zti-r6-evidence/1", "case_id": self.directory.name, "category": category,
                         "history_id": spec["id"] if spec["id"].startswith("I") else None,
                         "plan_id": spec["id"] if spec["id"].startswith("C") else None,
                         "diagnostic_id": spec["id"] if spec["id"].startswith("D") else None,
                         "client": sdk, "pair": pair, "mutant_id": mutant,
                         "context": corpus["context"]["key_contexts"],
                         "public_keys": {role: item["jwk"] for role, item in self.keys.items()},
                         "initial_clock": corpus["context"]["clock"], "source": options.source,
                         "runtime_receipt_sha256": options.runtime_receipt_sha256,
                         "distribution_guard_sha256": getattr(options, "distribution_guard_sha256", None),
                         "build_receipt_sha256": getattr(options, "build_receipt_sha256", None),
                         "files": {"database": "provider.sqlite", "fixtures": "fixtures.json", "observation": "observation.json"}}
        self.persist()

    def principal(self, alias):
        return self.corpus["context"]["principals"]["A" if alias == "A2" else alias]

    def sdk_for(self, alias):
        if not self.pair:
            return self.sdk
        roles = self.spec["pair_roles"]
        if roles["first"] == alias or alias == "A":
            return self.pair[0]
        if roles["second"] == alias or alias in ("B", "A2"):
            return self.pair[1]
        if alias == "admin" and self.spec["family"] in ("revocation", "cancellation"):
            return self.pair[1]
        return "P"

    def event(self, kind, **details):
        self.observation["events"].append({"sequence": len(self.observation["events"]) + 1,
            "kind": kind, "timestamp_ns": time.monotonic_ns(), **details})

    def persist(self):
        write(self.directory / "manifest.json", self.manifest)
        write(self.directory / "fixtures.json", self.fixture)
        write(self.directory / "observation.json", self.observation)

    async def launch(self, alias, sdk=None):
        old = self.channels.get(alias)
        if old and not old.closed:
            return old
        generation = self.generations.get(alias, 0) + 1
        self.generations[alias] = generation
        bridge = Bridge(self, alias, sdk or self.sdk_for(alias), generation)
        self.channels[alias] = bridge
        self.all_channels.append(bridge)
        await bridge.start()
        self.persist()
        return bridge

    async def bootstrap(self):
        await self.launch("admin", "P" if self.pair else self.sdk)
        for alias in ("root", "leafA", "leafB"):
            await self.request({"id": "bootstrap." + alias, "channel": "admin", "method": EXT + ".register", "args": {"mandate_ref": alias}})

    def operation(self, alias):
        action = self.fixture["actions"][alias]
        return {key: action[key] for key in ("tenant_id", "root_mandate_id", "operation_id")}

    def values(self, step):
        method, args = step["method"], step.get("args", {})
        action = None
        if method.endswith(".register"):
            alias = args["mandate_ref"]
            token = self.fixture["mandates"][alias]["jws"]
            if any(key in args for key in ("constraint_override", "sign_with", "claims_overrides", "header", "typ", "kid_role", "signature_xor")):
                record = signed_variant(self.fixture, alias, args, self.keys)
                self.fixture["request_mandates"][step["id"]] = record
                token = record["jws"]
            params = {"mandate": token}
        elif method.endswith(".reserve"):
            action = copy.deepcopy(self.fixture["actions"][args["action_ref"]])
            if "arguments_override" in args:
                action["arguments"] = copy.deepcopy(args["arguments_override"])
            if "action_override" in args:
                action.update(copy.deepcopy(args["action_override"]))
            params = {"action": action}
        elif method.endswith(".lookup") or method.endswith(".cancel"):
            params = self.operation(args["operation_ref"])
            if method.endswith(".cancel"):
                params["reservation_id"] = self.tokens[args["operation_ref"]]["reservation_id"]
        elif method.endswith(".revoke"):
            body = self.fixture["mandates"][args["mandate_ref"]]["body"]
            params = {key: body[key] for key in ("tenant_id", "root_mandate_id", "mandate_id")}
        elif method == "tools/call":
            alias = args["action_ref"]
            action = copy.deepcopy(self.fixture["actions"][alias])
            if "arguments_override" in args:
                action["arguments"] = copy.deepcopy(args["arguments_override"])
            metadata = {"revision": "0.1", "operation_id": action["operation_id"]}
            token = self.tokens[alias]["ict"]
            if "ict_mutation" in args:
                claims = claims_of(token)
                mutation = args["ict_mutation"]
                signer, kid_role = mutation.get("sign_with", "KI"), mutation.get("kid_role", "KI")
                token = issuer.sign_claims(claims, self.keys[signer]["private"], typ=mutation.get("typ", "zti-ict+jwt"),
                    kid=self.manifest["context"]["mandate_kid" if kid_role == "KI" else "permit_kid"])
                self.fixture["negative_icts"][step["id"]] = {"jws": token, "claims": claims, "signer_role": signer}
            if not args.get("omit_ict"):
                metadata["ict"] = token
            params = {"name": action["tool_name"], "arguments": action["arguments"], "_meta": {EXT: metadata}}
        elif method in ("server/discover", "tools/list"):
            params = {}
        else:
            raise ValueError("Undeclared method " + method)
        if step.get("request_meta"):
            params.setdefault("_meta", {}).update(step["request_meta"])
        if args.get("claimed_principal"):
            params.setdefault("_meta", {})["org.example/zti-mcp/claimedPrincipal"] = args["claimed_principal"]
        self.persist()
        return params, action

    async def request(self, step):
        alias, method, name = step.get("channel", "A"), step["method"], step["id"]
        if self.pair and alias == "admin" and self.spec["family"] in ("revocation", "cancellation") and method.endswith((".revoke", ".cancel")):
            existing = self.channels.get("admin")
            if existing and existing.sdk != self.pair[1]:
                await existing.close()
                await self.launch("admin", self.pair[1])
        bridge = await self.launch(alias)
        params, action = self.values(step)
        first = max((item["sequence"] for item in jsonl(bridge.wire)), default=0)
        before = revision(self.db)
        self.event("request_dispatched", step=name, connection=alias, endpoint_instance_id=bridge.instance)
        command = {"id": name, "method": method, "params": params}
        if action is not None:
            command["binding_action"] = action
        observed = {"method": method, "connection": alias, "client": bridge.sdk,
                    "endpoint_instance_id": bridge.instance, "action_ref": step.get("args", {}).get("action_ref"),
                    "before_revision": before, "request_params": params}
        try:
            reply = await bridge.request(command)
            if "binding" in reply:
                observed["client_binding"] = reply["binding"]
            if "binding_error" in reply:
                observed["client_binding_error"] = reply["binding_error"]
            observed["sdk_reply"] = reply
        except Exception as exc:
            reply = {"transport_error": {"type": type(exc).__name__, "message": str(exc)}}
            observed["sdk_reply"] = reply
        frames = [item for item in jsonl(bridge.wire) if item["sequence"] > first and isinstance(item.get("frame"), dict)]
        requests = [item for item in frames if item["direction"] == "client_to_server" and item["frame"].get("method") == method]
        if len(requests) != 1:
            raise RuntimeError("Expected one actual request for " + name + ", observed " + str(len(requests)))
        req = requests[0]
        observed.update(request_id=req["frame"]["id"], request=req["frame"], wire_request_sequence=req["sequence"])
        responses = [item for item in frames if item["direction"] == "server_to_client" and item["frame"].get("id") == req["frame"]["id"]]
        if responses:
            if len(responses) != 1:
                raise RuntimeError("Duplicate response for " + name)
            response = responses[0]
            observed["wire_response_sequence"] = response["sequence"]
            if "result" in response["frame"]:
                observed["result"] = response["frame"]["result"]
                if "result" not in reply:
                    raise RuntimeError("Actual result rejected by SDK/client schema for " + name + ": " + str(reply))
            elif "error" in response["frame"]:
                observed["error"] = response["frame"]["error"]
                if "error" not in reply:
                    raise RuntimeError("SDK failed to expose actual protocol error for " + name)
        elif bridge.expected_crashes():
            observed["transport_outcome"] = "EXPECTED_PROCESS_EXIT_WITHOUT_RESPONSE"
            observed["transport_error"] = reply.get("transport_error", reply.get("error"))
            self.observation["expected_faults"].append({"step": name, "endpoint_instance_id": bridge.instance,
                "events": bridge.expected_crashes(), "no_response": True})
        else:
            raise RuntimeError("Missing protocol response without selected actual fault: " + name + " " + str(reply))
        if method.endswith(".reserve") and "ict" in observed.get("result", {}):
            self.tokens[step["args"]["action_ref"]] = observed["result"]
        observed["after_revision"] = revision(self.db)
        self.observation["steps"][name] = observed
        self.event("request_observed", step=name, connection=alias, request_id=observed["request_id"],
                   wire_sequence=observed.get("wire_response_sequence"), outcome="result" if "result" in observed else ("error" if "error" in observed else "expected_fault"))
        self.persist()
        return observed

    async def arm(self, alias, event, operation, behavior="pause", rule_id=None):
        bridge = await self.launch(alias)
        rule_id = rule_id or "rule-" + secrets.token_hex(8)
        rule = {"id": rule_id, "event": event, "operation_id": self.fixture["operation_ids"][operation], "behavior": behavior, "release_file": rule_id + ".release"}
        self.rules.setdefault(bridge.instance, []).append(rule)
        self.rule_specs[rule_id] = (bridge, rule)
        atomic(bridge.control / "rules.json", json.dumps(self.rules[bridge.instance]))
        self.event("rule_armed", connection=alias, rule_id=rule_id, event=event, behavior=behavior)
        return rule_id

    async def await_rule(self, rule_id):
        bridge, rule = self.rule_specs[rule_id]
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            for index, item in enumerate(jsonl(bridge.control / "events.jsonl")):
                if item.get("rule_id") == rule_id and item.get("stage") == "arrived":
                    self.event("hook_observed", connection=bridge.alias, endpoint_instance_id=bridge.instance,
                        event=item["event"], stage="arrived", rule_id=rule_id, provider_event_index=index)
                    self.persist()
                    return item
            await asyncio.sleep(0.01)
        raise TimeoutError("Trusted arrival not observed for " + rule_id)

    def release(self, rule_id):
        bridge, rule = self.rule_specs[rule_id]
        atomic(bridge.control / rule["release_file"], "release\n")
        self.event("release_written", rule_id=rule_id, connection=bridge.alias)
        self.persist()

    async def observe_commit(self, step_id, event):
        observed = self.observation["steps"][step_id]
        bridge = next(item for item in self.all_channels if item.instance == observed["endpoint_instance_id"])
        operation = self.fixture["operation_ids"].get(observed.get("action_ref"))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            for index, item in enumerate(jsonl(bridge.control / "events.jsonl")):
                if (item.get("event") == event and item.get("request_id") == observed["request_id"]
                        and (operation is None or item.get("operation_id") == operation)):
                    self.event("commit_observed", step=step_id, connection=bridge.alias,
                        endpoint_instance_id=bridge.instance, event=event, provider_event_index=index)
                    self.persist()
                    return item
            await asyncio.sleep(0.01)
        raise RuntimeError("Actual postcommit hook absent for " + step_id + ": " + event)

    def checkpoint(self, label, *, immutable_source=False):
        target = self.directory / "checkpoints" / (label + ".sqlite")
        backup(self.db, target, immutable_source=immutable_source)
        projection = target.with_suffix(".tables.json")
        write(projection, tables(target, immutable=True))
        self.observation["checkpoints"].append({"label": label,
            "database": target.relative_to(self.directory).as_posix(),
            "tables_json": projection.relative_to(self.directory).as_posix(),
            "event_cursor": len(self.observation["events"])})
        self.event("checkpoint_saved", label=label)
        self.persist()

    async def stop_all(self):
        errors = []
        for bridge in reversed(self.all_channels):
            try:
                await bridge.close()
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            raise RuntimeError("; ".join(errors))

    async def run_steps(self, steps):
        for step in steps:
            kind, name = step["kind"], step["id"]
            if kind == "rpc":
                await self.request(step)
            elif kind == "trusted_control":
                self.last_rule = await self.arm(step.get("channel", "A"), step["event"], step["operation_ref"], step["behavior"], name)
            elif kind == "start_async":
                self.pending[step["step"]["id"]] = asyncio.create_task(self.request(step["step"]))
            elif kind == "await_event":
                await self.await_rule(self.last_rule)
            elif kind == "release":
                self.release(step["rule_ref"])
            elif kind == "await_request":
                await self.pending.pop(step["request"])
            elif kind == "checkpoint":
                self.checkpoint(name)
            elif kind == "stop_all_writers":
                await self.stop_all()
            elif kind == "restart_channel":
                alias = step["channel"]
                old = self.channels.get(alias)
                sdk = old.sdk if old else self.sdk_for(alias)
                if old:
                    await old.close()
                if step.get("new_client") == "other_sdk":
                    sdk = "T" if sdk == "P" else "P"
                await self.launch(alias, sdk)
            elif kind == "concurrent_group":
                rules = []
                # Launch and arm every channel before starting either request.
                for child in step["steps"]:
                    rules.append(await self.arm(child["channel"], step["event"], child["args"]["action_ref"]))
                tasks = [asyncio.create_task(self.request(child)) for child in step["steps"]]
                for rule_id in rules:
                    await self.await_rule(rule_id)
                if step.get("release_order"):
                    by_name = {child["id"]: index for index, child in enumerate(step["steps"])}
                    for child_name in step["release_order"]:
                        index = by_name[child_name]
                        self.release(rules[index])
                        await tasks[index]
                        if child_name == step["release_order"][0] and step["event"] == "reserve:before_transaction":
                            await self.observe_commit(child_name, "reserve:commit")
                else:
                    for rule_id in rules:
                        self.release(rule_id)
                    await asyncio.gather(*tasks)
                self.observation["groups"][name] = [child["id"] for child in step["steps"]]
            else:
                raise ValueError("Undeclared frozen step kind " + kind)

    async def finish(self):
        if self.pending:
            await asyncio.gather(*self.pending.values())
            self.pending.clear()
        await self.stop_all()
        maintenance = quiesce(self.db)
        self.event("database_quiescent", maintenance=maintenance, all_provider_processes_stopped=True)
        self.checkpoint("final", immutable_source=True)
        self.persist()

    async def execute_history(self):
        try:
            await self.bootstrap()
            await self.run_steps(self.spec["steps"])
        except Exception as exc:
            self.observation["infrastructure_errors"].append({"type": type(exc).__name__, "message": str(exc)})
            raise
        finally:
            try:
                await self.finish()
            finally:
                self.persist()
