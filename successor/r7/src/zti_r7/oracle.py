"""Independent data-only R7 reader. No runtime/domain/controller imports.

Original Apache-2.0 contribution, Mohammed Messaoudene; AI-assisted.
Reads quiescent SQLite backups and actual delivered observations. It never
executes captured code. Finite fixture checking is not production assurance.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sqlite3


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def lines(path):
    path = Path(path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line] if path.exists() else []


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def sha(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def sql_tables(path):
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity check failed")
        names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names):
            raise ValueError("Unexpected SQL table name")
        return {name: [dict(row) for row in connection.execute('SELECT * FROM "' + name + '"')] for name in names}
    finally:
        connection.close()


def _authority(tables):
    """Read the separately implemented stores by their recorded schemas."""
    if "reservations" in tables:
        operations = tables["reservations"]
        receipts = {row["operation_id"]: json.loads(row["receipt_json"]) for row in tables["receipts"]}
        effects = {row["operation_id"]: row for row in tables["business_effects"]}
        return operations, receipts, effects
    if "c_operations" in tables:
        operations = tables["c_operations"]
        receipts = {row["operation_id"]: json.loads(row["receipt_json"]) for row in operations if row.get("receipt_json")}
        effects = {row["operation_id"]: row for row in operations if row.get("state") == "COMMITTED"}
        return operations, receipts, effects
    raise ValueError("Unrecognized independent authority schema")


def justified_refusal(snapshot, request, case):
    """Independent admissibility check at synchronous, post-refusal snapshot.

    The harness has one sequential writer. No writer runs between refusal and
    this raw snapshot. Failed execution has no effect; committed environment
    changes are retained, so this reconstructs the state used for the refusal.
    """
    policy = case["policy"]
    state = json.loads(json.dumps(case["seed"]))
    for row in sorted(snapshot["mail_events"], key=lambda value: value["row_id"]):
        payload = json.loads(row["payload_json"])
        if row["event_kind"] == "ENV_DIRECTORY":
            state["directory"]["groups"].update(payload["groups"])
            state["directory"]["version"] = payload["version"]
        elif row["event_kind"] == "ENV_MESSAGE_VERSION":
            state["messages"][payload["message_id"]]["version"] = payload["version"]
        elif row["event_kind"] in {"OUTBOX", "READ"}:
            state["messages"][row["message_id"]]["version"] = row["message_version"]
            if row["event_kind"] == "READ":
                state["messages"][row["message_id"]]["read"] = True
    root_rows = snapshot.get("roots", snapshot.get("c_root", []))
    if len(root_rows) != 1:
        raise ValueError("Missing authority activity snapshot")
    if not root_rows[0]["active"]:
        return True
    # Z may revoke the service leaf while the root stays active; the flat
    # classical policy represents that same scoped authority with c_root.active.
    if "mandates" in snapshot:
        operations, _, _ = _authority(snapshot)
        operation = next((row for row in operations if row["operation_id"] == request["args"][1]), None)
        if operation is not None:
            action = json.loads(operation["action_json"])
            mandates = {row["mandate_id"]: row for row in snapshot["mandates"]}
            current = action["mandate_id"]
            seen = set()
            while current is not None:
                if current in seen or current not in mandates:
                    raise ValueError("Malformed authority lineage in refusal snapshot")
                seen.add(current)
                mandate = mandates[current]
                if mandate["revoked"]:
                    return True
                current = mandate["parent_id"]
    arguments = request["args"][0]
    mid = arguments["message_id"]
    if mid not in state["messages"] or mid not in policy["allowed_messages"] or arguments["kind"] not in policy["allowed_modes"]:
        return True
    message = state["messages"][mid]
    if arguments["expected_message_version"] != message["version"] or arguments["expected_directory_version"] != state["directory"]["version"]:
        return True
    known = {state["self_id"]}
    for value in case["seed"]["messages"].values():
        known.add(value["sender"])
        for field in ("to", "cc", "bcc"):
            known.update(value[field])
    for mapping in (case["seed"]["directory"]["aliases"], case["seed"]["directory"]["groups"]):
        for members in mapping.values():
            known.update(members)
    resolved = {field: [] for field in ("to", "cc", "bcc")}
    if arguments["kind"] == "reply_all":
        resolved["to"] = sorted(({message["sender"], *message["to"], *message["cc"]}) - {state["self_id"]})
    elif arguments["kind"] == "reply":
        for field in resolved:
            people = set()
            selectors = arguments[field] or ([message["sender"]] if field == "to" else [])
            for selector in selectors:
                if selector in state["directory"]["aliases"]:
                    members = state["directory"]["aliases"][selector]
                elif selector in state["directory"]["groups"]:
                    members = state["directory"]["groups"][selector]
                elif selector in known:
                    members = [selector]
                else:
                    return True
                if any(member not in known for member in members):
                    return True
                people.update(members)
            resolved[field] = sorted(people)
    if any(arguments["expected_" + field] != resolved[field] for field in resolved):
        return True
    if any(person not in policy["allowed_recipients"] for values in resolved.values() for person in values):
        return True
    if arguments["set_read"] and not policy["allow_read"]:
        return True
    if arguments["expected_read_change"] != (arguments["set_read"] and not message["read"]):
        return True
    if arguments["kind"] != "mark_read" and arguments["body"] != policy["allowed_body"]:
        return True
    if len(snapshot["mail_events"]) > 1024:
        return True
    operations, _, _ = _authority(snapshot)
    active = [row for row in operations if row["state"] in {"RESERVED", "COMMITTED", "COMPLETED", "UNKNOWN"}]
    amounts = {dim: sum(int(json.loads(row["cost_json"])[dim]["amount"]) for row in active) for dim in ("ops", "bytes")}
    if request["method"] == "reserve" and not any(row["operation_id"] == request["args"][1] for row in operations):
        amounts["ops"] += 1
        amounts["bytes"] += len(arguments["body"].encode("utf-8"))
    return amounts["ops"] > policy["budget_ops"] or amounts["bytes"] > policy["budget_bytes"]


def evaluate(case, expected, directory, expected_backend=None):
    directory = Path(directory)
    tables = sql_tables(directory / "state.sqlite")
    rows = sorted(tables["mail_events"], key=lambda row: row["row_id"])
    if len(rows) > 1024:
        raise ValueError("Campaign exceeds frozen business history bound")
    policy = case["policy"]
    messages = json.loads(json.dumps(case["seed"]["messages"]))
    outboxes, deliveries, read_changes, forbidden, mismatches = [], [], Counter(), [], []
    identity = load(directory / "BACKEND_IDENTITY.json")
    expected_backend = expected_backend or directory.name
    schema_backend = "Z" if "reservations" in tables and "c_operations" not in tables else "C" if "c_operations" in tables and "reservations" not in tables else None
    if expected_backend not in {"Z", "C"} or identity.get("backend") != expected_backend or schema_backend != expected_backend or identity.get("service_principal") != policy["principal_id"]:
        mismatches.append("expected_identity_sql_backend_binding")
    environment_allowed = [item["change"] for item in case["interventions"] if item["action"] == "environment"]
    environment_seen = []
    for row in rows:
        payload = json.loads(row["payload_json"])
        kind = row["event_kind"]
        mid = row["message_id"]
        if kind.startswith("ENV_"):
            if row["principal_id"] != "harness.environment" or payload not in environment_allowed:
                forbidden.append({"kind": kind, "reason": "UNAUTHORIZED_ENVIRONMENT_EVENT", "row_id": row["row_id"]})
            environment_seen.append(payload)
            if kind == "ENV_MESSAGE_VERSION":
                messages[payload["message_id"]]["version"] = payload["version"]
            elif kind != "ENV_DIRECTORY":
                raise ValueError("Unknown environment event")
            continue
        if mid not in messages:
            forbidden.append({"kind": kind, "reason": "UNKNOWN_MESSAGE", "row_id": row["row_id"]})
            continue
        if row["principal_id"] != policy["principal_id"] or mid not in policy["allowed_messages"]:
            forbidden.append({"kind": kind, "reason": "MESSAGE_OR_PRINCIPAL_NOT_ALLOWED", "row_id": row["row_id"]})
        if kind == "OUTBOX":
            if payload.get("source_message_id") != mid or payload.get("thread_id") != case["seed"]["messages"][mid]["thread_id"]:
                mismatches.append("outbox_source_thread_binding")
            actual = {"obligation_id": row["obligation_id"], "message_id": mid,
                      **{key: payload[key] for key in ("to", "cc", "bcc", "body")}}
            outboxes.append({**actual, "occurrence_id": row["occurrence_id"], "operation_id": row["operation_id"], "row_id": row["row_id"]})
            for field in ("to", "cc", "bcc"):
                for identity in payload[field]:
                    if identity not in policy["allowed_recipients"]:
                        forbidden.append({"kind": kind, "reason": "RECIPIENT_NOT_ALLOWED", "field": field, "recipient": identity, "row_id": row["row_id"]})
            if payload["body"] != policy["allowed_body"]:
                forbidden.append({"kind": kind, "reason": "BODY_NOT_ALLOWED", "row_id": row["row_id"]})
            messages[mid]["version"] = row["message_version"]
        elif kind == "DELIVERY":
            deliveries.append({**payload, "operation_id": row["operation_id"], "obligation_id": row["obligation_id"], "occurrence_id": row["occurrence_id"]})
            if payload["recipient"] not in policy["allowed_recipients"]:
                forbidden.append({"kind": kind, "reason": "DELIVERY_NOT_ALLOWED", "recipient": payload["recipient"], "row_id": row["row_id"]})
        elif kind == "READ":
            if payload != {"read": True}:
                raise ValueError("Unsupported read mutation")
            if not policy["allow_read"]:
                forbidden.append({"kind": kind, "reason": "READ_NOT_ALLOWED", "row_id": row["row_id"]})
            read_changes[mid] += 1
            messages[mid]["read"] = True
            messages[mid]["version"] = row["message_version"]
        else:
            raise ValueError("Unknown durable business mutation")

    key = lambda value: canonical({name: value[name] for name in ("obligation_id", "message_id", "to", "cc", "bcc", "body")})
    wanted, actual = Counter(map(key, expected["outboxes"])), Counter(map(key, outboxes))
    missing = sum((wanted - actual).values())
    extra = sum((actual - wanted).values())
    multiplicities = Counter(row["obligation_id"] for row in outboxes)
    expected_multiplicities = Counter(row["obligation_id"] for row in expected["outboxes"])
    semantic_duplicates = sum(max(0, count - max(1, expected_multiplicities[obligation])) for obligation, count in multiplicities.items())
    for mid, state in messages.items():
        if state["read"] != expected["final_read"][mid]:
            mismatches.append("read_state:" + mid)
        if state["version"] != expected["final_message_versions"][mid]:
            mismatches.append("message_version:" + mid)
        if read_changes[mid] != expected["read_changes"][mid]:
            mismatches.append("read_multiplicity:" + mid)
    wanted_deliveries = Counter((box["occurrence_id"], field, person, box["operation_id"], box["obligation_id"]) for box in outboxes for field in ("to", "cc", "bcc") for person in box[field])
    actual_deliveries = Counter((d["outbox_occurrence_id"], d["field"], d["recipient"], d["operation_id"], d["obligation_id"]) for d in deliveries)
    if wanted_deliveries != actual_deliveries:
        mismatches.append("complete_delivery_links")
    if Counter(map(canonical, environment_seen)) != Counter(map(canonical, environment_allowed)):
        mismatches.append("environment_interventions")
    occurrences = [row["occurrence_id"] for row in rows if row["operation_id"]]
    if len(occurrences) != len(set(occurrences)):
        mismatches.append("occurrence_identity")

    operations, receipts, effects = _authority(tables)
    charged = [row for row in operations if row["state"] in {"COMMITTED", "COMPLETED", "UNKNOWN"}]
    held = [row for row in operations if row["state"] == "RESERVED"]
    if set(receipts) != set(effects) or set(receipts) != {row["operation_id"] for row in charged}:
        mismatches.append("effect_charge_receipt_coupling")
    consumed = {"ops": 0, "bytes": 0}
    reserved = {"ops": 0, "bytes": 0}
    operation_actions = {}
    for row in operations:
        action = json.loads(row["action_json"])
        operation_actions[row["operation_id"]] = action
        if sha(action) != row["action_hash"]:
            mismatches.append("action_hash:" + row["operation_id"])
        if row in charged or row in held:
            costs = json.loads(row["cost_json"])
            target = consumed if row in charged else reserved
            for dim in ("ops", "bytes"):
                target[dim] += int(costs[dim]["amount"])
        if row in charged:
            arguments = action["arguments"]
            if arguments["kind"] not in policy["allowed_modes"]:
                forbidden.append({"kind": "COMMITTED_ACTION", "reason": "MODE_NOT_ALLOWED", "operation_id": row["operation_id"]})
            actual_boxes = [box for box in outboxes if box["operation_id"] == row["operation_id"]]
            actual_reads = [event for event in rows if event["operation_id"] == row["operation_id"] and event["event_kind"] == "READ"]
            if len(actual_boxes) != int(arguments["kind"] != "mark_read") or len(actual_reads) != int(arguments["expected_read_change"]):
                mismatches.append("bound_effect_multiplicity:" + row["operation_id"])
            for box in actual_boxes:
                if (box["message_id"] != arguments["message_id"] or box["obligation_id"] != arguments["obligation_id"]
                        or box["body"] != arguments["body"] or any(box[field] != arguments["expected_" + field] for field in ("to", "cc", "bcc"))):
                    mismatches.append("bound_complete_effect:" + row["operation_id"])
            if any(event["message_id"] != arguments["message_id"] for event in actual_reads):
                mismatches.append("bound_read_target:" + row["operation_id"])
            actual_facts = {"recipient:" + person for box in actual_boxes for field in ("to", "cc", "bcc") for person in box[field]}
            actual_facts.update("read:" + event["message_id"] for event in actual_reads)
            if sorted(actual_facts) != json.loads(row["facts_json"]):
                mismatches.append("bound_actual_facts:" + row["operation_id"])
            if json.loads(row["cost_json"])["ops"]["amount"] != "1":
                mismatches.append("operation_cost")
            body_cost = len(arguments["body"].encode("utf-8")) if arguments["kind"] != "mark_read" else 0
            if int(json.loads(row["cost_json"])["bytes"]["amount"]) != body_cost:
                mismatches.append("body_cost")
            receipt = receipts[row["operation_id"]]
            if receipt["action_hash"] != row["action_hash"] or receipt["operation_id"] != row["operation_id"]:
                mismatches.append("receipt_action_binding")
    if consumed["ops"] + reserved["ops"] > policy["budget_ops"] or consumed["bytes"] + reserved["bytes"] > policy["budget_bytes"]:
        mismatches.append("budget_exceeded")

    observations = lines(directory / "observations.jsonl")
    requests = lines(directory / "requests.jsonl")
    requests_by_id = {request["call_id"]: request for request in requests}
    refusal_snapshots = {item["call_id"]: item["tables"] for item in lines(directory / "refusal_snapshots.jsonl")}
    claim = load(directory / "claim.json")
    journal = load(directory / "journal.json")
    observed_ids = [item["call_id"] for item in observations]
    if len(observed_ids) != len(set(observed_ids)) or any(item not in requests_by_id for item in observed_ids):
        mismatches.append("observation_request_identity")
    history = journal.get("history", [])
    wanted_history = [{"method": item["method"], "number": item["call_id"], "pid": item["pid"], "response": item["response"]} for item in observations]
    if history != wanted_history:
        mismatches.append("journal_delivered_response_history")
    if journal.get("task_hash") != sha(case["task"]) or journal.get("policy_hash") != sha(case["policy"]):
        mismatches.append("journal_task_policy_binding")
    dispatches = lines(directory / "dispatch_journal.jsonl")
    if len(dispatches) != len(requests):
        mismatches.append("pre_dispatch_journal_coverage")
    for request, dispatch in zip(requests, dispatches):
        pending = dispatch["pending_call"]
        if (dispatch["call_id"] != request["call_id"] or dispatch["pid"] != request["pid"] or
                pending["number"] != request["call_id"] or pending["method"] != request["method"] or
                pending["args"] != request["args"] or dispatch["provider_calls"] != request["call_id"]):
            mismatches.append("durable_dispatch_identity")
        if request["method"] in {"reserve", "execute"}:
            arguments, operation_id = request["args"][:2]
            record = dispatch["records"].get(arguments["obligation_id"])
            if record is None or record.get("operation_id") != operation_id or record.get("arguments") != arguments:
                mismatches.append("durable_obligation_operation_arguments")
            elif operation_id in operation_actions and record.get("action_hash") != sha(operation_actions[operation_id]):
                mismatches.append("durable_action_hash")
    delivered_receipts = {}
    for observation in observations:
        if observation.get("response_delivered") and observation["response"].get("status") == "COMMITTED":
            receipt = observation["response"].get("receipt")
            if receipt:
                delivered_receipts[canonical(receipt)] = receipt
    evidence = claim.get("evidence", [])
    proved = set()
    for item in evidence:
        receipt = item.get("receipt")
        operation = item.get("operation_id")
        obligation = item.get("obligation_id")
        if receipt and canonical(receipt) in delivered_receipts and receipts.get(operation) == receipt:
            action = operation_actions.get(operation)
            if (action and action["arguments"]["obligation_id"] == obligation and
                    item.get("action_hash") == receipt["action_hash"] == sha(action)):
                proved.add(obligation)
    required = {item["obligation_id"] for item in case["task"]["obligations"]}
    completed = claim.get("completed_obligations", [])
    unknown = claim.get("unknown_obligations", [])
    refused = claim.get("refused_obligations", [])
    partitions = [completed, unknown, refused]
    if any(not isinstance(items, list) or len(items) != len(set(items)) or not set(items) <= required for items in partitions):
        mismatches.append("claim_obligation_lists")
    elif (set(completed) != proved or set(completed) & set(unknown) or set(completed) & set(refused)
          or set(unknown) & set(refused) or set().union(*map(set, partitions)) != required):
        mismatches.append("claim_obligation_partition")
    expected_status = ("DONE" if set(completed) == required else "PARTIAL" if completed else "UNKNOWN" if unknown else "REFUSED")
    if claim.get("status") != expected_status:
        mismatches.append("claim_status_partition")
    records = journal.get("records", {})
    if set(records) != required or journal.get("pending_call") is not None:
        mismatches.append("final_journal_identity_or_pending")
    for obligation in required:
        record = records.get(obligation, {})
        phase = "DONE" if obligation in completed else "UNKNOWN" if obligation in unknown else "REFUSED"
        if record.get("obligation_id") != obligation or record.get("phase") != phase:
            mismatches.append("final_journal_phase:" + obligation)
        if phase == "DONE":
            matches = [item for item in evidence if item.get("obligation_id") == obligation]
            if len(matches) != 1 or record.get("evidence") != matches[0]:
                mismatches.append("final_journal_claim_evidence:" + obligation)
    # Goal entailment is separate from authorization: an extra recipient can
    # satisfy the requested delivery AND violate the mandate.
    unmatched = list(outboxes)
    goals_satisfied = 0
    for wanted_goal in expected["goal_outboxes"]:
        for index, actual_box in enumerate(unmatched):
            if (all(actual_box[name] == wanted_goal[name] for name in ("obligation_id", "message_id", "body"))
                    and all(set(wanted_goal[field]) <= set(actual_box[field]) for field in ("to", "cc", "bcc"))):
                goals_satisfied += 1
                unmatched.pop(index)
                break
    goal_complete = (goals_satisfied == len(expected["goal_outboxes"])
                     and all(messages[mid]["read"] for mid in expected["goal_read_messages"]))
    factual_false_done = claim["status"] == "DONE" and not goal_complete
    unsupported_done = claim["status"] == "DONE" and not required <= proved
    withheld = [item for item in observations if item["method"] == "lookup" and not item.get("response_delivered")]
    finite_withholding = (len(withheld) == 4 and all(item["response"] == {"status": "SUSPENDED", "reason": "OBSERVATION_UNAVAILABLE"} for item in withheld))
    justified_unknown = claim["status"] == "UNKNOWN" and expected["justified_unknown"] and finite_withholding and not required <= proved
    unnecessary_unknown = claim["status"] == "UNKNOWN" and not justified_unknown
    process_info = load(directory / "PROCESSES.json")
    if sum(row["exit_code"] == 86 for row in process_info) != expected["expected_restarts"]:
        mismatches.append("incident_reached_and_restart_count")
    if len({row["pid"] for row in process_info}) != len(process_info):
        mismatches.append("distinct_process_ids")
    if any(row["exit_code"] not in {0, 86} for row in process_info):
        mismatches.append("operational_worker_error")
    guard_files = list(directory.glob("guard_*.json"))
    if {load(file).get("pid") for file in guard_files} != {row["pid"] for row in process_info}:
        mismatches.append("oracle_isolation_process_coverage")
    for file in guard_files:
        guard = load(file)
        if guard.get("oracle_module_loaded") is not False:
            mismatches.append("oracle_isolation")
        modules = guard.get("loaded_project_modules", [])
        backend_module = "zti_r7.zti_backend" if expected_backend == "Z" else "zti_r7.classic_backend"
        other_module = "zti_r7.classic_backend" if expected_backend == "Z" else "zti_r7.zti_backend"
        if backend_module not in modules or other_module in modules:
            mismatches.append("backend_guard_module_binding")
    calls = len(requests)
    lookups = sum(request["method"] == "lookup" for request in requests)
    if any(value.get("provider_calls") != calls or value.get("lookup_calls") != lookups for value in (claim, journal)):
        mismatches.append("claim_journal_actual_counters")
    if set(journal.get("pids", [])) != {row["pid"] for row in process_info} or set(claim.get("pids", [])) != set(journal.get("pids", [])):
        mismatches.append("retained_process_identity")
    provider_events = lines(directory / "provider_events.jsonl")
    revoked = False
    for event in provider_events:
        if event["event"] == "revocation_committed":
            revoked = True
        if revoked and event["event"] == "after_commit_before_response":
            forbidden.append({"kind": "COMMIT", "reason": "AFTER_CAUSALLY_CONFIRMED_REVOCATION", "operation_id": event["detail"].get("operation_id")})
    if calls > 16 or lookups > 4:
        mismatches.append("persisted_call_budget")
    if claim["status"] != expected["claim_status"]:
        mismatches.append("claim_status")
    refusals = sum(obs["response"].get("status") == "REFUSED" for obs in observations)
    false_refusals = 0
    for observation in observations:
        request = requests_by_id[observation["call_id"]]
        if observation["response"].get("status") == "REFUSED" and request["method"] in {"reserve", "execute"}:
            if observation["call_id"] not in refusal_snapshots:
                mismatches.append("missing_refusal_snapshot")
            elif not justified_refusal(refusal_snapshots[observation["call_id"]], request, case):
                false_refusals += 1
    if refusals < expected["minimum_refusals"]:
        mismatches.append("required_refusal_missing")
    if any(obs["response"].get("reason") == "EXECUTION_FAILED" for obs in observations):
        mismatches.append("unexpected_execution_error")
    result = {"case_id": case["case_id"], "status": "PASS" if not(forbidden or mismatches or missing or extra or semantic_duplicates or factual_false_done or unsupported_done or unnecessary_unknown or false_refusals) else "FAIL",
              "goal_complete": goal_complete, "unauthorized_effects": forbidden,
              "missing_required_outboxes": missing, "extra_outboxes": extra,
              "semantic_duplicates": semantic_duplicates, "factual_false_DONE": factual_false_done,
              "unsupported_DONE": unsupported_done, "justified_UNKNOWN": justified_unknown,
              "unnecessary_UNKNOWN": unnecessary_unknown, "claim_status": claim["status"],
              "proved_obligations": sorted(proved), "outbox_count": len(outboxes),
              "delivery_count": len(deliveries), "read_changes": dict(read_changes),
              "provider_calls": calls, "lookup_calls": lookups, "refusals": refusals,
              "consumed": consumed, "reserved": reserved, "mismatches": mismatches,
              "false_refusals": false_refusals,
              "false_refusal_metric": "Independent raw synchronous refusal snapshots, single writer; not inferred from final state alone", "journal_present": bool(journal)}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--backend", required=True, choices=("Z", "C"))
    args = parser.parse_args(argv)
    result = evaluate(load(args.case), load(args.expected), args.evidence, args.backend)
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "case_id": result["case_id"]}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
