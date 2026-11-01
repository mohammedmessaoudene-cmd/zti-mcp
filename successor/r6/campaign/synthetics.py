"""Explicit data-only copies that test the independent evidence reader.

These are never described as real SDK executions. The original positive case
is inventory-checked unchanged. No script from a copied archive is executed.
"""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
from common import EXT, encoded, jsonl, read, tables, write


def inventory(directory):
    return {p.relative_to(directory).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.rglob("*")) if p.is_file()}


def walk(value, transform):
    if isinstance(value, dict):
        value = {key: walk(child, transform) for key, child in value.items()}
    elif isinstance(value, list):
        value = [walk(child, transform) for child in value]
    return transform(value)


def discovery_change(value, name):
    if not isinstance(value, dict) or "supportedVersions" not in value:
        return value
    if name == "SD01":
        value["supportedVersions"] = ["2025-03-26"]
        value["protocolVersion"] = "2026-07-28"
    elif name == "SD02":
        value.setdefault("_meta", {})["io.modelcontextprotocol/serverCapabilities"] = value.pop("capabilities")
    elif name == "SD03":
        value.pop("supportedVersions")
        value["protocolVersion"] = "2026-07-28"
    return value


def replace_token(value, original, replacement):
    return value.replace(original, replacement) if isinstance(value, str) else value


def change_sql(path, name, original=None, replacement=None):
    conn = sqlite3.connect(path)
    try:
        if name == "SE01":
            names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            for table in names:
                columns = [row[1] for row in conn.execute('PRAGMA table_info("' + table.replace('"', '""') + '")') if row[2] == "TEXT"]
                for column in columns:
                    t, c = '"' + table.replace('"', '""') + '"', '"' + column.replace('"', '""') + '"'
                    conn.execute("UPDATE " + t + " SET " + c + "=replace(" + c + ",?,?) WHERE instr(" + c + ",?)>0", (original, replacement, original))
        elif name == "SE02":
            conn.execute("UPDATE demo_records SET label='bravo' WHERE label='alpha'")
        elif name == "SE03":
            rows = conn.execute("SELECT rowid,cost_json FROM reservations WHERE state='COMMITTED'").fetchall()
            for rowid, cost in rows:
                cost = json.loads(cost)
                if cost["ops"]["amount"] != "2":
                    raise ValueError("SE03 requires the frozen committed quantity2 witness")
                cost["ops"]["amount"] = "1"
                conn.execute("UPDATE reservations SET cost_json=? WHERE rowid=?", (encoded(cost).decode("utf-8"), rowid))
        conn.commit()
    finally:
        conn.close()


def make_synthetics(output, corpus):
    output = Path(output)
    source = output / "cases" / "base" / "I01__P"
    if not source.is_dir():
        raise ValueError("Synthetic reader tests require original completed I01__P evidence")
    before = inventory(source)
    observation = read(source / "observation.json")
    token = observation["steps"]["r1"]["result"]["ict"]
    h, p, _ = token.split(".")
    invalid = h + "." + p + "." + base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
    result = []
    for spec in corpus["synthetics"]:
        name = spec["id"]
        dest = output / "cases" / "synthetic" / name
        shutil.copytree(source, dest)
        manifest = read(dest / "manifest.json")
        manifest.update(category="synthetic", case_id=name, synthetic_id=name,
                        source_case_id="I01__P", actual_sdk_execution=False)
        write(dest / "manifest.json", manifest)
        transform = (lambda v: discovery_change(v, name)) if name.startswith("SD") else (
            (lambda v: replace_token(v, token, invalid)) if name == "SE01" else (lambda v: v))
        # Update all decoded JSON views, then regenerate each frame's own raw
        # bytes. This is deliberately synthetic data, not a captured new peer.
        for path in sorted(dest.rglob("*.json")):
            if path.name.endswith(".tables.json"):
                continue
            write(path, walk(read(path), transform))
        for path in sorted(dest.rglob("*.jsonl")):
            rows = []
            changed = False
            for item in jsonl(path):
                if isinstance(item.get("frame"), dict):
                    updated = walk(item["frame"], transform)
                    if updated != item["frame"]:
                        item["frame"] = updated
                        item["raw_base64"] = base64.b64encode(encoded(updated) + b"\n").decode("ascii")
                        changed = True
                elif name == "SE01":
                    updated = walk(item, transform)
                    changed = changed or updated != item
                    item = updated
                rows.append(item)
            if changed:
                path.write_text("".join(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")
        if name.startswith("SE"):
            for path in sorted(dest.rglob("*.sqlite")):
                change_sql(path, name, token, invalid)
                projection = path.with_suffix(".tables.json")
                if projection.exists():
                    write(projection, tables(path, immutable=True))
        after = inventory(source)
        if after != before:
            raise RuntimeError("Original positive evidence changed while making synthetic copy")
        receipt = {"format": "zti-r6-synthetic/1", "synthetic_id": name,
            "kind": "SYNTHETIC_COPIED_EVIDENCE_NOT_SDK_EXECUTION", "source_case_id": "I01__P",
            "source_inventory_sha256": hashlib.sha256(encoded(before)).hexdigest(),
            "source_unchanged": True, "declared_delta": spec["fault"], "copied_files": inventory(dest)}
        write(dest / "SYNTHETIC_COPY.json", receipt)
        result.append({"id": name, "directory": dest.relative_to(output).as_posix(),
            "source_unchanged": True, "new_sdk_execution": False})
    write(output / "SYNTHETICS.json", {"original_inventory": before,
        "original_unchanged": inventory(source) == before, "copies": result})
    return result
