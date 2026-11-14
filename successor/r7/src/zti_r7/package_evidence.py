"""Closed data-only evidence export and path/hash-checked import.

Apache-2.0, Mohammed Messaoudene; AI-assisted. No captured code is executed.
Private configuration, keys, installation logs and runtime folders are excluded.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

ALLOWED = frozenset({"state.sqlite", "input.json", "control.json", "claim.json", "journal.json",
    "provider_events.jsonl", "requests.jsonl", "observations.jsonl", "refusal_snapshots.jsonl",
    "dispatch_journal.jsonl",
    "BACKEND_IDENTITY.json", "PROCESSES.json", "AUDIT.json", "audit_case.json", "audit_expected.json",
    "SUMMARY.json", "SOURCE.json", "INSTRUMENT.json"})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def allowed(path):
    return path.name in ALLOWED or re.fullmatch(r"(?:guard_\d+|injection_\d+|error_\d+)\.json", path.name) is not None


def export(run, target):
    run, target = Path(run).resolve(), Path(target).resolve()
    if target.exists():
        raise ValueError("Fresh archive target required")
    files = {}
    for path in sorted(run.rglob("*")):
        if not path.is_file() or not allowed(path) or "private" in path.relative_to(run).parts:
            continue
        if path.is_symlink():
            raise ValueError("Evidence symlink refused")
        data = path.read_bytes()
        relative = path.relative_to(run).as_posix()
        if path.suffix in {".json", ".jsonl"}:
            text = data.decode("utf-8")
            if re.search(r"-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----", text):
                raise ValueError("Private key in evidence")
            if re.search(r"(?i)(?:[A-Z]:[\\/](?:Users|securite_agent)|/home/|/Users/)", text):
                raise ValueError("Absolute private path in evidence")
        files[relative] = {"bytes": len(data), "sha256": sha(data)}
    if "SUMMARY.json" not in files or "SOURCE.json" not in files:
        raise ValueError("Run summary/source identity missing")
    manifest = {"format": "zti-r7-data-export/1", "files": files,
                "interpretation": "SQLite files are separately created committed-state backups after workers exit; original private stores/keys are not included. Hashes establish internal consistency, not independent provenance."}
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED) as archive:
        for relative in files:
            archive.writestr(relative, (run / relative).read_bytes())
        archive.writestr("EXPORT_MANIFEST.json", json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return {"files": len(files), "bytes": target.stat().st_size, "sha256": sha(target.read_bytes())}


def extract(archive_path, target):
    target = Path(target).resolve()
    if target.exists():
        raise ValueError("Fresh extraction directory required")
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or "EXPORT_MANIFEST.json" not in names:
            raise ValueError("Duplicate/missing archive manifest")
        if sum(entry.file_size for entry in entries) > 128 * 1024 * 1024:
            raise ValueError("Evidence size bound exceeded")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if (path.is_absolute() or ".." in path.parts or "\\" in entry.filename or ":" in entry.filename
                    or stat.S_ISLNK(entry.external_attr >> 16) or entry.is_dir()):
                raise ValueError("Unsafe data archive member")
        manifest = json.loads(archive.read("EXPORT_MANIFEST.json"))
        if set(names) != set(manifest["files"]) | {"EXPORT_MANIFEST.json"}:
            raise ValueError("Archive is not a closed manifest set")
        for relative, metadata in manifest["files"].items():
            payload = archive.read(relative)
            if len(payload) != metadata["bytes"] or sha(payload) != metadata["sha256"]:
                raise ValueError("Archive data hash mismatch")
        target.mkdir(parents=True)
        for relative in manifest["files"]:
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.read(relative))
        (target / "EXPORT_MANIFEST.json").write_bytes(archive.read("EXPORT_MANIFEST.json"))
    return manifest
