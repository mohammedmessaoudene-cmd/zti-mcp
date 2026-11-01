"""Evidence I/O and fixture serialization; no authorization decision helpers."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
from contextlib import closing

R6 = Path(__file__).resolve().parents[1]
ROOT = R6.parents[1]
EXT = "org.example/zti-mcp"
PROTOCOL = "2026-07-28"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def atomic(path, value):
    path = Path(path)
    temp = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    temp.write_text(value, encoding="utf-8", newline="\n")
    os.replace(temp, path)


def jsonl(path):
    path = Path(path)
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines()
    if raw and not raw.endswith("\n"):
        lines = lines[:-1]
    return [json.loads(line) for line in lines if line]


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def tables(path, *, immutable=False):
    path = Path(path)
    if not path.exists():
        return {}
    uri = path.resolve().as_uri() + "?mode=ro" + ("&immutable=1" if immutable else "")
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        return {name: [dict(row) for row in conn.execute('SELECT * FROM "' + name.replace('"', '""') + '"')] for name in names}


def revision(path):
    rows = tables(path).get("roots", [])
    return rows[0]["state_revision"] if rows else None


def backup(source, destination, *, immutable_source=False):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    uri = Path(source).resolve().as_uri() + "?mode=ro" + ("&immutable=1" if immutable_source else "")
    with closing(sqlite3.connect(uri, uri=True)) as src:
        with closing(sqlite3.connect(destination)) as dest:
            src.backup(dest)


def quiesce(path):
    """After all providers stop, drain WAL without changing any table contents.

    This explicit maintenance is recorded by the campaign. Snapshots themselves
    still use mode=ro and the SQLite backup API, with both handles closed.
    """
    if not Path(path).is_file():
        raise RuntimeError("Provider database does not exist; no evidence database will be invented")
    before = tables(path)
    with closing(sqlite3.connect(path)) as conn:
        row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if row[0] != 0 or tables(path, immutable=True) != before:
        raise RuntimeError("WAL maintenance busy or changed table contents")
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm")):
        raise RuntimeError("SQLite sidecar remains after stopped-writer maintenance")
    return {"busy": row[0], "log_frames": row[1], "checkpointed_frames": row[2],
            "base_tables_unchanged": True, "nonempty_wal": False, "sidecars_present": False}
