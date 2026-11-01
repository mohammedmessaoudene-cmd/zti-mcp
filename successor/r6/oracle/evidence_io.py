"""Data-only SQLite/JSON snapshot loading; never import code from evidence."""
import json
from pathlib import Path
import sqlite3

TABLES = ('roots','mandates','reservations','business_effects','receipts','transitions','demo_records')

def snapshot(path):
    path = Path(path).resolve()
    if path.suffix!='.sqlite':
        raise ValueError('A real SQLite backup is required; JSON is only an auxiliary projection')
    connection = sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA query_only=ON')
        declared = {r['name']:r for r in connection.execute("SELECT name,type,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'")}
        result = {}
        for name in TABLES:
            row = declared.get(name)
            if row is None:
                raise ValueError('Missing required ordinary table '+name)
            if row['type']!='table' or not row['sql'].lstrip().upper().startswith('CREATE TABLE'):
                raise ValueError('Evidence must use ordinary tables, never views or virtual tables')
            # Name is a fixed local constant, not data-supplied SQL.
            result[name] = [dict(x) for x in connection.execute('SELECT * FROM '+name)]
        return result
    finally:
        connection.close()
