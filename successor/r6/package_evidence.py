#!/usr/bin/env python3
"""Export only portable R6 data. Never copy runtime, keys, configs or caches.

Raw wire, provider events and SQLite bytes are immutable. Selected coordinator
JSON metadata may explicitly project local paths; every projection records both
hashes and JSON pointers. Originals remain untouched in the private source run.
This is an allowlist/privacy exporter, not a semantic audit or an attestation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import zipfile

# A word boundary splits public base64url at '-' and compact JWS at '.'.
# Recognize standalone credential-shaped strings instead of those substrings;
# a bare encoding indistinguishable from a credential still fails closed.
SECRET = re.compile(r'-----BEGIN (?:[A-Z ]* )?PRIVATE KEY-----|(?<![A-Za-z0-9_.-])(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-(?:proj-)?[A-Za-z0-9_-]{30,})(?![A-Za-z0-9_-])|https://chatgpt\.com/(?:c/|library\?)', re.I)
LOCAL_PATH = re.compile(r'(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/][^\s"\'<>]+|/(?:home|Users|private|tmp|workspace|root|runner|__w|var/tmp)/[^\s"\'<>]+)')
FORBIDDEN_PARTS = {'_runtime', 'node_modules', 'pip-cache', 'npm-cache', '__pycache__', 'keys'}
CASE_METADATA = {'manifest.json', 'fixtures.json', 'observation.json', 'SYNTHETIC_COPY.json'}
TOP_JSON = {'SUMMARY.json', 'SOURCE.json', 'DISTRIBUTIONS.json', 'SYNTHETICS.json', 'RUNTIME.json', 'DISTRIBUTION_GUARD.json', 'BUILD.json'}
BOOTSTRAP_JSON = {'BOOTSTRAP.json', 'SOURCE.json', 'SOURCE_FINAL.json', 'DISTRIBUTIONS.json', 'AUDIT.json', 'RUNTIME.portable.json', 'DISTRIBUTION_GUARD.json'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2)+'\n').encode('utf-8')


def safe_json(value):
    """Reject secret material even when nested in otherwise allowed metadata."""
    if isinstance(value, dict):
        if value.get('kty') in ('EC', 'RSA', 'OKP') and any(k in value for k in ('d', 'p', 'q', 'dp', 'dq', 'qi')):
            raise ValueError('Private JWK material is not exportable')
        for key, item in value.items():
            safe_json(key)
            safe_json(item)
    elif isinstance(value, list):
        for item in value:
            safe_json(item)
    elif isinstance(value, str) and SECRET.search(value):
        raise ValueError('Secret or private account link is not exportable')


def public_text(text):
    if SECRET.search(text) or LOCAL_PATH.search(text):
        raise ValueError('Sensitive or local-path material in immutable evidence')


def project_metadata(value, changes, pointer='', allowed_pointers=None):
    """Explicitly change paths only in metadata, never in captured evidence."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            public_text(key)
            escaped = key.replace('~', '~0').replace('/', '~1')
            result[key] = project_metadata(item, changes, pointer+'/'+escaped, allowed_pointers)
        return result
    if isinstance(value, list):
        return [project_metadata(item, changes, pointer+'/'+str(index), allowed_pointers) for index, item in enumerate(value)]
    if isinstance(value, str):
        if SECRET.search(value):
            raise ValueError('Secret material cannot be projected')
        if LOCAL_PATH.search(value):
            if allowed_pointers is not None and not any(re.match(pattern, pointer) for pattern in allowed_pointers):
                raise ValueError('Local path outside declared metadata projection fields')
            def replacement(match):
                basename = re.split(r'[\\/]', match.group(0))[-1]
                return '<local-path>/'+basename
            changed = LOCAL_PATH.sub(replacement, value)
            changes.append({'json_pointer': pointer, 'operation': 'local_path_to_explicit_portable_label'})
            public_text(changed)
            return changed
    return value


def ordinary_file(path, source):
    relative = path.relative_to(source)
    if any(part in FORBIDDEN_PARTS for part in relative.parts) or not path.is_file():
        raise ValueError('Disallowed evidence path')
    current = source
    for part in relative.parts:
        current = current/part
        if current.is_symlink() or (hasattr(current, 'is_junction') and current.is_junction()):
            raise ValueError('Linked evidence is not exportable')
    if not path.resolve().is_relative_to(source.resolve()):
        raise ValueError('Evidence escaped source directory')


def check_sqlite(path):
    # The final main database must be quiescent. Dropping a live WAL would alter
    # semantics; constructing a replacement backup would alter original bytes.
    wal = Path(str(path)+'-wal')
    if wal.exists() and wal.stat().st_size:
        raise ValueError('Quiescent SQLite evidence required; nonempty WAL exists')
    connection = sqlite3.connect(path.resolve().as_uri()+'?mode=ro&immutable=1', uri=True)
    try:
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA query_only=ON')
        names = list(connection.execute("SELECT name,type,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"))
        for name, kind, declaration in names:
            public_text(name)
            if kind != 'table' or not declaration.lstrip().upper().startswith('CREATE TABLE'):
                raise ValueError('Only ordinary SQLite tables are exportable')
            public_text(declaration)
            escaped = name.replace('"', '""')
            for row in connection.execute('SELECT * FROM "'+escaped+'"'):
                for item in row:
                    if isinstance(item, str):
                        public_text(item)
                        # JSON columns can carry public JWKs or compact claims.
                        try:
                            safe_json(json.loads(item))
                        except json.JSONDecodeError:
                            pass
                    elif isinstance(item, bytes):
                        raise ValueError('Unexpected opaque binary database value')
    finally:
        connection.close()


def campaign_files(campaign):
    for name in sorted(TOP_JSON):
        path = campaign/name
        if path.exists():
            yield path, name, True
    for directory in ('vectors', 'binding_auxiliary', 'raw_jws'):
        base = campaign/directory
        if base.exists():
            for path in sorted(base.iterdir()):
                if path.name in {'P.json', 'T.json', 'M01.json', 'raw_jws.json',
                    'P.stdout.txt', 'T.stdout.txt', 'P.stderr.txt', 'T.stderr.txt', 'M01.stdout.txt', 'M01.stderr.txt'}:
                    # JSON reports are metadata. Original stdout/stderr remain
                    # raw bytes and are never path-redacted.
                    yield path, path.relative_to(campaign).as_posix(), path.suffix == '.json' and directory != 'raw_jws'
    for manifest in sorted((campaign/'cases').glob('*/*/manifest.json')):
        case = manifest.parent
        for name in sorted(CASE_METADATA | {'provider.sqlite'}):
            path = case/name
            if path.exists():
                # fixtures and coordinator request/response copies are immutable
                # semantic evidence, not general metadata projection targets.
                mutable_metadata = ('observation' if name == 'observation.json' else
                                    name in {'manifest.json', 'SYNTHETIC_COPY.json'})
                yield path, path.relative_to(campaign).as_posix(), mutable_metadata
        for pattern in ('wire/*.jsonl', 'wire/*.lifecycle.stderr.txt', 'control/*/events.jsonl', 'checkpoints/*.sqlite', 'checkpoints/*.tables.json'):
            for path in sorted(case.glob(pattern)):
                yield path, path.relative_to(campaign).as_posix(), False


def export(run, output, distributions=None):
    run, output = run.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(run) or run.is_relative_to(output):
        raise ValueError('Use a fresh separate output directory')
    output.mkdir(parents=True)
    data = output/'data'
    data.mkdir()
    manifest = {'format': 'zti-r6-portable-data-export/1', 'status': 'RUNNING',
                'semantic_audit_performed': False, 'originals_modified': False,
                'raw_evidence_bytes_modified': False, 'files': {}, 'metadata_projections': []}
    seen = set()

    def copy_one(path, relative, project, source):
        ordinary_file(path, source)
        if relative in seen:
            raise ValueError('Duplicate selected export path')
        seen.add(relative)
        original = path.read_bytes()
        changes = []
        if path.suffix == '.sqlite':
            check_sqlite(path)
            result = original
        else:
            text = original.decode('utf-8', errors='strict')
            if path.suffix == '.json':
                value = json.loads(text)
                safe_json(value)
                if project:
                    allowed = None if project is True else (
                        r'^/connections/[0-9]+/loaded(?:/|$)',
                        r'^/client_events/[^/]+/loaded(?:/|$)',
                        r'^/client_events/[^/]+/asyncErrors/[0-9]+/message$',
                        r'^/infrastructure_errors/[0-9]+/(?:message|traceback)$')
                    projected = project_metadata(value, changes, allowed_pointers=allowed)
                    result = encoded(projected) if changes else original
                else:
                    public_text(text)
                    result = original
            else:
                public_text(text)
                if path.suffix == '.jsonl':
                    for line in text.splitlines():
                        if line:
                            safe_json(json.loads(line))
                result = original
        target = data/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(result)
        manifest['files'][relative] = {'sha256': sha(result), 'size': len(result),
                                       'original_sha256': sha(original), 'byte_preserved': result == original}
        if changes:
            manifest['metadata_projections'].append({'path': relative, 'source_sha256': sha(original),
                'original_sha256': sha(original), 'export_sha256': sha(result),
                'projection_pointers': [change['json_pointer'] for change in changes],
                'changes': changes, 'original_retention': 'untouched_source_run'})

    try:
        campaign = run/'campaign' if (run/'campaign').is_dir() else run
        campaign_present = (campaign/'cases').is_dir() or (campaign/'SUMMARY.json').exists()
        if campaign_present:
            for path, relative, projection in campaign_files(campaign):
                copy_one(path, relative, projection, campaign)
        if campaign != run or not campaign_present:
            for name in sorted(BOOTSTRAP_JSON):
                path = run/name
                if path.exists():
                    copy_one(path, 'bootstrap/'+name, True, run)
        distribution_source = Path(distributions).resolve() if distributions is not None else run/'distributions'
        distribution_receipt = distribution_source/'BUILD.json'
        if distribution_receipt.exists():
            copy_one(distribution_receipt, 'bootstrap/BUILD.json', True, distribution_source)
        manifest['campaign_present'] = campaign_present
        manifest['status'] = 'EXPORTED_DATA_NOT_YET_AUDITED' if campaign_present else 'RECEIPTS_ONLY_NO_CAMPAIGN'
        (data/'EXPORT_MANIFEST.json').write_bytes(encoded(manifest))
        archive = output/'R6_PUBLIC_EVIDENCE.zip'
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as packed:
            for path in sorted(data.rglob('*')):
                if path.is_file():
                    packed.write(path, path.relative_to(data).as_posix())
        result = {'format': manifest['format'], 'status': manifest['status'], 'files': len(manifest['files']),
                  'metadata_projections': len(manifest['metadata_projections']),
                  'raw_evidence_bytes_modified': False, 'semantic_audit_performed': False,
                  'archive': archive.name, 'archive_sha256': sha(archive.read_bytes()), 'archive_size': archive.stat().st_size}
        (output/'SAFE_EXPORT.json').write_bytes(encoded(result))
        return result
    except BaseException:
        # Already copied files passed checks before writing. No unreviewed source
        # bytes or exception text is copied into the public failure receipt.
        (output/'SAFE_EXPORT.json').write_bytes(encoded({'format': manifest['format'], 'status': 'EXPORT_FAILED',
            'semantic_audit_performed': False, 'archive_published': False,
            'safe_files_copied': len(manifest['files'])}))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--distributions', type=Path, help='Include only BUILD.json from the exact reused distribution directory.')
    args = parser.parse_args()
    print(json.dumps(export(args.run_dir, args.output_dir, args.distributions), sort_keys=True))


if __name__ == '__main__':
    main()
