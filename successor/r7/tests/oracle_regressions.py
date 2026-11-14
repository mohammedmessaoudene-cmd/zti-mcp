"""Five S1 data-only reader regressions, with intact captured controls.

Apache-2.0, Mohammed Messaoudene. AI-assisted, author B. No provider,
controller, qualification campaign or captured executable is run. Inputs are
already reviewed public evidence extractions; all mutations affect fresh copies.

Run with Python 3.12 from a verified checkout, including under -I:
  python tests/oracle_regressions.py --selected-data <extracted-selected-data> \
      --instrument-data <extracted-instrument-data> --output <absent-directory>
Exit 0 requires intact PASS and five named semantic FAIL verdicts. An old
reader's false PASS verdicts are retained and cause exit 1, never a test PASS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys

SRC = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(SRC))
from zti_r7.runner import HERE, evaluate_one


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def file_map(root):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError('Existing reviewed extracted-data root required')
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
            raise ValueError('Evidence symlink/junction refused')
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if 'private' in path.relative_to(root).parts:
                raise ValueError('Input contains a private runtime directory')
            result[relative] = {'bytes': path.stat().st_size, 'sha256': sha(path)}
    return result


def mutate_sql(directory, statement, params=()):
    path = directory / 'state.sqlite'
    if not path.is_file():
        raise ValueError('Captured SQLite backup missing')
    connection = sqlite3.connect(path)
    try:
        connection.execute('PRAGMA trusted_schema=OFF')
        changed = connection.execute(statement, params).rowcount
        if changed < 1:
            raise ValueError('Regression mutation did not reach a real business row')
        connection.commit()
        return changed
    finally:
        connection.close()


def delivery_version(directory, output):
    return {'changed_business_rows': mutate_sql(directory,
        "UPDATE mail_events SET message_version=999 WHERE event_kind='DELIVERY'")}


def read_obligation(directory, output):
    return {'changed_business_rows': mutate_sql(directory,
        "UPDATE mail_events SET obligation_id='unrelated.obligation' WHERE event_kind='READ'")}


def intermediate_versions(directory, output):
    return {'changed_business_rows': mutate_sql(directory,
        'UPDATE mail_events SET message_version=999 WHERE obligation_id=?', ('instrument.obl.001',))}


def incident_erased(directory, output):
    (directory / 'provider_events.jsonl').write_text('', encoding='utf-8')
    removed = []
    for name in ('injection_0.json', 'injection_1.json'):
        path = directory / name
        if not path.is_file() or not path.resolve().is_relative_to(output.resolve()):
            raise ValueError('Expected copied injection marker missing/outside output')
        path.unlink()  # Only explicitly named files inside this fresh output copy.
        removed.append(name)
    return {'emptied_provider_events': True, 'removed_copied_markers': removed}


def unrelated_lookups(directory, output):
    def rewrite(name, pending):
        path = directory / name
        rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]
        count = 0
        for row in rows:
            request = row['pending_call'] if pending else row
            if request['method'] == 'lookup':
                request['args'] = ['op.unrelated']
                count += 1
        if count != 4:
            raise ValueError('Regression requires four actual lookup records')
        path.write_text(''.join(encoded(row) + '\n' for row in rows), encoding='utf-8')
        return count
    events = sha(directory / 'provider_events.jsonl')
    changes = {'changed_lookup_requests': rewrite('requests.jsonl', False),
               'changed_lookup_predispatch_records': rewrite('dispatch_journal.jsonl', True)}
    if sha(directory / 'provider_events.jsonl') != events:
        raise ValueError('Unrelated-lookup mutation changed the retained provider events')
    changes['provider_events_unchanged_sha256'] = events
    return changes


VECTORS = (
    ('R01_DELIVERY_VERSION', 'selected', 'cases/T01A/Z', 'Z', delivery_version,
     {'delivery_event_binding'}),
    ('R02_READ_OBLIGATION', 'selected', 'cases/T01A/C', 'C', read_obligation,
     {'read_event_binding'}),
    ('R03_INTERMEDIATE_VERSION', 'instrument', 'positives/P02/Z', 'Z', intermediate_versions,
     {'business_version_transition'}),
    ('R04_MISSING_INCIDENT', 'selected', 'cases/T12B/Z', 'Z', incident_erased,
     {'required_incident_witness', 'unknown_observation_witness'}),
    ('R05_UNRELATED_LOOKUPS', 'selected', 'cases/T12B/C', 'C', unrelated_lookups,
     {'unknown_lookup_operation_binding'}),
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selected-data', type=Path, required=True)
    parser.add_argument('--instrument-data', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args(argv)
    roots = {'selected': options.selected_data.resolve(), 'instrument': options.instrument_data.resolve()}
    output = options.output.resolve()
    if output.exists() or any(output.is_relative_to(root) or root.is_relative_to(output) for root in roots.values()):
        raise ValueError('Fresh regression output outside input roots required')
    before = {name: file_map(root) for name, root in roots.items()}
    reader = HERE / 'oracle.py'
    reader_before = sha(reader)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'READER_SOURCE_CAPTURE.txt').write_bytes(reader.read_bytes())
    baselines, mutations = [], []
    for name, root_name, relative, backend, mutate, diagnostic_names in VECTORS:
        original = roots[root_name] / relative
        if not original.is_dir():
            raise ValueError('Required captured positive baseline missing: ' + relative)
        case = read(original / 'audit_case.json')
        expected = read(original / 'audit_expected.json')
        # evaluate_one starts only the trusted source reader, with explicit arm.
        baseline = evaluate_one(case, expected, original,
            review_output=output / 'baseline_audits' / name, expected_backend=backend)
        baselines.append({'vector': name, 'captured_case': relative, 'backend': backend,
                          'status': baseline.get('status'), 'audit': baseline})
        copied = output / 'copies' / name / backend
        shutil.copytree(original, copied)
        detail = mutate(copied, output)
        verdict = evaluate_one(case, expected, copied,
            review_output=output / 'mutation_audits' / name, expected_backend=backend)
        diagnostics = set(verdict.get('mismatches', []))
        matched = sorted(diagnostics & diagnostic_names)
        semantic = verdict.get('status') == 'FAIL' and bool(matched)
        mutations.append({'vector': name, 'backend': backend, 'mutation': detail,
            'status': verdict.get('status'), 'expected_named_diagnostics': sorted(diagnostic_names),
            'matched_named_diagnostics': matched, 'named_semantic_rejection': semantic,
            'false_PASS_observed': verdict.get('status') == 'PASS', 'audit': verdict})
    after = {name: file_map(root) for name, root in roots.items()}
    inputs_unchanged = before == after
    reader_unchanged = reader_before == sha(reader)
    good_baselines = all(item['status'] == 'PASS' for item in baselines)
    detected = all(item['named_semantic_rejection'] for item in mutations)
    receipt = {'format': 'zti-r7-s1-oracle-regressions/1',
        'status': 'PASS_DATA_ONLY_REGRESSIONS' if good_baselines and detected and inputs_unchanged and reader_unchanged else 'FAIL_DATA_ONLY_REGRESSIONS',
        'reader_sha256': reader_before, 'reader_source_unchanged_during_test': reader_unchanged,
        'test_source_sha256': sha(Path(__file__)), 'baselines': baselines, 'mutations': mutations,
        'intact_baseline_PASS': sum(item['status'] == 'PASS' for item in baselines),
        'named_semantic_rejections': sum(item['named_semantic_rejection'] for item in mutations),
        'retained_false_PASS': sum(item['false_PASS_observed'] for item in mutations),
        'original_input_bytes_unchanged': inputs_unchanged,
        'input_manifest_before': before, 'input_manifest_after': after,
        'new_provider_executions': 0, 'new_controller_executions': 0,
        'qualification_campaign': False, 'captured_code_executed': False}
    (output / 'RECEIPT.json').write_text(json.dumps(receipt, sort_keys=True, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(encoded({key: receipt[key] for key in ('status', 'intact_baseline_PASS',
        'named_semantic_rejections', 'retained_false_PASS', 'original_input_bytes_unchanged',
        'new_provider_executions')}))
    return 0 if receipt['status'] == 'PASS_DATA_ONLY_REGRESSIONS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
