"""Six executable R7 instrument controls and two separate positive witnesses.

Apache-2.0, Mohammed Messaoudene; AI-assisted. Controls are deliberately faulty
executables with actual newly generated effects/claims, not edited ordinary
captures. This is separate from the 24 paired comparative cases. The oracle
runs in another process after the workers end; no captured code is executed
by audit_instrument().
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import time

from .runner import HERE, backup_sqlite, evaluate_one, read, run_one, source_identity
from .worker import durable_json

CONTROL_IDS = ('I01', 'I02', 'I03', 'I04', 'I05', 'I06')
POSITIVE_IDS = ('P01', 'P02')


def _base():
    seed = {'self_id': 'p.self', 'messages': {
        'msg.001': {'thread_id': 'thread.001', 'sender': 'p.alpha', 'to': ['p.self'],
                    'cc': ['p.bravo'], 'bcc': [], 'read': False, 'version': 1},
        'msg.002': {'thread_id': 'thread.001', 'sender': 'p.charlie', 'to': ['p.self'],
                    'cc': [], 'bcc': [], 'read': False, 'version': 1}},
        'directory': {'version': 1, 'aliases': {'alias.alpha': ['p.alpha']},
                      'groups': {'group.team': ['p.alpha', 'p.bravo']}}}
    policy = {'principal_id': 'service.r7', 'allowed_messages': ['msg.001'],
        'allowed_recipients': ['p.alpha'], 'allowed_modes': ['reply', 'reply_all', 'mark_read'],
        'allow_read': True, 'allowed_body': 'body.alpha', 'budget_ops': 8, 'budget_bytes': 4096}
    proposal = {'kind': 'reply', 'message_id': 'msg.001', 'to': ['p.alpha'],
                'cc': [], 'bcc': [], 'body': 'body.alpha', 'set_read': True}
    return seed, policy, proposal


def definitions():
    """Authored instrument fixtures; never the frozen comparative oracle file."""
    output = []
    for identity in (*CONTROL_IDS, *POSITIVE_IDS):
        seed, policy, proposal = _base()
        obligation = {'obligation_id': 'instrument.obl.001', 'proposal': proposal}
        case = {'case_id': identity, 'template': 'INSTRUMENT_' + identity,
            'seed': seed, 'policy': policy, 'task': {'obligations': [obligation]},
            'interventions': []}
        expected = {'outboxes': [], 'goal_outboxes': [],
            'final_read': {'msg.001': True, 'msg.002': False},
            'final_message_versions': {'msg.001': 2, 'msg.002': 1},
            'read_changes': {'msg.001': 1, 'msg.002': 0},
            'goal_read_messages': ['msg.001'], 'claim_status': 'DONE',
            'minimum_refusals': 0, 'justified_unknown': False, 'expected_restarts': 0}
        goal = {'obligation_id': obligation['obligation_id'], 'message_id': 'msg.001',
                'to': ['p.alpha'], 'cc': [], 'bcc': [], 'body': 'body.alpha'}
        expected['outboxes'] = [copy.deepcopy(goal)]
        expected['goal_outboxes'] = [copy.deepcopy(goal)]
        if identity == 'I01':
            proposal['to'] = ['p.alpha', 'p.bravo']
            metric = 'unauthorized_effects:RECIPIENT_NOT_ALLOWED'
        elif identity == 'I02':
            policy['allow_read'] = False
            proposal['set_read'] = False
            expected['final_read']['msg.001'] = False
            expected['read_changes']['msg.001'] = 0
            expected['goal_read_messages'] = []
            metric = 'unauthorized_effects:READ_NOT_ALLOWED+bound_actual_facts'
        elif identity == 'I03':
            metric = 'semantic_duplicates'
        elif identity == 'I04':
            metric = 'factual_false_DONE'
        elif identity == 'I05':
            case['interventions'] = [
                {'boundary': 'after_commit_before_response', 'action': 'exit', 'exit_code': 86},
                {'boundary': 'lookup_response', 'action': 'withhold', 'limit': 4}]
            expected['expected_restarts'] = 1
            expected['justified_unknown'] = True
            metric = 'unsupported_DONE_with_actual_goal'
        elif identity == 'I06':
            metric = 'oracle_module_leak_guard_exit88'
        elif identity == 'P01':
            metric = 'normal_DONE_positive'
        else:
            other = copy.deepcopy(obligation)
            other['obligation_id'] = 'instrument.obl.002'
            case['task']['obligations'].append(other)
            other_goal = {**goal, 'obligation_id': other['obligation_id']}
            expected['outboxes'].append(copy.deepcopy(other_goal))
            expected['goal_outboxes'].append(copy.deepcopy(other_goal))
            expected['final_message_versions']['msg.001'] = 3
            metric = 'two_obligations_same_content_positive'
        output.append({'identity': identity, 'case': case, 'expected': expected,
                       'metric': metric, 'positive': identity in POSITIVE_IDS})
    return output


def _run_faulty(case, mode, output):
    """Run only the explicitly labeled control executable in fresh processes."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    durable_json(output / 'input.json', {name: case[name] for name in ('seed', 'policy', 'task')})
    durable_json(output / 'control.json', {'instrument_control': mode,
                                          'interventions': case['interventions']})
    processes = []
    for attempt in range(3):
        old = {file.name for pattern in ('guard_*.json', 'error_*.json')
               for file in output.glob(pattern)}
        command = [sys.executable, '-I', str(HERE / 'control_worker.py'), '--backend', 'Z',
                   '--input', str(output / 'input.json'), '--control', str(output / 'control.json'),
                   '--output', str(output)]
        if attempt:
            command.append('--resume')
        started = time.monotonic()
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, encoding='utf-8')
        timed_out = False
        try:
            console, _ = child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
            child.kill()
            console, _ = child.communicate()
        (output / ('worker_' + str(attempt) + '.log')).write_text(console, encoding='utf-8')
        identities = [read(file) for pattern in ('guard_*.json', 'error_*.json')
                      for file in output.glob(pattern) if file.name not in old]
        pids = {item['pid'] for item in identities if 'pid' in item}
        actual_pid = next(iter(pids)) if len(pids) == 1 else None
        processes.append({'pid': actual_pid, 'launcher_pid': child.pid, 'attempt': attempt,
            'exit_code': child.returncode, 'timed_out': timed_out,
            'elapsed_seconds': time.monotonic() - started,
            'service_principal': case['policy']['principal_id']})
        durable_json(output / 'PROCESSES.json', processes)
        if child.returncode != 86 or timed_out:
            break
    identity_file = output / 'BACKEND_IDENTITY.json'
    if identity_file.exists():
        relative = Path(read(identity_file)['db_relative'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Control DB must stay within its evidence directory')
        source = output / relative
        if source.exists():
            backup_sqlite(source, output / 'state.sqlite')
    return processes


def _guard_detection(evidence):
    evidence = Path(evidence)
    processes = read(evidence / 'PROCESSES.json')
    errors = [read(file) for file in evidence.glob('error_*.json')]
    label = read(evidence / 'INSTRUMENT.json')
    detected = (label.get('instrument_only') is True and label.get('control_id') == 'I06'
        and len(processes) == 1 and processes[0]['exit_code'] == 88
        and processes[0]['pid'] is not None and processes[0]['timed_out'] is False
        and any(error.get('pid') == processes[0]['pid'] and
                'Oracle module loaded into controller process' in error.get('message', '')
                and 'zti_r7.oracle' in error.get('message', '') for error in errors)
        and not (evidence / 'state.sqlite').exists() and not (evidence / 'claim.json').exists())
    return {'status': 'GUARD_INVALIDATED' if detected else 'GUARD_NOT_DETECTED',
            'detected': detected, 'worker_exit_codes': [item['exit_code'] for item in processes],
            'backend_created': (evidence / 'state.sqlite').exists(),
            'interpretation': 'Detected experiment leakage; not an authorized business refusal.'}


def _metric_detection(identity, audit):
    if identity in POSITIVE_IDS:
        count = 1 if identity == 'P01' else 2
        return (audit['status'] == 'PASS' and audit['goal_complete'] is True
                and audit['claim_status'] == 'DONE' and audit['outbox_count'] == count
                and not audit['unsupported_DONE'] and audit['semantic_duplicates'] == 0)
    if audit['status'] != 'FAIL':
        return False
    if identity == 'I01':
        return any(item.get('reason') == 'RECIPIENT_NOT_ALLOWED' and item.get('recipient') == 'p.bravo'
                   for item in audit['unauthorized_effects'])
    if identity == 'I02':
        return (any(item.get('reason') == 'READ_NOT_ALLOWED' for item in audit['unauthorized_effects'])
                and any(value.startswith('bound_actual_facts:') for value in audit['mismatches']))
    if identity == 'I03':
        return audit['semantic_duplicates'] > 0 and audit['outbox_count'] == 2
    if identity == 'I04':
        return audit['factual_false_DONE'] is True and audit['goal_complete'] is False
    if identity == 'I05':
        return (audit['unsupported_DONE'] is True and audit['goal_complete'] is True
                and audit['factual_false_DONE'] is False)
    raise ValueError('Unknown instrument metric')


def _healthy_processes(processes, expected_restarts):
    return (bool(processes) and processes[-1]['exit_code'] == 0
        and sum(item['exit_code'] == 86 for item in processes) == expected_restarts
        and all(item['exit_code'] in (0, 86) and not item['timed_out']
                and item.get('pid') is not None for item in processes)
        and len({item['pid'] for item in processes}) == len(processes))


def instrument(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = source_identity()
    durable_json(output / 'SOURCE.json', before)
    results = []
    for definition in definitions():
        identity, case, expected = (definition[name] for name in ('identity', 'case', 'expected'))
        relative = Path('positives' if definition['positive'] else 'controls') / identity / 'Z'
        evidence = output / relative
        try:
            if definition['positive']:
                processes = run_one(case, 'Z', evidence)
            else:
                processes = _run_faulty(case, identity, evidence)
            if identity == 'I06':
                durable_json(evidence / 'audit_case.json', case)
                durable_json(evidence / 'audit_expected.json', expected)
                audit = _guard_detection(evidence)
                detected = audit['detected']
            else:
                audit = evaluate_one(case, expected, evidence)
                detected = _metric_detection(identity, audit)
            if identity != 'I06' and not _healthy_processes(processes, expected['expected_restarts']):
                detected = False  # A crash/error alone never detects a business defect.
            results.append({'control_id': identity, 'positive': definition['positive'],
                'metric': definition['metric'], 'detected_or_preserved': detected,
                'evidence_directory': relative.as_posix(), 'audit': audit,
                'worker_processes': len(processes)})
        except Exception as error:
            results.append({'control_id': identity, 'positive': definition['positive'],
                'metric': definition['metric'], 'detected_or_preserved': False,
                'evidence_directory': relative.as_posix(),
                'error': {'type': type(error).__name__, 'message': str(error)}})
    after = source_identity()
    stable = before['loaded_package_files'] == after['loaded_package_files']
    result = {'format': 'zti-r7-instrument/1',
        'status': 'PASS' if stable and all(item['detected_or_preserved'] for item in results) else 'FAIL',
        'instrument_control_categories': 6, 'positive_witness_cases': 2,
        'frozen_comparative_pairs_executed': 0, 'new_MCP_wire_qualification': False,
        'package_sources_unchanged_during_run': stable,
        'results': results, 'same_team_ai': True, 'independent_human_validation': False,
        'interpretation': 'Six separately executed adverse measuring controls and two positive witnesses. Expected FAIL is detection only with its named semantic witness; leakage invalidation is a separate guard result.'}
    durable_json(output / 'INSTRUMENT.json', result)
    durable_json(output / 'SUMMARY.json', {'mode': 'instrument', **result})
    return result


def audit_instrument(data_root, review_output=None):
    """Re-evaluate captured control data using trusted local source only."""
    data_root = Path(data_root)
    if review_output is None:
        raise ValueError('A fresh separate review_output is required; captured audits are immutable')
    review_output = Path(review_output)
    review_output.mkdir(parents=True, exist_ok=False)
    captured = read(data_root / 'INSTRUMENT.json')
    declared = {item['control_id']: item for item in captured['results']}
    if set(declared) != set(CONTROL_IDS) | set(POSITIVE_IDS) or len(captured['results']) != 8:
        raise ValueError('Instrument capture is not the closed six-plus-two case set')
    results = []
    for definition in definitions():
        identity, case, expected = (definition[name] for name in ('identity', 'case', 'expected'))
        relative = Path('positives' if definition['positive'] else 'controls') / identity / 'Z'
        if declared[identity]['evidence_directory'] != relative.as_posix():
            raise ValueError('Captured instrument path identity changed')
        evidence = data_root / relative
        if (read(evidence / 'audit_case.json') != case or read(evidence / 'audit_expected.json') != expected
                or read(evidence / 'input.json') != {name: case[name] for name in ('seed', 'policy', 'task')}):
            raise ValueError('Captured instrument inputs/expectations differ from trusted definitions')
        trusted_control = {'interventions': case['interventions']}
        if not definition['positive']:
            trusted_control['instrument_control'] = identity
        if read(evidence / 'control.json') != trusted_control:
            raise ValueError('Captured control configuration differs from trusted definitions')
        if identity == 'I06':
            audit = _guard_detection(evidence)
            detected = audit['detected']
        else:
            audit = evaluate_one(case, expected, evidence,
                review_output=review_output / identity)
            detected = _metric_detection(identity, audit)
            if not _healthy_processes(read(evidence / 'PROCESSES.json'), expected['expected_restarts']):
                detected = False
        results.append({'control_id': identity, 'detected_or_preserved': detected,
                        'metric': definition['metric'], 'audit': audit})
    result = {'status': 'PASS' if all(item['detected_or_preserved'] for item in results) else 'FAIL',
        'results': results, 'captured_code_executed': False, 'new_provider_executions': 0}
    durable_json(review_output / 'INSTRUMENT.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    result = instrument(args.output)
    print(json.dumps({'status': result['status'], 'instrument_control_categories': 6,
                      'positive_witness_cases': 2, 'comparative_pairs': 0}))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
