"""Explicitly faulty, control-only executables for the R7 measuring instrument.

Apache-2.0, Mohammed Messaoudene; AI-assisted. These modes NEVER run in the
ordinary worker or comparative pilot. They generate new actual SQL/claims;
they do not edit an ordinary captured database, observation or final report.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import sys
import traceback

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = 'zti_r7'

from .pilot import _Driver
from .worker import FaultHooks, VisibleBackend, append, durable_json, encoded, guard
from .zti_backend import ZtiBackend

MODES = frozenset({'I01', 'I02', 'I03', 'I04', 'I05', 'I06'})


def activation(output, mode, detail):
    append(Path(output) / 'provider_events.jsonl', {
        'pid': os.getpid(), 'event': 'instrument_control_activated',
        'detail': {'control_id': mode, **detail}})


class DeliberatelyFaultyBackend(ZtiBackend):
    """A named instrument mutant, isolated from the published normal backend."""

    def __init__(self, *args, instrument_mode, instrument_output, **kwargs):
        self.instrument_mode = instrument_mode
        self.instrument_output = Path(instrument_output)
        super().__init__(*args, **kwargs)

    def _authorize(self, args, full_plan):
        if self.instrument_mode == 'I01':
            omitted = 'p.bravo'
            incomplete = copy.deepcopy(full_plan)
            for field in ('to', 'cc', 'bcc'):
                incomplete[field] = [person for person in incomplete[field] if person != omitted]
            # The trusted mutant checks an incomplete representation but sends
            # the original complete plan to the real transaction's INSERT path.
            super()._authorize(args, incomplete)
            activation(self.instrument_output, 'I01', {
                'omitted_from_authorization': omitted,
                'actual_recipients': {field: full_plan[field] for field in ('to', 'cc', 'bcc')}})
            return
        super()._authorize(args, full_plan)

    def _verify_bound_plan(self, current, args, full_plan):
        super()._verify_bound_plan(current, args, full_plan)
        if self.instrument_mode == 'I02':
            if args['set_read'] or args['expected_read_change'] or full_plan['read_change']:
                raise ValueError('I02 requires the declared operation to omit READ')
            # This is an executable implicit-effect bug: the real callback
            # writes READ although the linked plan/footprint omitted it.
            full_plan['set_read'] = True
            full_plan['read_change'] = True
            activation(self.instrument_output, 'I02', {
                'declared_set_read': False, 'declared_read_change': False,
                'actual_read_change_injected': True})


def deliberately_bad_claim(driver, mode, output):
    required = [item['obligation_id'] for item in driver.task['obligations']]
    if mode == 'I04':
        # No mutation is attempted. This producer actually emits the false
        # statement before claim.json has ever been created.
        activation(output, mode, {'emitted_claim': 'DONE', 'mutations_attempted': 0})
        return {'status': 'DONE', 'completed_obligations': required,
            'unknown_obligations': [], 'refused_obligations': [], 'evidence': [],
            'provider_calls': driver.journal['provider_calls'],
            'lookup_calls': driver.journal['lookup_calls'],
            'pids': driver.journal['pids'], 'journal_format': driver.journal['format']}

    ordinary = driver.run()
    if mode == 'I03':
        if ordinary['status'] != 'DONE' or len(driver.task['obligations']) != 1:
            raise ValueError('Duplicate control requires one completed obligation')
        obligation = driver.task['obligations'][0]
        record = driver.journal['records'][obligation['obligation_id']]
        original = record['operation_id']
        view = driver.call('observe')
        arguments = driver._arguments(obligation, obligation['proposal'], view)
        operation = 'op.instrument.repeat'
        prepared = driver.backend.prepare(arguments, operation)
        record.update(arguments=arguments, operation_id=operation,
            action_hash=prepared['action_hash'], reservation=None,
            phase='RESERVE_PENDING', evidence=None, attempt_number=record['attempt_number'] + 1)
        driver.save()  # Authentic changed operation is durable before dispatch.
        activation(output, mode, {'same_obligation': obligation['obligation_id'],
                                 'original_operation': original, 'new_operation': operation})
        response = driver.call('reserve', arguments, operation)
        driver._reserved(obligation, record, response)
        if record['phase'] != 'EXECUTE_READY':
            raise ValueError('Duplicate control could not reserve its real second effect')
        record['phase'] = 'EXECUTE_PENDING'
        driver.save()
        response = driver.call('execute', arguments, operation, record['reservation'])
        driver._proof(record, response)
        return driver.run()  # Produces the first and only captured final claim.

    if mode == 'I05':
        if ordinary['status'] != 'UNKNOWN' or ordinary['evidence']:
            raise ValueError('Unsupported-DONE control requires unresolved, withheld evidence')
        activation(output, mode, {'ordinary_status_before_bad_report': 'UNKNOWN',
                                 'evidence_available_to_claim_producer': []})
        return {**ordinary, 'status': 'DONE', 'completed_obligations': required,
                'unknown_obligations': [], 'refused_obligations': [], 'evidence': []}
    return ordinary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=('Z',), required=True)
    parser.add_argument('--input', required=True)
    parser.add_argument('--control', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args(argv)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    public = json.loads(Path(args.input).read_text(encoding='utf-8'))
    control = json.loads(Path(args.control).read_text(encoding='utf-8'))
    try:
        mode = control['instrument_control']
        if mode not in MODES or set(control) != {'instrument_control', 'interventions'}:
            raise ValueError('Closed, explicit instrument-only control required')
        durable_json(output / 'INSTRUMENT.json', {
            'instrument_only': True, 'control_id': mode,
            'normal_runtime_code_modified': False, 'captured_data_rewritten': False})
        if mode == 'I06':
            from . import oracle  # Deliberate leak; the real guard must exit88.
        module_guard = guard(public)
        durable_json(output / ('guard_' + str(os.getpid()) + '.json'), module_guard)
        hooks = FaultHooks(output, control['interventions'])
        if mode in {'I01', 'I02'}:
            backend = DeliberatelyFaultyBackend(output / 'private', public['seed'], public['policy'],
                hook=hooks, initialize=not args.resume,
                instrument_mode=mode, instrument_output=output)
        else:
            backend = ZtiBackend(output / 'private', public['seed'], public['policy'],
                                 hook=hooks, initialize=not args.resume)
        hooks.backend = backend
        durable_json(output / 'BACKEND_IDENTITY.json', {'backend': 'Z',
            'db_relative': Path(backend.db_path).relative_to(output).as_posix(),
            'service_principal': public['policy']['principal_id']})
        view = VisibleBackend(backend, output, hooks)
        driver = _Driver(view, public['task'], public['policy'], output / 'journal.json')
        claim = deliberately_bad_claim(driver, mode, output)
        guard(public)
        if (output / 'claim.json').exists():
            raise ValueError('Instrument refuses to overwrite an existing captured claim')
        durable_json(output / 'claim.json', claim)
        print(encoded({'status': 'INSTRUMENT_WORKER_COMPLETED', 'control_id': mode,
                       'pid': os.getpid(), 'claim': claim['status']}))
        return 0
    except Exception as error:
        durable_json(output / ('error_' + str(os.getpid()) + '.json'), {
            'status': 'OPERATIONAL_ERROR', 'pid': os.getpid(),
            'type': type(error).__name__, 'message': str(error)})
        traceback.print_exc()
        return 88 if 'Oracle module loaded' in str(error) else 1


if __name__ == '__main__':
    raise SystemExit(main())
