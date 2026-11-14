"""Common bounded adaptive pilot; no fixture, oracle or fault-calendar imports.

Apache-2.0, Mohammed Messaoudene. AI-assisted. The durable journal records
the exact action before dispatch; counters survive a new process. A receipt
is evidence of historical local completion only, not current authority.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

MAX_CALLS = 16
MAX_LOOKUPS = 4
PROPOSAL_FIELDS = {'kind', 'message_id', 'to', 'cc', 'bcc', 'body', 'set_read'}


def _encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False)


def _hash(value):
    return hashlib.sha256(_encoded(value).encode('utf-8')).hexdigest()


def _save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.pending')
    with temporary.open('w', encoding='utf-8', newline='\n') as handle:
        handle.write(_encoded(value) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


class _BudgetStop(Exception):
    pass


class _Driver:
    def __init__(self, backend, task, policy, path):
        self.backend = backend
        self.task = copy.deepcopy(task)
        self.policy = copy.deepcopy(policy)
        self.path = Path(path)
        if (type(task) is not dict or set(task) not in
                ({'obligations'}, {'obligations', 'stale_report'}) or
                type(task['obligations']) is not list):
            raise ValueError('Closed public task required')
        if 'stale_report' in task:
            if type(task['stale_report']) is not str or len(task['stale_report']) > 512:
                raise ValueError('Bounded opaque prior report required')
            task['stale_report'].encode('utf-8')
            # Retained in task_hash as context; never used as completion evidence.
        ids = []
        for obligation in task['obligations']:
            if (type(obligation) is not dict or set(obligation) not in
                    ({'obligation_id', 'proposal'}, {'obligation_id', 'proposal', 'fallback'})):
                raise ValueError('Closed public obligation required')
            identity = obligation['obligation_id']
            if type(identity) is not str or not identity or identity in ids:
                raise ValueError('Distinct public obligation identity required')
            ids.append(identity)
            for key in ('proposal', 'fallback'):
                if key in obligation and (type(obligation[key]) is not dict or
                                          set(obligation[key]) != PROPOSAL_FIELDS):
                    raise ValueError('Closed public proposal required')
        task_hash, policy_hash = _hash(task), _hash(policy)
        if self.path.exists():
            self.journal = json.loads(self.path.read_text(encoding='utf-8'))
            if (self.journal['task_hash'] != task_hash or self.journal['policy_hash'] != policy_hash or
                    self.journal['format'] != 'zti-r7-pilot-journal/1'):
                raise ValueError('Restart task/policy identity mismatch')
        else:
            self.journal = {'format': 'zti-r7-pilot-journal/1', 'task_hash': task_hash,
                'policy_hash': policy_hash, 'provider_calls': 0, 'lookup_calls': 0,
                'pids': [], 'records': {}, 'history': [], 'pending_call': None}
        if os.getpid() not in self.journal['pids']:
            self.journal['pids'].append(os.getpid())
        if (not 0 <= self.journal['provider_calls'] <= MAX_CALLS or
                not 0 <= self.journal['lookup_calls'] <= MAX_LOOKUPS):
            raise ValueError('Invalid retained budget counters')
        self.save()

    def save(self):
        _save(self.path, self.journal)

    def call(self, method, *args):
        if self.journal['provider_calls'] >= MAX_CALLS:
            raise _BudgetStop('Provider-call budget exhausted')
        if method == 'lookup' and self.journal['lookup_calls'] >= MAX_LOOKUPS:
            raise _BudgetStop('Lookup budget exhausted')
        self.journal['provider_calls'] += 1
        if method == 'lookup':
            self.journal['lookup_calls'] += 1
        self.journal['pending_call'] = {'method': method, 'args': copy.deepcopy(args),
            'number': self.journal['provider_calls'], 'pid': os.getpid()}
        self.save()  # Both dispatch identity and cumulative counters are durable first.
        response = getattr(self.backend, method)(*args)
        if type(response) is not dict:
            raise RuntimeError('Backend returned an unexpected response shape')
        self.journal['history'].append({'method': method, 'response': copy.deepcopy(response),
            'number': self.journal['provider_calls'], 'pid': os.getpid()})
        self.journal['pending_call'] = None
        self.save()
        return response

    @staticmethod
    def _arguments(obligation, proposal, view):
        if not {'messages', 'directory', 'self_id'} <= set(view):
            raise _BudgetStop('Current-state observation unavailable')
        message = view['messages'].get(proposal['message_id'])
        # Unknown targets are still submitted as unsupported, never secretly repaired.
        message_version = message['version'] if message else 1
        directory = view['directory']
        def resolve(selectors):
            members = set()
            for selector in selectors:
                if selector in directory['aliases']:
                    members.update(directory['aliases'][selector])
                elif selector in directory['groups']:
                    members.update(directory['groups'][selector])
                else:
                    members.add(selector)
            return sorted(members)
        kind = proposal['kind']
        if kind == 'mark_read':
            recipients = {'to': [], 'cc': [], 'bcc': []}
        elif kind == 'reply_all' and message:
            recipients = {'to': sorted({message['sender'], *message['to'], *message['cc']} -
                                      {view['self_id']}), 'cc': [], 'bcc': []}
        else:
            recipients = {field: resolve(proposal[field]) for field in ('to', 'cc', 'bcc')}
            if kind == 'reply' and not proposal['to'] and message:
                recipients['to'] = [message['sender']]
        return {**copy.deepcopy(proposal), 'obligation_id': obligation['obligation_id'],
                'expected_message_version': message_version,
                'expected_directory_version': directory['version'],
                **{'expected_' + field: recipients[field] for field in ('to', 'cc', 'bcc')},
                'expected_read_change': bool(proposal['set_read'] and message and not message['read'])}

    def _proof(self, record, response):
        receipt = response.get('receipt')
        if (response.get('status') != 'COMMITTED' or type(receipt) is not dict or
                receipt.get('status') != 'COMMITTED' or
                receipt.get('operation_id') != record['operation_id'] or
                receipt.get('action_hash') != record['action_hash'] or
                record['arguments']['obligation_id'] != record['obligation_id']):
            raise RuntimeError('Completion receipt is not bound to the durable obligation/action')
        prepared = self.backend.prepare(record['arguments'], record['operation_id'])
        if prepared['action_hash'] != record['action_hash']:
            raise RuntimeError('Retained action hash no longer matches its exact arguments')
        record['evidence'] = {'obligation_id': record['obligation_id'],
            'operation_id': record['operation_id'], 'action_hash': record['action_hash'],
            'receipt': copy.deepcopy(receipt)}
        record['phase'] = 'DONE'
        self.save()

    def _new_action(self, obligation, record):
        alternatives = [obligation['proposal']]
        if 'fallback' in obligation:
            alternatives.append(obligation['fallback'])
        index = record['proposal_index']
        view = self.call('observe')
        arguments = self._arguments(obligation, alternatives[index], view)
        operation_id = 'op.' + hashlib.sha256((obligation['obligation_id'] + ':' +
                            str(record['attempt_number'])).encode('utf-8')).hexdigest()[:24]
        prepared = self.backend.prepare(arguments, operation_id)
        record.update(arguments=arguments, operation_id=operation_id,
                      action_hash=prepared['action_hash'], reservation=None,
                      phase='RESERVE_PENDING', evidence=None)
        self.save()

    def _after_refusal(self, obligation, record, response):
        record['refusals'].append({'operation_id': record['operation_id'],
            'action_hash': record['action_hash'], 'reason': response.get('reason')})
        record['last_reason'] = response.get('reason')
        if record.get('reservation'):
            record['phase'] = 'CANCEL_PENDING'
            self.save()
            cancelled = self.call('cancel', record['operation_id'], record['reservation'])
            if cancelled.get('status') == 'COMMITTED':
                self._proof(record, cancelled)
                return
            if cancelled.get('status') not in ('CANCELLED', 'NOT_FOUND'):
                record['phase'] = 'UNKNOWN'
                self.save()
                return
        self._continue_after_cancel(obligation, record)

    def _continue_after_cancel(self, obligation, record):
        # A changed action always gets a new op, only after the old hold is resolved.
        if 'fallback' in obligation and record['proposal_index'] == 0:
            record['proposal_index'] = 1
        elif record.get('last_reason') == 'STALE_STATE' and record['attempt_number'] < 2:
            pass  # Refresh current versions of the same proposal, with a new operation.
        else:
            record['phase'] = 'REFUSED'
            self.save()
            return
        record['attempt_number'] += 1
        if record['attempt_number'] > 2:
            record['phase'] = 'REFUSED'
        else:
            record['phase'] = 'NEW'
        record['reservation'] = None
        self.save()

    def _recover(self, obligation, record):
        # An interrupted cancellation must be resolved before choosing another action.
        cancelling = record['phase'] == 'CANCEL_PENDING'
        while True:
            response = self.call('lookup', record['operation_id'])
            status = response.get('status')
            if status == 'COMMITTED':
                self._proof(record, response)
                return
            if status == 'SUSPENDED':
                continue  # Bounded by the persisted four-lookup budget.
            if cancelling:
                if status in ('CANCELLED', 'NOT_FOUND'):
                    self._continue_after_cancel(obligation, record)
                elif status == 'RESERVED':
                    record['reservation'] = {**(record.get('reservation') or {}),
                                             'reservation_id': response['reservation_id']}
                    cancelled = self.call('cancel', record['operation_id'], record['reservation'])
                    if cancelled.get('status') == 'COMMITTED':
                        self._proof(record, cancelled)
                    elif cancelled.get('status') in ('CANCELLED', 'NOT_FOUND'):
                        self._continue_after_cancel(obligation, record)
                    else:
                        record['phase'] = 'UNKNOWN'
                        self.save()
                else:
                    record['phase'] = 'UNKNOWN'
                    self.save()
                return
            if status in ('NOT_FOUND', 'RESERVED'):
                # reserve is idempotent for EXACT retained arguments/op, and retrieves
                # the owner's still-valid execution handle if the reservation exists.
                response = self.call('reserve', record['arguments'], record['operation_id'])
                self._reserved(obligation, record, response)
                return
            record['phase'] = 'UNKNOWN'
            self.save()
            return

    def _reserved(self, obligation, record, response):
        status = response.get('status')
        if status == 'COMMITTED':
            self._proof(record, response)
        elif status == 'RESERVED':
            record['reservation'] = copy.deepcopy(response)
            record['phase'] = 'EXECUTE_READY'
            self.save()
        elif status == 'REFUSED':
            self._after_refusal(obligation, record, response)
        elif status == 'SUSPENDED':
            record['phase'] = 'RESERVE_PENDING'
            self.save()
        else:
            raise RuntimeError('Unexpected reserve status: ' + str(status))

    def run(self):
        for obligation in self.task['obligations']:
            identity = obligation['obligation_id']
            record = self.journal['records'].get(identity)
            if record is None:
                record = {'obligation_id': identity, 'proposal_index': 0,
                    'attempt_number': 0, 'phase': 'NEW', 'refusals': [], 'evidence': None}
                self.journal['records'][identity] = record
                self.save()
            try:
                # A pending request from a previous PID is evidence of uncertainty.
                if record['phase'] in ('RESERVE_PENDING', 'EXECUTE_PENDING', 'CANCEL_PENDING'):
                    self._recover(obligation, record)
                while record['phase'] not in ('DONE', 'UNKNOWN', 'REFUSED'):
                    if record['phase'] == 'NEW':
                        self._new_action(obligation, record)
                        response = self.call('reserve', record['arguments'], record['operation_id'])
                        self._reserved(obligation, record, response)
                    elif record['phase'] == 'EXECUTE_READY':
                        record['phase'] = 'EXECUTE_PENDING'
                        self.save()
                        response = self.call('execute', record['arguments'], record['operation_id'], record['reservation'])
                        status = response.get('status')
                        if status == 'COMMITTED':
                            self._proof(record, response)
                        elif status == 'REFUSED':
                            self._after_refusal(obligation, record, response)
                        elif status == 'SUSPENDED':
                            self._recover(obligation, record)
                        else:
                            raise RuntimeError('Unexpected execute status: ' + str(status))
                    elif record['phase'] in ('RESERVE_PENDING', 'EXECUTE_PENDING', 'CANCEL_PENDING'):
                        self._recover(obligation, record)
                    else:
                        raise RuntimeError('Unexpected pilot phase')
            except _BudgetStop as error:
                record['phase'] = 'UNKNOWN'
                record['unknown_reason'] = str(error)
                self.save()
        records = list(self.journal['records'].values())
        done = [record for record in records if record['phase'] == 'DONE']
        unknown = [record['obligation_id'] for record in records if record['phase'] == 'UNKNOWN']
        refused = [record['obligation_id'] for record in records if record['phase'] == 'REFUSED']
        status = ('DONE' if len(done) == len(self.task['obligations']) else
                  'PARTIAL' if done else 'UNKNOWN' if unknown else 'REFUSED')
        return {'status': status, 'completed_obligations': [record['obligation_id'] for record in done],
            'unknown_obligations': unknown, 'refused_obligations': refused,
            'evidence': [record['evidence'] for record in done],
            'provider_calls': self.journal['provider_calls'],
            'lookup_calls': self.journal['lookup_calls'], 'pids': self.journal['pids'],
            'journal_format': self.journal['format']}


def run_pilot(backend, task, policy, journal_path):
    return _Driver(backend, task, policy, journal_path).run()
