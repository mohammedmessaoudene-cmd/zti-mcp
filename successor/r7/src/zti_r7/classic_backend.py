"""Independent durable ACL comparator for R7's local messaging model.

Apache-2.0, Mohammed Messaoudene. AI-assisted. No ZTI authority, binding,
budget or signature checker is imported. Only the neutral business engine
and its closed business-refusal type are shared with the other arm.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
from types import MappingProxyType, SimpleNamespace

from . import domain
from ._provider.integration import BusinessRefusal

NOW = 2_000_000_000
SAFE = (1 << 53) - 1
POLICY_FIELDS = {'principal_id', 'allowed_messages', 'allowed_recipients',
                 'allowed_modes', 'allow_read', 'allowed_body', 'budget_ops', 'budget_bytes'}
SCHEMA = '''
CREATE TABLE c_root(id INTEGER PRIMARY KEY CHECK(id=1),active INTEGER NOT NULL,
 epoch INTEGER NOT NULL,revision INTEGER NOT NULL);
CREATE TABLE c_operations(operation_id TEXT PRIMARY KEY,state TEXT NOT NULL,
 action_json TEXT NOT NULL,action_hash TEXT NOT NULL,cost_json TEXT NOT NULL,
 facts_json TEXT NOT NULL,reservation_id TEXT NOT NULL UNIQUE,subject TEXT NOT NULL,
 epoch INTEGER NOT NULL,valid_until INTEGER NOT NULL,receipt_json TEXT,result_json TEXT);
CREATE TABLE c_transitions(revision INTEGER PRIMARY KEY,event TEXT NOT NULL,
 operation_id TEXT,detail_json TEXT NOT NULL);
CREATE TABLE mail_events(row_id INTEGER PRIMARY KEY AUTOINCREMENT,
 event_kind TEXT NOT NULL,message_id TEXT NOT NULL,message_version INTEGER NOT NULL,
 obligation_id TEXT NOT NULL,occurrence_id TEXT NOT NULL,operation_id TEXT NOT NULL,
 principal_id TEXT NOT NULL,payload_json TEXT NOT NULL);
'''


def _canonical(value):
    """Comparator-owned bounded encoding; no ZTI canonicalizer dependency."""
    def check(item):
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if abs(item) > SAFE:
                raise ValueError('Unsafe JSON integer')
        elif type(item) is str:
            item.encode('utf-8')
        elif type(item) is list:
            for child in item:
                check(child)
        elif type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or not key.isascii():
                    raise ValueError('ASCII JSON object keys required')
                check(child)
        else:
            raise ValueError('Unsupported JSON value')
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False)


def _policy(value):
    if type(value) is not dict or set(value) != POLICY_FIELDS:
        raise ValueError('Closed classic ACL required')
    if type(value['principal_id']) is not str or not value['principal_id']:
        raise ValueError('Service principal required')
    for key in ('allowed_messages', 'allowed_recipients', 'allowed_modes'):
        items = value[key]
        if (type(items) is not list or len(items) > 32 or
                any(type(item) is not str or not item for item in items) or
                len(set(items)) != len(items)):
            raise ValueError('Invalid classic ACL list')
    if (set(value['allowed_modes']) - {'reply', 'reply_all', 'mark_read'} or
            type(value['allow_read']) is not bool or type(value['allowed_body']) is not str):
        raise ValueError('Invalid classic mode/read/body ACL')
    for key in ('budget_ops', 'budget_bytes'):
        if type(value[key]) is not int or not 0 <= value[key] <= SAFE:
            raise ValueError('Invalid classic ACL budget')
    _canonical(value)
    return copy.deepcopy(value)


class _ClassicWriter:
    """Transaction-scoped business-table access; no authority tables exposed."""
    def __init__(self, conn, inserted):
        self._conn = conn
        self._inserted = inserted
        self._active = True

    def _check(self, table):
        if not self._active or not self._conn.in_transaction:
            raise ValueError('Classic writer lifetime ended')
        if type(table) is not str or table != domain.TABLE:
            raise ValueError('Undeclared classic business table')

    def read_rows(self, table):
        self._check(table)
        rows = self._conn.execute('SELECT * FROM mail_events ORDER BY row_id LIMIT 1025').fetchall()
        if len(rows) > 1024:
            raise BusinessRefusal('READ_LIMIT')
        return tuple(MappingProxyType(dict(row)) for row in rows)

    def insert(self, table, values):
        self._check(table)
        if set(values) != set(domain.COLUMNS):
            raise ValueError('Classic business column mismatch')
        for key, typ in domain.COLUMNS.items():
            if typ == 'TEXT':
                if type(values[key]) is not str:
                    raise ValueError('Classic TEXT value required')
                values[key].encode('utf-8')
            elif type(values[key]) is not int or abs(values[key]) > SAFE:
                raise ValueError('Classic safe INTEGER required')
        names = tuple(domain.COLUMNS)
        cursor = self._conn.execute('INSERT INTO mail_events (' + ','.join(names) +
            ') VALUES (' + ','.join('?' for _ in names) + ')', tuple(values[key] for key in names))
        row_id = cursor.lastrowid
        self._inserted(table, row_id)
        return row_id

    def finish(self):
        self._active = False


class ClassicBackend:
    def __init__(self, work_dir, seed, policy, *, hook=None, initialize=True):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.seed = domain.validate_seed(seed)
        self.policy = _policy(policy)
        self.db_path = self.work_dir / 'state.sqlite'
        self.hook = hook
        if initialize:
            if self.db_path.exists() or (self.work_dir / 'policy.json').exists():
                raise ValueError('Classic initialization requires fresh state')
            for name, value in (('seed.json', self.seed), ('policy.json', self.policy)):
                (self.work_dir / name).write_text(_canonical(value), encoding='utf-8')
            (self.work_dir / 'clock').write_text(str(NOW), encoding='ascii')
            conn = self._connect()
            try:
                conn.executescript(SCHEMA)
                conn.execute('INSERT INTO c_root VALUES (1,1,0,2)')
                conn.execute('INSERT INTO c_transitions VALUES (1,?,?,?)',
                             ('ROOT_REGISTERED', None, '{}'))
                conn.execute('INSERT INTO c_transitions VALUES (2,?,?,?)',
                             ('ACL_REGISTERED', None, '{}'))
            finally:
                conn.close()
        else:
            if not self.db_path.is_file():
                raise ValueError('Classic restart requires retained state')
            for name, value in (('seed.json', self.seed), ('policy.json', self.policy)):
                if json.loads((self.work_dir / name).read_text(encoding='utf-8')) != value:
                    raise ValueError('Classic restart input identity mismatch')

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=FULL')
        conn.execute('PRAGMA foreign_keys=ON')
        return conn

    @contextlib.contextmanager
    def _transaction(self):
        conn = self._connect()
        try:
            conn.execute('BEGIN IMMEDIATE')
            try:
                yield conn
                conn.execute('COMMIT')
            except BaseException:
                if conn.in_transaction:
                    conn.execute('ROLLBACK')
                raise
        finally:
            conn.close()

    def _event(self, name, operation_id=None):
        if self.hook is not None:
            self.hook(name, {'backend': 'classic', 'pid': os.getpid(),
                             'operation_id': operation_id})

    def _now(self):
        value = int((self.work_dir / 'clock').read_text(encoding='ascii'))
        if value < 0:
            raise ValueError('Invalid classic trusted clock')
        return value

    @staticmethod
    def _root(conn):
        root = conn.execute('SELECT * FROM c_root WHERE id=1').fetchone()
        if root is None:
            raise RuntimeError('Missing classic authority state')
        return root

    def _transition(self, conn, event, operation_id=None):
        revision = self._root(conn)['revision'] + 1
        if revision > SAFE:
            raise RuntimeError('Classic revision overflow')
        conn.execute('UPDATE c_root SET revision=? WHERE id=1', (revision,))
        conn.execute('INSERT INTO c_transitions VALUES (?,?,?,?)',
                     (revision, event, operation_id, '{}'))
        return str(revision)

    def prepare(self, arguments, operation_id):
        domain.validate_arguments(arguments)
        if type(operation_id) is not str or not operation_id:
            raise ValueError('Operation identity required')
        # Compatibility data envelope only; no ZTI token/authority logic.
        action = {'profile': 'zti-mcp/0.1', 'tenant_id': 'tenant.r7',
            'root_mandate_id': 'root.r7', 'mandate_id': 'leaf.r7',
            'operation_id': operation_id, 'executor_id': 'executor.r7',
            'resource_id': 'resource.r7', 'method': 'tools/call',
            'tool_name': 'message.mutate', 'tool_revision': '1',
            'arguments': copy.deepcopy(arguments)}
        return {'operation_id': operation_id, 'action': action,
                'action_hash': hashlib.sha256(_canonical(action).encode('utf-8')).hexdigest()}

    @staticmethod
    def _cost(arguments):
        size = 0 if arguments['kind'] == 'mark_read' else len(arguments['body'].encode('utf-8'))
        return {'ops': {'unit': 'operation', 'amount': '1'},
                'bytes': {'unit': 'byte', 'amount': str(size)}}

    @staticmethod
    def _facts(arguments):
        recipients = set()
        for field in ('expected_to', 'expected_cc', 'expected_bcc'):
            recipients.update(arguments[field])
        facts = ['recipient:' + value for value in recipients]
        if arguments['expected_read_change']:
            facts.append('read:' + arguments['message_id'])
        return sorted(facts)

    def _budget(self, conn, extra=None):
        ops = byte_count = 0
        for row in conn.execute('SELECT state,cost_json FROM c_operations'):
            if row['state'] not in ('RESERVED', 'COMMITTED', 'CANCELLED'):
                raise RuntimeError('Unknown classic operation state')
            if row['state'] in ('RESERVED', 'COMMITTED'):
                costs = json.loads(row['cost_json'])
                ops += int(costs['ops']['amount'])
                byte_count += int(costs['bytes']['amount'])
        if extra is not None:
            ops += int(extra['ops']['amount'])
            byte_count += int(extra['bytes']['amount'])
        if ops > self.policy['budget_ops'] or byte_count > self.policy['budget_bytes']:
            raise BusinessRefusal('POLICY_DENIED')

    def _operation(self, conn, operation_id):
        row = conn.execute('SELECT * FROM c_operations WHERE operation_id=?', (operation_id,)).fetchone()
        if row is not None and row['subject'] != self.policy['principal_id']:
            raise BusinessRefusal('POLICY_DENIED')
        return row

    def _outcome(self, conn, row, *, handle=False):
        result = {'status': row['state'], 'operation_id': row['operation_id'],
                  'reservation_id': row['reservation_id'],
                  'state_revision': str(self._root(conn)['revision'])}
        if row['state'] == 'COMMITTED':
            result['receipt'] = json.loads(row['receipt_json'])
        elif handle and row['state'] == 'RESERVED':
            root = self._root(conn)
            if root['active'] and row['epoch'] == root['epoch'] and self._now() < row['valid_until']:
                result['handle'] = row['reservation_id']
        return result

    @staticmethod
    def _refusal(error, operation_id=None):
        return {'status': 'REFUSED', 'reason': error.reason, 'operation_id': operation_id,
                'raw': {'type': 'ClassicBusinessRefusal', 'reason': error.reason}}

    def reserve(self, arguments, operation_id):
        try:
            prepared = self.prepare(arguments, operation_id)
            cost = self._cost(arguments)
            with self._transaction() as conn:
                old = self._operation(conn, operation_id)
                if old is not None:
                    if old['action_json'] != _canonical(prepared['action']) or old['action_hash'] != prepared['action_hash']:
                        raise BusinessRefusal('OPERATION_CONFLICT')
                    result = self._outcome(conn, old, handle=True)
                else:
                    root = self._root(conn)
                    if not root['active'] or not NOW - 60 <= self._now() < NOW + 3600:
                        raise BusinessRefusal('REVOKED')
                    self._budget(conn, cost)
                    reservation_id = 'c-' + secrets.token_hex(16)
                    conn.execute('INSERT INTO c_operations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                        (operation_id, 'RESERVED', _canonical(prepared['action']), prepared['action_hash'],
                         _canonical(cost), _canonical(self._facts(arguments)), reservation_id,
                         self.policy['principal_id'], root['epoch'], min(self._now() + 60, NOW + 3600), None, None))
                    self._transition(conn, 'RESERVED', operation_id)
                    result = self._outcome(conn, self._operation(conn, operation_id), handle=True)
            return {**result, 'action_hash': prepared['action_hash'], 'raw': copy.deepcopy(result)}
        except BusinessRefusal as error:
            return self._refusal(error, operation_id)

    def _check_current(self, current, arguments, plan):
        message = current['messages'][arguments['message_id']]
        if arguments['expected_message_version'] != message['version']:
            raise BusinessRefusal('STALE_STATE')
        if arguments['expected_directory_version'] != current['directory']['version']:
            raise BusinessRefusal('STALE_STATE')
        if (arguments['expected_to'] != plan['to'] or arguments['expected_cc'] != plan['cc'] or
                arguments['expected_bcc'] != plan['bcc'] or
                arguments['expected_read_change'] != plan['read_change']):
            raise BusinessRefusal('STALE_STATE')
        acl = self.policy
        if arguments['message_id'] not in acl['allowed_messages'] or arguments['kind'] not in acl['allowed_modes']:
            raise BusinessRefusal('POLICY_DENIED')
        if arguments['set_read'] and not acl['allow_read']:
            raise BusinessRefusal('POLICY_DENIED')
        if arguments['kind'] != 'mark_read' and arguments['body'] != acl['allowed_body']:
            raise BusinessRefusal('POLICY_DENIED')
        actual = set(plan['to']) | set(plan['cc']) | set(plan['bcc'])
        if not actual.issubset(set(acl['allowed_recipients'])):
            raise BusinessRefusal('POLICY_DENIED')

    def execute(self, arguments, operation_id, reservation):
        try:
            prepared = self.prepare(arguments, operation_id)
            self._event('before_effect_transaction', operation_id)
            with self._transaction() as conn:
                row = self._operation(conn, operation_id)
                if row is None:
                    raise BusinessRefusal('OPERATION_CONFLICT')
                handle = reservation.get('handle') or reservation.get('reservation_id')
                if (row['reservation_id'] != handle or row['action_hash'] != prepared['action_hash'] or
                        row['action_json'] != _canonical(prepared['action'])):
                    raise BusinessRefusal('OPERATION_CONFLICT')
                if row['state'] == 'COMMITTED':
                    result = {'status': 'COMMITTED', 'operation_id': operation_id,
                              'receipt': json.loads(row['receipt_json']), 'result': json.loads(row['result_json'])}
                else:
                    root = self._root(conn)
                    if (row['state'] != 'RESERVED' or not root['active'] or row['epoch'] != root['epoch'] or
                            not NOW - 60 <= self._now() < row['valid_until']):
                        raise BusinessRefusal('REVOKED')
                    self._budget(conn)
                    first_insert = False
                    def inserted(table, row_id):
                        nonlocal first_insert
                        if not first_insert:
                            first_insert = True
                            self._event('after_first_insert_before_commit', operation_id)
                    writer = _ClassicWriter(conn, inserted)
                    try:
                        current = domain.project(self.seed, writer.read_rows(domain.TABLE))
                        full_plan = domain.plan(current, arguments)
                        self._check_current(current, arguments, full_plan)
                        business = domain.insert_plan(writer, SimpleNamespace(operation_id=operation_id,
                            principal_id=self.policy['principal_id']), arguments, full_plan)
                        _canonical(business)
                    finally:
                        writer.finish()
                    revision = self._transition(conn, 'COMMITTED', operation_id)
                    receipt = {'profile': 'r7-classic/0.1', 'tenant_id': 'tenant.r7',
                        'root_mandate_id': 'root.r7', 'mandate_id': 'leaf.r7',
                        'operation_id': operation_id, 'reservation_id': row['reservation_id'],
                        'action_hash': prepared['action_hash'], 'effect_boundary': 'resource-mutation',
                        'status': 'COMMITTED', 'state_revision': revision}
                    conn.execute('UPDATE c_operations SET state=?,receipt_json=?,result_json=? WHERE operation_id=?',
                        ('COMMITTED', _canonical(receipt), _canonical(business), operation_id))
                    result = {'status': 'COMMITTED', 'operation_id': operation_id,
                              'receipt': receipt, 'result': business}
            self._event('after_commit_before_response', operation_id)
            return {**result, 'raw': copy.deepcopy(result)}
        except BusinessRefusal as error:
            return self._refusal(error, operation_id)

    def lookup(self, operation_id):
        with self._transaction() as conn:
            row = self._operation(conn, operation_id)
            result = ({'status': 'NOT_FOUND', 'operation_id': operation_id} if row is None
                      else self._outcome(conn, row))
        # Same observation boundary as Z: lookup never exposes result_json.
        return {**result, 'raw': copy.deepcopy(result)}

    def cancel(self, operation_id, reservation):
        try:
            with self._transaction() as conn:
                row = self._operation(conn, operation_id)
                if row is None:
                    return {'status': 'NOT_FOUND', 'operation_id': operation_id}
                if row['reservation_id'] != reservation.get('reservation_id'):
                    raise BusinessRefusal('OPERATION_CONFLICT')
                if row['state'] == 'RESERVED':
                    conn.execute('UPDATE c_operations SET state=? WHERE operation_id=?', ('CANCELLED', operation_id))
                    self._transition(conn, 'CANCELLED', operation_id)
                    row = self._operation(conn, operation_id)
                result = self._outcome(conn, row)
            return {**result, 'raw': copy.deepcopy(result)}
        except BusinessRefusal as error:
            return self._refusal(error, operation_id)

    def revoke(self):
        with self._transaction() as conn:
            root = self._root(conn)
            if root['active']:
                conn.execute('UPDATE c_root SET active=0,epoch=epoch+1 WHERE id=1')
                self._transition(conn, 'REVOKED')
            root = self._root(conn)
            return {'status': 'REVOKED', 'authority_epoch': str(root['epoch']),
                    'state_revision': str(root['revision'])}

    def observe(self):
        with self._transaction() as conn:
            writer = _ClassicWriter(conn, lambda *_: None)
            try:
                return domain.observe_state(self.seed, writer.read_rows(domain.TABLE))
            finally:
                writer.finish()

    def inject_environment(self, change):
        with self._transaction() as conn:
            writer = _ClassicWriter(conn, lambda *_: None)
            try:
                writer.insert(domain.TABLE, domain.environment_row(self.seed,
                    writer.read_rows(domain.TABLE), change))
            finally:
                writer.finish()
        return {'status': 'COMMITTED', 'environment': copy.deepcopy(change)}

    def export_state(self):
        with self._transaction() as conn:
            result = {'seed': copy.deepcopy(self.seed), 'policy': copy.deepcopy(self.policy)}
            for name in ('c_root', 'c_operations', 'c_transitions', 'mail_events'):
                result[name] = [dict(row) for row in conn.execute('SELECT * FROM ' + name)]
            result['projected'] = domain.project(self.seed, result['mail_events'])
            return result


Backend = ClassicBackend
