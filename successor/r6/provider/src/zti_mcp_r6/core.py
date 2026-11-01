"""R6 provider-owned SQLite authorization and installed-tool effect boundary.

Authority transitions adapted from integration/stdio_r5/core.py at
3b5b696fe6837e99bad9526c69aa253366d503f5 (Apache-2.0). R6 supplies configured
role-separated keys, generic installed tools, bounded callback writes and new
startup-only laboratory mutants. Historical R4/R5 bytes remain untouched.
"""
from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path

from collections.abc import Mapping
from .crypto import (DomainError, KeyContext, PROFILE, SAFE, U64, canonical,
                     digest, numbers, quantities, reject, uint)
from .integration import ExecutionContext, Footprint, Writer, freeze, thaw
CHARGED = {'COMMITTED', 'COMPLETED', 'UNKNOWN'}
STATES = CHARGED | {'RESERVED', 'CANCELLED', 'EXPIRED', 'REVOKED'}
BODY_FIELDS = {'profile', 'tenant_id', 'principal_id', 'root_mandate_id', 'mandate_id',
               'parent_id', 'parent_hash', 'correlation_id', 'delegatee_id',
               'valid_from', 'valid_until', 'constraints', 'root_policy', 'policy_hash'}
CONSTRAINT_FIELDS = {'allowed_executors', 'allowed_resources', 'allowed_methods',
                     'allowed_tools', 'action_caps'}
ACTION_FIELDS = {'profile', 'tenant_id', 'root_mandate_id', 'mandate_id', 'operation_id',
                 'executor_id', 'resource_id', 'method', 'tool_name', 'tool_revision', 'arguments'}
ZTI_FIELDS = {'profile', 'mode', 'tenant_id', 'root_mandate_id', 'mandate_id',
              'mandate_hash', 'correlation_id', 'operation_id', 'reservation_id',
              'action_hash', 'policy_hash', 'authority_epoch', 'cost_bounds', 'facts'}

SCHEMA = '''
CREATE TABLE IF NOT EXISTS roots(
 tenant_id TEXT NOT NULL, root_mandate_id TEXT NOT NULL, policy_json TEXT NOT NULL,
 active INTEGER NOT NULL, authority_epoch TEXT NOT NULL, state_revision TEXT NOT NULL,
 PRIMARY KEY(tenant_id,root_mandate_id));
CREATE TABLE IF NOT EXISTS mandates(
 tenant_id TEXT NOT NULL, mandate_id TEXT NOT NULL, root_mandate_id TEXT NOT NULL,
 parent_id TEXT, parent_hash TEXT, delegatee_id TEXT NOT NULL, body_json TEXT NOT NULL,
 mandate_hash TEXT NOT NULL, jws TEXT NOT NULL, revoked INTEGER NOT NULL,
 PRIMARY KEY(tenant_id,mandate_id));
CREATE TABLE IF NOT EXISTS reservations(
 tenant_id TEXT NOT NULL, root_mandate_id TEXT NOT NULL, operation_id TEXT NOT NULL,
 reservation_id TEXT NOT NULL, mandate_id TEXT NOT NULL, subject TEXT NOT NULL,
 audience TEXT NOT NULL, action_json TEXT NOT NULL, action_hash TEXT NOT NULL,
 cost_json TEXT NOT NULL, facts_json TEXT NOT NULL, state TEXT NOT NULL,
 ict_claims_json TEXT NOT NULL, ict_jws TEXT NOT NULL,
 PRIMARY KEY(tenant_id,root_mandate_id,operation_id),
 UNIQUE(tenant_id,root_mandate_id,reservation_id));
CREATE TABLE IF NOT EXISTS business_effects(
 tenant_id TEXT NOT NULL, root_mandate_id TEXT NOT NULL, operation_id TEXT NOT NULL,
 reservation_id TEXT NOT NULL, mandate_id TEXT NOT NULL, action_json TEXT NOT NULL,
 arguments_json TEXT NOT NULL, action_hash TEXT NOT NULL, cost_json TEXT NOT NULL,
 facts_json TEXT NOT NULL, provider_pid INTEGER NOT NULL, result_json TEXT NOT NULL,
 PRIMARY KEY(tenant_id,root_mandate_id,operation_id),
 UNIQUE(tenant_id,root_mandate_id,reservation_id));
CREATE TABLE IF NOT EXISTS receipts(
 tenant_id TEXT NOT NULL, root_mandate_id TEXT NOT NULL, operation_id TEXT NOT NULL,
 reservation_id TEXT NOT NULL, receipt_json TEXT NOT NULL, state_revision TEXT NOT NULL,
 PRIMARY KEY(tenant_id,root_mandate_id,operation_id),
 UNIQUE(tenant_id,root_mandate_id,reservation_id));
CREATE TABLE IF NOT EXISTS transitions(
 tenant_id TEXT NOT NULL, root_mandate_id TEXT NOT NULL, state_revision TEXT NOT NULL,
 event TEXT NOT NULL, operation_id TEXT, reservation_id TEXT, provider_pid INTEGER NOT NULL,
 detail_json TEXT NOT NULL, PRIMARY KEY(tenant_id,root_mandate_id,state_revision));
'''


def encoded(value):
    return canonical(value).decode('utf-8')


def decoded(value):
    return json.loads(value)


def valid_mandate_times(body):
    """Do not let Python bool/int equality substitute for timestamp typing."""
    if type(body) is not dict:
        return False
    start, end = body.get('valid_from'), body.get('valid_until')
    return (type(start) is int and type(end) is int and
            0 <= start < end <= SAFE)


class Provider:
    def __init__(self, config, tools, *, hook=None):
        mutant = config.get('mutant')
        if mutant not in (None, 'M02', 'M03', 'M04', 'M05', 'M06'):
            raise ValueError('Unknown startup-only mutant')
        principal, role = config['principal'], config['role']
        if role not in ('admin', 'agent', 'intruder'):
            raise ValueError('Unknown trusted role')
        for key in ('principal', 'tenant_id', 'admin_principal', 'registry_id',
                    'executor_id', 'resource_id', 'mandate_issuer', 'mandate_kid',
                    'permit_issuer', 'permit_kid'):
            if type(config[key]) is not str or not config[key]:
                raise ValueError('Nonempty trusted context required')
        self.tenant = config['tenant_id']
        self.admin_principal = config['admin_principal']
        self.registry_id = config['registry_id']
        self.executor_id = config['executor_id']
        self.resource_id = config['resource_id']
        if role == 'admin' and principal != self.admin_principal:
            raise ValueError('Admin principal mismatch')
        self.db_path = Path(config['db_path'])
        self.principal = principal
        self.role = role
        self.clock_path = Path(config['clock_path'])
        self.hook = hook
        self.mutant = mutant
        self.keys = KeyContext(config)
        self.tools = {tool.name: tool for tool in tools}
        if not self.tools or len(self.tools) != len(tools):
            raise ValueError('Distinct installed tools required')
        table_names = [table.name for tool in tools for table in tool.tables]
        if len(table_names) != len(set(table_names)):
            raise ValueError('One owner per application table required')
        self.initialize()

    def connect(self):
        conn = sqlite3.connect(str(self.db_path), timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA busy_timeout=30000')
        conn.execute('PRAGMA synchronous=FULL')
        return conn

    def initialize(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self.connect()
        try:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.executescript(SCHEMA)
            if 'result_json' not in {row[1] for row in conn.execute('PRAGMA table_info(business_effects)')}:
                raise ValueError('R6 requires a separate compatible database')
            for tool in self.tools.values():
                for table in tool.tables:
                    columns = ','.join(f'"{name}" {kind} NOT NULL' for name, kind in table.columns.items())
                    conn.execute(f'CREATE TABLE IF NOT EXISTS "{table.name}" '
                                 f'(row_id INTEGER PRIMARY KEY AUTOINCREMENT,{columns})')
                    actual = list(conn.execute(f'PRAGMA table_info("{table.name}")'))
                    if ([(row[1], row[2]) for row in actual] !=
                            [('row_id', 'INTEGER'), *table.columns.items()] or
                            any(not row[3] for row in actual[1:])):
                        raise ValueError('Application table schema mismatch')
        finally:
            conn.close()

    @contextlib.contextmanager
    def transaction(self):
        conn = self.connect()
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

    def now(self):
        value = self.clock_path.read_text(encoding='utf-8').strip()
        if len(value) > 16 or not re.fullmatch(r'0|[1-9][0-9]*', value) or int(value) > SAFE:
            raise ValueError('Invalid trusted clock input')
        return int(value)

    def event(self, name, **detail):
        if self.hook is not None:
            self.hook(name, {**detail, 'provider_pid': os.getpid()})

    def root(self, conn, tenant, root_id):
        row = conn.execute('SELECT * FROM roots WHERE tenant_id=? AND root_mandate_id=?',
                           (tenant, root_id)).fetchone()
        if row is None:
            reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
        return row

    def transition(self, conn, tenant, root_id, event, *, operation_id=None,
                   reservation_id=None, initial=False, detail=None):
        root = self.root(conn, tenant, root_id)
        old = uint(root['state_revision'])
        if initial:
            revision = old
        else:
            if old == U64:
                reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
            revision = old + 1
            conn.execute('UPDATE roots SET state_revision=? WHERE tenant_id=? AND root_mandate_id=?',
                         (str(revision), tenant, root_id))
        conn.execute('INSERT INTO transitions VALUES (?,?,?,?,?,?,?,?)',
                     (tenant, root_id, str(revision), event, operation_id, reservation_id,
                      os.getpid(), encoded(detail or {})))
        return str(revision)

    def validate_policy(self, policy):
        if type(policy) is not dict or set(policy) != {'budgets', 'forbidden_sets'}:
            reject('CONSTRAINT_VIOLATION')
        numbers(policy['budgets'])
        if type(policy['forbidden_sets']) is not list:
            reject('CONSTRAINT_VIOLATION')
        for facts in policy['forbidden_sets']:
            if (type(facts) is not list or not facts or
                    any(type(v) is not str or not v for v in facts) or len(facts) != len(set(facts))):
                reject('CONSTRAINT_VIOLATION')

    def validate_constraints(self, constraints):
        if type(constraints) is not dict or set(constraints) != CONSTRAINT_FIELDS:
            reject('CONSTRAINT_VIOLATION')
        numbers(constraints['action_caps'])
        for key in CONSTRAINT_FIELDS - {'action_caps'}:
            values = constraints[key]
            if (type(values) is not list or any(type(v) is not str or not v for v in values)
                    or len(values) != len(set(values))):
                reject('CONSTRAINT_VIOLATION')

    def attenuated(self, parent, child):
        for key in CONSTRAINT_FIELDS - {'action_caps'}:
            if not set(child['constraints'][key]) <= set(parent['constraints'][key]):
                reject('CONSTRAINT_VIOLATION')
        p, c = numbers(parent['constraints']['action_caps']), numbers(child['constraints']['action_caps'])
        if any(c[key] > p[key] for key in p):
            reject('CONSTRAINT_VIOLATION')
        if not parent['valid_from'] <= child['valid_from'] < child['valid_until'] <= parent['valid_until']:
            reject('CONSTRAINT_VIOLATION')

    def lineage(self, conn, tenant, mandate_id):
        line, seen = [], set()
        while mandate_id is not None:
            if mandate_id in seen or len(line) >= 8:
                reject('CONSTRAINT_VIOLATION')
            seen.add(mandate_id)
            row = conn.execute('SELECT * FROM mandates WHERE tenant_id=? AND mandate_id=?',
                               (tenant, mandate_id)).fetchone()
            if row is None:
                reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
            body = decoded(row['body_json'])
            if not valid_mandate_times(body):
                reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
            claims = self.keys.verify_jws(row['jws'], 'zti-mandate+jwt', self.now())
            if digest(body) != row['mandate_hash'] or claims['zti_mandate'] != body:
                reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
            root = self.root(conn, tenant, body['root_mandate_id'])
            if not root['active'] or row['revoked']:
                reject('REVOKED')
            if digest(decoded(root['policy_json'])) != body['policy_hash']:
                reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
            self.validate_constraints(body['constraints'])
            if line:
                child = line[-1]
                if (child['parent_hash'] != row['mandate_hash'] or
                        any(child[k] != body[k] for k in
                            ('tenant_id', 'root_mandate_id', 'principal_id', 'correlation_id', 'policy_hash'))):
                    reject('CONSTRAINT_VIOLATION')
                self.attenuated(body, child)
            line.append(body)
            mandate_id = body['parent_id']
        return line

    def register(self, params):
        token = params.get('mandate')
        with self.transaction() as conn:
            claims = self.keys.verify_jws(token, 'zti-mandate+jwt', self.now())
            body = claims['zti_mandate']
            if type(body) is not dict or set(body) != BODY_FIELDS:
                reject('INVALID_TOKEN')
            if not valid_mandate_times(body):
                reject('INVALID_TOKEN')
            if (body['profile'] != PROFILE or body['tenant_id'] != self.tenant or
                    (type(body['principal_id']) is not str or not body['principal_id']) or claims['aud'] != self.registry_id or
                    claims['sub'] != body['delegatee_id'] or claims['nbf'] != body['valid_from'] or
                    claims['exp'] != body['valid_until']):
                reject('INVALID_TOKEN')
            for key in ('root_mandate_id', 'mandate_id', 'correlation_id', 'delegatee_id'):
                if type(body[key]) is not str or not body[key]:
                    reject('INVALID_TOKEN')
            if (type(body['policy_hash']) is not str or not re.fullmatch(r'[0-9a-f]{64}', body['policy_hash']) or
                    (body['parent_id'] is not None and (type(body['parent_id']) is not str or not body['parent_id'])) or
                    (body['parent_hash'] is not None and
                     (type(body['parent_hash']) is not str or not re.fullmatch(r'[0-9a-f]{64}', body['parent_hash'])))):
                reject('INVALID_TOKEN')
            self.validate_constraints(body['constraints'])
            parent = None
            if body['parent_id'] is None:
                if self.role != 'admin':
                    reject('NOT_AUTHORIZED')
                if body['root_mandate_id'] != body['mandate_id'] or body['parent_hash'] is not None:
                    reject('CONSTRAINT_VIOLATION')
                self.validate_policy(body['root_policy'])
                if digest(body['root_policy']) != body['policy_hash']:
                    reject('CONSTRAINT_VIOLATION')
            else:
                p = conn.execute('SELECT * FROM mandates WHERE tenant_id=? AND mandate_id=?',
                                 (self.tenant, body['parent_id'])).fetchone()
                if p is None:
                    reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
                parent = decoded(p['body_json'])
                if self.role != 'admin' and self.principal != parent['delegatee_id']:
                    reject('NOT_AUTHORIZED')
                if body['root_policy'] is not None:
                    reject('CONSTRAINT_VIOLATION')
            old = conn.execute('SELECT * FROM mandates WHERE tenant_id=? AND mandate_id=?',
                               (self.tenant, body['mandate_id'])).fetchone()
            body_hash = digest(body)
            if old is not None:
                if old['mandate_hash'] != body_hash or decoded(old['body_json']) != body:
                    reject('MANDATE_CONFLICT')
                root = self.root(conn, self.tenant, body['root_mandate_id'])
                return self.register_result(body, body_hash, root, old['revoked'])
            if parent is None:
                conn.execute('INSERT INTO roots VALUES (?,?,?,?,?,?)',
                             (self.tenant, body['root_mandate_id'], encoded(body['root_policy']), 1, '0', '1'))
            else:
                line = self.lineage(conn, self.tenant, parent['mandate_id'])
                if len(line) >= 8 or body['parent_hash'] != digest(parent):
                    reject('CONSTRAINT_VIOLATION')
                if any(body[k] != parent[k] for k in
                       ('tenant_id', 'root_mandate_id', 'principal_id', 'correlation_id', 'policy_hash')):
                    reject('CONSTRAINT_VIOLATION')
                self.attenuated(parent, body)
            conn.execute('INSERT INTO mandates VALUES (?,?,?,?,?,?,?,?,?,?)',
                         (self.tenant, body['mandate_id'], body['root_mandate_id'], body['parent_id'],
                          body['parent_hash'], body['delegatee_id'], encoded(body), body_hash, token, 0))
            self.transition(conn, self.tenant, body['root_mandate_id'], 'ROOT_REGISTERED' if parent is None else 'CHILD_REGISTERED',
                            initial=parent is None, detail={'mandate_id': body['mandate_id']})
            root = self.root(conn, self.tenant, body['root_mandate_id'])
            return self.register_result(body, body_hash, root, 0)

    @staticmethod
    def register_result(body, body_hash, root, revoked):
        return {'resultType': 'complete', 'status': 'REVOKED' if revoked or not root['active'] else 'ACTIVE',
                'tenant_id': body['tenant_id'], 'root_mandate_id': body['root_mandate_id'],
                'mandate_id': body['mandate_id'], 'mandate_hash': body_hash,
                'policy_hash': body['policy_hash'], 'state_revision': root['state_revision']}

    def catalog(self, action):
        canonical(action)
        if type(action) is not dict or set(action) != ACTION_FIELDS:
            reject('BINDING_MISMATCH')
        if any(type(action[key]) is not str or not action[key] for key in ACTION_FIELDS - {'arguments'}):
            reject('BINDING_MISMATCH')
        if (action['profile'] != PROFILE or action['tenant_id'] != self.tenant or
                action['executor_id'] != self.executor_id or action['resource_id'] != self.resource_id or
                action['method'] != 'tools/call' or action['tool_name'] not in self.tools):
            reject('BINDING_MISMATCH')
        tool = self.tools[action['tool_name']]
        if action['tool_revision'] != tool.revision:
            reject('BINDING_MISMATCH')
        args = action['arguments']
        before = canonical(args)
        try:
            candidate = copy.deepcopy(args)
            tool.validate(candidate)
            if canonical(candidate) != before:
                reject('CONSTRAINT_VIOLATION')
            footprint = tool.footprint(freeze(copy.deepcopy(args)))
            if not isinstance(footprint, Footprint):
                reject('CONSTRAINT_VIOLATION')
            cost, facts = thaw(footprint.costs), list(footprint.facts)
            numbers(cost)
            if (any(type(item) is not str or not item for item in facts) or
                    facts != sorted(set(facts))):
                reject('CONSTRAINT_VIOLATION')
        except DomainError:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError):
            reject('CONSTRAINT_VIOLATION')
        return cost, facts

    def gate(self, conn, line, action, cost, facts, *, new):
        for body in line:
            constraints = body['constraints']
            mapping = {'allowed_executors': 'executor_id', 'allowed_resources': 'resource_id',
                       'allowed_methods': 'method', 'allowed_tools': 'tool_name'}
            if any(action[field] not in constraints[allowed] for allowed, field in mapping.items()):
                reject('CONSTRAINT_VIOLATION')
            caps, actual = numbers(constraints['action_caps']), numbers(cost)
            if any(actual[key] > caps[key] for key in caps):
                reject('CONSTRAINT_VIOLATION')
        root = self.root(conn, action['tenant_id'], action['root_mandate_id'])
        policy = decoded(root['policy_json'])
        self.validate_policy(policy)
        totals = {'ops': 0, 'bytes': 0}
        possible = set()
        omitted = []
        for row in conn.execute('SELECT cost_json,facts_json,state,operation_id,reservation_id FROM reservations WHERE tenant_id=? AND root_mandate_id=?',
                                (action['tenant_id'], action['root_mandate_id'])):
            if row['state'] not in STATES:
                reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
            if row['state'] in CHARGED | {'RESERVED'}:
                amount = numbers(decoded(row['cost_json']))
                for key in totals:
                    totals[key] += amount[key]
                if (self.mutant == 'M06' and row['state'] == 'RESERVED' and
                        row['operation_id'] != action['operation_id']):
                    omitted.append(row['reservation_id'])
                else:
                    possible.update(decoded(row['facts_json']))
        if omitted:
            self.event('mutant:M06', operation_id=action['operation_id'], omitted_reservations=omitted)
        if new:
            amount = numbers(cost)
            for key in totals:
                totals[key] += amount[key]
        limits = numbers(policy['budgets'])
        if any(totals[key] > min(U64, limits[key]) for key in totals):
            reject('CUMULATIVE_VIOLATION')
        possible.update(facts)
        if any(set(forbidden) <= possible for forbidden in policy['forbidden_sets']):
            reject('CUMULATIVE_VIOLATION')
        return root

    def reservation(self, conn, params):
        if params.get('tenant_id') != self.tenant:
            reject('NOT_AUTHORIZED')
        row = conn.execute('SELECT * FROM reservations WHERE tenant_id=? AND root_mandate_id=? AND operation_id=?',
                           (params.get('tenant_id'), params.get('root_mandate_id'), params.get('operation_id'))).fetchone()
        if row is None:
            reject('NOT_FOUND')
        if self.principal != row['subject'] and self.role != 'admin':
            reject('NOT_AUTHORIZED')
        if row['state'] not in STATES:
            reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
        return row

    def outcome(self, conn, row, *, include_ict=False):
        root = self.root(conn, row['tenant_id'], row['root_mandate_id'])
        result = {'resultType': 'complete', 'status': row['state'], 'tenant_id': row['tenant_id'],
                  'root_mandate_id': row['root_mandate_id'], 'operation_id': row['operation_id'],
                  'reservation_id': row['reservation_id'], 'state_revision': root['state_revision']}
        if row['state'] in CHARGED:
            receipt = conn.execute('SELECT receipt_json FROM receipts WHERE tenant_id=? AND root_mandate_id=? AND operation_id=?',
                                   (row['tenant_id'], row['root_mandate_id'], row['operation_id'])).fetchone()
            if receipt is None:
                reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
            result['receipt'] = decoded(receipt['receipt_json'])
        elif include_ict and row['state'] == 'RESERVED':
            try:
                claims = self.keys.verify_jws(row['ict_jws'], 'zti-ict+jwt', self.now())
                self.lineage(conn, row['tenant_id'], row['mandate_id'])
                if claims['zti']['authority_epoch'] == root['authority_epoch']:
                    result['ict'] = row['ict_jws']
            except DomainError as error:
                if error.reason not in ('EXPIRED', 'REVOKED'):
                    raise
        return result

    def reserve(self, params):
        action = copy.deepcopy(params.get('action'))
        cost, facts = self.catalog(action)
        self.event('reserve:before_transaction', operation_id=action['operation_id'])
        with self.transaction() as conn:
            old = conn.execute('SELECT * FROM reservations WHERE tenant_id=? AND root_mandate_id=? AND operation_id=?',
                               (action['tenant_id'], action['root_mandate_id'], action['operation_id'])).fetchone()
            if old is not None:
                if self.principal != old['subject']:
                    reject('NOT_AUTHORIZED')
                if old['action_hash'] != digest(action) or decoded(old['action_json']) != action:
                    reject('OPERATION_CONFLICT')
                return self.outcome(conn, old, include_ict=True)
            line = self.lineage(conn, action['tenant_id'], action['mandate_id'])
            leaf = line[0]
            if self.principal != leaf['delegatee_id'] or self.role != 'agent':
                reject('NOT_AUTHORIZED')
            if action['root_mandate_id'] != leaf['root_mandate_id']:
                reject('BINDING_MISMATCH')
            root = self.gate(conn, line, action, cost, facts, new=True)
            reservation_id = 'r-' + secrets.token_hex(16)
            now = self.now()
            zti = {'profile': PROFILE, 'mode': 'current-online', 'tenant_id': self.tenant,
                   'root_mandate_id': leaf['root_mandate_id'], 'mandate_id': leaf['mandate_id'],
                   'mandate_hash': digest(leaf), 'correlation_id': leaf['correlation_id'],
                   'operation_id': action['operation_id'], 'reservation_id': reservation_id,
                   'action_hash': digest(action), 'policy_hash': leaf['policy_hash'],
                   'authority_epoch': root['authority_epoch'], 'cost_bounds': cost, 'facts': facts}
            claims = {'iss': self.keys.issuer, 'sub': self.principal, 'aud': self.executor_id, 'iat': now, 'nbf': now,
                      'exp': min(now + 60, *(body['valid_until'] for body in line)),
                      'jti': 'ict-' + secrets.token_hex(16), 'zti': zti}
            token = self.keys.sign_ict(claims)
            conn.execute('INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                         (self.tenant, leaf['root_mandate_id'], action['operation_id'], reservation_id,
                          leaf['mandate_id'], self.principal, self.executor_id, encoded(action), digest(action),
                          encoded(cost), encoded(facts), 'RESERVED', encoded(claims), token))
            self.transition(conn, self.tenant, leaf['root_mandate_id'], 'RESERVED',
                            operation_id=action['operation_id'], reservation_id=reservation_id)
            row = self.reservation(conn, action)
            result = self.outcome(conn, row, include_ict=True)
        self.event('reserve:commit', operation_id=action['operation_id'],
                   reservation_id=reservation_id, state_revision=result['state_revision'])
        return result

    def lookup(self, params):
        with self.transaction() as conn:
            return self.outcome(conn, self.reservation(conn, params))

    def cancel(self, params):
        changed = False
        with self.transaction() as conn:
            row = self.reservation(conn, params)
            if params.get('reservation_id') != row['reservation_id']:
                reject('BINDING_MISMATCH')
            if row['state'] == 'RESERVED':
                conn.execute('UPDATE reservations SET state=? WHERE tenant_id=? AND root_mandate_id=? AND operation_id=?',
                             ('CANCELLED', row['tenant_id'], row['root_mandate_id'], row['operation_id']))
                self.transition(conn, row['tenant_id'], row['root_mandate_id'], 'CANCELLED',
                                operation_id=row['operation_id'], reservation_id=row['reservation_id'])
                changed = True
                row = self.reservation(conn, params)
            result = self.outcome(conn, row)
        if changed:
            self.event('cancel:commit', operation_id=row['operation_id'], reservation_id=row['reservation_id'])
        return result

    def revoke(self, params):
        if self.role != 'admin' or params.get('tenant_id') != self.tenant:
            reject('NOT_AUTHORIZED')
        changed = False
        with self.transaction() as conn:
            row = conn.execute('SELECT * FROM mandates WHERE tenant_id=? AND mandate_id=? AND root_mandate_id=?',
                               (self.tenant, params.get('mandate_id'), params.get('root_mandate_id'))).fetchone()
            if row is None:
                reject('NOT_FOUND')
            root = self.root(conn, self.tenant, row['root_mandate_id'])
            if not row['revoked']:
                epoch = uint(root['authority_epoch'])
                if epoch == U64:
                    reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
                conn.execute('UPDATE mandates SET revoked=1 WHERE tenant_id=? AND mandate_id=?',
                             (self.tenant, row['mandate_id']))
                conn.execute('UPDATE roots SET authority_epoch=?,active=? WHERE tenant_id=? AND root_mandate_id=?',
                             (str(epoch + 1), 0 if row['mandate_id'] == row['root_mandate_id'] else root['active'],
                              self.tenant, row['root_mandate_id']))
                self.transition(conn, self.tenant, row['root_mandate_id'], 'REVOKED',
                                detail={'mandate_id': row['mandate_id']})
                changed = True
            root = self.root(conn, self.tenant, row['root_mandate_id'])
            result = {'resultType': 'complete', 'status': 'REVOKED', 'tenant_id': self.tenant,
                      'root_mandate_id': row['root_mandate_id'], 'mandate_id': row['mandate_id'],
                      'authority_epoch': root['authority_epoch'], 'state_revision': root['state_revision']}
        if changed:
            self.event('revoke:commit', mandate_id=row['mandate_id'])
        return result

    def prepare_execution(self, conn, tool_name, arguments, meta):
        if type(meta) is not dict or meta.get('revision') != '0.1':
            reject('PROFILE_UNSUPPORTED')
        if set(meta) != {'revision', 'operation_id', 'ict'}:
            reject('INVALID_TOKEN')
        if type(meta['operation_id']) is not str or not meta['operation_id']:
            reject('BINDING_MISMATCH')
        if type(tool_name) is not str or tool_name not in self.tools:
            reject('BINDING_MISMATCH')
        claims = self.keys.verify_jws(meta['ict'], 'zti-ict+jwt')
        zti = claims['zti']
        if type(zti) is not dict or set(zti) != ZTI_FIELDS or zti['profile'] != PROFILE or zti['mode'] != 'current-online':
            reject('INVALID_TOKEN')
        if any(type(zti[key]) is not str or not zti[key] for key in ZTI_FIELDS - {'cost_bounds', 'facts'}):
            reject('INVALID_TOKEN')
        if any(not re.fullmatch(r'[0-9a-f]{64}', zti[key]) for key in ('mandate_hash', 'action_hash', 'policy_hash')):
            reject('INVALID_TOKEN')
        try:
            uint(zti['authority_epoch'])
            numbers(zti['cost_bounds'])
            if (type(zti['facts']) is not list or any(type(item) is not str or not item for item in zti['facts'])
                    or zti['facts'] != sorted(set(zti['facts']))):
                reject('INVALID_TOKEN')
        except DomainError:
            reject('INVALID_TOKEN')
        if claims['sub'] != self.principal or self.role != 'agent':
            reject('NOT_AUTHORIZED')
        if claims['aud'] != self.executor_id or zti['tenant_id'] != self.tenant:
            reject('BINDING_MISMATCH')
        if zti['operation_id'] != meta['operation_id']:
            reject('BINDING_MISMATCH')
        row = self.reservation(conn, zti)
        stored = decoded(row['ict_claims_json'])
        if claims != stored:
            reject('BINDING_MISMATCH')
        action = {'profile': PROFILE, 'tenant_id': self.tenant, 'root_mandate_id': row['root_mandate_id'],
                  'mandate_id': row['mandate_id'], 'operation_id': row['operation_id'],
                  'executor_id': self.executor_id, 'resource_id': self.resource_id, 'method': 'tools/call',
                  'tool_name': tool_name, 'tool_revision': self.tools[tool_name].revision, 'arguments': copy.deepcopy(arguments)}
        cost, facts = self.catalog(action)
        if digest(action) != row['action_hash'] or action != decoded(row['action_json']):
            reject('BINDING_MISMATCH')
        if row['state'] in CHARGED:
            return dict(row), action, cost, facts, self.outcome(conn, row)['receipt']
        if row['state'] != 'RESERVED':
            reject('REVOKED')
        self.keys.verify_jws(meta['ict'], 'zti-ict+jwt', self.now())
        line = self.lineage(conn, self.tenant, row['mandate_id'])
        leaf = line[0]
        root = self.root(conn, self.tenant, row['root_mandate_id'])
        if (leaf['delegatee_id'] != self.principal or leaf['root_mandate_id'] != row['root_mandate_id'] or
                zti['mandate_hash'] != digest(leaf) or zti['correlation_id'] != leaf['correlation_id'] or
                zti['policy_hash'] != leaf['policy_hash']):
            reject('BINDING_MISMATCH')
        if zti['authority_epoch'] != root['authority_epoch']:
            reject('REVOKED')
        if zti['cost_bounds'] != cost or zti['facts'] != facts or cost != decoded(row['cost_json']) or facts != decoded(row['facts_json']):
            reject('BINDING_MISMATCH')
        self.gate(conn, line, action, cost, facts, new=False)
        return dict(row), action, cost, facts, None

    def stored_result(self, conn, row):
        effect = conn.execute('SELECT result_json FROM business_effects WHERE tenant_id=? AND root_mandate_id=? AND operation_id=?',
                              (row['tenant_id'], row['root_mandate_id'], row['operation_id'])).fetchone()
        if effect is None:
            reject('AUTHORITY_UNAVAILABLE', 'SUSPENDED')
        return decoded(effect['result_json'])

    def run_callback(self, conn, prepared, *, early_commit=False):
        row, action, cost, facts, _ = prepared
        args = copy.deepcopy(action['arguments'])
        if self.mutant == 'M02' and type(args.get('label')) is str:
            old_hash = digest(action)
            args['label'] = 'bravo'
            changed_action = {**action, 'arguments': args}
            self.event('mutant:M02', operation_id=row['operation_id'],
                       original_action_hash=old_hash, final_action_hash=digest(changed_action))
        context = ExecutionContext(row['tenant_id'], row['root_mandate_id'], row['mandate_id'],
                                   row['operation_id'], row['reservation_id'], row['action_hash'], os.getpid())
        def inserted(table, row_id):
            if early_commit:
                self.event('mutant:M03', operation_id=row['operation_id'], table=table, row_id=row_id)
                conn.execute('COMMIT')
                self.event('mutant:M03_business_commit', operation_id=row['operation_id'], table=table, row_id=row_id)
            self.event('call:business_inserted', operation_id=row['operation_id'],
                       reservation_id=row['reservation_id'], table=table, row_id=row_id)
        writer = Writer(conn, self.tools[action['tool_name']].tables, inserted)
        try:
            result = self.tools[action['tool_name']].apply(writer, context, freeze(args))
            if not isinstance(result, Mapping):
                raise ValueError('Application result must be a mapping')
            result = thaw(result)
            canonical(result)
            return result, args
        except sqlite3.Error:
            raise
        except Exception as error:
            raise DomainError('EXECUTION_FAILED') from error
        finally:
            writer._finish()

    def stage_effect(self, conn, prepared, *, callback_result=None):
        row, action, cost, facts, existing_receipt = prepared
        if existing_receipt is not None:
            if self.mutant == 'M04':
                self.event('mutant:M04', operation_id=row['operation_id'])
                self.run_callback(conn, prepared)
            return {'receipt': existing_receipt, 'result': self.stored_result(conn, row)}
        current = self.reservation(conn, row)
        if current['state'] in CHARGED:
            return {'receipt': self.outcome(conn, current)['receipt'], 'result': self.stored_result(conn, current)}
        if current['state'] != 'RESERVED':
            reject('REVOKED')
        result, applied_arguments = self.run_callback(conn, prepared) if callback_result is None else callback_result
        conn.execute('INSERT INTO business_effects VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                     (row['tenant_id'], row['root_mandate_id'], row['operation_id'], row['reservation_id'],
                      row['mandate_id'], encoded(action), encoded(applied_arguments), digest(action),
                      encoded(cost), encoded(facts), os.getpid(), encoded(result)))
        conn.execute('UPDATE reservations SET state=? WHERE tenant_id=? AND root_mandate_id=? AND operation_id=?',
                     ('COMMITTED', row['tenant_id'], row['root_mandate_id'], row['operation_id']))
        revision = self.transition(conn, row['tenant_id'], row['root_mandate_id'], 'COMMITTED',
                                   operation_id=row['operation_id'], reservation_id=row['reservation_id'])
        receipt = {'profile': PROFILE, 'tenant_id': row['tenant_id'], 'root_mandate_id': row['root_mandate_id'],
                   'mandate_id': row['mandate_id'], 'operation_id': row['operation_id'],
                   'reservation_id': row['reservation_id'], 'action_hash': digest(action),
                   'effect_boundary': 'resource-mutation', 'status': 'COMMITTED', 'state_revision': revision}
        conn.execute('INSERT INTO receipts VALUES (?,?,?,?,?,?)',
                     (row['tenant_id'], row['root_mandate_id'], row['operation_id'], row['reservation_id'],
                      encoded(receipt), revision))
        self.event('call:staged_before_commit', operation_id=row['operation_id'],
                   reservation_id=row['reservation_id'], state_revision=revision)
        return {'receipt': receipt, 'result': result}

    def execute(self, tool_name, arguments, action_meta):
        operation = action_meta.get('operation_id') if type(action_meta) is dict else None
        if self.mutant == 'M05':
            with self.transaction() as conn:
                cached = self.prepare_execution(conn, tool_name, arguments, action_meta)
                self.event('call:validated', operation_id=operation, action_hash=digest(cached[1]))
            self.event('call:validation_transaction_finished', operation_id=operation)
            self.event('call:pause_after_validation', operation_id=operation)
            self.event('call:before_transaction', operation_id=operation, cached_validation=True, mutant='M05')
            with self.transaction() as conn:
                self.event('mutant:M05', operation_id=operation)
                result = self.stage_effect(conn, cached)
        elif self.mutant == 'M03':
            self.event('call:before_transaction', operation_id=operation)
            with self.transaction() as conn:
                prepared = self.prepare_execution(conn, tool_name, arguments, action_meta)
                self.event('call:validated', operation_id=operation, action_hash=digest(prepared[1]))
            if prepared[4] is None:
                broken = self.connect()
                try:
                    broken.execute('BEGIN IMMEDIATE')
                    callback_result = self.run_callback(broken, prepared, early_commit=True)
                    if broken.in_transaction:
                        broken.execute('COMMIT')
                finally:
                    if broken.in_transaction:
                        broken.execute('ROLLBACK')
                    broken.close()
                with self.transaction() as conn:
                    result = self.stage_effect(conn, prepared, callback_result=callback_result)
            else:
                with self.transaction() as conn:
                    result = self.stage_effect(conn, prepared)
        else:
            self.event('call:before_transaction', operation_id=operation)
            with self.transaction() as conn:
                prepared = self.prepare_execution(conn, tool_name, arguments, action_meta)
                self.event('call:validated', operation_id=operation, action_hash=digest(prepared[1]))
                result = self.stage_effect(conn, prepared)
        receipt = result['receipt']
        self.event('call:commit', operation_id=operation, reservation_id=receipt['reservation_id'])
        self.event('call:after_commit', operation_id=operation, reservation_id=receipt['reservation_id'])
        return result
