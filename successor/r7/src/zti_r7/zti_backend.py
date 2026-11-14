"""R7 programmatic Z backend: attributed R6 authority plus a local mail tool.

Original contribution Mohammed Messaoudene, Apache-2.0; AI-assisted.
No MCP SDK, wire, real email or cross-principal delegation is executed here.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import domain
from ._provider.core import Provider
from ._provider.crypto import DomainError, b64, canonical, digest, quantities
from ._provider.integration import BusinessRefusal, Footprint, TableSpec, ToolSpec, Writer, thaw

NOW = 2_000_000_000
ROOT = 'root.r7'
LEAF = 'leaf.r7'
TENANT = 'tenant.r7'
TOOL = 'message.mutate'
POLICY_FIELDS = frozenset({'principal_id', 'allowed_messages', 'allowed_recipients',
    'allowed_modes', 'allow_read', 'allowed_body', 'budget_ops', 'budget_bytes'})


def _policy(policy):
    """Z-specific policy validation; C implements its own authority checks."""
    if type(policy) is not dict or set(policy) != POLICY_FIELDS:
        raise ValueError('Closed Z policy required')
    if type(policy['principal_id']) is not str or not policy['principal_id']:
        raise ValueError('Policy principal required')
    for field in ('allowed_messages', 'allowed_recipients', 'allowed_modes'):
        value = policy[field]
        if (type(value) is not list or len(value) > 32 or
                any(type(item) is not str or not item for item in value) or
                len(value) != len(set(value))):
            raise ValueError('Invalid policy list')
    if (set(policy['allowed_modes']) - {'reply', 'reply_all', 'mark_read'} or
            type(policy['allow_read']) is not bool or type(policy['allowed_body']) is not str):
        raise ValueError('Invalid policy mode/read/body')
    for field in ('budget_ops', 'budget_bytes'):
        if type(policy[field]) is not int or not 0 <= policy[field] <= (1 << 53) - 1:
            raise ValueError('Invalid policy budget')
    return copy.deepcopy(policy)


class ZtiBackend:
    def __init__(self, work_dir, seed, policy, *, hook=None, initialize=True):
        self.work_dir = Path(work_dir)
        self.seed = domain.validate_seed(seed)
        self.policy = _policy(policy)
        self.hook = hook
        self._first_insert_seen = False
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.work_dir / 'state.sqlite'
        self._table = TableSpec(domain.TABLE, domain.COLUMNS)
        self._tool = self._make_tool()
        if initialize:
            if self.db_path.exists() or (self.work_dir / 'config.json').exists():
                raise ValueError('New initialization requires fresh state/config')
            self._initialize()
        else:
            if not self.db_path.is_file():
                raise ValueError('Restart requires retained state')
            for name, value in (('seed.json', self.seed), ('policy.json', self.policy)):
                if json.loads((self.work_dir / name).read_text(encoding='utf-8')) != value:
                    raise ValueError('Restart input identity mismatch')
        self.config = json.loads((self.work_dir / 'config.json').read_text(encoding='utf-8'))
        if self.config['principal'] != self.policy['principal_id']:
            raise ValueError('Restart principal mismatch')
        self.provider = Provider(self.config, (self._tool,), hook=self._provider_hook)
        self.admin = Provider({**self.config, 'principal': 'admin.r7', 'role': 'admin'},
                              (self._tool,))

    def _initialize(self):
        issuer = ec.generate_private_key(ec.SECP256R1())
        permit = ec.generate_private_key(ec.SECP256R1())
        (self.work_dir / 'KI.public').write_bytes(issuer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        (self.work_dir / 'KP.private').write_bytes(permit.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        (self.work_dir / 'clock').write_text(str(NOW), encoding='ascii')
        config = {'db_path': str(self.db_path.resolve()),
            'principal': self.policy['principal_id'], 'role': 'agent', 'tenant_id': TENANT,
            'admin_principal': 'admin.r7', 'registry_id': 'registry.r7',
            'executor_id': 'executor.r7', 'resource_id': 'resource.r7',
            'mandate_issuer': 'issuer.r7', 'mandate_kid': 'KI.r7',
            'mandate_public_key_path': str((self.work_dir / 'KI.public').resolve()),
            'permit_issuer': 'permit.r7', 'permit_kid': 'KP.r7',
            'permit_private_key_path': str((self.work_dir / 'KP.private').resolve()),
            'clock_path': str((self.work_dir / 'clock').resolve())}
        for name, value in (('seed.json', self.seed), ('policy.json', self.policy), ('config.json', config)):
            (self.work_dir / name).write_text(domain.canonical(value) + '\n', encoding='utf-8')
        admin = Provider({**config, 'principal': 'admin.r7', 'role': 'admin'}, (self._tool,))
        root_policy = {'budgets': quantities(self.policy['budget_ops'], self.policy['budget_bytes']),
                       'forbidden_sets': []}
        root = {'profile': 'zti-mcp/0.1', 'tenant_id': TENANT, 'principal_id': 'owner.r7',
            'root_mandate_id': ROOT, 'mandate_id': ROOT, 'parent_id': None, 'parent_hash': None,
            'correlation_id': 'r7.local', 'delegatee_id': 'admin.r7',
            'valid_from': NOW - 60, 'valid_until': NOW + 3600,
            'constraints': {'allowed_executors': ['executor.r7'],
                'allowed_resources': ['resource.r7'], 'allowed_methods': ['tools/call'],
                'allowed_tools': [TOOL], 'action_caps': quantities((1 << 64) - 1, (1 << 64) - 1)},
            'root_policy': root_policy, 'policy_hash': digest(root_policy)}
        leaf = {**root, 'mandate_id': LEAF, 'parent_id': ROOT, 'parent_hash': digest(root),
                'delegatee_id': self.policy['principal_id'], 'root_policy': None}

        def sign(body):
            claims = {'iss': 'issuer.r7', 'sub': body['delegatee_id'], 'aud': 'registry.r7',
                'iat': NOW - 60, 'nbf': NOW - 60, 'exp': NOW + 3600,
                'jti': 'r7.initial.' + body['mandate_id'], 'zti_mandate': body}
            head = b64(canonical({'alg': 'ES256', 'typ': 'zti-mandate+jwt', 'kid': 'KI.r7'}))
            payload = b64(canonical(claims))
            r, s = utils.decode_dss_signature(issuer.sign((head + '.' + payload).encode('ascii'),
                                                        ec.ECDSA(hashes.SHA256())))
            return head + '.' + payload + '.' + b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))

        admin.register({'mandate': sign(root)})
        admin.register({'mandate': sign(leaf)})
        # The issuer private key is not persisted or passed to the Provider.

    def _authorize(self, args, full_plan):
        """Z-specific fine policy, evaluated before the first business INSERT."""
        rights = self.policy
        if (args['message_id'] not in rights['allowed_messages'] or
                args['kind'] not in rights['allowed_modes'] or
                (args['set_read'] and not rights['allow_read']) or
                (args['kind'] != 'mark_read' and args['body'] != rights['allowed_body'])):
            raise BusinessRefusal('POLICY_DENIED')
        for field in ('to', 'cc', 'bcc'):
            if any(recipient not in rights['allowed_recipients'] for recipient in full_plan[field]):
                raise BusinessRefusal('POLICY_DENIED')

    def _verify_bound_plan(self, current, args, full_plan):
        """Z-specific current-state/action binding, separate from C's checks."""
        message = current['messages'][args['message_id']]
        if (args['expected_message_version'] != message['version'] or
                args['expected_directory_version'] != current['directory']['version']):
            raise BusinessRefusal('STALE_STATE')
        if any(args['expected_' + field] != full_plan[field] for field in ('to', 'cc', 'bcc')):
            raise BusinessRefusal('STALE_STATE')
        if args['expected_read_change'] != full_plan['read_change']:
            raise BusinessRefusal('STALE_STATE')

    def _make_tool(self):
        def validate(args):
            domain.validate_arguments(args)

        def footprint(args):
            costs, facts = domain.footprint(args)
            return Footprint(costs, facts)

        def apply(writer, context, arguments):
            args = thaw(arguments)
            rows = writer.read_rows(domain.TABLE)
            current = domain.project(self.seed, rows)
            full_plan = domain.plan(current, args)
            self._verify_bound_plan(current, args, full_plan)
            self._authorize(args, full_plan)
            ctx = SimpleNamespace(operation_id=context.operation_id,
                                  principal_id=self.policy['principal_id'])
            return domain.insert_plan(writer, ctx, args, full_plan)

        return ToolSpec(TOOL, '1', {'type': 'object'}, (self._table,),
                        validate, footprint, apply)

    def _provider_hook(self, event, detail):
        detail = {**detail, 'backend': 'zti', 'pid': os.getpid(), 'provider_event': event}
        semantic = None
        if event == 'call:before_transaction':
            self._first_insert_seen = False
            semantic = 'before_effect_transaction'
        elif event == 'call:business_inserted' and not self._first_insert_seen:
            self._first_insert_seen = True
            semantic = 'after_first_insert_before_commit'
        elif event == 'call:after_commit':
            semantic = 'after_commit_before_response'
        if semantic and self.hook is not None:
            self.hook(semantic, detail)

    def prepare(self, arguments, operation_id):
        domain.validate_arguments(arguments)
        if type(operation_id) is not str or not operation_id:
            raise ValueError('Operation identity required')
        action = {'profile': 'zti-mcp/0.1', 'tenant_id': TENANT,
            'root_mandate_id': ROOT, 'mandate_id': LEAF, 'operation_id': operation_id,
            'executor_id': 'executor.r7', 'resource_id': 'resource.r7',
            'method': 'tools/call', 'tool_name': TOOL, 'tool_revision': '1',
            'arguments': copy.deepcopy(arguments)}
        return {'action': action, 'action_hash': digest(action), 'operation_id': operation_id}

    @staticmethod
    def _refusal(error, operation_id):
        if isinstance(error, BusinessRefusal):
            return {'status': 'REFUSED', 'reason': error.reason, 'operation_id': operation_id,
                    'raw': {'type': 'BusinessRefusal', 'reason': error.reason}}
        if error.reason == 'EXECUTION_FAILED':
            raise RuntimeError('Unexpected application/engine failure; not a qualified business refusal') from error
        if error.reason == 'NOT_FOUND':
            return {'status': 'NOT_FOUND', 'operation_id': operation_id,
                    'raw': {'reason': error.reason}}
        reasons = {'CONSTRAINT_VIOLATION': 'POLICY_DENIED',
            'CUMULATIVE_VIOLATION': 'POLICY_DENIED', 'NOT_AUTHORIZED': 'POLICY_DENIED',
            'REVOKED': 'REVOKED', 'EXPIRED': 'REVOKED',
            'OPERATION_CONFLICT': 'OPERATION_CONFLICT', 'BINDING_MISMATCH': 'OPERATION_CONFLICT'}
        if error.reason not in reasons:
            raise RuntimeError('Unexpected provider refusal/error: ' + error.reason) from error
        return {'status': 'REFUSED', 'reason': reasons[error.reason], 'operation_id': operation_id,
                'raw': {'type': 'DomainError', 'reason': error.reason, 'status': error.status}}

    def reserve(self, arguments, operation_id):
        try:
            prepared = self.prepare(arguments, operation_id)
            raw = self.provider.reserve({'action': prepared['action']})
            return {**raw, 'action_hash': prepared['action_hash'],
                    'handle': raw.get('ict'), 'raw': raw}
        except (BusinessRefusal, DomainError) as error:
            return self._refusal(error, operation_id)

    def execute(self, arguments, operation_id, reservation):
        try:
            handle = reservation.get('handle') or reservation.get('ict')
            if not handle and type(reservation.get('raw')) is dict:
                handle = reservation['raw'].get('ict')
            if not handle:
                raise ValueError('Reservation handle required')
            raw = self.provider.execute(TOOL, arguments,
                {'revision': '0.1', 'operation_id': operation_id, 'ict': handle})
            return {'status': 'COMMITTED', 'operation_id': operation_id,
                    'receipt': raw['receipt'], 'result': raw['result'], 'raw': raw}
        except (BusinessRefusal, DomainError) as error:
            return self._refusal(error, operation_id)

    def lookup(self, operation_id):
        try:
            raw = self.provider.lookup({'tenant_id': TENANT, 'root_mandate_id': ROOT,
                                        'operation_id': operation_id})
            # R6 lookup exposes its receipt, not its stored business result.
            return {**raw, 'raw': raw}
        except DomainError as error:
            return self._refusal(error, operation_id)

    def cancel(self, operation_id, reservation):
        try:
            raw = self.provider.cancel({'tenant_id': TENANT, 'root_mandate_id': ROOT,
                'operation_id': operation_id, 'reservation_id': reservation['reservation_id']})
            return {**raw, 'raw': raw}
        except DomainError as error:
            return self._refusal(error, operation_id)

    def revoke(self):
        raw = self.admin.revoke({'tenant_id': TENANT, 'root_mandate_id': ROOT,
                                 'mandate_id': LEAF})
        return {**raw, 'raw': raw}

    def _read_rows(self, conn):
        rows = conn.execute('SELECT * FROM mail_events ORDER BY row_id LIMIT 1025').fetchall()
        if len(rows) > 1024:
            raise BusinessRefusal('READ_LIMIT')
        return [dict(row) for row in rows]

    def observe(self):
        conn = sqlite3.connect(self.db_path.resolve().as_uri() + '?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute('PRAGMA query_only=ON')
            conn.execute('BEGIN')
            return domain.observe_state(self.seed, self._read_rows(conn))
        finally:
            conn.close()

    def inject_environment(self, change):
        """Harness-only environment transition; never part of the pilot API."""
        with self.provider.transaction() as conn:
            writer = Writer(conn, (self._table,), lambda *_: None)
            try:
                row = domain.environment_row(self.seed, writer.read_rows(domain.TABLE), change)
                writer.insert(domain.TABLE, row)
            finally:
                writer._finish()
        return {'status': 'COMMITTED', 'environment': copy.deepcopy(change)}

    def export_state(self):
        """Audit-only; no pilot may use this stronger view."""
        conn = sqlite3.connect(self.db_path.resolve().as_uri() + '?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute('PRAGMA query_only=ON')
            conn.execute('BEGIN')
            result = {'seed': copy.deepcopy(self.seed), 'policy': copy.deepcopy(self.policy)}
            for name in ('mail_events', 'roots', 'mandates', 'reservations',
                         'business_effects', 'receipts', 'transitions'):
                result[name] = [dict(row) for row in conn.execute('SELECT * FROM "' + name + '"')]
            result['projected'] = domain.project(self.seed, result['mail_events'])
            return result
        finally:
            conn.close()


Backend = ZtiBackend
