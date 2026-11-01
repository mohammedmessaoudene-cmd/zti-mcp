"""Targeted development/unit checks, separate from the frozen R6 corpus counts.

Run with an installed wheel: python -I successor/r6/provider/tests/test_boundary.py
The test-only issuer below is not part of the provider distribution/package.
"""
import copy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from zti_mcp_r6 import Footprint, TableSpec, ToolSpec, Writer
from zti_mcp_r6.core import Provider
from zti_mcp_r6.crypto import DomainError, b64, canonical, digest, quantities

NOW = 2000000000


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        folder = Path(self.tmp.name)
        self.ki, self.kp = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
        (folder/'KI.public').write_bytes(self.ki.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        (folder/'KP.private').write_bytes(self.kp.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (folder/'clock').write_text(str(NOW), encoding='utf-8')
        self.config = dict(db_path=str(folder/'state.sqlite'), principal='admin', role='admin',
            tenant_id='tenant', admin_principal='admin', registry_id='registry', executor_id='executor',
            resource_id='resource', mandate_issuer='issuer-KI', mandate_kid='KI',
            mandate_public_key_path=str(folder/'KI.public'), permit_issuer='issuer-KP', permit_kid='KP',
            permit_private_key_path=str(folder/'KP.private'), clock_path=str(folder/'clock'))
        self.fail = False

        def validate(args):
            if type(args) is not dict or set(args) != {'label'} or type(args['label']) is not str:
                raise ValueError('label required')

        def apply(writer, context, args):
            with self.assertRaises(TypeError):
                args['label'] = 'mutated'
            row = writer.insert('app_rows', {'operation_id': context.operation_id, 'label': args['label']})
            if self.fail:
                raise RuntimeError('intentional callback failure after INSERT')
            return {'row_id': row, 'label': args['label']}

        self.tools = (ToolSpec('test.write', '1', {'type':'object'},
            (TableSpec('app_rows', {'operation_id':'TEXT', 'label':'TEXT'}),), validate,
            lambda args: Footprint(quantities(1, len(args['label'].encode('utf-8'))), ()), apply),)
        self.admin = Provider(self.config, self.tools)
        self.agent = Provider({**self.config, 'role':'agent', 'principal':'agent'}, self.tools)
        caps = quantities(10, 1024)
        constraints = dict(allowed_executors=['executor'], allowed_resources=['resource'],
            allowed_methods=['tools/call'], allowed_tools=['test.write'], action_caps=caps)
        policy = {'budgets':caps, 'forbidden_sets':[]}
        self.root = dict(profile='zti-mcp/0.1', tenant_id='tenant', principal_id='owner',
            root_mandate_id='root', mandate_id='root', parent_id=None, parent_hash=None,
            correlation_id='correlation', delegatee_id='admin', valid_from=NOW-60,
            valid_until=NOW+3600, constraints=constraints, root_policy=policy, policy_hash=digest(policy))
        leaf = {**self.root, 'mandate_id':'leaf', 'parent_id':'root', 'parent_hash':digest(self.root),
                'delegatee_id':'agent', 'root_policy':None}
        self.admin.register({'mandate': self.signed(self.root)})
        self.admin.register({'mandate': self.signed(leaf)})
        self.action = dict(profile='zti-mcp/0.1', tenant_id='tenant', root_mandate_id='root',
            mandate_id='leaf', operation_id='operation', executor_id='executor', resource_id='resource',
            method='tools/call', tool_name='test.write', tool_revision='1', arguments={'label':'hello'})

    def signed(self, body, *, key=None, kid='KI'):
        claims = dict(iss='issuer-KI', sub=body['delegatee_id'], aud='registry',
            iat=NOW-60, nbf=NOW-60, exp=NOW+3600, jti='test-id', zti_mandate=body)
        head = b64(canonical({'alg':'ES256', 'typ':'zti-mandate+jwt', 'kid':kid}))
        payload = b64(canonical(claims))
        r, s = utils.decode_dss_signature((key or self.ki).sign(
            (head+'.'+payload).encode('ascii'), ec.ECDSA(hashes.SHA256())))
        return head+'.'+payload+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))

    def snapshot(self):
        with closing(sqlite3.connect(self.config['db_path'])) as connection:
            return {table: connection.execute('SELECT * FROM '+table).fetchall()
                    for table in ('roots','reservations','app_rows','business_effects','receipts','transitions')}

    def meta(self, reservation):
        return {'revision':'0.1', 'operation_id':'operation', 'ict':reservation['ict']}

    def test_effect_and_historical_retry_survive_late_revocation(self):
        committed_admissions = []
        def observe(event, detail):
            if event == 'reserve:commit':
                # A distinct reader must see the committed row at this event.
                with closing(sqlite3.connect(self.config['db_path'])) as reader:
                    count = reader.execute('SELECT COUNT(*) FROM reservations').fetchone()[0]
                self.assertEqual(1, count)
                committed_admissions.append(detail)
        self.agent.hook = observe
        reserved = self.agent.reserve({'action':self.action})
        result = self.agent.execute('test.write', {'label':'hello'}, self.meta(reserved))
        self.admin.revoke({'tenant_id':'tenant', 'root_mandate_id':'root', 'mandate_id':'leaf'})
        before = self.snapshot()
        self.assertEqual(result, self.agent.execute('test.write', {'label':'hello'}, self.meta(reserved)))
        retry = self.agent.reserve({'action':self.action})
        self.assertEqual('COMMITTED', retry['status'])
        self.assertEqual(result['receipt'], retry['receipt'])
        self.assertNotIn('ict', retry)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(1, len(before['app_rows']))
        self.assertEqual(1, len(committed_admissions))
        self.assertEqual(reserved['state_revision'], committed_admissions[0]['state_revision'])

    def test_callback_insert_then_exception_rolls_back_everything(self):
        reserved = self.agent.reserve({'action':self.action})
        before = self.snapshot()
        self.fail = True
        with self.assertRaises(DomainError) as raised:
            self.agent.execute('test.write', {'label':'hello'}, self.meta(reserved))
        self.assertEqual('EXECUTION_FAILED', raised.exception.reason)
        self.assertEqual(before, self.snapshot())
        self.fail = False
        self.agent.execute('test.write', {'label':'hello'}, self.meta(reserved))
        self.assertEqual(1, len(self.snapshot()['app_rows']))

    def test_bound_type_and_signing_role_fail_without_state_change(self):
        before = self.snapshot()
        malformed = {**self.action, 'tool_name':[]}
        with self.assertRaises(DomainError) as raised:
            self.agent.reserve({'action':malformed})
        self.assertEqual('BINDING_MISMATCH', raised.exception.reason)
        for token in (self.signed(self.root, key=self.kp, kid='KP'),
                      self.signed({**self.root, 'valid_from':True})):
            with self.assertRaises(DomainError) as raised:
                self.admin.register({'mandate':token})
            self.assertEqual('INVALID_TOKEN', raised.exception.reason)
        self.assertEqual(before, self.snapshot())

    def test_configured_tenant_guard_precedes_database_query(self):
        class NoDatabaseAccess:
            calls = 0
            def execute(self, *args):
                self.calls += 1
                raise AssertionError('A different tenant must be refused before a query')
        connection = NoDatabaseAccess()
        with self.assertRaises(DomainError) as raised:
            self.admin.reservation(connection, {'tenant_id':'different-fixture-tenant',
                'root_mandate_id':'unused', 'operation_id':'unused'})
        self.assertEqual('NOT_AUTHORIZED', raised.exception.reason)
        self.assertEqual(0, connection.calls)

    def test_writer_scope_and_expired_handle_reject_writes(self):
        with closing(sqlite3.connect(':memory:', isolation_level=None)) as connection:
            connection.execute('CREATE TABLE app(row_id INTEGER PRIMARY KEY, value TEXT NOT NULL)')
            connection.execute('CREATE TABLE roots(value TEXT NOT NULL)')
            connection.execute('BEGIN IMMEDIATE')
            events = []
            writer = Writer(connection, (TableSpec('app', {'value':'TEXT'}),),
                            lambda table, row: events.append((table, row)))
            with self.assertRaises(ValueError):
                writer.insert('roots', {'value':'unauthorized'})
            writer.insert('app', {'value':'allowed'})
            writer._finish()
            with self.assertRaises(ValueError):
                writer.insert('app', {'value':'too late'})
            self.assertEqual(0, connection.execute('SELECT COUNT(*) FROM roots').fetchone()[0])
            self.assertEqual([('app', 1)], events)
            connection.execute('ROLLBACK')
            self.assertEqual(0, connection.execute('SELECT COUNT(*) FROM app').fetchone()[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
