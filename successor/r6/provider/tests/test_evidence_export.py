"""Data-export sensitivity checks. No frozen semantic campaign is simulated."""
from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('r6_exporter_test', Path(__file__).resolve().parents[2]/'package_evidence.py')
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.run, self.output = root/'private-run', root/'export'
        self.case = self.run/'cases/base/I01__P'
        (self.case/'wire').mkdir(parents=True)
        (self.case/'control/instance').mkdir(parents=True)
        (self.run/'_runtime/keys').mkdir(parents=True)
        (self.run/'_runtime/keys/KI.private.pem').write_text('-----BEGIN PRIVATE KEY-----\nnot-public\n')
        (self.case/'control/instance/rules.json').write_text('{"private":true}')
        (self.case/'manifest.json').write_text(json.dumps({'source':{'entrypoint':'/home/private/project/client.ts'}}))
        (self.case/'fixtures.json').write_text('{}')
        (self.case/'observation.json').write_text('{}')
        self.raw = b'{"direction":"client_to_server","frame":{"id":1,"method":"tools/list"}}\n'
        (self.case/'wire/instance.jsonl').write_bytes(self.raw)
        (self.case/'control/instance/events.jsonl').write_text('{"event":"endpoint_ready","provider_pid":1}\n')
        with closing(sqlite3.connect(self.case/'provider.sqlite')) as connection:
            connection.execute('CREATE TABLE demo_records(label TEXT)')
            connection.execute('INSERT INTO demo_records VALUES (?)', ('fictional',))
            connection.commit()

    def test_original_wire_and_sqlite_preserved_metadata_projection_declared(self):
        original_db = (self.case/'provider.sqlite').read_bytes()
        original_manifest = (self.case/'manifest.json').read_bytes()
        report = exporter.export(self.run, self.output)
        self.assertEqual('EXPORTED_DATA_NOT_YET_AUDITED', report['status'])
        data = self.output/'data/cases/base/I01__P'
        self.assertEqual(self.raw, (data/'wire/instance.jsonl').read_bytes())
        self.assertEqual(original_db, (data/'provider.sqlite').read_bytes())
        self.assertEqual(original_manifest, (self.case/'manifest.json').read_bytes())
        mapping = json.loads((self.output/'data/EXPORT_MANIFEST.json').read_text())
        entry = mapping['metadata_projections'][0]
        self.assertEqual(hashlib.sha256(original_manifest).hexdigest(), entry['original_sha256'])
        self.assertTrue(entry['changes'][0]['json_pointer'])
        with zipfile.ZipFile(self.output/'R6_PUBLIC_EVIDENCE.zip') as archive:
            names = archive.namelist()
            self.assertFalse(any('_runtime' in name or 'rules.json' in name or 'private.pem' in name for name in names))
            self.assertEqual(self.raw, archive.read('cases/base/I01__P/wire/instance.jsonl'))

    def test_private_jwk_refused_before_copy(self):
        (self.case/'fixtures.json').write_text(json.dumps({'kty':'EC','d':'private-scalar'}))
        with self.assertRaises(ValueError):
            exporter.export(self.run, self.output)
        self.assertFalse((self.output/'data/cases/base/I01__P/fixtures.json').exists())
        self.assertFalse((self.output/'R6_PUBLIC_EVIDENCE.zip').exists())
        self.assertEqual('EXPORT_FAILED', json.loads((self.output/'SAFE_EXPORT.json').read_text())['status'])

    def test_raw_private_path_is_rejected_and_never_redacted(self):
        private_raw = b'{"frame":{"private_path":"C:/Users/private-account/key.pem"}}\n'
        (self.case/'wire/instance.jsonl').write_bytes(private_raw)
        with self.assertRaises(ValueError):
            exporter.export(self.run, self.output)
        self.assertFalse((self.output/'data/cases/base/I01__P/wire/instance.jsonl').exists())
        self.assertEqual(private_raw, (self.case/'wire/instance.jsonl').read_bytes())

    def test_receipts_only_never_claims_campaign(self):
        empty_run = self.run.parent/'no-campaign'
        empty_run.mkdir()
        (empty_run/'BOOTSTRAP.json').write_text(json.dumps({'status':'FAIL','runtime_directory':'C:/private/runtime'}))
        report = exporter.export(empty_run, self.output)
        self.assertEqual('RECEIPTS_ONLY_NO_CAMPAIGN', report['status'])
        self.assertFalse(json.loads((self.output/'data/EXPORT_MANIFEST.json').read_text())['campaign_present'])

    def test_loaded_identity_metadata_projects_without_editing_source(self):
        observed = {'connections':[{'loaded':{'entry':{'path':'file:///home/private/client.ts', 'sha256':'a'*64}}}], 'steps':{}}
        source = json.dumps(observed).encode()
        (self.case/'observation.json').write_bytes(source)
        exporter.export(self.run, self.output)
        projected = json.loads((self.output/'data/cases/base/I01__P/observation.json').read_text())
        self.assertEqual('a'*64, projected['connections'][0]['loaded']['entry']['sha256'])
        self.assertNotIn('/home/private', projected['connections'][0]['loaded']['entry']['path'])
        self.assertEqual(source, (self.case/'observation.json').read_bytes())

    def test_business_input_path_never_projects_as_metadata(self):
        observed = {'steps':{'call':{'request':{'params':{'label':'C:/Users/private-account/key.pem'}}}}}
        source = json.dumps(observed).encode()
        (self.case/'observation.json').write_bytes(source)
        with self.assertRaises(ValueError):
            exporter.export(self.run, self.output)
        self.assertEqual(source, (self.case/'observation.json').read_bytes())
        self.assertFalse((self.output/'data/cases/base/I01__P/observation.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
