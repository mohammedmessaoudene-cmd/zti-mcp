"""Runtime attribution sensitivity checks using temporary source maps, not H/M."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('r6_runtime_receipt_test', Path(__file__).resolve().parents[2]/'runtime_receipt.py')
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)


class RuntimeReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.site = Path(self.temp.name)/'site-packages'
        self.root = self.site/'zti_mcp_r6'
        self.root.mkdir(parents=True)
        (self.root/'__init__.py').write_text('# package\n')
        (self.root/'core.py').write_text('# core\n')
        self.expected = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.glob('*.py')}

    def test_closed_file_set_and_changed_bytes_are_rejected(self):
        self.assertEqual(self.expected, receipt.source_tree(self.root, self.expected))
        (self.root/'unexpected.py').write_text('# extra source\n')
        with self.assertRaises(ValueError):
            receipt.source_tree(self.root, self.expected)
        (self.root/'unexpected.py').unlink()
        (self.root/'core.py').write_text('# modified bytes\n')
        with self.assertRaises(ValueError):
            receipt.source_tree(self.root, self.expected)

    def test_editable_installation_rejected(self):
        module = SimpleNamespace(__name__='zti_mcp_r6', __file__=str(self.root/'__init__.py'), __path__=[str(self.root)])
        site = self.site
        class Distribution:
            def locate_file(self, name):
                return site/name
            def read_text(self, name):
                return json.dumps({'dir_info':{'editable':True}, 'url':'file:///fictional-source'})
        with self.assertRaises(ValueError):
            receipt.ordinary_install(module, Distribution(), {self.site})

    def test_manifest_path_escape_rejected(self):
        prefix = 'successor/r6/provider/src/zti_mcp_r6/'
        mapping = {prefix+name:digest for name,digest in self.expected.items()}
        self.assertEqual(self.expected, receipt.expected_tree(mapping, prefix))
        mapping[prefix+'../outside.py'] = '0'*64
        with self.assertRaises(ValueError):
            receipt.expected_tree(mapping, prefix)


if __name__ == '__main__':
    unittest.main(verbosity=2)
