"""Evidence-resource regression, separate from all frozen R6 scenario counts."""
from contextlib import closing
import gc
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True
from common import backup, quiesce, tables


class EvidenceConnections(unittest.TestCase):
    def test_no_gc_needed_to_close_readers_and_backup(self):
        was_enabled = gc.isenabled()
        gc.disable()
        try:
            with tempfile.TemporaryDirectory(prefix="r6-connection-regression-") as directory:
                source = Path(directory) / "source.sqlite"
                target = Path(directory) / "snapshot.sqlite"
                with closing(sqlite3.connect(source)) as writer:
                    writer.execute("PRAGMA journal_mode=WAL")
                    writer.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
                    writer.execute("INSERT INTO evidence VALUES ('durable')")
                    writer.commit()
                    self.assertEqual(tables(source), {"evidence": [{"value": "durable"}]})
                    backup(source, target)
                # The last writer can checkpoint/unlink its WAL because neither
                # evidence helper leaves a live readonly connection behind.
                wal = Path(str(source) + "-wal")
                self.assertFalse(wal.exists() and wal.stat().st_size)
                self.assertEqual(tables(target, immutable=True), {"evidence": [{"value": "durable"}]})
                self.assertTrue(quiesce(source)["base_tables_unchanged"])
                self.assertEqual(tables(source, immutable=True), tables(target, immutable=True))
                self.assertFalse(any(Path(str(path) + suffix).exists()
                    for path in (source, target) for suffix in ("-wal", "-shm")))
        finally:
            if was_enabled:
                gc.enable()


if __name__ == "__main__":
    unittest.main()
