import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('archive', Path(__file__).with_name('archive.py'))
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)


class ArchiveTest(unittest.TestCase):
    def test_duplicate_restart_retention_and_search(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            exporter = root/'export.py'
            exporter.write_text('import json,sys\njson.loads(sys.stdin.readline())\nprint('+repr(json.dumps({'cursor':'cursor-1','time':int(time.time()*1e6),'service':'openxdr-ha-server-1','container':'old-container','message':'incident completed'}))+')\n')
            config = {'sources':[{'name':'node','command':[sys.executable,str(exporter)]}]}
            path = root/'logs.sqlite'
            db = archive.open_db(path)
            archive.collect(db,config)
            db.close()
            db = archive.open_db(path)
            archive.collect(db,config)
            self.assertEqual(db.execute('SELECT count(*) FROM logs').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT cursor FROM cursors').fetchone()[0],'cursor-1')
            with db:
                db.execute('INSERT INTO logs VALUES (?,?,?,?,?,?)',('node','expired',0,'server','old','expired'))
            archive.collect(db,config)
            self.assertEqual(db.execute('SELECT count(*) FROM logs').fetchone()[0],1)
            db.close()

    def test_failure_preserves_cursor(self):
        with tempfile.TemporaryDirectory() as root:
            db = archive.open_db(Path(root)/'logs.sqlite')
            with db: db.execute('INSERT INTO cursors VALUES (?,?)',('node','before'))
            with self.assertRaises(RuntimeError): archive.collect(db,{'sources':[{'name':'node','command':[sys.executable,'-c','raise SystemExit(1)']}]})
            self.assertEqual(db.execute('SELECT cursor FROM cursors').fetchone()[0],'before')
            db.close()


if __name__ == '__main__':
    unittest.main()
