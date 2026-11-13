import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from alert_resume import resume_point


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'alerts.json'
        self.path.write_text('{"id":"old"}\n',encoding='utf-8')
        self.cursor=Path(self.temp.name)/'cursor.json'
        stat=self.path.stat()
        self.state=dict(path=str(self.path),inode=stat.st_ino,device=stat.st_dev,offset=stat.st_size,already_processed_ids=['old'])

    def tearDown(self):
        self.temp.cleanup()

    def read(self,state):
        self.cursor.write_text(json.dumps(state),encoding='utf-8')
        with patch.dict(os.environ,{'SOC_ALERT_RESUME_FILE':str(self.cursor)}),self.path.open(encoding='utf-8') as stream:
            offset,ids=resume_point(stream,str(self.path))
            stream.seek(offset)
            return stream.read(),ids

    def test_cutover_records_are_read_from_exact_boundary(self):
        with self.path.open('a',encoding='utf-8') as stream: stream.write('{"id":"cutover"}\n')
        text,ids=self.read(self.state)
        self.assertIn('cutover',text)
        self.assertNotIn('old',text)
        self.assertEqual(ids,{'old'})

    def test_wrong_or_truncated_file_fails_closed(self):
        for change in [{'inode':-1},{'device':-1},{'offset':9999},{'offset':-1},{'offset':3},{'path':str(self.path)+'other'}]:
            with self.assertRaises(ValueError): self.read({**self.state,**change})

    def test_default_still_starts_at_eof(self):
        with patch.dict(os.environ,{'SOC_ALERT_RESUME_FILE':''}),self.path.open(encoding='utf-8') as stream:
            offset,ids=resume_point(stream,str(self.path))
        self.assertEqual(offset,self.path.stat().st_size)
        self.assertFalse(ids)
