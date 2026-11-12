import unittest,json,tempfile
from pathlib import Path
from app import open_state,accept,reschedule_pending
class Reschedule(unittest.TestCase):
 def test_pending_job_keeps_attempt_history(self):
  with tempfile.TemporaryDirectory()as tmp:
   with open_state(Path(tmp)/'state.db')as db:
    accept({'event':'deployment_failed','success':False,'deployment_uuid':'fixture-1'},db);db.execute("UPDATE events SET attempts=3,next_attempt_at=99999");db.commit();x=reschedule_pending(db,'fixture-1',now=100);self.assertTrue(x['rescheduled']);self.assertEqual(db.execute('SELECT attempts,next_attempt_at FROM events').fetchone(),(3,100));self.assertFalse(x['deployment_restarted'])
 def test_done_job_not_reopened(self):
  with tempfile.TemporaryDirectory()as tmp:
   with open_state(Path(tmp)/'state.db')as db:
    accept({'event':'deployment_failed','success':False,'deployment_uuid':'fixture-1'},db);db.execute("UPDATE events SET status='done'");db.commit();self.assertFalse(reschedule_pending(db,'fixture-1',now=100)['rescheduled'])
