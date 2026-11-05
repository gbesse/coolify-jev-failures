import unittest
from app import open_state,accept,queue_health
class QueueHealthTests(unittest.TestCase):
 def test_delayed_retry_and_ready(self):
  with open_state(':memory:')as db:
   for uid in ['a','b']:accept(dict(event='deployment_failed',success=False,deployment_uuid=uid),db)
   db.execute("UPDATE events SET attempts=2,next_attempt_at=20 WHERE uuid='a'");db.commit();x=queue_health(db,now=10);self.assertEqual((x['due'],x['delayed'],x['attempts']),(1,1,2));self.assertFalse(x['contains_log_text'])
 def test_empty(self):
  with open_state(':memory:')as db:self.assertIsNone(queue_health(db,now=0)['next_pending_at'])
