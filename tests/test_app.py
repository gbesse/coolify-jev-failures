import io
import json
import tempfile
import unittest
from pathlib import Path

from app import accept, fetch_deployment, first_failure, make_app, open_state, work_once
from jev import normalize


class CoolifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = str(Path(self.tmp.name) / "events.sqlite")
        with open("examples/policy.json", encoding="utf-8") as source:
            self.policy = json.load(source)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ingest_is_durable_and_idempotent(self):
        event = {"event": "deployment_failed", "success": False,
                 "deployment_uuid": "abc-123", "application_name": "shop"}
        payload = json.dumps(event).encode()
        app = make_app(self.state, "0123456789abcdef")
        for _ in range(2):
            status = []
            environ = {"REQUEST_METHOD": "POST", "PATH_INFO": "/webhook/0123456789abcdef",
                       "CONTENT_LENGTH": str(len(payload)), "wsgi.input": io.BytesIO(payload)}
            b"".join(app(environ, lambda code, headers: status.append(code)))
            self.assertEqual(status[0], "202 Accepted")
        with open_state(self.state) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)

    def test_worker_classifies_first_error_and_keeps_only_decision(self):
        with open_state(self.state) as db:
            accept({"event": "deployment_failed", "success": False,
                    "deployment_uuid": "abc-123"}, db)
            result = work_once(db, self.policy,
                               lambda _: normalize("image", 0.96, self.policy),
                               lambda _: {"deployment_uuid": "abc-123", "logs": "Error: image not found\nError: later failure"})
            self.assertEqual(result["outcome"], "image")
            self.assertEqual(db.execute("SELECT status FROM events").fetchone()[0], "done")
            self.assertIsNone(work_once(db, self.policy, lambda _: None, lambda _: None))

    def test_redaction(self):
        line = first_failure("Error token=supersecret Authorization: Bearer abc.def failed")
        self.assertNotIn("supersecret", line)
        self.assertNotIn("abc.def", line)

    def test_fetch_uses_deployment_uuid_endpoint(self):
        requests = []
        def open_response(request, timeout):
            requests.append(request)
            return io.BytesIO(b'{"deployment_uuid":"abc-123","logs":"Error: failed"}')
        result = fetch_deployment("https://coolify.example.org", "fake-token", "abc-123",
                                  opener=open_response)
        self.assertEqual(result["deployment_uuid"], "abc-123")
        self.assertEqual(requests[0].full_url,
                         "https://coolify.example.org/api/v1/deployments/abc-123")


if __name__ == "__main__":
    unittest.main()
