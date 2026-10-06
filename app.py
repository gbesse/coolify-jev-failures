"""Queue Coolify deployment failures and classify the first useful error line."""
import argparse
from contextlib import contextmanager
import hmac
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from wsgiref.simple_server import WSGIRequestHandler, make_server

from jev import evaluate, fixture_evaluator

MAX_BODY = 1024 * 1024
UUID = re.compile(r"^[A-Za-z0-9-]{1,100}$")
ERROR = re.compile(r"\b(error|failed|failure|exception|denied|refused|not found)\b", re.I)
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SECRET = re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+")
BEARER = re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]+")


def validate_origin(origin):
    parsed = urlsplit(origin)
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or parsed.scheme not in ("http", "https")
            or (parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"))):
        raise ValueError("invalid_coolify_origin")
    return origin.rstrip("/")


@contextmanager
def open_state(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE IF NOT EXISTS events (uuid TEXT PRIMARY KEY, app_name TEXT NOT NULL, environment TEXT NOT NULL, status TEXT NOT NULL, outcome TEXT, choice TEXT, probability REAL, policy_version TEXT, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0)")
    try:
        yield db
    finally:
        db.close()


def accept(event, db):
    if not isinstance(event, dict) or not isinstance(event.get("event"), str):
        raise ValueError("invalid_event")
    if event["event"] != "deployment_failed":
        return "ignored"
    uuid = event.get("deployment_uuid")
    if not isinstance(uuid, str) or not UUID.fullmatch(uuid) or event.get("success") is not False:
        raise ValueError("invalid_deployment")
    app_name = event.get("application_name") or "unknown"
    environment = event.get("environment") or "unknown"
    if not isinstance(app_name, str) or not isinstance(environment, str):
        raise ValueError("invalid_deployment")
    db.execute("INSERT OR IGNORE INTO events(uuid,app_name,environment,status) VALUES(?,?,?,'pending')",
               (uuid, app_name[:100], environment[:100]))
    db.commit()
    return "accepted"


def first_failure(logs):
    if not isinstance(logs, str):
        raise ValueError("invalid_logs")
    for raw_line in logs.splitlines():
        line = ANSI.sub("", raw_line).strip()
        if ERROR.search(line):
            line = SECRET.sub(lambda m: m.group(1) + "=[REDACTED]", line)
            line = BEARER.sub("Bearer [REDACTED]", line)
            return line[:4000]
    return "No explicit error line found in deployment logs."


def fetch_deployment(origin, token, uuid, *, opener=urlopen):
    if not UUID.fullmatch(uuid) or not token:
        raise ValueError("invalid_request")
    request = Request(validate_origin(origin) + "/api/v1/deployments/" + uuid,
                      headers={"Authorization": "Bearer " + token,
                               "Accept": "application/json"})
    with opener(request, timeout=15) as response:
        result = json.load(response)
    if not isinstance(result, dict) or result.get("deployment_uuid") != uuid:
        raise ValueError("deployment_mismatch")
    return result


def work_once(db, policy, judge, fetch, *, now=None):
    now = time.time() if now is None else now
    row = db.execute("SELECT uuid,app_name,environment,attempts FROM events WHERE status='pending' AND next_attempt_at<=? ORDER BY rowid LIMIT 1", (now,)).fetchone()
    if row is None:
        return None
    uuid, app_name, environment, attempts = row
    try:
        deployment = fetch(uuid)
        signal = first_failure(deployment.get("logs"))
        result = judge("Application: " + app_name + "\nEnvironment: " + environment + "\nFirst failure: " + signal)
    except Exception:
        db.execute("UPDATE events SET attempts=attempts+1,next_attempt_at=? WHERE uuid=?",
                   (now + min(300, 2 ** min(attempts + 1, 8)), uuid))
        db.commit()
        raise
    db.execute("UPDATE events SET status='done',choice=?,outcome=?,probability=?,policy_version=?,attempts=attempts+1 WHERE uuid=?",
               (result["choice"], result["outcome"], result["probability"], result["policy_version"], uuid))
    db.commit()
    return {"deployment_uuid": uuid, "application_name": app_name, "environment": environment,
            **result}


def make_app(state_path, secret):
    if not isinstance(secret, str) or len(secret) < 16 or "/" in secret:
        raise ValueError("invalid_webhook_secret")

    def app(environ, start_response):
        path = environ.get("PATH_INFO", "")
        if environ.get("REQUEST_METHOD") != "POST" or not hmac.compare_digest(path, "/webhook/" + secret):
            start_response("404 Not Found", [("Content-Type", "application/json")]); return [b"{}"]
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            length = -1
        if length < 1 or length > MAX_BODY:
            start_response("413 Payload Too Large", [("Content-Type", "application/json")]); return [b"{}"]
        try:
            event = json.loads(environ["wsgi.input"].read(length))
            with open_state(state_path) as db:
                status = accept(event, db)
        except (json.JSONDecodeError, ValueError):
            start_response("400 Bad Request", [("Content-Type", "application/json")]); return [b"{}"]
        except Exception:
            start_response("503 Service Unavailable", [("Content-Type", "application/json")]); return [b"{}"]
        body = json.dumps({"status": status}).encode()
        start_response("202 Accepted", [("Content-Type", "application/json"),
                                        ("Content-Length", str(len(body)))])
        return [body]
    return app


class QuietHandler(WSGIRequestHandler):
    def log_message(self, fmt, *args):
        pass  # The webhook URL contains a secret and must not appear in access logs.


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--demo", action="store_true")
    modes.add_argument("--serve", action="store_true")
    modes.add_argument("--worker", action="store_true")
    modes.add_argument("--results", action="store_true")
    parser.add_argument("--state", default=".local/events.sqlite")
    parser.add_argument("--fixtures")
    args = parser.parse_args()
    with open("examples/policy.json", encoding="utf-8") as source:
        policy = json.load(source)
    if args.demo:
        with open("examples/deployment.json", encoding="utf-8") as source:
            deployment = json.load(source)
        with open("examples/fixtures.json", encoding="utf-8") as source:
            fixtures = json.load(source)
        with open_state(":memory:") as db:
            accept({"event": "deployment_failed", "success": False,
                    "deployment_uuid": deployment["deployment_uuid"],
                    "application_name": "shop", "environment": "production"}, db)
            print(json.dumps(work_once(db, policy, fixture_evaluator(fixtures, policy),
                                       lambda _: deployment), indent=2))
        return
    if args.serve:
        app = make_app(args.state, os.environ["COOLIFY_WEBHOOK_SECRET"])
        with make_server("127.0.0.1", int(os.environ.get("PORT", "8092")),
                         app, handler_class=QuietHandler) as server:
            server.serve_forever()
        return
    if args.results:
        with open_state(args.state) as db:
            for row in db.execute("SELECT uuid,app_name,environment,choice,outcome,probability,policy_version FROM events WHERE status='done'"):
                print(json.dumps(dict(zip(("deployment_uuid","application_name","environment","choice","outcome","probability","policy_version"), row))))
        return
    if args.fixtures:
        with open(args.fixtures, encoding="utf-8") as source:
            judge = fixture_evaluator(json.load(source), policy)
    else:
        key = os.environ["TYPESAFE_API_KEY"]
        judge = lambda text: evaluate(text, policy, key)
    origin = validate_origin(os.environ["COOLIFY_ORIGIN"])
    token = os.environ["COOLIFY_API_TOKEN"]
    while True:
        try:
            with open_state(args.state) as db:
                result = work_once(db, policy, judge,
                                   lambda uuid: fetch_deployment(origin, token, uuid))
            if result is None:
                time.sleep(5)
        except Exception:
            time.sleep(15)


if __name__ == "__main__":
    main()
