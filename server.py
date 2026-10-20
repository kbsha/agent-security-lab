"""Live demo server for the Trust, But Verify lab. Standard library only.

    python3 server.py            # then open http://localhost:8000
    python3 server.py --port 9000 --host 0.0.0.0
"""

import argparse
import itertools
import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from lab.agent import DEFAULT_TASK, run_agent
from lab.kb import KnowledgeBase, default_poison_text
from lab.llm import make_llm
from lab.scorecard import run_scorecard
from lab.tools import World

WEB = Path(__file__).parent / "web"
PACE = {"slow": 1.4, "normal": 0.7, "fast": 0.15}
APPROVAL_TIMEOUT = 120

state_lock = threading.Lock()
worlds = {"insecure": World(), "secure": World()}
poison = {"text": default_poison_text()}
runs = {}
run_ids = itertools.count(1)


class Run:
    def __init__(self):
        self.events = queue.Queue()
        self.approvals = {}  # call_id -> [threading.Event, decision]


def start_run(params: dict) -> str:
    mode = params.get("mode", "insecure")
    run_id = f"{mode}-{next(run_ids)}"
    run = runs[run_id] = Run()
    delay = PACE.get(params.get("pace", "normal"), 0.7)

    def emit(event):
        run.events.put(event)
        if event["type"] in {"think", "tool_call", "tool_result", "blocked"}:
            time.sleep(delay)

    def approver(call_id, name, args):
        waiter = run.approvals[call_id] = [threading.Event(), False]
        emit({"type": "approval_request", "call_id": call_id, "name": name, "args": args})
        if not waiter[0].wait(APPROVAL_TIMEOUT):
            emit({"type": "info", "text": "No decision within time limit: treated as denied."})
        return waiter[1]

    def work():
        try:
            with state_lock:
                world = worlds[mode] = World()
            llm = make_llm(params.get("provider", "mock"), params.get("base_url") or None, params.get("model") or None)
            kb = KnowledgeBase(include_poison=params.get("include_poison", True), poison_text=poison["text"])
            run_agent(mode, params.get("task") or DEFAULT_TASK, llm, kb, world, emit=emit, approver=approver)
        except Exception as exc:
            run.events.put({"type": "error", "text": f"{type(exc).__name__}: {exc}"})
        run.events.put({"type": "done"})

    threading.Thread(target=work, daemon=True).start()
    return run_id


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in {"/", "/index.html"}:
            body = (WEB / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/config":
            self._json({"task": DEFAULT_TASK, "poison": poison["text"], "default_poison": default_poison_text()})
        elif path == "/api/events":
            self._stream(self.path.split("run=")[-1])
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        data = self._body()
        if self.path == "/api/run":
            self._json({"run": start_run(data)})
        elif self.path == "/api/approve":
            run = runs.get(data.get("run"))
            waiter = run and run.approvals.get(data.get("call_id"))
            if not waiter:
                return self._json({"error": "no such approval"}, 404)
            waiter[1] = bool(data.get("approve"))
            waiter[0].set()
            self._json({"ok": True})
        elif self.path == "/api/poison":
            poison["text"] = data.get("text") or default_poison_text()
            self._json({"ok": True, "poison": poison["text"]})
        elif self.path == "/api/reset":
            with state_lock:
                worlds.update(insecure=World(), secure=World())
            self._json({"ok": True})
        elif self.path == "/api/scorecard":
            llm = make_llm(data.get("provider", "mock"), data.get("base_url") or None, data.get("model") or None)
            self._json(run_scorecard(llm, data.get("task") or DEFAULT_TASK, poison["text"]))
        else:
            self._json({"error": "not found"}, 404)

    def _stream(self, run_id):
        run = runs.get(run_id)
        if not run:
            return self._json({"error": "no such run"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        try:
            while True:
                try:
                    event = run.events.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    continue
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                self.wfile.flush()
                if event["type"] == "done":
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Trust, But Verify lab running at http://{'localhost' if args.host == '127.0.0.1' else args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
