#!/usr/bin/env python3
"""Demo backends for the gateway demo.

  :9100  /v1/query          mock read-only data API
  :9200  /v1/chat/completions  LLM sidecar: mock reply, or forward to
                               DeepSeek when DEEPSEEK_API_KEY is set.
"""

import http.server
import json
import os
import socketserver
import threading
import urllib.request

DEEPSEEK_KEY = os.environ.get("DEEPSEEK_API_KEY", "")


class DataHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/v1/query"):
            body = json.dumps({
                "ok": True,
                "rows": [
                    {"id": 1, "name": "Acme", "tenant_id": "org-a"},
                    {"id": 2, "name": "Beta", "tenant_id": "org-a"},
                ],
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


class ChatHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(ln) or b"{}")
        if DEEPSEEK_KEY:
            url = "https://api.deepseek.com/v1/chat/completions"
            data = json.dumps({
                "model": req.get("model", "deepseek-chat"),
                "messages": req.get("messages", [{"role": "user", "content": "hi"}]),
            }).encode()
            r = urllib.request.Request(
                url, data=data, method="POST",
                headers={"Authorization": "Bearer " + DEEPSEEK_KEY,
                         "Content-Type": "application/json"})
            with urllib.request.urlopen(r, timeout=60) as resp:
                payload = json.load(resp)
        else:
            payload = {
                "id": "demo-1",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant",
                                "content": "mock reply from LLM sidecar"},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 5, "completion_tokens": 7,
                          "total_tokens": 12},
            }
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def serve(port, handler):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"backend {handler.__name__} on :{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    t1 = threading.Thread(target=serve, args=(9100, DataHandler), daemon=True)
    t2 = threading.Thread(target=serve, args=(9200, ChatHandler), daemon=True)
    t1.start()
    t2.start()
    t1.join()
