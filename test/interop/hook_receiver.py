"""A webhook receiver for the interop test (ADR 0010).

It checks every delivery as docs/hooks.md tells receivers to (the signature
over the raw body, compared in constant time; the timestamp; a delivery ID
seen before) and appends one JSON line per request to OUT_FILE, with "ok"
telling whether the request passed. It writes its port to PORT_FILE.

Usage: hook_receiver.py SECRET_FILE PORT_FILE OUT_FILE
"""

import hashlib
import hmac
import http.server
import json
import os
import sys
import threading
import time

secret = open(sys.argv[1], "rb").read().strip()
port_file, out_file = sys.argv[2], sys.argv[3]
seen = set()
lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        delivery = self.headers.get("X-Gosftpd-Delivery", "")
        timestamp = self.headers.get("X-Gosftpd-Timestamp", "0")
        mac = hmac.new(secret, f"{delivery}.{timestamp}.".encode() + body, hashlib.sha256)
        signed = hmac.compare_digest("sha256=" + mac.hexdigest(), self.headers.get("X-Gosftpd-Signature", ""))
        fresh = abs(time.time() - int(timestamp)) <= 300
        with lock:
            new = delivery not in seen
            seen.add(delivery)
            record = {
                "ok": signed and fresh and new,
                "event": self.headers.get("X-Gosftpd-Event"),
                "delivery": delivery,
                "user_agent": self.headers.get("User-Agent"),
                "url_path": self.path,
                "body": json.loads(body),
            }
            with open(out_file, "a") as f:
                f.write(json.dumps(record) + "\n")
        self.send_response(204 if record["ok"] else 401)
        self.end_headers()

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(port_file + ".tmp", "w") as f:
    f.write(str(server.server_address[1]))
os.replace(port_file + ".tmp", port_file)
server.serve_forever()
