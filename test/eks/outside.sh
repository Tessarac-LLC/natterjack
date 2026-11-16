#!/bin/bash
# "outside": answers from the internet side. GET / returns the caller's
# address; GET /stream?seconds=N writes "<address> <n>" every 200 ms for N
# seconds, so a test can tell whether a long connection survived; iperf3
# measures throughput.
set -euxo pipefail
dnf -y install iperf3
cat >/usr/local/bin/whoami.py <<'PY'
import http.server, socketserver, time, urllib.parse

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        addr = self.client_address[0]
        if u.path == "/stream":
            q = urllib.parse.parse_qs(u.query)
            seconds = min(int(q.get("seconds", ["60"])[0]), 3600)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "close")
            self.end_headers()
            for n in range(seconds * 5):
                self.wfile.write(f"{addr} {n}\n".encode())
                self.wfile.flush()
                time.sleep(0.2)
            return
        body = f"{addr}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

S(("0.0.0.0", 80), H).serve_forever()
PY
cat >/etc/systemd/system/whoami.service <<'UNIT'
[Unit]
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 -I /usr/local/bin/whoami.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/iperf3.service <<'UNIT'
[Unit]
After=network-online.target
[Service]
ExecStart=/usr/bin/iperf3 --server
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now whoami iperf3
touch /var/run/natterjack-e2e-ready
