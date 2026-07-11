"""
webhoneypot — a self-written low-interaction HTTP honeypot.

Unlike the off-the-shelf sensors (Cowrie, Dionaea), this one is built from
scratch for this project. It presents believable decoy pages for the paths
scanners hammer (WordPress, phpMyAdmin, admin panels, exposed .env / .git) and
records every request as newline-delimited JSON that the analytics pipeline
tails — the same contract Cowrie uses.

What it captures per request: source IP, method, path + query, User-Agent,
Referer, any submitted credentials (form bodies and HTTP Basic auth), and a
coarse classification (recon / credential-harvest / exploit / scanner-tool).

It only ever returns canned responses and never makes an outbound request, so
it has no proxy/SSRF surface. For authorised research and education only.
"""
from __future__ import annotations
import json
import os
import re
import sys
import threading
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = os.getenv("WEBTRAP_LOG", "/logs/webtrap/webtrap.json")
BIND_PORT = int(os.getenv("WEBTRAP_PORT", "80"))
SERVER_BANNER = os.getenv("WEBTRAP_BANNER", "Apache/2.4.41 (Ubuntu)")

# paths that only a scanner/attacker would request — high signal
SENSITIVE = (
    "/.env", "/.git", "/wp-login", "/wp-admin", "/xmlrpc.php", "/phpmyadmin",
    "/pma", "/admin", "/administrator", "/manager/html", "/.aws", "/.ssh",
    "/config", "/shell", "/cgi-bin", "/boaform", "/solr", "/actuator",
    "/.well-known/security.txt", "/vendor/phpunit", "/owa",
)
# tokens that indicate an automated scanner / attack tool in the UA
SCANNER_UA = (
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "hydra", "gobuster",
    "dirbuster", "wpscan", "python-requests", "curl", "go-http-client", "libwww",
    "censys", "zmeu", "l9explore",
)
# obvious exploit / traversal / RCE signatures in path or body
EXPLOIT = re.compile(
    r"\.\./|/etc/passwd|union\s+select|<\?php|\$\{jndi:|/bin/sh|cmd\.exe|"
    r"base64_decode|wget\s|curl\s|;\s*id;|%00", re.I)

CRED_FIELDS = ("username", "user", "usr", "login", "log", "email",
               "password", "pass", "pwd", "passwd", "pw")

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write(event: dict) -> None:
    line = json.dumps(event, ensure_ascii=False)
    with _lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def _extract_creds(body: str, headers) -> tuple[str | None, str | None]:
    user = pwd = None
    # HTTP Basic auth
    auth = headers.get("Authorization", "")
    if auth.startswith("Basic "):
        import base64
        try:
            dec = base64.b64decode(auth[6:]).decode("utf-8", "replace")
            if ":" in dec:
                user, pwd = dec.split(":", 1)
        except Exception:
            pass
    # form-encoded body
    if body:
        try:
            fields = urllib.parse.parse_qs(body, keep_blank_values=True)
            flat = {k.lower(): v[0] for k, v in fields.items() if v}
            for k, v in flat.items():
                if any(t in k for t in ("user", "login", "log", "email", "usr")) and not user:
                    user = v
                if any(t in k for t in ("pass", "pwd", "pw")) and not pwd:
                    pwd = v
        except Exception:
            pass
    return user, pwd


PAGES = {
    "wp-login": """<!doctype html><html><head><title>Log In &lsaquo; WordPress</title></head>
<body class="login"><form name="loginform" action="/wp-login.php" method="post">
<p><label>Username<br><input type="text" name="log"></label></p>
<p><label>Password<br><input type="password" name="pwd"></label></p>
<p><input type="submit" value="Log In"></p></form></body></html>""",
    "admin": """<!doctype html><html><head><title>Admin Login</title></head>
<body><h2>Administrator Login</h2><form method="post" action="/admin/login">
Username: <input name="username"><br>Password: <input type="password" name="password"><br>
<button>Sign in</button></form></body></html>""",
    "phpmyadmin": """<!doctype html><html><head><title>phpMyAdmin</title></head>
<body><h1>phpMyAdmin</h1><form method="post" action="/phpmyadmin/index.php">
<input name="pma_username" placeholder="Username">
<input name="pma_password" type="password" placeholder="Password">
<input type="submit" value="Go"></form></body></html>""",
    "env": "APP_ENV=production\nAPP_KEY=base64:REDACTED\nDB_HOST=127.0.0.1\n"
           "DB_DATABASE=app\nDB_USERNAME=app_user\nDB_PASSWORD=changeme\n",
    "git": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
           "[remote \"origin\"]\n\turl = git@github.com:example/app.git\n",
}


def _body_and_status(path: str) -> tuple[bytes, int, str]:
    low = path.lower()
    if "wp-login" in low or "wp-admin" in low:
        return PAGES["wp-login"].encode(), 200, "text/html"
    if "phpmyadmin" in low or "/pma" in low:
        return PAGES["phpmyadmin"].encode(), 200, "text/html"
    if "/admin" in low or "administrator" in low:
        return PAGES["admin"].encode(), 200, "text/html"
    if low.endswith("/.env") or "/.env" in low:
        return PAGES["env"].encode(), 200, "text/plain"
    if "/.git" in low:
        return PAGES["git"].encode(), 200, "text/plain"
    if low in ("/", "/index.html"):
        return b"<html><body><h1>It works!</h1></body></html>", 200, "text/html"
    return b"<html><head><title>404 Not Found</title></head><body>"\
           b"<h1>Not Found</h1></body></html>", 404, "text/html"


def classify(path: str, ua: str, body: str, user, pwd) -> str:
    blob = f"{path} {body}"
    if EXPLOIT.search(blob):
        return "exploit"
    if user is not None or pwd is not None:
        return "credential"
    if any(t in ua.lower() for t in SCANNER_UA):
        return "scanner"
    if any(path.lower().startswith(p) or p in path.lower() for p in SENSITIVE):
        return "recon"
    return "request"


class Handler(BaseHTTPRequestHandler):
    server_version = "webtrap"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):        # silence default stderr logging
        pass

    def _handle(self, method: str):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        body = ""
        if 0 < length <= 65536:
            try:
                body = self.rfile.read(length).decode("utf-8", "replace")
            except Exception:
                body = ""
        parsed = urllib.parse.urlsplit(self.path)
        ua = self.headers.get("User-Agent", "")
        user, pwd = _extract_creds(body, self.headers)
        kind = classify(self.path, ua, body, user, pwd)

        event = {
            "timestamp": _now(),
            "eventid": f"webtrap.{kind}",
            "src_ip": self.client_address[0],
            "src_port": self.client_address[1],
            "method": method,
            "path": parsed.path[:512],
            "query": parsed.query[:512],
            "user_agent": ua[:512],
            "referer": self.headers.get("Referer", "")[:512],
            "username": user,
            "password": pwd,
            "kind": kind,
        }
        try:
            _write(event)
        except Exception:
            pass

        payload, status, ctype = _body_and_status(parsed.path)
        try:
            self.send_response(status)
            self.send_header("Server", SERVER_BANNER)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        except Exception:
            pass

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_HEAD(self):
        self._handle("HEAD")

    def do_PUT(self):
        self._handle("PUT")


def main() -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    # touch the log so the collector's tail can open it immediately
    open(LOG_PATH, "a", encoding="utf-8").close()
    httpd = ThreadingHTTPServer(("0.0.0.0", BIND_PORT), Handler)
    print(f"webhoneypot listening on :{BIND_PORT}, logging to {LOG_PATH}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
