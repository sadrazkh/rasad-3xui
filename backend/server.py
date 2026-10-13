"""Rasad HTTP service. Python 3.10+, no third-party application dependencies."""
import argparse
import hashlib
import hmac
import json
import mimetypes
import os
from pathlib import Path
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from core import Store, Collector

ROOT = Path(__file__).resolve().parent.parent


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return f"scrypt${salt}${digest}"


def password_ok(password, encoded):
    try:
        _, salt, _ = encoded.split("$")
        return hmac.compare_digest(password_hash(password, salt), encoded)
    except (ValueError, TypeError):
        return False


class App:
    def __init__(self, config, store, collector=None):
        self.config, self.store, self.collector = config, store, collector
        self.sessions, self.failures = {}, {}
        self.lock = threading.Lock()
        self.secure = config["public_origin"].startswith("https://")

    def session(self, cookie):
        try:
            jar = SimpleCookie(cookie or "")
            token = jar["rasad_session"].value
        except (KeyError, ValueError):
            return None
        with self.lock:
            s = self.sessions.get(token)
            if s and s["expiry"] > time.time():
                return s
            self.sessions.pop(token, None)
        return None


def handler_for(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Rasad"

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass  # no per-request logs containing user identities

        def respond(self, code, data, content_type="application/json; charset=utf-8", cookie=None):
            payload = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store" if self.path.startswith("/api") else "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(payload)

        def json_body(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 16384:
                raise ValueError("invalid_body")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("invalid_body")
            return data

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/api/health":
                self.respond(200, {"ok": True})
                return
            if path == "/runtime.json":
                self.respond(200, {"mode": "live"})
                return
            if path.startswith("/api/"):
                session = app.session(self.headers.get("Cookie"))
                if not session:
                    self.respond(401, {"error": "unauthorized"})
                    return
                if path == "/api/session":
                    self.respond(200, {"csrf": session["csrf"], "username": app.config["admin_username"]})
                elif path == "/api/report":
                    args = parse_qs(urlsplit(self.path).query)
                    period = args.get("period", ["today"])[0]
                    if period not in ("today", "yesterday", "week", "month"):
                        self.respond(400, {"error": "invalid_period"})
                        return
                    email = args.get("email", [None])[0]
                    self.respond(200, app.store.report(period, email))
                else:
                    self.respond(404, {"error": "not_found"})
                return
            file = (ROOT / "dist" / ("index.html" if path == "/" else path.lstrip("/"))).resolve()
            if not file.is_relative_to((ROOT / "dist").resolve()) or not file.is_file():
                self.respond(404, {"error": "not_found"})
                return
            self.respond(200, file.read_bytes(), mimetypes.guess_type(file)[0] or "application/octet-stream")

        def do_POST(self):
            path = urlsplit(self.path).path
            try:
                # Exact configured origin, never trust arbitrary forwarded headers.
                if self.headers.get("Origin") != app.config["public_origin"].rstrip("/"):
                    self.respond(403, {"error": "origin_rejected"})
                    return
                data = self.json_body()
                if path == "/api/login":
                    ip = self.client_address[0]
                    with app.lock:
                        app.failures = {k: v for k, v in app.failures.items() if v[1] > time.time()}
                        failures, until = app.failures.get(ip, (0, time.time() + 300))
                    if failures >= 8:
                        self.respond(429, {"error": "too_many_attempts"})
                        return
                    username, password = data.get("username", ""), data.get("password", "")
                    if not isinstance(username, str) or not isinstance(password, str) or len(password) > 512:
                        raise ValueError("invalid_body")
                    valid_password = password_ok(password, app.config["admin_password_hash"])
                    if not hmac.compare_digest(username.encode(), app.config["admin_username"].encode()) or not valid_password:
                        with app.lock:
                            app.failures[ip] = (failures + 1, until)
                        self.respond(401, {"error": "invalid_credentials"})
                        return
                    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
                    with app.lock:
                        app.sessions = {k: v for k, v in app.sessions.items() if v["expiry"] > time.time()}
                        if len(app.sessions) > 100:
                            app.sessions.clear()
                        app.sessions[token] = {"csrf": csrf, "expiry": time.time() + 43200}
                        app.failures.pop(ip, None)
                    cookie = f"rasad_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200" + ("; Secure" if app.secure else "")
                    self.respond(200, {"csrf": csrf, "username": username}, cookie=cookie)
                    return
                session = app.session(self.headers.get("Cookie"))
                if not session:
                    self.respond(401, {"error": "unauthorized"})
                    return
                if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
                    self.respond(403, {"error": "csrf_rejected"})
                    return
                if path == "/api/settings":
                    app.store.settings(data)
                elif path == "/api/monitor":
                    if type(data.get("enabled")) is not bool or not isinstance(data.get("email"), str):
                        raise ValueError("invalid_body")
                    app.store.set_user(data["email"], data["enabled"])
                elif path == "/api/monitor-all":
                    if type(data.get("enabled")) is not bool:
                        raise ValueError("invalid_body")
                    app.store.bulk(data["enabled"])
                elif path == "/api/logout":
                    with app.lock:
                        for token, s in list(app.sessions.items()):
                            if s is session:
                                del app.sessions[token]
                    self.respond(200, {"ok": True}, cookie="rasad_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
                    return
                else:
                    self.respond(404, {"error": "not_found"})
                    return
                if app.collector:
                    app.collector.metrics.write_policy()
                self.respond(200, {"ok": True})
            except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
                self.respond(400, {"error": "invalid_request"})
            except Exception:
                self.respond(500, {"error": "internal_error"})

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=os.environ.get("RASAD_CONFIG", "/etc/rasad/config.json"))
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    origin = urlsplit(config["public_origin"])
    if origin.scheme not in ("http", "https") or not origin.hostname or origin.path not in ("", "/") or origin.query or origin.fragment:
        raise ValueError("public_origin must be an HTTP(S) origin without a path")
    if not config.get("admin_password_hash", "").startswith("scrypt$"):
        raise ValueError("Set the admin password with configure.py")
    db_path = Path(config.get("database", "/var/lib/rasad/rasad.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = Store(str(db_path), config.get("timezone", "Asia/Tehran"))
    collector = Collector(store, config)
    app = App(config, store, collector)
    server = ThreadingHTTPServer((config.get("listen", "127.0.0.1"), int(config.get("port", 8787))), handler_for(app))
    collector.start()
    print("Rasad listening on port", server.server_port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        collector.stop_event.set()
        server.server_close()


if __name__ == "__main__":
    main()
