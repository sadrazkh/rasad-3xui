"""Rasad: local, bounded, consent-scoped traffic accounting. No proxying."""
import datetime as dt
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from zoneinfo import ZoneInfo
from http.cookiejar import CookieJar
from urllib import request, parse, error

DEFAULTS = {"scope": "selected", "interval": 60, "retention": 7, "domains_enabled": False}

UNKNOWN_DESTINATION_SQL = "(instr(domain,'__unknown_')=1 OR instr(domain,'__overflow_')=1)"
DESTINATION_TOTALS_SQL = f"""COALESCE(SUM(up),0) measured_up,COALESCE(SUM(down),0) measured_down,
    COALESCE(SUM(n),0) connections,COUNT(*) records,
    COALESCE(SUM(CASE WHEN {UNKNOWN_DESTINATION_SQL} THEN up ELSE 0 END),0) unknown_up,
    COALESCE(SUM(CASE WHEN {UNKNOWN_DESTINATION_SQL} THEN down ELSE 0 END),0) unknown_down,
    COUNT(DISTINCT CASE WHEN NOT {UNKNOWN_DESTINATION_SQL} THEN domain END) supported_domains"""


def destination_summary(row, config_bytes=0):
    values = dict(row) if row is not None else {}
    summary = {key: int(values.get(key) or 0) for key in
               ("measured_up", "measured_down", "connections", "unknown_up", "unknown_down", "supported_domains")}
    summary["measured_bytes"] = summary["measured_up"] + summary["measured_down"]
    summary["unknown_bytes"] = summary["unknown_up"] + summary["unknown_down"]
    summary["supported_up"] = summary["measured_up"] - summary["unknown_up"]
    summary["supported_down"] = summary["measured_down"] - summary["unknown_down"]
    summary["supported_bytes"] = summary["supported_up"] + summary["supported_down"]
    summary["attribution_ratio"] = summary["supported_bytes"] / summary["measured_bytes"] if summary["measured_bytes"] else None
    summary["config_bytes"] = int(config_bytes)
    # These sources have different byte bases; this comparison is not coverage.
    summary["counter_ratio"] = summary["measured_bytes"] / config_bytes if config_bytes else None
    summary["has_measurements"] = bool(values.get("records"))
    return summary


class SameOriginRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = parse.urlsplit(req.full_url), parse.urlsplit(newurl)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise ValueError("panel_redirect_rejected")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def normalize(inbounds):
    """Only retain display/counter fields; never UUIDs, passwords or subscription URLs.
    New panels can attach a single client to multiple inbounds. Identical counters
    are de-duplicated; inconsistent counters for the same email fail closed.
    """
    result = {}
    for inbound in inbounds:
        settings = inbound.get("settings") or {}
        if isinstance(settings, str):
            settings = json.loads(settings)
        stats = {x["email"]: x for x in inbound.get("clientStats") or [] if x.get("email")}
        clients = {x["email"]: x for x in settings.get("clients", []) if x.get("email")}
        for email in stats.keys() | clients.keys():
            c, s = clients.get(email, {}), stats.get(email, {})
            # Missing counters are unknown, not a fabricated zero.
            item = {"email": email, "name": str(c.get("comment") or email)[:100],
                    "inbound": str(inbound.get("remark") or inbound.get("id", ""))[:100],
                    "protocol": str(inbound.get("protocol", "")),
                    "enabled": bool(c.get("enable", s.get("enable", True))),
                    "up": max(0, int(s["up"])) if "up" in s else None,
                    "down": max(0, int(s["down"])) if "down" in s else None,
                    "total": max(0, int(s.get("total", c.get("totalGB", 0)) or 0)),
                    "expiry": int(s.get("expiryTime", c.get("expiryTime", 0)) or 0)}
            if email in result:
                previous = result[email]
                if (previous["up"], previous["down"]) != (item["up"], item["down"]):
                    raise ValueError("duplicate_email_conflicting_counters")
                previous["inbound"] += " · " + item["inbound"]
            else:
                result[email] = item
    return list(result.values())


class Panel:
    def __init__(self, config):
        self.config = config
        self.base = config.get("panel_url", "").rstrip("/")
        u = parse.urlsplit(self.base)
        if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.query or u.fragment:
            raise ValueError("Invalid panel_url; include the panel web base path, without credentials")
        if u.scheme == "http" and u.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("Use HTTPS for a remote panel, or HTTP on loopback")
        self.opener = request.build_opener(request.ProxyHandler({}), SameOriginRedirect(), request.HTTPCookieProcessor(CookieJar()))
        self.csrf = ""
        self.logged = False
        self.bytes = 0
        self.calls = 0
        self.online_path = None
        self.list_path = None

    def raw(self, path, method="GET", data=None):
        headers = {"Accept": "application/json"}
        token = self.config.get("panel_token", "")
        if token:
            headers["Authorization"] = "Bearer " + token
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        body = parse.urlencode(data or {}).encode() if method == "POST" else None
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = request.Request(self.base + path, data=body, headers=headers, method=method)
        self.calls += 1
        with self.opener.open(req, timeout=8) as resp:
            if parse.urlsplit(resp.url).netloc != parse.urlsplit(self.base).netloc:
                raise ValueError("panel_redirect")
            payload = resp.read(8 * 1024 * 1024 + 1)
        if len(payload) > 8 * 1024 * 1024:
            raise ValueError("panel_payload_too_large")
        self.bytes += len(payload)
        obj = json.loads(payload)
        if obj.get("success") is False:
            # Do not forward upstream messages that may contain configuration.
            raise ValueError("panel_request_rejected")
        return obj.get("obj", obj)

    def login(self):
        if self.config.get("panel_token"):
            self.logged = True
            return
        self.raw("/login", "POST", {"username": self.config.get("panel_username", ""),
                                   "password": self.config.get("panel_password", "")})
        try:
            obj = self.raw("/csrf-token")
            self.csrf = (obj.get("token") or obj.get("csrfToken") or "") if isinstance(obj, dict) else str(obj)
        except (error.HTTPError, ValueError):
            self.csrf = ""  # legacy panels have no CSRF endpoint
        self.logged = True

    def call(self, path, method="GET"):
        if not self.logged:
            self.login()
        try:
            return self.raw(path, method)
        except (error.HTTPError, json.JSONDecodeError, ValueError) as exc:
            if not self.config.get("panel_token") and (
                isinstance(exc, (json.JSONDecodeError, ValueError)) or getattr(exc, "code", 0) in (401, 403)
            ):
                self.login()
                return self.raw(path, method)
            raise

    def snapshot(self):
        if self.list_path is None:
            try:
                inbounds = self.call("/panel/api/inbounds/list/slim")
                self.list_path = "/panel/api/inbounds/list/slim"
            except error.HTTPError as exc:
                if exc.code != 404:
                    raise
                self.list_path = "/panel/api/inbounds/list"
                inbounds = self.call(self.list_path)
        else:
            inbounds = self.call(self.list_path)
        users = normalize(inbounds)
        online = None
        paths = [self.online_path] if self.online_path else ["/panel/api/clients/onlines", "/panel/api/inbounds/onlines"]
        for path in paths:
            try:
                obj = self.call(path, "POST")
                if isinstance(obj, list):
                    online = set(obj)
                    self.online_path = path
                    break
            except (error.URLError, ValueError, TimeoutError):
                pass
        return users, online


class Store:
    def __init__(self, path, timezone="Asia/Tehran"):
        self.tz = ZoneInfo(timezone)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY,name TEXT,inbound TEXT,protocol TEXT,
          enabled INTEGER,online INTEGER,up INTEGER,down INTEGER,total INTEGER,expiry INTEGER,
          consent INTEGER DEFAULT 0,consent_at INTEGER,selected INTEGER DEFAULT 0,present INTEGER DEFAULT 1,ts INTEGER);
        CREATE TABLE IF NOT EXISTS traffic(email TEXT,bucket INTEGER,up INTEGER,down INTEGER,PRIMARY KEY(email,bucket));
        CREATE INDEX IF NOT EXISTS traffic_time ON traffic(bucket);
        CREATE TABLE IF NOT EXISTS domains(email TEXT,bucket INTEGER,domain TEXT,n INTEGER,last INTEGER,
          PRIMARY KEY(email,bucket,domain));
        CREATE INDEX IF NOT EXISTS domains_time ON domains(bucket);
        CREATE TABLE IF NOT EXISTS measured(email TEXT,bucket INTEGER,domain TEXT,up INTEGER,down INTEGER,n INTEGER,last INTEGER,
          PRIMARY KEY(email,bucket,domain));
        CREATE INDEX IF NOT EXISTS measured_time ON measured(bucket);
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,ts INTEGER,action TEXT,target TEXT);
        """)
        if "generation" not in {row[1] for row in self.db.execute("PRAGMA table_info(users)")}:
            self.db.execute("ALTER TABLE users ADD COLUMN generation INTEGER DEFAULT 0")
        if self.meta("settings") is None:
            self.put("settings", DEFAULTS)
        self.db.commit()

    def meta(self, key):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, json.dumps(value)))

    def log(self, action, target="server"):
        self.db.execute("INSERT INTO audit(ts,action,target) VALUES(?,?,?)", (int(time.time()), action, target))

    def invalidate_metrics(self, email=None):
        cursor = self.meta("metrics_cursor")
        if cursor:
            for field in ("rows", "first_seen", "last_seen"):
                cursor[field] = {key: value for key, value in cursor.get(field, {}).items()
                                 if email is not None and json.loads(key)[0] != email}
            self.put("metrics_cursor", cursor)

    def bucket(self, ts):
        return int(dt.datetime.fromtimestamp(ts, self.tz).replace(minute=0, second=0, microsecond=0).timestamp())

    def add_delta(self, email, start, end, up, down):
        # Distribute boundary-crossing samples uniformly. Counters are measured;
        # placement within a polling interval is an estimate, stated in the UI.
        cursor = start
        remaining_up, remaining_down = up, down
        while cursor < end:
            bucket = self.bucket(cursor)
            stop = min(end, bucket + 3600)
            if stop <= cursor:
                stop = end
            portion = (stop - cursor) / (end - start)
            u = remaining_up if stop == end else min(remaining_up, int(up * portion))
            d = remaining_down if stop == end else min(remaining_down, int(down * portion))
            self.db.execute("""INSERT INTO traffic VALUES(?,?,?,?) ON CONFLICT(email,bucket)
                DO UPDATE SET up=up+excluded.up,down=down+excluded.down""", (email, bucket, u, d))
            remaining_up -= u
            remaining_down -= d
            cursor = stop

    def ingest(self, users, online, now=None):
        now = int(time.time() if now is None else now)
        with self.lock, self.db:
            # Remember the actual prior presence before resetting this snapshot.
            # A removed email may later be assigned to a different person.
            previously_present = {r[0] for r in self.db.execute("SELECT email FROM users WHERE present=1")}
            self.db.execute("UPDATE users SET present=0")
            for user in users:
                email = user["email"]
                previous = self.db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                up, down = user["up"], user["down"]
                if previous and previous["ts"] is not None and previous["ts"] < now and None not in (up, down, previous["up"], previous["down"]):
                    if up >= previous["up"] and down >= previous["down"]:
                        self.add_delta(email, previous["ts"], now, up - previous["up"], down - previous["down"])
                        if now - previous["ts"] > self.meta("settings")["interval"] * 3:
                            self.log("sampling_gap", email)
                    else:
                        self.log("counter_reset", email)
                values = (email, user["name"], user["inbound"], user["protocol"], int(user["enabled"]),
                          int(email in online) if online is not None else None, up, down, user["total"], user["expiry"], now)
                self.db.execute("""INSERT INTO users(email,name,inbound,protocol,enabled,online,up,down,total,expiry,ts)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET name=excluded.name,
                  inbound=excluded.inbound,protocol=excluded.protocol,enabled=excluded.enabled,online=excluded.online,
                  up=excluded.up,down=excluded.down,total=excluded.total,expiry=excluded.expiry,present=1,ts=excluded.ts""", values)
            for email in previously_present - {user["email"] for user in users}:
                # Keep server-wide history under an internal identity that a
                # real email cannot share, while erasing private destinations.
                archive = "\x00archived:" + secrets.token_hex(16)
                self.db.execute("UPDATE traffic SET email=? WHERE email=?", (archive, email))
                self.db.execute("DELETE FROM domains WHERE email=?", (email,))
                self.db.execute("DELETE FROM measured WHERE email=?", (email,))
                self.invalidate_metrics(email)
                self.db.execute("""UPDATE users SET consent=0,selected=0,consent_at=NULL,
                    generation=?,up=NULL,down=NULL,ts=NULL WHERE email=?""", (secrets.randbits(62) + 1, email))
                self.log("user_removed_and_erased", email)
            if self.meta("started") is None:
                self.put("started", now)
            self.put("last_sync", now)
            self.put("error", None)

    def selected(self):
        s = self.meta("settings")
        if not s["domains_enabled"]:
            return set()
        query = "SELECT email FROM users WHERE consent=1 AND present=1"
        if s["scope"] == "selected":
            query += " AND selected=1"
        return {row[0] for row in self.db.execute(query)}

    def set_user(self, email, enabled):
        with self.lock, self.db:
            if not self.db.execute("SELECT 1 FROM users WHERE email=? AND present=1", (email,)).fetchone():
                raise ValueError("user_not_found")
            self.db.execute("UPDATE users SET consent=?,selected=?,consent_at=?,generation=? WHERE email=?",
                            (int(enabled), int(enabled), int(time.time()) if enabled else None, secrets.randbits(62) + 1, email))
            if not enabled:
                self.db.execute("DELETE FROM domains WHERE email=?", (email,))
                self.db.execute("DELETE FROM measured WHERE email=?", (email,))
            self.invalidate_metrics(email)
            self.log("monitor_on" if enabled else "monitor_off_and_erased", email)

    def settings(self, data):
        s = {key: data.get(key, DEFAULTS[key]) for key in DEFAULTS}
        if s["scope"] not in ("selected", "all") or s["interval"] not in (60, 120, 300) or s["retention"] not in (3, 7, 14, 30) or type(s["domains_enabled"]) is not bool:
            raise ValueError("invalid_settings")
        with self.lock, self.db:
            previous = self.meta("settings")
            if previous["domains_enabled"] and not s["domains_enabled"]:
                self.put("domains_paused_at", time.time())
            elif not previous["domains_enabled"] and s["domains_enabled"] and self.meta("domains_paused_at") is not None:
                # Store this at the administrative transition, not at a poll:
                # the log reader may never observe a short off/on interval.
                self.put("domains_resumed_at", time.time())
                # Old cumulative rows must not cross an administrative pause.
                # New generations only count freshly instrumented connections.
                self.db.execute("UPDATE users SET generation=? WHERE consent=1 AND present=1", (secrets.randbits(62) + 1,))
                self.invalidate_metrics()
            self.put("settings", s)
            self.log("settings_saved")
        self.prune()

    def bulk(self, enabled):
        with self.lock, self.db:
            self.db.execute("UPDATE users SET consent=?,selected=?,consent_at=?,generation=? WHERE present=1",
                            (int(enabled), int(enabled), int(time.time()) if enabled else None, secrets.randbits(62) + 1))
            if not enabled:
                self.db.execute("DELETE FROM domains")
                self.db.execute("DELETE FROM measured")
            self.invalidate_metrics()
            self.log("monitor_all_current_on" if enabled else "monitor_all_off_and_erased")

    def add_domains(self, events):
        with self.lock, self.db:
            allowed = self.selected()
            for email, domain, ts in events:
                if email in allowed:
                    self.db.execute("""INSERT INTO domains VALUES(?,?,?,1,?) ON CONFLICT(email,bucket,domain)
                        DO UPDATE SET n=n+1,last=MAX(last,excluded.last)""", (email, self.bucket(ts), domain, ts))

    def prune(self):
        with self.lock, self.db:
            cutoff = time.time() - self.meta("settings")["retention"] * 86400
            self.db.execute("DELETE FROM traffic WHERE bucket<?", (cutoff,))
            self.db.execute("DELETE FROM domains WHERE bucket<?", (cutoff,))
            self.db.execute("DELETE FROM measured WHERE bucket<?", (cutoff,))
            self.db.execute("DELETE FROM audit WHERE ts<?", (time.time() - 30 * 86400,))
            self.db.execute("PRAGMA incremental_vacuum")

    def bounds(self, period):
        now = dt.datetime.now(self.tz)
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if period == "yesterday":
            start, end = midnight - dt.timedelta(days=1), midnight
        elif period == "week":
            start, end = midnight - dt.timedelta(days=6), now
        elif period == "month":
            start, end = midnight - dt.timedelta(days=29), now
        else:
            start, end = midnight, now
        return int(start.timestamp()), int(end.timestamp())

    def report(self, period="today", email=None):
        start, end = self.bounds(period)
        with self.lock:
            users = [dict(x) for x in self.db.execute("SELECT * FROM users WHERE present=1 ORDER BY email")]
            totals = {r["email"]: dict(r) for r in self.db.execute("SELECT email,SUM(up) up,SUM(down) down FROM traffic WHERE bucket>=? AND bucket<? GROUP BY email", (start, end))}
            per_user_destinations = {r["email"]: dict(r) for r in self.db.execute("SELECT email," + DESTINATION_TOTALS_SQL + " FROM measured WHERE bucket>=? AND bucket<? GROUP BY email", (start, end))}
            allowed = self.selected()
            for u in users:
                value = totals.get(u["email"], {"up": 0, "down": 0})
                u.update({"period_up": value["up"], "period_down": value["down"], "monitored": u["email"] in allowed,
                          "destination_summary": destination_summary(per_user_destinations.get(u["email"]), value["up"] + value["down"])})
            where, args = "bucket>=? AND bucket<?", [start, end]
            if email:
                where += " AND email=?"
                args.append(email)
            measures = [dict(r) for r in self.db.execute("SELECT domain,SUM(up) up,SUM(down) down,SUM(n) connections,MAX(last) last FROM measured WHERE " + where + " GROUP BY domain", args)]
            # Three separate collections prevent unknown traffic or log-only
            # connection counts from consuming the measured website limit.
            unmeasured = [dict(r, up=None, down=None, bytes=None, source="access_log") for r in self.db.execute(
                "SELECT domain,SUM(n) connections,MAX(last) last FROM domains WHERE " + where +
                " AND NOT EXISTS (SELECT 1 FROM measured m WHERE m.domain=domains.domain AND " + where +
                ") GROUP BY domain ORDER BY connections DESC LIMIT 100", args + args)]
            known, unknown = [], []
            for row in measures:
                item = dict(row, bytes=row["up"] + row["down"], source="dispatcher_counter",
                            unknown=row["domain"].startswith(("__unknown_", "__overflow_")))
                (unknown if item["unknown"] else known).append(item)
            domains = sorted(known, key=lambda d: (d["bytes"], d["connections"]), reverse=True)[:100]
            unknown = sorted(unknown, key=lambda d: (d["bytes"], d["connections"]), reverse=True)
            series = [dict(r) for r in self.db.execute("SELECT bucket,SUM(up) up,SUM(down) down FROM traffic WHERE " + where + " GROUP BY bucket ORDER BY bucket", args)]
            summary = destination_summary(self.db.execute("SELECT " + DESTINATION_TOTALS_SQL + " FROM measured WHERE " + where, args).fetchone(), sum(r["up"] + r["down"] for r in series))
            destination_series = []
            for row in self.db.execute("SELECT bucket," + DESTINATION_TOTALS_SQL + " FROM measured WHERE " + where + " GROUP BY bucket ORDER BY bucket", args):
                item = destination_summary(row)
                destination_series.append({"bucket": row["bucket"], "up": item["measured_up"], "down": item["measured_down"],
                    "bytes": item["measured_bytes"], "supported_bytes": item["supported_bytes"], "unknown_bytes": item["unknown_bytes"]})
            info = self.meta("metrics_info") or {}
            last_snapshot = (self.meta("metrics_seen") or self.meta("metrics_cursor") or {}).get("ts")
            snapshot_age = max(0, time.time() - last_snapshot) if last_snapshot is not None else None
            metrics_status = self.meta("metrics_status") or "unavailable"
            if metrics_status == "ready" and snapshot_age is not None and snapshot_age > max(120, self.meta("settings")["interval"] * 2):
                metrics_status = "stale"
            module = {"status": metrics_status, "connected": metrics_status == "ready", "last_snapshot": last_snapshot,
                "snapshot_age": snapshot_age, "enabled": self.meta("settings")["domains_enabled"],
                "dropped_flows": info.get("dropped_flows", 0), "rows": info.get("rows", 0),
                "started_at": info.get("started_at"), "byte_basis": "dispatcher_payload",
                "first_snapshot_is_baseline": info.get("first_snapshot_is_baseline", True),
                "baseline_skipped_bytes": info.get("baseline_skipped_bytes", 0), "counter_resets": info.get("counter_resets", 0)}
            return {"mode": "live", "users": users, "domains": domains, "series": series,
                    "unknown_destinations": unknown, "unmeasured_destinations": unmeasured,
                    "destination_summary": summary, "destination_series": destination_series, "module": module,
                    "start": start, "end": end, "period": period, "settings": self.meta("settings"),
                    "last_sync": self.meta("last_sync"), "started": self.meta("started"),
                    "error": self.meta("error"), "collector": self.meta("collector") or {},
                    "log_status": self.meta("log_status") or "disabled", "timezone": str(self.tz),
                    "metrics_status": metrics_status, "metrics_info": info,
                    "audit": [dict(r) for r in self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 60")]}


ACCESS = re.compile(r"(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? .*?\baccepted (?P<net>tcp|udp):(?P<host>\[[^\]]+\]|[^\s:]+):\d+ .*?\bemail: (?P<email>\S+)\s*$")


def parse_access(line, tz):
    match = ACCESS.search(line)
    if not match:
        return None
    host = match["host"].strip("[]").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return None  # do not mislabel IP destinations as domains
    except ValueError:
        pass
    if "." not in host or len(host) > 253 or not re.fullmatch(r"[a-z0-9._-]+", host):
        return None
    try:
        ts = int(dt.datetime.strptime(match["date"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=tz).timestamp())
    except ValueError:
        return None
    return match["email"], host, ts


class Tail:
    def __init__(self, path, store, log_timezone="UTC"):
        self.path, self.store, self.tz = path, store, ZoneInfo(log_timezone)
        self.identity, self.offset = None, 0
        self.discard_partial = False
        self.active_since = {}

    def read(self):
        allowed = self.store.selected()
        resumed_at = self.store.meta("domains_resumed_at") or 0
        # Only persist lines newer than the latest user activation. Even when the
        # reader has a backlog, activating a user never imports their earlier use.
        for email in allowed - self.active_since.keys():
            self.active_since[email] = int(time.time())
        for row in self.store.db.execute("SELECT email,consent_at FROM users WHERE consent=1"):
            if row["email"] in self.active_since:
                self.active_since[row["email"]] = max(self.active_since[row["email"]], row["consent_at"] or 0, resumed_at)
        self.active_since = {k: v for k, v in self.active_since.items() if k in allowed}
        if not self.path or not allowed:
            self.identity = None
            return "disabled"
        try:
            stat = os.stat(self.path)
            identity = (stat.st_dev, stat.st_ino)
            with open(self.path, "rb") as file:
                if self.identity is None:
                    self.identity, self.offset = identity, stat.st_size
                    return "ready"  # begin at EOF; historical consent is unknown
                if identity != self.identity or stat.st_size < self.offset:
                    self.identity, self.offset = identity, 0
                    self.discard_partial = False
                file.seek(self.offset)
                # Hard budget: at most 512 KiB per cycle, no payload captures.
                block = file.read(512 * 1024)
                ending = block.rfind(b"\n")
                if ending < 0:
                    if len(block) == 512 * 1024:
                        self.offset += len(block)
                        self.discard_partial = True
                    return "ready"
                lines = block[:ending + 1].decode("utf-8", errors="replace").splitlines()
                if self.discard_partial and lines:
                    lines = lines[1:]
                    self.discard_partial = False
                self.offset += ending + 1
                cutoff = int(time.time()) - self.store.meta("settings")["retention"] * 86400
                events = []
                for line in lines:
                    event = parse_access(line, self.tz)
                    if event and event[0] in allowed and max(cutoff, self.active_since[event[0]]) <= event[2] <= time.time() + 60:
                        events.append(event)
                self.store.add_domains(events)
            return "backlog" if stat.st_size - self.offset > 512 * 1024 else "ready"
        except (FileNotFoundError, PermissionError):
            return "unavailable"


class Collector(threading.Thread):
    def __init__(self, store, config):
        super().__init__(daemon=True)
        self.store, self.config = store, config
        self.panel = Panel(config)
        self.tail = Tail(config.get("access_log", ""), store, config.get("log_timezone", "UTC"))
        self.metrics = Metrics(config.get("domain_metrics", ""), config.get("domain_policy", ""), store)
        self.stop_event = threading.Event()

    def run(self):
        cycle = 0
        while not self.stop_event.is_set():
            started = time.monotonic()
            self.metrics.write_policy()
            try:
                users, online = self.panel.snapshot()
                self.store.ingest(users, online)
            except Exception:
                with self.store.lock, self.store.db:
                    self.store.put("error", "panel_unavailable")
            try:
                with self.store.lock:
                    log_status = self.tail.read()
                with self.store.lock, self.store.db:
                    self.store.put("log_status", log_status)
                    self.store.put("metrics_status", self.metrics.read())
                    self.store.put("collector", {"cycle_ms": round((time.monotonic() - started) * 1000),
                        "api_bytes": self.panel.bytes, "api_calls": self.panel.calls, "log_budget": 524288})
                if cycle % 30 == 0:
                    self.store.prune()
            except Exception:
                with self.store.lock, self.store.db:
                    self.store.put("log_status", "error")
            cycle += 1
            interval = self.store.meta("settings")["interval"]
            self.stop_event.wait(max(1, interval - (time.monotonic() - started)))


class Metrics:
    """Read bounded cumulative snapshots from the dispatcher module.
    A matching generation and a known process start allow complete first-sample
    accounting. Legacy snapshots without a start time use a safe baseline.
    """
    def __init__(self, path, policy, store):
        self.path, self.policy, self.store = path, policy, store

    def write_policy(self):
        if not self.policy:
            return
        with self.store.lock:
            settings = self.store.meta("settings")
            query = "SELECT email,generation FROM users WHERE consent=1 AND present=1"
            if settings["scope"] == "selected":
                query += " AND selected=1"
            users = {row[0]: row[1] for row in self.store.db.execute(query)}
            value = {"enabled": settings["domains_enabled"], "expires": int(time.time()) + settings["interval"] * 3 + 30, "users": users}
        try:
            from pathlib import Path
            target = Path(self.policy)
            target.parent.mkdir(parents=True, exist_ok=True)
            temp = target.with_suffix(".tmp")
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "w") as file:
                json.dump(value, file)
            os.replace(temp, target)
        except OSError:
            pass

    def read(self):
        if not self.path:
            return "unavailable"
        try:
            with open(self.path, "rb") as file:
                raw = file.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                return "invalid"
            data = json.loads(raw)
            if data.get("version") != 1 or not isinstance(data.get("rows"), list) or len(data["rows"]) > 8192:
                return "invalid"
            ts = int(data["ts"])
            boot = data["boot"]
            if not isinstance(boot, str) or not boot or len(boot) > 128:
                return "invalid"
            started_at = data.get("started_at")
            if started_at is not None:
                started_at = int(started_at)
                if not 0 < started_at <= ts:
                    return "invalid"
            dropped = int(data.get("dropped_flows", 0))
            if dropped < 0:
                return "invalid"
            previous = self.store.meta("metrics_cursor") or {}
            current = {}
            first_seen = {}
            seen_keys = set()
            allowed = self.store.selected()
            consent = {r["email"]: dict(r) for r in self.store.db.execute("SELECT email,generation,consent_at FROM users WHERE consent=1 AND present=1")}
            for row in data["rows"]:
                email, domain = row["email"], row["domain"]
                generation = int(row["generation"])
                if not isinstance(email, str) or not isinstance(domain, str) or not email or not domain or len(domain) > 253 or len(email) > 320:
                    return "invalid"
                key = json.dumps([email, domain, generation])
                if key in seen_keys:
                    return "invalid"
                seen_keys.add(key)
                u, d, n = int(row["up"]), int(row["down"]), int(row["connections"])
                if min(u, d, n) < 0 or max(u, d, n) >= 2**63:
                    return "invalid"
                first_ts = row.get("first_ts")
                if first_ts is not None:
                    first_ts = int(first_ts)
                    if not (started_at or 1) <= first_ts <= ts:
                        return "invalid"
                # Rejected users/generations never leave private domains in the
                # persistent cursor, including snapshots after revocation.
                if email in consent and generation == consent[email]["generation"]:
                    current[key] = [u, d, n]
                    if first_ts is not None:
                        first_seen[key] = first_ts
            # Validate all records before a single transaction can persist any.
            with self.store.db:
                same_process = previous.get("boot") == boot
                if same_process and ts < previous.get("ts", ts):
                    return "stale"  # never move a cumulative cursor backwards
                self.store.put("metrics_seen", {"boot": boot, "ts": ts})
                if abs(time.time() - ts) > max(120, self.store.meta("settings")["interval"] * 2):
                    return "stale"
                info = self.store.meta("metrics_info") or {}
                skipped = int(info.get("baseline_skipped_bytes", 0))
                resets = int(info.get("counter_resets", 0))
                if same_process and ts == previous.get("ts"):
                    return "ready"  # rereading a snapshot cannot add bytes
                previous_rows = previous.get("rows", {}) if same_process else {}
                previous_first = previous.get("first_seen", {}) if same_process else {}
                previous_last = previous.get("last_seen", {}) if same_process else {}
                for key, counters in current.items():
                    email, domain, _ = json.loads(key)
                    if email not in allowed:
                        continue
                    old = previous_rows.get(key)
                    row_restarted = old is not None and (any(a < b for a, b in zip(counters, old)) or
                        key in first_seen and key in previous_first and first_seen[key] != previous_first[key])
                    if row_restarted:
                        resets += 1
                    if old is not None and not row_restarted:
                        delta = [a - b for a, b in zip(counters, old)]
                        start = previous_last.get(key, previous["ts"])
                    elif started_at is not None:
                        delta = counters[:]
                        start = max(started_at, first_seen.get(key, started_at), consent[email]["consent_at"] or started_at)
                        if same_process and previous.get("evicted") and old is None and first_seen.get(key, ts) < previous["ts"]:
                            # A resurfacing row whose cursor was evicted cannot
                            # safely replay its complete cumulative history.
                            skipped += counters[0] + counters[1]
                            continue
                    elif same_process and old is None:
                        delta = counters[:]
                        start = previous["ts"]
                    else:
                        skipped += counters[0] + counters[1]
                        continue
                    if start > ts:
                        skipped += delta[0] + delta[1]
                        continue
                    if not any(delta):
                        continue
                    # A long-lost cursor cannot recover historical placement
                    # from one cumulative total. Do not fabricate old periods.
                    if start < time.time() - self.store.meta("settings")["retention"] * 86400:
                        skipped += delta[0] + delta[1]
                        continue
                    self.add(email, domain, start, ts, delta)
                # Retain omitted rows so a partial snapshot cannot make an
                # existing cumulative total look like a new zero-based row.
                retained = {key: value for key, value in previous_rows.items()
                    if json.loads(key)[0] in consent and json.loads(key)[2] == consent[json.loads(key)[0]]["generation"]}
                retained.update(current)
                retained_first = {key: value for key, value in previous_first.items() if key in retained}
                retained_first.update(first_seen)
                retained_last = {key: previous_last.get(key, previous.get("ts", ts)) for key in retained}
                retained_last.update({key: ts for key in current})
                # The producer and consumer both enforce a bounded cursor.
                # Current rows take priority if an inconsistent producer omits
                # many older records; this loss is exposed rather than hidden.
                evictions = max(0, len(retained) - 8192)
                if evictions:
                    for key in [key for key in retained if key not in current][:evictions]:
                        retained.pop(key, None)
                        retained_first.pop(key, None)
                        retained_last.pop(key, None)
                self.store.put("metrics_cursor", {"boot": boot, "ts": ts, "rows": retained, "first_seen": retained_first, "last_seen": retained_last,
                    "evicted": bool(evictions or same_process and previous.get("evicted"))})
                self.store.put("metrics_info", {"dropped_flows": dropped, "rows": len(current), "started_at": started_at,
                    "byte_basis": "dispatcher_payload", "first_snapshot_is_baseline": started_at is None,
                    "baseline_skipped_bytes": skipped, "counter_resets": resets,
                    "cursor_evictions": int(info.get("cursor_evictions", 0)) + evictions})
            return "ready"
        except FileNotFoundError:
            return "unavailable"
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            return "invalid"

    def add(self, email, domain, start, end, counters):
        cursor, remaining = start, counters[:]
        while cursor < end:
            bucket = self.store.bucket(cursor)
            stop = min(end, bucket + 3600)
            fraction = (stop - cursor) / (end - start)
            piece = remaining[:] if stop == end else [min(left, int(value * fraction)) for left, value in zip(remaining, counters)]
            self.store.db.execute("""INSERT INTO measured VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(email,bucket,domain) DO UPDATE SET up=up+excluded.up,
                down=down+excluded.down,n=n+excluded.n,last=MAX(last,excluded.last)""", (email, bucket, domain, *piece, end))
            remaining = [left - value for left, value in zip(remaining, piece)]
            cursor = stop
        if start >= end:
            # An entire first flow may fit within the snapshot's second.
            self.store.db.execute("""INSERT INTO measured VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(email,bucket,domain) DO UPDATE SET up=up+excluded.up,
                down=down+excluded.down,n=n+excluded.n,last=MAX(last,excluded.last)""", (email, self.store.bucket(end), domain, *counters, end))
