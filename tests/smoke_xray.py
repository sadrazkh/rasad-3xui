"""Real authenticated VLESS fixtures, using loopback only and known byte counts."""
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

binary = str(Path(sys.argv[1]).resolve())
payload = b"Rasad measured payload\n" * 8192
response = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(payload)).encode()
            + b"\r\nConnection: close\r\n\r\n" + payload)
udp_payload = b"Rasad UDP remains explicitly unattributed"
selected_uuid = "550e8400-e29b-41d4-a716-446655440000"
unselected_uuid = "550e8400-e29b-41d4-a716-446655440001"


class PayloadHandler(socketserver.BaseRequestHandler):
    def handle(self):
        request = b""
        self.request.settimeout(5)
        while b"\r\n\r\n" not in request:
            part = self.request.recv(4096)
            if not part:
                return
            request += part
        self.request.sendall(response)


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, conn = self.request
        conn.sendto(packet, self.client_address)


def recv_exact(conn, length):
    result = b""
    while len(result) < length:
        part = conn.recv(length - len(result))
        assert part, "VLESS connection ended before delivering all fixture bytes"
        result += part
    return result


def vless_header(user_id, command, target, port):
    try:
        address = b"\x01" + socket.inet_aton(target)
    except OSError:
        domain = target.encode("ascii")
        address = b"\x02" + bytes([len(domain)]) + domain
    return b"\x00" + uuid.UUID(user_id).bytes + b"\x00" + bytes([command]) + struct.pack("!H", port) + address


def request_tcp(target, host, inbound=15500, user_id=selected_uuid):
    request = b"GET /payload HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n"
    with socket.create_connection(("127.0.0.1", inbound), timeout=5) as conn:
        conn.sendall(vless_header(user_id, 1, target, 15502) + request)
        assert recv_exact(conn, 2) == b"\x00\x00", "unexpected VLESS response header"
        assert recv_exact(conn, len(response)) == response, "proxy delivered different TCP payload"
    return len(request)


def request_udp():
    with socket.create_connection(("127.0.0.1", 15500), timeout=5) as conn:
        conn.sendall(vless_header(selected_uuid, 2, "127.0.0.1", 15506)
                     + struct.pack("!H", len(udp_payload)) + udp_payload)
        assert recv_exact(conn, 2) == b"\x00\x00", "unexpected UDP VLESS response header"
        length = struct.unpack("!H", recv_exact(conn, 2))[0]
        assert recv_exact(conn, length) == udp_payload, "proxy delivered different UDP payload"


def verify_web_report(root, metrics, snapshot, expected):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
    from core import Store, Metrics, DEFAULTS
    store = Store(str(root / "web-accounting.db"))
    try:
        store.ingest([dict(email="smoke-user", name="Fixture", inbound="vless", protocol="vless",
                           enabled=True, up=sum(v[0] for v in expected.values()),
                           down=sum(v[1] for v in expected.values()), total=0, expiry=0)], set())
        store.settings(dict(DEFAULTS, domains_enabled=True))
        with store.db:
            store.db.execute("UPDATE users SET consent=1,selected=1,generation=123,consent_at=? WHERE email=?",
                             (snapshot["started_at"], "smoke-user"))
        # Keep this backend's policy path separate from the running fixture.
        reader = Metrics(str(metrics), str(root / "web-policy.json"), store)
        status = reader.read()
        assert status == "ready", f"real snapshot rejected by backend: {status}"
        with store.db:
            store.put("metrics_status", status)
        assert reader.read() == "ready"  # reading twice must never double count
        report = store.report("week", "smoke-user")  # remains stable across local midnight
        rows = report["domains"] + report["unknown_destinations"]
        actual = {r["domain"]: (r["up"], r["down"]) for r in rows if r["bytes"] is not None}
        assert actual == expected, f"web report lost or misattributed first snapshot: {actual}"
        for row in rows:
            assert row["bytes"] == sum(expected[row["domain"]]) and row["source"] == "dispatcher_counter"
        summary = report["destination_summary"]
        assert summary["measured_up"] == sum(u for u, _ in expected.values())
        assert summary["measured_down"] == sum(d for _, d in expected.values())
        assert summary["measured_bytes"] == sum(u + d for u, d in expected.values())
        assert summary["unknown_bytes"] == sum(sum(v) for k, v in expected.items() if k.startswith("__unknown_"))
        assert summary["supported_bytes"] + summary["unknown_bytes"] == summary["measured_bytes"]
        assert report["module"]["connected"] and not report["module"]["first_snapshot_is_baseline"]
        assert report["module"]["baseline_skipped_bytes"] == 0
        json.dumps(report)  # the same report object is serialized by the HTTP API
    finally:
        store.db.close()


target = socketserver.ThreadingTCPServer(("127.0.0.1", 15502), PayloadHandler)
target.daemon_threads = True
udp_target = socketserver.ThreadingUDPServer(("127.0.0.1", 15506), EchoHandler)
udp_target.daemon_threads = True
for fixture in (target, udp_target):
    threading.Thread(target=fixture.serve_forever, daemon=True).start()

try:
    with tempfile.TemporaryDirectory(prefix="rasad-xray-smoke-") as directory:
        root = Path(directory)
        policy, metrics = root / "policy.json", root / "domains.json"

        def write_policy(enabled):
            temp = policy.with_suffix(".tmp")
            temp.write_text(json.dumps({"enabled": enabled, "expires": int(time.time()) + 300,
                                        "users": {"smoke-user": 123}}))
            temp.replace(policy)

        write_policy(True)
        settings = {"clients": [{"id": selected_uuid, "email": "smoke-user"},
                                 {"id": unselected_uuid, "email": "unselected-user"}], "decryption": "none"}
        server = {
            "log": {"loglevel": "debug"},
            # No fixture lookup can reach an Internet DNS server. localhost
            # is static; an accidental routeOnly regression fails locally.
            "dns": {"hosts": {"localhost": "127.0.0.1"},
                    "servers": [{"address": "127.0.0.1", "port": 15507}]},
            "inbounds": [
                {"listen": "127.0.0.1", "port": 15500, "protocol": "vless", "settings": settings},
                {"listen": "127.0.0.1", "port": 15503, "protocol": "vless", "settings": settings,
                 "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"],
                              "metadataOnly": False, "routeOnly": True}},
            ],
            "outbounds": [{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "ForceIPv4"}}, "settings": {"finalRules": [
                {"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"], "port": 15502},
                {"action": "allow", "network": "udp", "ip": ["127.0.0.1/32"], "port": 15506},
            ]}}],
        }
        config = root / "server.json"
        config.write_text(json.dumps(server))
        subprocess.run([binary, "run", "-test", "-config", str(config)], check=True)
        env = dict(os.environ, RASAD_POLICY=str(policy), RASAD_METRICS=str(metrics))
        process = subprocess.Popen([binary, "run", "-config", str(config)], env=env)
        try:
            time.sleep(6)  # first policy refresh plus listener startup
            expected = {
                "localhost": (request_tcp("localhost", "localhost:15502"), len(response)),
                "__unknown_tcp__": (request_tcp("127.0.0.1", "127.0.0.1:15502"), len(response)),
                # This domain cannot resolve. routeOnly must keep the loopback IP.
                "measured.example": (request_tcp("127.0.0.1", "measured.example", 15503), len(response)),
                "__unknown_udp__": (len(udp_payload), len(udp_payload)),
            }
            request_udp()
            request_tcp("localhost", "localhost:15502", user_id=unselected_uuid)
            snapshot = {}
            rows = {}
            for _ in range(25):
                if metrics.exists():
                    snapshot = json.loads(metrics.read_text())
                    rows = {r["domain"]: r for r in snapshot["rows"] if r["email"] == "smoke-user"}
                    if all(name in rows and (rows[name]["up"], rows[name]["down"]) == counts
                           for name, counts in expected.items()):
                        break
                time.sleep(1)
            for domain, counts in expected.items():
                assert domain in rows, f"missing destination: {domain}"
                assert (rows[domain]["up"], rows[domain]["down"]) == counts, f"incorrect exact payload counts: {domain}"
                assert rows[domain]["generation"] == 123 and rows[domain]["connections"] == 1
                assert snapshot["started_at"] <= rows[domain]["first_ts"] <= snapshot["ts"]
            assert not any(r["email"] == "unselected-user" for r in snapshot["rows"]), "unselected user's traffic was recorded"
            verify_web_report(root, metrics, snapshot, expected)
            before = {name: (r["up"], r["down"], r["connections"]) for name, r in rows.items()}
            write_policy(False)
            time.sleep(6)
            request_tcp("localhost", "localhost:15502")
            request_tcp("127.0.0.1", "measured.example", 15503)
            request_udp()
            time.sleep(16)
            after = {r["domain"]: (r["up"], r["down"], r["connections"])
                     for r in json.loads(metrics.read_text())["rows"] if r["email"] == "smoke-user"}
            assert after == before, "disabled telemetry continued counting"
            print("Real VLESS -> snapshot -> SQLite -> web report: exact TCP domain/IP/sniff-routeOnly bytes, UDP unknown, selected users, first timestamps and disable: PASS")
        finally:
            process.terminate()
            process.wait(timeout=10)
finally:
    for fixture in (target, udp_target):
        fixture.shutdown()
        fixture.server_close()
