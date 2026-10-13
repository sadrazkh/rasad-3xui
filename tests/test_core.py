import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from core import Store, normalize, parse_access, Tail, Metrics, DEFAULTS


def user(up=100, down=200, email="alice"):
    return dict(email=email, name=email, inbound="test", protocol="vless", enabled=True,
                up=up, down=down, total=10000, expiry=0)


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.db.close()

    def test_baseline_delta_reset(self):
        self.store.ingest([user()], {"alice"}, 100000)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM traffic").fetchone()[0], 0)
        self.store.ingest([user(150, 280)], set(), 100060)
        self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM traffic").fetchone()), (50, 80))
        self.store.ingest([user(10, 20)], set(), 100120)
        self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM traffic").fetchone()), (50, 80))
        self.assertEqual(self.store.db.execute("SELECT action FROM audit ORDER BY id DESC LIMIT 1").fetchone()[0], "counter_reset")
        self.store.ingest([user(20, 40)], set(), 100180)
        self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM traffic").fetchone()), (60, 100))

    def test_tehran_midnight_split_preserves_bytes(self):
        midnight = int(dt.datetime(2026, 10, 13, tzinfo=ZoneInfo("Asia/Tehran")).timestamp())
        self.store.add_delta("alice", midnight-30, midnight+30, 101, 201)
        rows = self.store.db.execute("SELECT * FROM traffic ORDER BY bucket").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(x["up"] for x in rows), 101)
        self.assertEqual(sum(x["down"] for x in rows), 201)
        self.assertEqual(rows[1]["bucket"], midnight)

    def test_unknown_counters_never_become_zero(self):
        self.store.ingest([user()], None, 100000)
        missing = user(); missing["up"] = missing["down"] = None
        self.store.ingest([missing], None, 100060)
        self.store.ingest([user(200, 300)], None, 100120)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM traffic").fetchone()[0], 0)

    def test_scope_consent_revocation(self):
        self.store.ingest([user(),user(email="bob")], set())
        self.store.settings(dict(DEFAULTS, domains_enabled=True, scope="all"))
        self.assertEqual(self.store.selected(), set())
        self.store.set_user("alice", True)
        self.assertEqual(self.store.selected(), {"alice"})
        old_generation = self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0]
        self.store.add_domains([("alice","example.com",int(time.time())),("bob","private.example",int(time.time()))])
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM domains").fetchone()[0], 1)
        self.store.set_user("alice", False)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM domains").fetchone()[0], 0)
        self.store.set_user("alice", True)
        self.assertNotEqual(old_generation,self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0])
        self.store.bulk(True)
        self.assertEqual(self.store.selected(), {"alice","bob"})
        self.store.ingest([user(),user(email="bob"),user(email="new")], set())
        self.assertNotIn("new", self.store.selected())

    def test_removed_email_does_not_inherit_consent_or_history(self):
        self.store.ingest([user()], set(), 100000)
        self.store.settings(dict(DEFAULTS, domains_enabled=True))
        self.store.set_user("alice", True)
        generation = self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0]
        self.store.ingest([user(150, 280)], set(), 100060)
        self.store.add_domains([("alice", "previous-person.example", int(time.time()))])
        self.store.db.execute("INSERT INTO measured VALUES(?,?,?,?,?,?,?)", ("alice", self.store.bucket(time.time()), "previous-person.example", 5, 10, 1, int(time.time())))
        self.store.db.commit()
        self.store.ingest([], set(), 100120)
        self.assertEqual(self.store.selected(), set())
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM domains").fetchone()[0], 0)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM measured").fetchone()[0], 0)
        archived = self.store.db.execute("SELECT email FROM traffic").fetchone()[0]
        self.assertTrue(archived.startswith("\x00archived:"))
        self.store.ingest([user(1000, 2000)], set(), 100180)
        replacement = self.store.db.execute("SELECT * FROM users WHERE email='alice'").fetchone()
        self.assertEqual((replacement["consent"], replacement["selected"]), (0, 0))
        self.assertNotEqual(replacement["generation"], generation)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM traffic WHERE email='alice'").fetchone()[0], 0)
        self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM traffic").fetchone()), (50, 80))
        self.store.ingest([user(1020, 2050)], set(), 100240)
        self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM traffic WHERE email='alice'").fetchone()), (20, 50))
        self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM traffic").fetchone()), (70, 130))

    def test_master_switch_off_on_between_polls_skips_disabled_log_lines(self):
        initial = int(time.time()) - 120
        with tempfile.TemporaryDirectory(prefix=".rasad-test-", dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "access.log"
            path.write_text("")
            def line(domain, ts):
                stamp = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
                return stamp + f" from 1.2.3.4:123 accepted tcp:{domain}:443 [in -> out] email: alice\n"
            with patch("core.time.time", return_value=initial):
                self.store.ingest([user()], set())
                self.store.settings(dict(DEFAULTS, domains_enabled=True))
                self.store.set_user("alice", True)
                tail = Tail(str(path), self.store)
                tail.read()
            with patch("core.time.time", return_value=initial + 5):
                self.store.settings(dict(DEFAULTS, domains_enabled=False))
            path.write_text(line("during-off.example", initial + 10) + line("same-second-before-on.example", initial + 20))
            with patch("core.time.time", return_value=initial + 20.5):
                self.store.settings(dict(DEFAULTS, domains_enabled=True))
            with path.open("a") as file:
                file.write(line("after-on.example", initial + 21))
            with patch("core.time.time", return_value=initial + 30):
                tail.read()
            self.assertEqual([r[0] for r in self.store.db.execute("SELECT domain FROM domains")], ["after-on.example"])

    def test_retention_and_invalid_settings(self):
        self.store.add_delta("alice", 1, 60, 1, 1)
        self.store.prune()
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM traffic").fetchone()[0],0)
        with self.assertRaises(ValueError): self.store.settings(dict(DEFAULTS,interval=1))

    def test_normalize_versions_and_no_secrets(self):
        value = [{"id":1,"remark":"entry","protocol":"vless","settings":json.dumps({"clients":[{"email":"alice","id":"SECRET_UUID","subId":"SECRET_SUB","enable":True}]}),"clientStats":[{"email":"alice","up":2,"down":4,"total":100}]}]
        result=normalize(value)
        self.assertEqual(result[0]["down"],4)
        self.assertNotIn("SECRET",json.dumps(result))
        self.assertEqual(len(normalize(value+value)),1)
        different=json.loads(json.dumps(value));different[0]["clientStats"][0]["up"]=3
        with self.assertRaises(ValueError): normalize(value+different)
        value[0]["settings"]=json.loads(value[0]["settings"])
        self.assertEqual(normalize(value)[0]["up"],2)

    def test_access_parser_does_not_invent_ip_domains_or_bytes(self):
        line="2026/10/13 07:00:00.123 from 1.2.3.4:123 accepted tcp:EXAMPLE.com:443 [in -> out] email: alice"
        event=parse_access(line,ZoneInfo("UTC"))
        self.assertEqual(event[:2],("alice","example.com"))
        self.assertIsNone(parse_access(line.replace("EXAMPLE.com","1.2.3.4"),ZoneInfo("UTC")))
        self.assertIsNone(parse_access(line.replace("EXAMPLE.com","[2001:db8::1]"),ZoneInfo("UTC")))
        self.assertIsNone(parse_access(line.replace("accepted","rejected"),ZoneInfo("UTC")))

    def test_tail_skips_history_and_handles_rotation(self):
        self.store.ingest([user()],set())
        self.store.settings(dict(DEFAULTS,domains_enabled=True))
        self.store.set_user("alice",True)
        with tempfile.TemporaryDirectory(prefix=".rasad-test-", dir=Path(__file__).resolve().parents[1]) as directory:
            file=Path(directory)/"access.log"
            def line(domain): return dt.datetime.now(dt.timezone.utc).strftime("%Y/%m/%d %H:%M:%S")+f" from 1.2.3.4:123 accepted tcp:{domain}:443 [in -> out] email: alice\n"
            file.write_text(line("old.example"))
            tail=Tail(str(file),self.store)
            tail.read()
            with file.open("a") as f:f.write(line("new.example"))
            tail.read()
            self.assertEqual([r[0] for r in self.store.db.execute("SELECT domain FROM domains")],["new.example"])
            file.rename(file.with_suffix(".old"))
            file.write_text(line("rotated.example"))
            tail.read()
            self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM domains").fetchone()[0],2)

    def test_metrics_baseline_disable_restart_and_generation(self):
        now=int(time.time())
        self.store.ingest([user()],set())
        self.store.settings(dict(DEFAULTS,domains_enabled=True))
        with patch("core.time.time", return_value=now-60): self.store.set_user("alice",True)
        generation=self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0]
        with tempfile.TemporaryDirectory(prefix=".rasad-test-", dir=Path(__file__).resolve().parents[1]) as directory:
            path=Path(directory)/"metrics.json";metrics=Metrics(str(path),str(Path(directory)/"policy.json"),self.store)
            def snapshot(up,down,ts,boot="one"):
                path.write_text(json.dumps({"version":1,"boot":boot,"ts":ts,"rows":[{"email":"alice","domain":"example.com","generation":generation,"up":up,"down":down,"connections":up}]}))
            snapshot(10,20,now-30);self.assertEqual(metrics.read(),"ready")
            snapshot(15,30,now-15);metrics.read()
            self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM measured").fetchone()),(5,10))
            self.store.settings(dict(DEFAULTS,domains_enabled=False))
            snapshot(20,40,now-5);metrics.read()
            self.store.settings(dict(DEFAULTS,domains_enabled=True))
            generation=self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0]
            snapshot(1,1,now);metrics.read()
            self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM measured").fetchone()),(6,11))
            snapshot(100,200,now,boot="two");metrics.read()
            self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM measured").fetchone()),(6,11))
            self.store.set_user("alice",False)
            snapshot(101,201,now+1,boot="two");metrics.read()
            self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM measured").fetchone()[0],0)
            metrics.write_policy()
            self.assertEqual(json.loads((Path(directory)/"policy.json").read_text())["users"],{})

    def test_destination_report_keeps_unknown_and_unlisted_bytes_in_totals(self):
        now = int(time.time())
        bucket = self.store.bucket(now)
        self.store.ingest([user(), user(email="bob")], set())
        self.store.db.execute("INSERT INTO traffic VALUES(?,?,?,?)", ("alice", bucket, 3000, 7000))
        self.store.db.execute("INSERT INTO traffic VALUES(?,?,?,?)", ("bob", bucket, 1000, 2000))
        self.store.db.executemany("INSERT INTO measured VALUES(?,?,?,?,?,?,?)",
            [("alice", bucket, f"site-{i}.example", 1, 2, 1, now) for i in range(101)] +
            [("alice", bucket, "__unknown_udp__", 500, 700, 2, now), ("bob", bucket, "bob.example", 3, 4, 1, now)])
        self.store.db.execute("INSERT INTO domains VALUES(?,?,?,?,?)", ("alice", bucket, "access-only.example", 9999, now))
        self.store.put("metrics_seen", {"boot": "one", "ts": now})
        self.store.put("metrics_status", "ready")
        self.store.put("metrics_info", {"dropped_flows": 2, "first_snapshot_is_baseline": False})
        self.store.db.commit()
        with patch.object(self.store, "bounds", return_value=(bucket, now + 60)):
            report = self.store.report()
            alice = self.store.report(email="alice")
        summary = report["destination_summary"]
        self.assertEqual(summary["measured_bytes"], 1510)
        self.assertEqual((summary["supported_up"], summary["supported_down"], summary["supported_bytes"]), (104, 206, 310))
        self.assertEqual((summary["unknown_up"], summary["unknown_down"], summary["unknown_bytes"]), (500, 700, 1200))
        self.assertEqual(summary["supported_domains"], 102)
        self.assertEqual(summary["connections"], 104)
        self.assertAlmostEqual(summary["attribution_ratio"], 310 / 1510)
        self.assertEqual(summary["config_bytes"], 13000)
        self.assertEqual(len(report["domains"]), 100)
        self.assertFalse(any(row["unknown"] for row in report["domains"]))
        self.assertEqual(report["unknown_destinations"][0]["domain"], "__unknown_udp__")
        self.assertEqual(report["unknown_destinations"][0]["bytes"], 1200)
        self.assertEqual(report["unmeasured_destinations"][0]["domain"], "access-only.example")
        self.assertEqual(report["destination_series"][0]["bytes"], 1510)
        self.assertEqual(report["destination_series"][0]["supported_bytes"], 310)
        self.assertEqual(alice["destination_summary"]["measured_bytes"], 1503)
        self.assertNotIn("bob.example", [row["domain"] for row in alice["domains"]])
        summaries = {row["email"]: row["destination_summary"] for row in report["users"]}
        self.assertEqual(summaries["bob"]["measured_bytes"], 7)
        self.assertEqual(summaries["alice"]["config_bytes"], 10000)
        self.assertTrue(report["module"]["connected"])
        self.assertEqual(report["module"]["last_snapshot"], now)
        self.assertEqual(report["module"]["dropped_flows"], 2)
        with patch.object(self.store, "bounds", return_value=(bucket, now + 60)), patch("core.time.time", return_value=now + 181):
            self.assertEqual(self.store.report()["module"]["status"], "stale")

    def test_access_log_fallback_does_not_fabricate_destination_bytes(self):
        now = int(time.time())
        bucket = self.store.bucket(now)
        self.store.ingest([user()], set())
        self.store.db.execute("INSERT INTO domains VALUES(?,?,?,?,?)", ("alice", bucket, "fallback.example", 5, now))
        self.store.db.commit()
        with patch.object(self.store, "bounds", return_value=(bucket, now + 60)):
            report = self.store.report(email="alice")
        self.assertEqual(report["domains"], [])
        self.assertEqual(report["unmeasured_destinations"][0]["connections"], 5)
        self.assertIsNone(report["unmeasured_destinations"][0]["bytes"])
        self.assertIsNone(report["unmeasured_destinations"][0]["up"])
        self.assertIsNone(report["unmeasured_destinations"][0]["down"])
        self.assertFalse(report["destination_summary"]["has_measurements"])
        self.assertIsNone(report["destination_summary"]["attribution_ratio"])
        self.assertEqual(report["destination_series"], [])

    def test_small_unknown_destination_survives_known_website_limit(self):
        now = int(time.time())
        bucket = self.store.bucket(now)
        self.store.ingest([user()], set())
        self.store.db.executemany("INSERT INTO measured VALUES(?,?,?,?,?,?,?)",
            [("alice", bucket, f"site-{i}.example", 1000 + i, 2000 + i, 1, now) for i in range(101)] +
            [("alice", bucket, "__unknown_udp__", 1, 2, 1, now), ("alice", bucket, "__unknown_tcp__", 2, 3, 1, now)])
        self.store.db.execute("INSERT INTO domains VALUES(?,?,?,?,?)", ("alice", bucket, "site-100.example", 9000, now))
        self.store.db.execute("INSERT INTO domains VALUES(?,?,?,?,?)", ("alice", bucket, "log-only.example", 5, now))
        self.store.db.commit()
        with patch.object(self.store, "bounds", return_value=(bucket, now + 60)):
            report = self.store.report(email="alice")
        self.assertEqual(len(report["domains"]), 100)
        self.assertEqual(report["domains"][0]["domain"], "site-100.example")
        self.assertEqual(report["domains"][-1]["domain"], "site-1.example")
        self.assertEqual({row["domain"] for row in report["unknown_destinations"]}, {"__unknown_tcp__", "__unknown_udp__"})
        self.assertEqual(sum(row["bytes"] for row in report["unknown_destinations"]), 8)
        self.assertEqual(report["destination_summary"]["unknown_bytes"], 8)
        self.assertEqual(report["destination_summary"]["supported_domains"], 101)
        self.assertEqual([row["domain"] for row in report["unmeasured_destinations"]], ["log-only.example"])

    def test_started_snapshot_counts_first_bytes_and_preserves_partial_cursor(self):
        now = int(time.time())
        with patch("core.time.time", return_value=now - 60):
            self.store.ingest([user()], set())
            self.store.settings(dict(DEFAULTS, domains_enabled=True))
            self.store.set_user("alice", True)
        generation = self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0]
        with tempfile.TemporaryDirectory(prefix=".rasad-test-", dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "metrics.json"
            metrics = Metrics(str(path), "", self.store)
            def snapshot(up, down, ts, boot="one", start=None, first=None, empty=False):
                start = now - 50 if start is None else start
                first = now - 40 if first is None else first
                rows = [] if empty else [{"email": "alice", "domain": "example.com", "generation": generation,
                    "up": up, "down": down, "connections": 1, "first_ts": first}]
                path.write_text(json.dumps({"version": 1, "boot": boot, "started_at": start, "ts": ts, "rows": rows}))
                return metrics.read()
            def totals():
                return tuple(self.store.db.execute("SELECT COALESCE(SUM(up),0),COALESCE(SUM(down),0) FROM measured").fetchone())
            self.assertEqual(snapshot(10, 20, now - 30), "ready")
            self.assertEqual(totals(), (10, 20))
            self.assertFalse(self.store.meta("metrics_info")["first_snapshot_is_baseline"])
            self.assertEqual(self.store.meta("metrics_info")["baseline_skipped_bytes"], 0)
            snapshot(15, 30, now - 15)
            snapshot(15, 30, now - 15)
            self.assertEqual(totals(), (15, 30))
            snapshot(0, 0, now - 10, empty=True)
            snapshot(20, 40, now)
            self.assertEqual(totals(), (20, 40))
            self.assertEqual(snapshot(17, 34, now - 20), "stale")
            snapshot(25, 50, now + 10)
            self.assertEqual(totals(), (25, 50))
            self.assertEqual(snapshot(2, 3, now + 15, first=now + 11), "ready")
            self.assertEqual(totals(), (27, 53))
            self.assertEqual(self.store.meta("metrics_info")["counter_resets"], 1)
            snapshot(7, 9, now + 20, boot="two", start=now + 11, first=now + 12)
            self.assertEqual(totals(), (34, 62))
            self.store.set_user("alice", False)
            self.assertEqual(self.store.meta("metrics_cursor")["rows"], {})
            self.assertEqual(self.store.meta("metrics_cursor")["first_seen"], {})
            snapshot(8, 10, now + 21, boot="two", start=now + 11, first=now + 12)
            self.assertEqual(self.store.meta("metrics_cursor")["rows"], {})
            self.assertNotIn("example.com", json.dumps(self.store.meta("metrics_cursor")))
            self.assertEqual(totals(), (0, 0))

    def test_global_resume_ignores_old_generation_and_counts_new_source_rows(self):
        now = int(time.time())
        with patch("core.time.time", return_value=now - 60):
            self.store.ingest([user()], set())
            self.store.settings(dict(DEFAULTS, domains_enabled=True))
            self.store.set_user("alice", True)
        generation = self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0]
        with tempfile.TemporaryDirectory(prefix=".rasad-test-", dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "metrics.json"
            metrics = Metrics(str(path), "", self.store)
            def sample(value, ts, selected_generation, first):
                path.write_text(json.dumps({"version": 1, "boot": "one", "started_at": now - 50, "ts": ts,
                    "rows": [{"email": "alice", "domain": "example.com", "generation": selected_generation,
                              "first_ts": first, "up": value, "down": value, "connections": 1}]}))
                return metrics.read()
            sample(10, now - 30, generation, now - 40)
            with patch("core.time.time", return_value=now - 20):
                self.store.settings(dict(DEFAULTS, domains_enabled=False))
            sample(20, now - 15, generation, now - 40)
            with patch("core.time.time", return_value=now - 10):
                self.store.settings(dict(DEFAULTS, domains_enabled=True))
            resumed_generation = self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0]
            self.assertNotEqual(generation, resumed_generation)
            sample(100, now - 5, generation, now - 40)
            self.assertEqual(self.store.meta("metrics_cursor")["rows"], {})
            sample(3, now, resumed_generation, now - 4)
            self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM measured").fetchone()), (13, 13))

    def test_invalid_snapshot_cannot_partially_commit_measurements(self):
        now = int(time.time())
        with patch("core.time.time", return_value=now - 60):
            self.store.ingest([user()], set())
            self.store.settings(dict(DEFAULTS, domains_enabled=True))
            self.store.set_user("alice", True)
        generation = self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0]
        with tempfile.TemporaryDirectory(prefix=".rasad-test-", dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "metrics.json"
            metrics = Metrics(str(path), "", self.store)
            row = {"email": "alice", "domain": "example.com", "generation": generation, "first_ts": now - 40,
                   "up": 10, "down": 20, "connections": 1}
            snapshot = {"version": 1, "boot": "one", "started_at": now - 50, "ts": now - 30, "rows": [row]}
            path.write_text(json.dumps(snapshot)); self.assertEqual(metrics.read(), "ready")
            snapshot["ts"] = now
            snapshot["rows"] = [dict(row, up=30), dict(row, domain="invalid.example", up=-1)]
            path.write_text(json.dumps(snapshot)); self.assertEqual(metrics.read(), "invalid")
            self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM measured").fetchone()), (10, 20))
            self.assertEqual(self.store.meta("metrics_cursor")["ts"], now - 30)

    def test_partial_snapshot_uses_last_seen_time_across_midnight(self):
        midnight = int(dt.datetime.now(self.store.tz).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        with patch("core.time.time", return_value=midnight - 120):
            self.store.ingest([user()], set())
            self.store.settings(dict(DEFAULTS, domains_enabled=True))
            self.store.set_user("alice", True)
        generation = self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0]
        with tempfile.TemporaryDirectory(prefix=".rasad-test-", dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / "metrics.json"
            metrics = Metrics(str(path), "", self.store)
            def sample(up, down, ts, empty=False):
                rows = [] if empty else [{"email": "alice", "domain": "example.com", "generation": generation,
                    "up": up, "down": down, "connections": 1, "first_ts": midnight - 60}]
                path.write_text(json.dumps({"version": 1, "boot": "one", "started_at": midnight - 120, "ts": ts, "rows": rows}))
                with patch("core.time.time", return_value=ts): self.assertEqual(metrics.read(), "ready")
            sample(10, 20, midnight - 30)
            sample(0, 0, midnight + 1, empty=True)
            sample(20, 40, midnight + 30)
            rows = self.store.db.execute("SELECT bucket,up,down FROM measured ORDER BY bucket").fetchall()
            self.assertEqual([tuple(row) for row in rows], [(midnight - 3600, 15, 30), (midnight, 5, 10)])


if __name__ == "__main__": unittest.main()
