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
        self.store.ingest([user()],set())
        self.store.settings(dict(DEFAULTS,domains_enabled=True))
        self.store.set_user("alice",True)
        generation=self.store.db.execute("SELECT generation FROM users WHERE email='alice'").fetchone()[0]
        with tempfile.TemporaryDirectory(prefix=".rasad-test-", dir=Path(__file__).resolve().parents[1]) as directory:
            path=Path(directory)/"metrics.json";metrics=Metrics(str(path),str(Path(directory)/"policy.json"),self.store)
            def snapshot(up,down,ts,boot="one"):
                path.write_text(json.dumps({"version":1,"boot":boot,"ts":ts,"rows":[{"email":"alice","domain":"example.com","generation":generation,"up":up,"down":down,"connections":up}]}))
            now=int(time.time())
            snapshot(10,20,now-30);self.assertEqual(metrics.read(),"ready")
            snapshot(15,30,now-15);metrics.read()
            self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM measured").fetchone()),(5,10))
            self.store.settings(dict(DEFAULTS,domains_enabled=False))
            snapshot(20,40,now-5);metrics.read()
            self.store.settings(dict(DEFAULTS,domains_enabled=True))
            snapshot(21,41,now);metrics.read()
            self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM measured").fetchone()),(6,11))
            snapshot(100,200,now,boot="two");metrics.read()
            self.assertEqual(tuple(self.store.db.execute("SELECT SUM(up),SUM(down) FROM measured").fetchone()),(6,11))
            self.store.set_user("alice",False)
            snapshot(101,201,now+1,boot="two");metrics.read()
            self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM measured").fetchone()[0],0)
            metrics.write_policy()
            self.assertEqual(json.loads((Path(directory)/"policy.json").read_text())["users"],{})


if __name__ == "__main__": unittest.main()
