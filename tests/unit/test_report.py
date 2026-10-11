#!/usr/bin/env python3
"""Tests unitaires de scripts/fail2ban-report.py (base SQLite factice, sans fail2ban).

    python3 -m unittest discover -s tests/unit -v
"""
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
spec = importlib.util.spec_from_file_location(
    "f2b_report", os.path.join(ROOT, "scripts", "fail2ban-report.py"))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


def make_db(path, bans):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE bans(jail TEXT, ip TEXT, timeofban INTEGER, bantime INTEGER, "
                "bancount INTEGER, data JSON)")
    con.executemany("INSERT INTO bans VALUES (?,?,?,?,1,?)",
                    [(j, ip, int(ts), 86400, json.dumps({"failures": 5})) for j, ip, ts in bans])
    con.commit()
    con.close()


def days_ago(n, hour=12):
    d = dt.date.today() - dt.timedelta(days=n)
    return time.mktime(dt.datetime(d.year, d.month, d.day, hour).timetuple())


STATUS = {"sshd": {"failed_total": 10, "banned_now": 1, "banned_total": 3, "ips": {"203.0.113.7"}},
          "sshd-recidive": {"failed_total": 0, "banned_now": 0, "banned_total": 0, "ips": set()}}


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.db = os.path.join(d, "f2b.sqlite3")
        self.state = os.path.join(d, "state", "report-state.json")
        self.conf = os.path.join(d, "report.conf")
        with open(self.conf, "w") as fh:
            fh.write('F2B_DB="{}"\nREPORT_GEOIP=no\nREPORT_STATE={}\n'.format(self.db, self.state))
        self.status = dict(STATUS)
        R.jails_status = lambda: self.status

    def tearDown(self):
        self.tmp.cleanup()

    def run_report(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = R.main(["-c", self.conf, "--stdout", "--no-geoip"] + list(args))
        return rc, out.getvalue()

    def test_first_report_then_delta(self):
        make_db(self.db, [("sshd", "203.0.113.7", days_ago(3)), ("sshd", "203.0.113.7", days_ago(2)),
                          ("sshd", "198.51.100.1", days_ago(2)), ("sshd", "198.51.100.2", days_ago(1))])
        rc, text = self.run_report()
        self.assertEqual(rc, 0)
        self.assertIn("Premier rapport mémorisé", text)
        self.assertFalse(os.path.exists(self.state), "un aperçu ne doit pas mémoriser")

        rc, _ = self.run_report("--save-state")
        self.assertEqual(rc, 0)
        with open(self.state) as fh:
            st = json.load(fh)
        self.assertEqual(st["version"], R.STATE_VERSION)
        self.assertEqual(st["ips"]["203.0.113.7"], 2)
        self.assertIn("198.51.100.0/24", st["networks"])
        self.assertEqual(oct(os.stat(self.state).st_mode & 0o777), "0o600")

        # Jail disparue + IP déjà vue → nouveautés et alerte
        self.status = {"sshd": STATUS["sshd"]}
        rc, text = self.run_report()
        self.assertIn("Jail(s) disparue(s) : sshd-recidive", text)
        self.assertIn("déjà bannie(s) au rapport précédent", text)
        self.assertIn("/!\\ Jail(s) disparue(s)", text)

    def test_nothing_new(self):
        make_db(self.db, [("sshd", "203.0.113.7", days_ago(2))])
        self.run_report("--save-state")
        make_db_path = self.db + ".2"
        make_db(make_db_path, [("sshd", "192.0.2.50", days_ago(2))])
        rc, text = self.run_report("--no-state")
        self.assertIn("Premier rapport", text)  # --no-state ignore la mémoire
        with open(self.conf, "a") as fh:
            fh.write('F2B_DB="{}"\n'.format(make_db_path))
        rc, text = self.run_report()
        self.assertIn("Rien de nouveau", text)

    def test_lan_profile_alerts_on_internal_ip(self):
        make_db(self.db, [("sshd", "192.168.1.20", days_ago(1)), ("sshd", "203.0.113.7", days_ago(1))])
        rc, text = self.run_report("--profile", "lan")
        self.assertIn("Profil LAN : 1 IP interne bannie", text)
        self.assertIn("IP INTERNES BANNIES (profil LAN)", text)
        self.assertNotIn("203.0.113.7  ", text.split("IP INTERNES BANNIES")[1].split("BANS PAR JOUR")[0])
        rc, text = self.run_report("--profile", "vps")
        self.assertNotIn("Profil LAN", text)  # en VPS : section, pas d'alerte

    def test_is_internal(self):
        for ip in ("10.1.2.3", "172.16.5.10", "192.168.0.1", "100.64.0.1", "fd00::1",
                   "fe80::1", "::ffff:192.168.1.1"):
            self.assertTrue(R.is_internal(ip), ip)
        for ip in ("203.0.113.7", "198.51.100.1", "8.8.8.8", "2001:db8::1",
                   "172.32.0.1", "pas-une-ip"):
            self.assertFalse(R.is_internal(ip), ip)

    def test_month_period(self):
        first = dt.date.today().replace(day=1)
        last_month_end = first - dt.timedelta(days=1)
        ts_in = time.mktime(dt.datetime(last_month_end.year, last_month_end.month, 15, 12).timetuple())
        make_db(self.db, [("sshd", "203.0.113.9", ts_in), ("sshd", "203.0.113.10", time.time() - 60)])
        rc, text = self.run_report("--period", "month")
        self.assertEqual(rc, 0)
        self.assertIn(R.MONTHS[last_month_end.month - 1].capitalize(), text)
        self.assertIn("203.0.113.9", text)
        self.assertNotIn("203.0.113.10", text)  # mois en cours exclu

    def test_corrupt_state_is_ignored(self):
        make_db(self.db, [("sshd", "203.0.113.7", days_ago(1))])
        os.makedirs(os.path.dirname(self.state))
        with open(self.state, "w") as fh:
            fh.write("{pas du json")
        rc, text = self.run_report()
        self.assertEqual(rc, 0)
        self.assertIn("Premier rapport", text)

    def test_html_renders(self):
        make_db(self.db, [("sshd", "192.168.1.20", days_ago(1))])
        html_path = os.path.join(self.tmp.name, "r.html")
        rc, _ = self.run_report("--profile", "lan", "--html", html_path)
        with open(html_path, encoding="utf-8") as fh:
            doc = fh.read()
        self.assertIn("Nouveautés", doc)
        self.assertIn("IP internes bannies", doc)


if __name__ == "__main__":
    unittest.main()
