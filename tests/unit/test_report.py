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
R.CHECKS_ORIG = dict(R.CHECKS)
R.JAIL_PORTS_ORIG = R.jail_ports


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


SSHD = {"permitrootlogin": "prohibit-password", "passwordauthentication": "no",
        "kbdinteractiveauthentication": "no", "usepam": "yes", "permitemptypasswords": "no",
        "maxauthtries": "6", "ports": [22]}


def auth(hours_ago, msg):
    return (time.time() - hours_ago * 3600, "host sshd-session[42]: " + msg)


def section(text, title):
    return text.split(title, 1)[1].split("\n\n", 1)[0]


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
        # Sources système factices : aucun test ne lit la machine qui l'exécute
        self.auth = []
        self.sshd = dict(SSHD)
        self.jports = {22}
        self.fw = "table inet f2b-table {\n set addr-set-sshd {\n  elements = { 203.0.113.7 }\n }\n}"
        R.read_auth_lines = lambda since, until: (self.auth, "test")
        R.sshd_effective_config = lambda: self.sshd
        R.jail_ports = lambda jail="sshd": self.jports
        R.firewall_dump = lambda: self.fw
        R.passwd_accounts = lambda: {"root": "/bin/bash", "xav": "/bin/bash",
                                     "www-data": "/usr/sbin/nologin"}
        R.db_purge_age = lambda: 90 * 86400

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


    # -- contrôles de sécurité ---------------------------------------------------
    def test_checks_all_ok(self):
        make_db(self.db, [("sshd", "203.0.113.7", days_ago(1))])
        rc, text = self.run_report("--until-now")
        self.assertEqual(rc, 0)
        checks = section(text, "CONTRÔLES DE SÉCURITÉ")
        for title in R.CHECK_TITLES.values():
            self.assertIn(title, checks)
        self.assertNotIn("[ALERTE]", checks)
        self.assertNotIn("[ATTENTION]", checks)
        self.assertIn("tous présents dans le pare-feu", checks)
        self.assertIn("intégrité ok", checks)

    def test_ssh_login_from_banned_ip_is_alert(self):
        make_db(self.db, [("sshd", "203.0.113.7", days_ago(1))])
        self.auth = [auth(2, "Accepted publickey for xav from 203.0.113.7 port 50022 ssh2: ED25519"),
                     auth(1, "Accepted password for root from 198.51.100.5 port 4022 ssh2")]
        rc, text = self.run_report("--until-now")
        checks = section(text, "CONTRÔLES DE SÉCURITÉ")
        self.assertIn("[ALERTE]     Connexions SSH réussies", checks)
        self.assertIn("xav@203.0.113.7", checks)
        self.assertIn("IP BANNIE par Fail2ban", checks)
        self.assertIn("par mot de passe", checks)
        self.assertIn("/!\\ Connexions SSH réussies", text)  # remonté en tête
        # Mémorisation des sources, puis « source jamais vue » au rapport suivant
        self.run_report("--until-now", "--save-state")
        with open(self.state) as fh:
            self.assertIn("198.51.100.5", json.load(fh)["ssh_sources"])
        self.auth = [auth(1, "Accepted publickey for xav from 198.51.100.77 port 1 ssh2")]
        rc, text = self.run_report("--until-now")
        self.assertIn("source jamais vue", section(text, "CONTRÔLES DE SÉCURITÉ"))

    def test_lan_login_from_internet_is_alert(self):
        make_db(self.db, [])
        self.auth = [auth(1, "Accepted publickey for xav from 192.168.1.10 port 1 ssh2"),
                     auth(1, "Accepted publickey for xav from 198.51.100.9 port 1 ssh2")]
        rc, text = self.run_report("--until-now", "--profile", "lan")
        checks = section(text, "CONTRÔLES DE SÉCURITÉ")
        self.assertIn("depuis Internet sur une machine LAN", checks)
        self.assertNotIn("192.168.1.10 ", checks.split("depuis Internet")[0].split("\n")[-1])

    def test_sshd_port_not_covered_by_jail(self):
        make_db(self.db, [])
        self.sshd["ports"] = [2222]
        rc, text = self.run_report("--until-now")
        self.assertIn("sshd écoute sur 2222 mais la jail sshd ne protège pas 2222", text)
        self.assertIn("/!\\ Configuration effective de sshd", text)
        self.jports = "all"
        rc, text = self.run_report("--until-now")
        self.assertNotIn("ne protège pas", text)

    def test_sshd_root_with_passwords(self):
        make_db(self.db, [])
        self.sshd.update(permitrootlogin="yes", passwordauthentication="yes")
        rc, text = self.run_report("--until-now")
        self.assertIn("[ALERTE]     Configuration effective de sshd", text)
        rc, text = self.run_report("--until-now", "--profile", "lan")
        self.assertIn("[ATTENTION]  Configuration effective de sshd", text)

    def test_ban_missing_from_firewall(self):
        make_db(self.db, [])
        self.fw = "# Generated by iptables-save\n-A f2b-sshd -s 198.51.100.0/24 -j REJECT\n"
        rc, text = self.run_report("--until-now")
        self.assertIn("1 sur 1 ban actif absent(s) du pare-feu", text)
        self.assertIn("sshd : 203.0.113.7", text)  # un /24 ne prouve pas le ban d'une IP
        self.fw = "-A f2b-sshd -s 203.0.113.7/32 -j REJECT --reject-with icmp-port-unreachable"
        rc, text = self.run_report("--until-now")
        self.assertIn("tous présents dans le pare-feu", text)
        self.fw = None
        rc, text = self.run_report("--until-now")
        self.assertIn("règles du pare-feu illisibles", text)

    def test_accounts_targeted(self):
        make_db(self.db, [])
        self.auth = [auth(3, "Invalid user admin from 198.51.100.1 port 1"),
                     auth(3, "Failed password for invalid user admin from 198.51.100.1 port 1 ssh2"),
                     auth(2, "Connection closed by authenticating user root 198.51.100.2 port 2 [preauth]"),
                     auth(1, "Failed publickey for xav from 198.51.100.3 port 3 ssh2")]
        rc, text = self.run_report("--until-now")
        chk = section(text, "CONTRÔLES DE SÉCURITÉ")
        self.assertIn("[ATTENTION]  Comptes visés", chk)
        self.assertIn("Comptes existants visés : root (1 IP), xav (1 IP)", chk)
        self.assertIn("compte(s) réel(s) non standard visé(s) : xav", chk)
        self.assertIn("Noms inexistants les plus essayés : admin (1)", chk)

    def test_checks_selection_and_isolation(self):
        make_db(self.db, [])
        rc, text = self.run_report("--no-checks")
        self.assertNotIn("CONTRÔLES", text)
        rc, text = self.run_report("--checks", "firewall")
        self.assertIn("Cohérence Fail2ban", text)
        self.assertNotIn("Comptes visés", text)
        rc, _ = self.run_report("--checks", "inconnu")
        self.assertEqual(rc, 2)

        def boom():
            raise RuntimeError("sshd explose")
        R.sshd_effective_config = boom
        R.CHECKS["firewall"] = lambda ctx: 1 / 0  # contrôle cassé ≠ rapport perdu
        try:
            rc, text = self.run_report("--until-now")
        finally:
            R.CHECKS["firewall"] = R.CHECKS_ORIG["firewall"]
        self.assertEqual(rc, 0)
        self.assertIn("contrôle impossible : division by zero", text)
        self.assertIn("« sshd -T » indisponible", text)

    def test_database_health(self):
        make_db(self.db, [("sshd", "203.0.113.7", days_ago(2))])
        rc, text = self.run_report("--until-now", "--days", "30")
        chk = section(text, "CONTRÔLES DE SÉCURITÉ")
        self.assertIn("1 ban, intégrité ok, purge après 90 j", chk)
        self.assertIn("l'historique ne commence que le", chk)
        os.unlink(self.db)
        rc, text = self.run_report("--until-now")
        self.assertIn("[ALERTE]     Base de données Fail2ban", text)


class ParsingTest(unittest.TestCase):
    def test_syslog_timestamps(self):
        ts, rest = R.parse_syslog_ts("2026-10-11T19:00:00.123456+02:00 h sshd[1]: x")
        self.assertEqual(ts, R.calendar.timegm((2026, 10, 11, 17, 0, 0)))
        self.assertEqual(rest, "h sshd[1]: x")
        ts, _ = R.parse_syslog_ts("2026-10-11T17:00:00Z h sshd: x")
        self.assertEqual(ts, R.calendar.timegm((2026, 10, 11, 17, 0, 0)))
        now = time.mktime(dt.datetime(2026, 1, 2, 12).timetuple())
        ts, rest = R.parse_syslog_ts("Dec 31 23:59:00 h auth.info sshd[2]: y", now=now)
        self.assertEqual(dt.datetime.fromtimestamp(ts).year, 2025)  # lu en janvier
        self.assertEqual(rest, "h auth.info sshd[2]: y")
        self.assertEqual(R.parse_syslog_ts("n'importe quoi")[0], None)

    def test_sshd_t(self):
        cfg = R.parse_sshd_t("port 22\nport 2222\npermitrootlogin without-password\n")
        self.assertEqual(cfg["ports"], [22, 2222])
        self.assertEqual(cfg["permitrootlogin"], "without-password")
        cfg = R.parse_sshd_t("port 22\nlistenaddress [::]:2200\nlistenaddress 0.0.0.0:2200\n")
        self.assertEqual(cfg["ports"], [2200])  # ListenAddress avec port prime

    def test_jail_ports(self):
        with tempfile.TemporaryDirectory() as etc:
            os.makedirs(os.path.join(etc, "jail.d"))
            with open(os.path.join(etc, "jail.conf"), "w") as fh:
                fh.write("[INCLUDES]\nbefore = paths-debian.conf\n[DEFAULT]\nport = 0:65535\n"
                         "logpath = %(sshd_log)s\n[sshd]\nport = ssh\n")
            self.assertEqual(R.JAIL_PORTS_ORIG("sshd", etc), {22})
            with open(os.path.join(etc, "jail.d", "10-x.local"), "w") as fh:
                fh.write("[sshd]\nenabled = true\nport = 22,2222  # commentaire\n")
            self.assertEqual(R.JAIL_PORTS_ORIG("sshd", etc), {22, 2222})
            self.assertEqual(R.JAIL_PORTS_ORIG("absente", etc), "all")  # [DEFAULT] hérité
        self.assertEqual(R.resolve_ports("2200:2202"), {2200, 2201, 2202})

    def test_firewall_dump_requires_a_real_listing(self):
        run, find = R.run, R.find_exe
        R.find_exe = lambda name: "/usr/sbin/" + name
        try:
            R.run = lambda cmd, timeout=20, check=True: None  # netlink refusé, droits…
            self.assertIsNone(R.firewall_dump())  # hosts.deny seul ne permet pas de conclure
            R.run = lambda cmd, timeout=20, check=True: "" if cmd[0].endswith("nft") else None
            self.assertIsNotNone(R.firewall_dump())  # ruleset vide = lecture réussie
        finally:
            R.run, R.find_exe = run, find

    def test_addresses_in(self):
        found = R.addresses_in("elements = { 203.0.113.7 timeout 1h, 2001:db8::5 }\n"
                               "-s 198.51.100.0/24 -j DROP\n-s 192.0.2.1/32\n")
        self.assertIn(R.ipaddress.ip_address("203.0.113.7"), found)
        self.assertIn(R.ipaddress.ip_address("2001:db8::5"), found)
        self.assertIn(R.ipaddress.ip_address("192.0.2.1"), found)
        self.assertNotIn(R.ipaddress.ip_address("198.51.100.0"), found)


if __name__ == "__main__":
    unittest.main()
