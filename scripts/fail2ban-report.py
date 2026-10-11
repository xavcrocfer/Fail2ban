#!/usr/bin/env python3
# Source de vérité : copié dans setup.sh par scripts/embed.py (voir --check).
__version__ = "dev"
# ==== corps embarqué dans setup.sh (ne rien mettre au-dessus) ====
#
# fail2ban-report — rapport des bannissements Fail2ban (texte + HTML) par email
#
# Sources : base SQLite de Fail2ban (historique des bans, conservé `dbpurgeage`)
#           et fail2ban-client (état courant des jails).
#
#   fail2ban-report                      génère et envoie le rapport
#   fail2ban-report --stdout             affiche la version texte (n'envoie rien)
#   fail2ban-report --html /tmp/r.html   écrit la version HTML (n'envoie rien)
#   fail2ban-report --days 30 --to moi@exemple.fr --until-now
#   fail2ban-report --period month       mois calendaire précédent
#
# Mémoire entre deux rapports (REPORT_STATE, JSON) : IP, réseaux, pays et jails du
# rapport précédent → section « Nouveautés » qui ne montre que ce qui a changé.
# Elle n'est mise à jour qu'après un envoi réussi (ou avec --save-state), jamais
# par un aperçu (--stdout, --html, --until-now).
#
# Profil (HOST_PROFILE) : « vps » (exposé à Internet) ou « lan » (réseau interne).
# En LAN, tout ban d'une IP interne est une anomalie et déclenche une alerte.
#
import argparse
import collections
import datetime as dt
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from urllib.parse import quote

DEFAULT_CONF = "/etc/fail2ban/report.conf"
DEFAULT_DB = "/var/lib/fail2ban/fail2ban.sqlite3"
DEFAULT_STATE = "/var/lib/fail2ban-setup/report-state.json"
STATE_VERSION = 1
STATE_MAX_ITEMS = 5000          # plafond par liste/dictionnaire mémorisé
PROFILES = ("vps", "lan")
MONTHS = ("janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août",
          "septembre", "octobre", "novembre", "décembre")
WEEKDAYS = ("lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim.")
WHOIS_COUNTRY = re.compile(r"^\s*country(?:-?code)?\s*:\s*([A-Za-z]{2})\b", re.I | re.M)

# Styles en ligne : la plupart des clients mail ignorent les feuilles de style.
INK, MUTED, LINE, BG = "#0f172a", "#64748b", "#e2e8f0", "#f1f5f9"
ACCENT, DANGER, SUCCESS = "#2563eb", "#dc2626", "#16a34a"
FONT = ("font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"
        "'Helvetica Neue',Arial,sans-serif;")
MONO = "font-family:SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;"

Ban = collections.namedtuple("Ban", "jail ip ts bantime failures")


# ----------------------------------------------------------------- utilitaires
def warn(msg):
    print("fail2ban-report: " + msg, file=sys.stderr)


def load_conf(path):
    """Lit un fichier CLÉ=valeur (guillemets optionnels, # = commentaire)."""
    conf = {}
    try:
        with open(path, encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                conf[key.strip()] = value
    except FileNotFoundError:
        pass
    return conf


def run(cmd, timeout=20, check=True):
    """Exécute une commande ; renvoie sa sortie standard, ou None en cas d'échec."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              universal_newlines=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if check and proc.returncode != 0:
        return None
    return proc.stdout


def fail2ban_client(*args):
    exe = shutil.which("fail2ban-client") or "/usr/bin/fail2ban-client"
    return run([exe] + list(args))


def as_bool(value, default=True):
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in ("1", "y", "yes", "o", "oui", "true", "on")


def plural(count, word, word_plural=None):
    return "{} {}".format(count, word if count <= 1 else (word_plural or word + "s"))


def fmt_day(day):
    return "{} {:%d/%m}".format(WEEKDAYS[day.weekday()], day)


def fmt_date(day):
    return "{} {:%d/%m/%Y}".format(WEEKDAYS[day.weekday()], day)


def fmt_ts(ts):
    moment = dt.datetime.fromtimestamp(ts)
    return "{} {:%d/%m %H:%M}".format(WEEKDAYS[moment.weekday()], moment)


def fmt_until(ban):
    if ban.bantime is None:
        return "?"
    if ban.bantime < 0:
        return "permanent"
    end = dt.datetime.fromtimestamp(ban.ts + ban.bantime)
    return "{:%d/%m/%Y %H:%M}".format(end)


def na(value):
    return "n/d" if value is None else str(value)


def flag(country):
    """Code pays ISO → drapeau emoji (indicateurs régionaux Unicode)."""
    if len(country) != 2 or not country.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country.upper())


def network_of(ip):
    """Regroupe les IP par /24 (IPv4) ou /64 (IPv6)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network("{}/{}".format(addr, prefix), strict=False))


# Réseaux internes : RFC 1918, CGNAT, lien local, boucle locale, ULA IPv6.
# Liste explicite : is_global/is_private rangent aussi les plages de documentation
# (192.0.2.0/24, 203.0.113.0/24…) dans le « non global ».
INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128"))


def is_internal(ip):
    """IP d'un réseau interne (voir INTERNAL_NETS)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in INTERNAL_NETS if net.version == addr.version)


def load_state(path):
    """État du rapport précédent, ou None (absent, illisible, autre version)."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        warn("état {} illisible ({}) : ignoré".format(path, exc))
        return None
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        warn("état {} d'un format inconnu : ignoré".format(path))
        return None
    return data


def save_state(path, data):
    """Écriture atomique (fichier temporaire + rename), lisible par root seul."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".report-state.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def capped(items, limit=STATE_MAX_ITEMS):
    return sorted(items)[:limit]


def whois_country(ip):
    exe = shutil.which("whois")
    if not exe:
        return ""
    match = WHOIS_COUNTRY.search(run([exe, ip], timeout=15, check=False) or "")
    return match.group(1).upper() if match else ""


def lookup_countries(ips):
    if not ips or not shutil.which("whois"):
        return {}
    with ThreadPoolExecutor(max_workers=min(8, len(ips))) as pool:
        return dict(zip(ips, pool.map(whois_country, ips)))


# ----------------------------------------------------------------- données
def find_db(conf):
    if conf.get("F2B_DB"):
        return conf["F2B_DB"]
    out = fail2ban_client("get", "dbfile")
    if out:
        match = re.search(r"(/\S+)\s*$", out.strip())
        if match:
            return match.group(1)
    return DEFAULT_DB


def load_history(db_path, since, until, prev_since):
    """Bans de [since, until), nb de bans de la période précédente, IP déjà vues."""
    if not os.path.exists(db_path):
        raise RuntimeError("base introuvable")
    con = sqlite3.connect("file:{}?mode=ro".format(quote(db_path)), uri=True, timeout=30)
    try:
        cols = {row[1] for row in con.execute("PRAGMA table_info(bans)")}
        if not cols:
            raise RuntimeError("table « bans » absente")
        bantime_col = "bantime" if "bantime" in cols else "NULL"
        rows = con.execute(
            "SELECT jail, ip, timeofban, {}, data FROM bans "
            "WHERE timeofban >= ? AND timeofban < ? ORDER BY timeofban".format(bantime_col),
            (int(since), int(until))).fetchall()
        prev_count = con.execute(
            "SELECT COUNT(*) FROM bans WHERE timeofban >= ? AND timeofban < ?",
            (int(prev_since), int(since))).fetchone()[0]
        seen_before = {row[0] for row in con.execute(
            "SELECT DISTINCT ip FROM bans WHERE timeofban < ?", (int(since),))}
        oldest = con.execute("SELECT MIN(timeofban) FROM bans").fetchone()[0]
    finally:
        con.close()

    bans = []
    for jail, ip, ts, bantime, data in rows:
        failures = 0
        if data:
            try:
                failures = int(json.loads(data).get("failures") or 0)
            except (ValueError, TypeError, AttributeError):
                pass
        bans.append(Ban(jail, ip, int(ts), bantime, failures))
    # Pas de comparaison si la base ne couvre pas la période précédente
    if oldest is None or oldest > prev_since + 86400:
        prev_count = None
    return bans, prev_count, seen_before


def _count(text, label):
    match = re.search(re.escape(label) + r":\s*(\d+)", text)
    return int(match.group(1)) if match else 0


def jails_status():
    """État courant de chaque jail, ou None si fail2ban ne répond pas."""
    out = fail2ban_client("status")
    if out is None:
        return None
    match = re.search(r"Jail list:\s*(.*)", out)
    names = [n.strip() for n in match.group(1).split(",") if n.strip()] if match else []
    status = collections.OrderedDict()
    for name in names:
        text = fail2ban_client("status", name) or ""
        ips = re.search(r"Banned IP list:\s*(.*)", text)
        status[name] = {
            "failed_total": _count(text, "Total failed"),
            "banned_now": _count(text, "Currently banned"),
            "banned_total": _count(text, "Total banned"),
            "ips": set(ips.group(1).split()) if ips else set(),
        }
    return status


# ----------------------------------------------------------------- rapport
class Report(object):
    """Agrège les bans d'une période et produit les versions texte et HTML."""

    def __init__(self, host, days, bans, prev_count, seen_before, status, alerts,
                 top_n=10, geoip=True, db_path="", profile="vps", prev_state=None,
                 period_label=None):
        self.host = host
        self.profile = profile if profile in PROFILES else "vps"
        self.prev_state = prev_state
        self._period_label = period_label
        self.days = days
        self.prev_count = prev_count
        self.status = status
        self.alerts = list(alerts)
        self.db_path = db_path
        self.generated = dt.datetime.now()

        per_ip = collections.Counter(b.ip for b in bans)
        self.total = len(bans)
        self.unique = len(per_ip)
        self.new_ips = sum(1 for ip in per_ip if ip not in seen_before)

        per_day = collections.Counter(dt.date.fromtimestamp(b.ts) for b in bans)
        self.per_day = [(day, per_day.get(day, 0)) for day in days]

        per_jail = collections.Counter(b.jail for b in bans)
        self.jails = []
        for name in sorted(set(per_jail) | set(status or {})):
            st = (status or {}).get(name)
            self.jails.append({
                "name": name,
                "bans": per_jail.get(name, 0),
                "active": st["banned_now"] if st else None,
                "total": st["banned_total"] if st else None,
                "failed": st["failed_total"] if st else None,
            })
        self.banned_now = (sum(s["banned_now"] for s in status.values())
                           if status is not None else None)

        active_ips = set()
        for st in (status or {}).values():
            active_ips |= st["ips"]
        last_seen, ip_jails = {}, collections.defaultdict(set)
        for ban in bans:
            last_seen[ban.ip] = max(last_seen.get(ban.ip, 0), ban.ts)
            ip_jails[ban.ip].add(ban.jail)
        top = per_ip.most_common(top_n)
        # Cache des pays issu de l'état : pas de whois répété d'un rapport à l'autre
        self.geo = dict((prev_state or {}).get("geo") or {})
        if geoip:
            missing = [ip for ip, _ in top if ip not in self.geo]
            self.geo.update(lookup_countries(missing))
        countries = self.geo
        self.top_ips = [{
            "ip": ip, "count": count, "jails": sorted(ip_jails[ip]),
            "last": last_seen[ip], "country": countries.get(ip, ""),
            "active": ip in active_ips,
        } for ip, count in top]

        nets, net_ips = collections.Counter(), collections.defaultdict(set)
        for ban in bans:
            net = network_of(ban.ip)
            nets[net] += 1
            net_ips[net].add(ban.ip)
        self.networks = [{"net": net, "count": count, "ips": len(net_ips[net])}
                         for net, count in nets.most_common()
                         if len(net_ips[net]) > 1][:top_n]

        self.recidives = sorted((b for b in bans if "recidive" in b.jail),
                                key=lambda b: b.ts, reverse=True)

        # IP internes bannies : anomalie en LAN (poste compromis, scan, liste blanche)
        self.internal = [{"ip": ip, "count": count, "jails": sorted(ip_jails[ip]),
                          "last": last_seen[ip], "active": ip in active_ips}
                         for ip, count in per_ip.most_common() if is_internal(ip)]
        if self.internal and self.profile == "lan":
            self.alerts.append(
                "Profil LAN : {} bannie(s) depuis le réseau interne ({}) — poste compromis, "
                "scan interne ou liste blanche incomplète ?".format(
                    plural(len(self.internal), "IP interne", "IP internes"),
                    ", ".join(i["ip"] for i in self.internal[:5])
                    + (" …" if len(self.internal) > 5 else "")))

        self._per_ip = per_ip
        self._all_nets = {net for net in net_ips if len(net_ips[net]) > 1}
        self.delta = self._compute_delta(top_n)

    # -- mémoire entre rapports -----------------------------------------------
    def _current_jails(self):
        return set(self.status) if self.status is not None else None

    def _compute_delta(self, top_n):
        prev = self.prev_state
        if not prev:
            return None
        prev_ips = set(prev.get("ips") or {})
        returning = sorted((ip for ip in self._per_ip if ip in prev_ips),
                           key=lambda ip: (-self._per_ip[ip], ip))
        known_nets = set(prev.get("networks") or [])
        known_countries = set(prev.get("countries") or [])
        jails_now, jails_prev = self._current_jails(), set(prev.get("jails") or [])
        delta = {
            "since": prev.get("generated"),
            "prev_total": prev.get("total"),
            "returning": [{"ip": ip, "count": self._per_ip[ip],
                           "before": (prev.get("ips") or {}).get(ip, 0)}
                          for ip in returning[:top_n]],
            "returning_count": len(returning),
            "new_networks": [n for n in self.networks if n["net"] not in known_nets],
            "new_countries": sorted({i["country"] for i in self.top_ips if i["country"]}
                                    - known_countries),
            "jails_added": sorted(jails_now - jails_prev) if jails_now is not None else [],
            "jails_removed": sorted(jails_prev - jails_now) if jails_now is not None else [],
        }
        if delta["jails_removed"]:
            self.alerts.append("Jail(s) disparue(s) depuis le rapport précédent : "
                               + ", ".join(delta["jails_removed"]))
        return delta

    def has_news(self):
        d = self.delta
        return bool(d and (d["returning"] or d["new_networks"] or d["new_countries"]
                           or d["jails_added"] or d["jails_removed"]))

    def state_snapshot(self, since, until):
        """État à mémoriser : cumulatif pour pays/réseaux, période courante pour les IP."""
        prev = self.prev_state or {}
        jails = self._current_jails()
        if jails is None:  # fail2ban muet : on garde la référence précédente
            jails = set(prev.get("jails") or [])
        return {
            "version": STATE_VERSION,
            "generated": int(time.time()),
            "since": int(since), "until": int(until),
            "profile": self.profile,
            "total": self.total, "unique": self.unique,
            "ips": dict(self._per_ip.most_common(STATE_MAX_ITEMS)),
            "networks": capped(set(prev.get("networks") or []) | self._all_nets),
            "countries": capped(set(prev.get("countries") or [])
                                | {c for c in self.geo.values() if c}),
            "jails": sorted(jails),
            "geo": {ip: self.geo[ip] for ip in capped(self.geo)},
        }

    # -- libellés -------------------------------------------------------------
    def period_label(self):
        if self._period_label:
            return self._period_label
        return "Du {} au {} ({})".format(fmt_date(self.days[0]), fmt_date(self.days[-1]),
                                         plural(len(self.days), "jour"))

    def trend(self):
        """(texte, couleur) de l'évolution par rapport à la période précédente."""
        if self.prev_count is None and self.delta and self.delta["prev_total"] is not None:
            # Base trop courte : comparaison avec le rapport précédent mémorisé
            self.prev_count = self.delta["prev_total"]
        if self.prev_count is None:
            return "pas d'historique", MUTED
        if self.prev_count == 0:
            return ("0 la période préc." if self.total else "stable"), MUTED
        delta = (self.total - self.prev_count) * 100.0 / self.prev_count
        if abs(delta) < 0.5:
            return "stable (préc. : {})".format(self.prev_count), MUTED
        return ("{} {:+.0f} % (préc. : {})".format(
            "▲" if delta > 0 else "▼", delta, self.prev_count),
            DANGER if delta > 0 else SUCCESS)

    def subject(self, prefix):
        if self.profile == "lan":
            prefix = "{} [LAN]".format(prefix).strip()
        return "{} {}{} : {}, {} — {:%d/%m} → {:%d/%m}".format(
            prefix, "⚠ " if self.alerts else "", self.host,
            plural(self.total, "ban"), plural(self.unique, "IP", "IP"),
            self.days[0], self.days[-1]).strip()

    # -- version texte --------------------------------------------------------
    def as_text(self):
        out = []
        add = out.append
        add("RAPPORT FAIL2BAN — {}".format(self.host))
        add(self.period_label())
        add("=" * 78)
        for alert in self.alerts:
            add("/!\\ " + alert)
        if self.alerts:
            add("")

        add("SYNTHÈSE")
        add("  Bans ................ {:>6}   {}".format(self.total, self.trend()[0]))
        add("  IP uniques .......... {:>6}   (dont {} jamais vue(s) auparavant)".format(
            self.unique, self.new_ips))
        add("  Récidives ........... {:>6}".format(len(self.recidives)))
        add("  Bans actifs ......... {:>6}".format(na(self.banned_now)))
        add("")

        add("NOUVEAUTÉS " + self.delta_title().upper())
        for line in self.delta_lines():
            add("  " + line)
        add("")

        if self.internal:
            add("IP INTERNES BANNIES (profil {})".format(self.profile.upper()))
            for item in self.internal:
                add("  {:<39} {:>5} ban(s)  {:<24} {}{}".format(
                    item["ip"], item["count"], ",".join(item["jails"]), fmt_ts(item["last"]),
                    "  [banni]" if item["active"] else ""))
            add("")

        add("BANS PAR JOUR")
        peak = max([count for _, count in self.per_day] + [1])
        for day, count in self.per_day:
            add("  {:<11} {:>5}  {}".format(fmt_day(day), count,
                                            "█" * int(round(count * 40.0 / peak))))
        add("")

        add("PAR JAIL")
        add("  {:<24} {:>8} {:>8} {:>10} {:>10}".format("Jail", "Bans", "Actifs",
                                                      "Total*", "Échecs*"))
        for jail in self.jails:
            add("  {:<24} {:>8} {:>8} {:>10} {:>10}".format(
                jail["name"], jail["bans"], na(jail["active"]), na(jail["total"]),
                na(jail["failed"])))
        add("  * depuis le dernier démarrage de Fail2ban")
        add("")

        add("TOP DES IP")
        if not self.top_ips:
            add("  Aucun ban sur la période.")
        else:
            add("  {:>2}  {:<39} {:<4} {:>5}  {:<24} {}".format(
                "#", "IP", "Pays", "Bans", "Jails", "Dernier ban"))
            for rank, item in enumerate(self.top_ips, 1):
                add("  {:>2}  {:<39} {:<4} {:>5}  {:<24} {}{}".format(
                    rank, item["ip"], item["country"] or "-", item["count"],
                    ",".join(item["jails"]), fmt_ts(item["last"]),
                    "  [banni]" if item["active"] else ""))
        add("")

        if self.networks:
            add("RÉSEAUX LES PLUS ACTIFS (plusieurs IP d'un même /24 ou /64)")
            for item in self.networks:
                add("  {:<43} {:>5} bans  {:>4} IP".format(item["net"], item["count"],
                                                         item["ips"]))
            add("")

        add("RÉCIDIVES DE LA PÉRIODE (bannies sur tous les ports)")
        if not self.recidives:
            add("  Aucune.")
        for ban in self.recidives:
            add("  {:<39} le {}  →  jusqu'au {}".format(ban.ip, fmt_ts(ban.ts),
                                                       fmt_until(ban)))
        add("")
        add("-" * 78)
        add("Généré le {:%d/%m/%Y à %H:%M} par fail2ban-report {} — base : {}".format(
            self.generated, __version__, self.db_path))
        return "\n".join(out) + "\n"

    # -- nouveautés (communes texte / HTML) ------------------------------------
    def delta_title(self):
        if not self.delta:
            return "depuis le rapport précédent"
        since = self.delta.get("since")
        if not since:
            return "depuis le rapport précédent"
        return "depuis le rapport du {:%d/%m/%Y}".format(dt.datetime.fromtimestamp(since))

    def delta_lines(self):
        """Lignes en texte brut ; vide = rien à signaler."""
        d = self.delta
        if d is None:
            return ["Premier rapport mémorisé : les nouveautés apparaîtront au prochain envoi."]
        lines = []
        if d["jails_removed"]:
            lines.append("Jail(s) disparue(s) : " + ", ".join(d["jails_removed"]))
        if d["jails_added"]:
            lines.append("Nouvelle(s) jail(s) : " + ", ".join(d["jails_added"]))
        if d["new_countries"]:
            lines.append("Nouveau(x) pays dans le top : " + ", ".join(
                "{} {}".format(flag(c), c).strip() for c in d["new_countries"]))
        for net in d["new_networks"]:
            lines.append("Nouveau réseau actif : {} ({} bans, {} IP)".format(
                net["net"], net["count"], net["ips"]))
        if d["returning"]:
            lines.append("{} déjà bannie(s) au rapport précédent :".format(
                plural(d["returning_count"], "IP", "IP")))
            for item in d["returning"]:
                lines.append("  {:<39} {:>4} ban(s) (préc. : {})".format(
                    item["ip"], item["count"], item["before"]))
        return lines or ["Rien de nouveau : mêmes jails, pas de nouveau pays ni réseau, "
                         "aucune IP du rapport précédent."]

    # -- version HTML ---------------------------------------------------------
    @staticmethod
    def _section(title, body):
        return ('<tr><td style="padding:24px 28px 0">'
                '<div style="font-size:15px;font-weight:700;color:{};margin:0 0 10px">{}</div>'
                '{}</td></tr>').format(INK, html.escape(title), body)

    @staticmethod
    def _table(headers, rows, aligns):
        head = "".join(
            '<th align="{}" style="padding:6px 8px;font-size:11px;font-weight:600;color:{};'
            'text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid {}">{}</th>'
            .format(align, MUTED, LINE, html.escape(label))
            for label, align in zip(headers, aligns))
        body = "\n".join(
            "<tr>{}</tr>".format("".join(
                '<td align="{}" style="padding:7px 8px;font-size:14px;color:{};'
                'border-bottom:1px solid #f1f5f9">{}</td>'.format(align, INK, cell)
                for cell, align in zip(row, aligns)))
            for row in rows)
        return ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                'style="border-collapse:collapse">\n<tr>{}</tr>\n{}\n</table>').format(head, body)

    @staticmethod
    def _empty(text):
        return '<div style="font-size:14px;color:{}">{}</div>'.format(MUTED, html.escape(text))

    def as_html(self):
        esc = html.escape

        def mono(value):
            return '<span style="{}font-size:13px">{}</span>'.format(MONO, esc(value))

        rows = []

        rows.append(
            '<tr><td style="background:{};padding:24px 28px">'
            '<div style="font-size:12px;letter-spacing:.08em;text-transform:uppercase;'
            'color:#94a3b8">Rapport Fail2ban</div>'
            '<div style="font-size:22px;font-weight:700;margin-top:4px;color:#ffffff">{}</div>'
            '<div style="font-size:14px;margin-top:6px;color:#cbd5e1">{}</div>'
            '</td></tr>'.format(INK, esc(self.host), esc(self.period_label())))

        for alert in self.alerts:
            rows.append(
                '<tr><td style="padding:20px 28px 0"><div style="background:#fef2f2;'
                'border:1px solid #fecaca;border-radius:8px;padding:10px 14px;color:#991b1b;'
                'font-size:14px">&#9888;&nbsp;{}</div></td></tr>'.format(esc(alert)))

        trend_text, trend_color = self.trend()
        tiles = (
            ("Bans", str(self.total), trend_text, trend_color),
            ("IP uniques", str(self.unique), "dont {} nouvelle(s)".format(self.new_ips), MUTED),
            ("Récidives", str(len(self.recidives)), "bannies tous ports",
             DANGER if self.recidives else MUTED),
            ("Bans actifs", na(self.banned_now), "en ce moment", MUTED),
        )
        cells = "".join(
            '<td width="25%" valign="top" style="padding:6px">'
            '<div style="background:#f8fafc;border:1px solid {line};border-radius:10px;'
            'padding:12px 14px">'
            '<div style="font-size:11px;color:{muted};text-transform:uppercase;'
            'letter-spacing:.05em">{label}</div>'
            '<div style="font-size:26px;font-weight:700;color:{ink};margin-top:2px">{value}</div>'
            '<div style="font-size:12px;color:{color};margin-top:2px">{sub}</div>'
            '</div></td>'.format(line=LINE, muted=MUTED, ink=INK, label=esc(label),
                                 value=esc(value), sub=esc(sub), color=color)
            for label, value, sub, color in tiles)
        rows.append('<tr><td style="padding:18px 22px 0"><table role="presentation" '
                    'width="100%" cellpadding="0" cellspacing="0"><tr>{}</tr></table>'
                    '</td></tr>'.format(cells))

        news = self.delta_lines()
        rows.append(self._section(
            "Nouveautés " + self.delta_title(),
            '<ul style="margin:0;padding-left:18px;font-size:14px;line-height:1.6;color:{}">'
            '{}</ul>'.format(INK if self.has_news() else MUTED, "".join(
                '<li style="{}">{}</li>'.format(
                    MONO + "font-size:13px;list-style:none" if line.startswith("  ") else "",
                    esc(line.strip())) for line in news))))

        if self.internal:
            int_rows = [[mono(i["ip"]), str(i["count"]), esc(", ".join(i["jails"])),
                         esc(fmt_ts(i["last"]))] for i in self.internal]
            rows.append(self._section(
                "IP internes bannies (profil {})".format(self.profile.upper()),
                self._table(["IP", "Bans", "Jails", "Dernier ban"], int_rows,
                            ["left", "right", "left", "left"])))

        peak = max([count for _, count in self.per_day] + [1])
        bars = []
        for day, count in self.per_day:
            width = int(round(count * 100.0 / peak))
            fill = ('<td width="{w}%" bgcolor="{c}" style="background:{c};border-radius:3px;'
                    'font-size:1px;line-height:14px">&nbsp;</td>'.format(w=width, c=ACCENT)
                    if width else "")
            bars.append(
                '<tr><td width="92" style="padding:5px 8px;font-size:14px;color:{ink};'
                'white-space:nowrap">{day}</td>'
                '<td width="100%" style="padding:5px 8px"><table role="presentation" width="100%" '
                'cellpadding="0" cellspacing="0"><tr>{fill}<td style="font-size:1px;'
                'line-height:14px">&nbsp;</td></tr></table></td>'
                '<td width="48" align="right" style="padding:5px 8px;font-size:14px;color:{ink};'
                'font-weight:700">{count}</td></tr>'.format(
                    ink=INK, day=esc(fmt_day(day)), fill=fill, count=count))
        rows.append(self._section(
            "Bans par jour",
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">\n'
            + "\n".join(bars) + "\n</table>"))

        jail_rows = [[mono(j["name"]), str(j["bans"]), na(j["active"]), na(j["total"]),
                      na(j["failed"])] for j in self.jails]
        rows.append(self._section(
            "Par jail",
            (self._table(["Jail", "Bans période", "Actifs", "Total*", "Échecs*"], jail_rows,
                         ["left", "right", "right", "right", "right"])
             + '<div style="font-size:12px;color:{};margin-top:6px">* depuis le dernier '
               'démarrage de Fail2ban</div>'.format(MUTED))
            if jail_rows else self._empty("Aucune jail active.")))

        top_rows = []
        for rank, item in enumerate(self.top_ips, 1):
            country = item["country"]
            badge = (' <span style="background:#fee2e2;color:#991b1b;border-radius:9px;'
                     'padding:1px 7px;font-size:11px">banni</span>' if item["active"] else "")
            top_rows.append([
                str(rank), mono(item["ip"]) + badge,
                "{} {}".format(flag(country), esc(country)).strip() or "–",
                "<b>{}</b>".format(item["count"]), esc(", ".join(item["jails"])),
                esc(fmt_ts(item["last"]))])
        rows.append(self._section(
            "Top des IP",
            self._table(["#", "IP", "Pays", "Bans", "Jails", "Dernier ban"], top_rows,
                        ["right", "left", "left", "right", "left", "left"])
            if top_rows else self._empty("Aucun ban sur la période.")))

        if self.networks:
            net_rows = [[mono(n["net"]), str(n["count"]), str(n["ips"])] for n in self.networks]
            rows.append(self._section(
                "Réseaux les plus actifs",
                self._table(["Réseau", "Bans", "IP distinctes"], net_rows,
                            ["left", "right", "right"])))

        rec_rows = [[mono(b.ip), esc(fmt_ts(b.ts)), esc(fmt_until(b))] for b in self.recidives]
        rows.append(self._section(
            "Récidives de la période",
            self._table(["IP", "Bannie le", "Jusqu'au"], rec_rows, ["left", "left", "left"])
            if rec_rows else self._empty("Aucune récidive.")))

        rows.append(
            '<tr><td style="padding:24px 28px 26px"><div style="border-top:1px solid {};'
            'padding-top:14px;font-size:12px;line-height:1.6;color:{}">'
            'Débannir une IP : <span style="{}">fail2ban-client set &lt;jail&gt; unbanip '
            '&lt;IP&gt;</span><br>Généré le {} par fail2ban-report {} — base {}</div>'
            '</td></tr>'.format(LINE, MUTED, MONO,
                                esc("{:%d/%m/%Y à %H:%M}".format(self.generated)),
                                esc(__version__), esc(self.db_path)))

        return "\n".join([
            '<!DOCTYPE html>',
            '<html lang="fr"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            '<title>Rapport Fail2ban — {}</title></head>'.format(esc(self.host)),
            '<body style="margin:0;padding:0;background:{};{}">'.format(BG, FONT),
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="background:{}"><tr><td align="center" style="padding:24px 10px">'.format(BG),
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="max-width:700px;background:#ffffff;border:1px solid {};border-radius:12px;'
            'overflow:hidden">'.format(LINE),
        ] + rows + ['</table></td></tr></table></body></html>'])


# ----------------------------------------------------------------- envoi
def build_message(conf, recipients, subject, text, html_doc, host):
    sender = conf.get("REPORT_FROM") or "root@" + host
    msg = EmailMessage()
    msg["From"] = formataddr((conf.get("REPORT_FROM_NAME") or "Fail2ban", sender))
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender.rpartition("@")[2] or None)
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Mailer"] = "fail2ban-report " + __version__
    msg.set_content(text)
    msg.add_alternative(html_doc, subtype="html")
    return msg, sender


def send(msg, sender, conf):
    """Envoi via sendmail (Postfix, Exim, msmtp…) ou, à défaut, SMTP local."""
    sendmail = conf.get("SENDMAIL") or shutil.which("sendmail")
    if not sendmail:
        sendmail = next((p for p in ("/usr/sbin/sendmail", "/usr/lib/sendmail")
                         if os.access(p, os.X_OK)), None)
    if sendmail:
        proc = subprocess.run([sendmail, "-t", "-oi", "-f", sender], input=msg.as_bytes(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if proc.returncode != 0:
            raise RuntimeError("{} a échoué (code {}) : {}".format(
                sendmail, proc.returncode, proc.stderr.decode("utf-8", "replace").strip()))
        return sendmail
    import smtplib
    host = conf.get("SMTP_HOST") or "localhost"
    port = int(conf.get("SMTP_PORT") or 25)
    with smtplib.SMTP(host, port, timeout=60) as smtp:
        smtp.send_message(msg)
    return "smtp://{}:{}".format(host, port)


# ----------------------------------------------------------------- main
def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="fail2ban-report",
        description="Rapport des bannissements Fail2ban (texte + HTML) envoyé par email.")
    parser.add_argument("-c", "--config", default=DEFAULT_CONF,
                        help="fichier de configuration (défaut : %(default)s)")
    parser.add_argument("-d", "--days", type=int,
                        help="nombre de jours couverts (défaut : REPORT_DAYS ou 7)")
    parser.add_argument("--to", help="destinataire(s), remplace REPORT_TO")
    parser.add_argument("--stdout", action="store_true",
                        help="affiche la version texte sans envoyer d'email")
    parser.add_argument("--html", metavar="FICHIER",
                        help="écrit la version HTML dans FICHIER sans envoyer d'email")
    parser.add_argument("--until-now", action="store_true",
                        help="inclut la journée en cours (par défaut : jusqu'à minuit)")
    parser.add_argument("--period", choices=("days", "month"),
                        help="« days » : N derniers jours (défaut) ; « month » : mois "
                             "calendaire précédent (défaut : REPORT_PERIOD)")
    parser.add_argument("--profile", choices=PROFILES, help="remplace HOST_PROFILE")
    parser.add_argument("--state", metavar="FICHIER",
                        help="mémoire entre rapports (défaut : REPORT_STATE ou %s)" % DEFAULT_STATE)
    parser.add_argument("--no-state", action="store_true",
                        help="ignore la mémoire (ni lecture ni écriture)")
    parser.add_argument("--save-state", action="store_true",
                        help="mémorise ce rapport même sans envoi (aperçu, --until-now)")
    parser.add_argument("--no-geoip", action="store_true", help="pas de recherche whois")
    parser.add_argument("-q", "--quiet", action="store_true", help="aucun message si succès")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s " + __version__)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    conf = load_conf(args.config)
    try:
        days = args.days or int(conf.get("REPORT_DAYS") or 7)
        top_n = int(conf.get("REPORT_TOP") or 10)
    except ValueError:
        warn("REPORT_DAYS / REPORT_TOP doivent être des entiers")
        return 2
    if days < 1:
        warn("--days doit être >= 1")
        return 2
    host = conf.get("REPORT_HOSTNAME") or socket.getfqdn()

    period = args.period or (conf.get("REPORT_PERIOD") or "days").strip().lower()
    if period not in ("days", "month"):
        warn("REPORT_PERIOD invalide : {} (days|month)".format(period))
        return 2
    profile = args.profile or (conf.get("HOST_PROFILE") or "vps").strip().lower()
    if profile not in PROFILES:
        warn("HOST_PROFILE invalide : {} ({}) — « vps » utilisé".format(profile, "|".join(PROFILES)))
        profile = "vps"

    # Période : jours calendaires complets, se terminant hier soir à minuit
    # (ou maintenant avec --until-now). Bornes calculées en heure locale.
    today = dt.date.today()
    label = None
    if period == "month":
        # Mois précédent complet (mois en cours avec --until-now)
        end = today if args.until_now else today.replace(day=1) - dt.timedelta(days=1)
        first = end.replace(day=1)
        days = (end - first).days + 1
        until = time.time() if args.until_now else time.mktime(today.replace(day=1).timetuple())
        prev_first = (first - dt.timedelta(days=1)).replace(day=1)
        prev_since = time.mktime(prev_first.timetuple())
        label = "{} {} ({}{})".format(MONTHS[first.month - 1].capitalize(), first.year,
                                     plural(days, "jour"), ", en cours" if args.until_now else "")
    elif args.until_now:
        first = today - dt.timedelta(days=days - 1)
        until = time.time()
    else:
        first = today - dt.timedelta(days=days)
        until = time.mktime(today.timetuple())
    day_list = [first + dt.timedelta(days=i) for i in range(days)]
    since = time.mktime(first.timetuple())
    if period != "month":
        prev_since = time.mktime((first - dt.timedelta(days=days)).timetuple())

    state_path = args.state or conf.get("REPORT_STATE") or DEFAULT_STATE
    prev_state = None if args.no_state else load_state(state_path)

    alerts = []
    db_path = find_db(conf)
    bans, prev_count, seen_before = [], None, set()
    try:
        bans, prev_count, seen_before = load_history(db_path, since, until, prev_since)
    except (sqlite3.Error, RuntimeError, OSError) as exc:
        alerts.append("Lecture de la base Fail2ban impossible ({}) : {}".format(db_path, exc))

    status = jails_status()
    if status is None:
        alerts.append("fail2ban-client ne répond pas : le service Fail2ban est-il démarré ?")
    else:
        missing = [j for j in conf.get("EXPECTED_JAILS", "").split() if j not in status]
        if missing:
            alerts.append("Jail(s) attendue(s) inactive(s) : " + ", ".join(missing))

    geoip = as_bool(conf.get("REPORT_GEOIP"), True) and not args.no_geoip
    report = Report(host, day_list, bans, prev_count, seen_before, status, alerts,
                    top_n=top_n, geoip=geoip, db_path=db_path, profile=profile,
                    prev_state=prev_state, period_label=label)
    text, html_doc = report.as_text(), report.as_html()

    def remember():
        if args.no_state:
            return
        try:
            save_state(state_path, report.state_snapshot(since, until))
        except OSError as exc:
            warn("mémorisation impossible ({}) : {}".format(state_path, exc))

    if args.stdout or args.html:
        if args.stdout:
            out = getattr(sys.stdout, "buffer", None)
            if out is not None:
                out.write(text.encode("utf-8"))
                out.flush()
            else:
                sys.stdout.write(text)
        if args.html:
            with open(args.html, "w", encoding="utf-8") as handle:
                handle.write(html_doc)
        if args.save_state:
            remember()
        return 0

    recipients = [a for a in re.split(r"[\s,;]+", args.to or conf.get("REPORT_TO", "")) if a]
    if not recipients:
        warn("aucun destinataire (REPORT_TO ou --to)")
        return 2
    subject = report.subject(conf.get("REPORT_SUBJECT_PREFIX") or "[Fail2ban]")
    msg, sender = build_message(conf, recipients, subject, text, html_doc, host)
    try:
        via = send(msg, sender, conf)
    except Exception as exc:  # noqa: BLE001 — tout échec d'envoi doit être signalé
        warn("échec de l'envoi : {}".format(exc))
        return 1
    if not args.quiet:
        warn("rapport envoyé à {} via {}".format(", ".join(recipients), via))
    # Un aperçu (--until-now) ne doit pas devenir la référence du prochain rapport
    if args.save_state or not args.until_now:
        remember()
    return 0


if __name__ == "__main__":
    sys.exit(main())
