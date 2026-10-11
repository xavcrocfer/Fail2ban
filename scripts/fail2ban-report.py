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
# Contrôles de sécurité (REPORT_CHECKS, --checks / --no-checks) : connexions SSH
# réussies (IP bannie, source jamais vue, mot de passe, Internet en LAN), « sshd -T »
# (root, mots de passe, ports ↔ jail), bans actifs absents du pare-feu, comptes
# visés, santé de la base ; niveau 2 : mises à jour/redémarrage, ports en écoute,
# comptes et clés SSH, services en échec, disque, heure. Un contrôle en ALERTE
# remonte en tête du rapport.
#
# Mode alertes (--alert-only, timer quotidien) : contrôles sur les dernières 24 h,
# mail UNIQUEMENT s'il existe une alerte nouvelle (ou un rappel tous les
# ALERT_REMIND_DAYS jours), mémoire séparée (<REPORT_STATE>-alerts.json). Ne
# modifie jamais la référence du rapport périodique.
#
# Masquage (REPORT_REDACT=yes) : un nom d'utilisateur ressemblant à un mot de passe
# (tapé par erreur dans le champ « login ») n'apparaît jamais dans un mail.
#
import argparse
import base64
import calendar
import collections
import datetime as dt
import hashlib
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


# ----------------------------------------------------------------- contrôles
# Niveau 1 : contrôles locaux, sans dépendance ni requête réseau. Chaque source
# système (journaux, sshd -T, pare-feu, comptes) est une fonction de module que
# les tests remplacent. Un contrôle qui plante devient un « INFO » : il ne doit
# jamais empêcher l'envoi du rapport.
# headline : phrase reprise en tête du rapport quand le contrôle est en ALERTE
Check = collections.namedtuple("Check", "key level title summary lines headline")
LEVELS = ("ok", "info", "warn", "alert")
LEVEL_LABELS = {"ok": "OK", "info": "INFO", "warn": "ATTENTION", "alert": "ALERTE"}
CHECK_KEYS = ("ssh_logins", "sshd_config", "firewall", "accounts", "database")
CHECK_TITLES = {
    "ssh_logins": "Connexions SSH réussies",
    "sshd_config": "Configuration effective de sshd",
    "firewall": "Cohérence Fail2ban ↔ pare-feu",
    "accounts": "Comptes visés par les attaques",
    "database": "Base de données Fail2ban",
}
AUTH_LOGS = ("/var/log/auth.log", "/var/log/secure", "/var/log/messages")
SSH_ACCEPTED = re.compile(r"\bAccepted (\S+) for (\S+) from (\S+) port \d+")
SSH_FAILED = re.compile(r"\bFailed (\S+) for (invalid user )?(\S+) from (\S+) port \d+")
SSH_INVALID = re.compile(r"\bInvalid user (\S*) from (\S+)")
SSH_PREAUTH = re.compile(r"\b(?:Connection closed by|Disconnected from) "
                         r"(authenticating|invalid) user (\S+) (\S+) port \d+")
SYSLOG_ISO = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)?\s+")
SYSLOG_BSD = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d):(\d\d):(\d\d)\s+")
BSD_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
PASSWORD_METHODS = ("password", "keyboard-interactive", "keyboard-interactive/pam")
NO_LOGIN_SHELLS = ("nologin", "false", "sync", "shutdown", "halt")
IP_TOKEN = re.compile(r"[0-9A-Fa-f:.]{2,}(?:/\d{1,3})?")
DB_SIZE_WARN = 1 << 30


def parse_syslog_ts(line, now=None):
    """(horodatage, reste de la ligne) d'une ligne syslog RFC 3339 ou BSD, ou (None, line)."""
    match = SYSLOG_ISO.match(line)
    if match:
        stamp, tz = match.group(1), match.group(2)
        parsed = time.strptime(stamp, "%Y-%m-%dT%H:%M:%S")
        if tz:
            offset = 0
            if tz != "Z":
                offset = (int(tz[1:3]) * 3600 + int(tz[-2:]) * 60) * (1 if tz[0] == "+" else -1)
            return calendar.timegm(parsed) - offset, line[match.end():]
        return time.mktime(parsed), line[match.end():]
    match = SYSLOG_BSD.match(line)
    if match and match.group(1) in BSD_MONTHS:
        now = now or time.time()
        year = time.localtime(now).tm_year
        fields = (BSD_MONTHS.index(match.group(1)) + 1, int(match.group(2)),
                  int(match.group(3)), int(match.group(4)), int(match.group(5)))
        try:
            ts = time.mktime(dt.datetime(year, *fields).timetuple())
            if ts > now + 86400:  # journal de décembre lu en janvier
                ts = time.mktime(dt.datetime(year - 1, *fields).timetuple())
        except ValueError:
            return None, line
        return ts, line[match.end():]
    return None, line


def find_exe(name):
    return shutil.which(name) or next(
        (p for p in ("/usr/sbin/" + name, "/sbin/" + name, "/usr/bin/" + name)
         if os.access(p, os.X_OK)), None)


def read_auth_lines(since, until):
    """([(horodatage, ligne sshd)], source) de la période, ou (None, raison)."""
    jctl = find_exe("journalctl")
    if jctl and os.path.isdir("/run/systemd/system"):
        # Facilités auth (4) et authpriv (10) : sshd, sshd-session, sshd-auth, PAM
        out = run([jctl, "--no-pager", "-q", "-o", "short-unix",
                   "--since", "@{}".format(int(since)), "--until", "@{}".format(int(until)),
                   "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"], timeout=120)
        if out:
            lines = []
            for line in out.splitlines():
                stamp, _, rest = line.partition(" ")
                if "sshd" not in rest:
                    continue
                try:
                    lines.append((float(stamp), rest))
                except ValueError:
                    continue
            return lines, "journald"
    lines, sources = [], []
    for base in AUTH_LOGS:
        for path in (base + ".1", base):  # rotation non compressée comprise
            try:
                if os.path.getmtime(path) < since:
                    continue
                with open(path, encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        if "sshd" not in line:
                            continue
                        ts, rest = parse_syslog_ts(line)
                        if ts is not None and since <= ts < until:
                            lines.append((ts, rest.rstrip("\n")))
                sources.append(path)
            except OSError:
                continue
        if sources:
            break
    if not sources:
        return None, "aucun journal d'authentification lisible (journald, " + \
            ", ".join(AUTH_LOGS) + ")"
    return lines, ", ".join(sources)


def parse_ssh_events(lines):
    """Connexions réussies et noms d'utilisateur visés à partir des lignes sshd."""
    accepted, targets, invalid = [], collections.defaultdict(set), set()
    for ts, line in lines:
        match = SSH_ACCEPTED.search(line)
        if match:
            accepted.append({"ts": ts, "method": match.group(1), "user": match.group(2),
                             "ip": match.group(3)})
            continue
        match = SSH_FAILED.search(line)
        if match:
            targets[match.group(3)].add(match.group(4))
            if match.group(2):
                invalid.add(match.group(3))
            continue
        match = SSH_INVALID.search(line)
        if match:
            targets[match.group(1)].add(match.group(2))
            invalid.add(match.group(1))
            continue
        match = SSH_PREAUTH.search(line)
        if match:
            targets[match.group(2)].add(match.group(3))
            if match.group(1) == "invalid":
                invalid.add(match.group(2))
    return accepted, targets, invalid


def parse_sshd_t(text):
    """Sortie de « sshd -T » → dict (clés en minuscules ; ports = liste d'entiers)."""
    conf, ports, listen_ports = {}, [], []
    for line in text.splitlines():
        key, _, value = line.strip().partition(" ")
        key = key.lower()
        if key == "port":
            ports.append(int(value))
        elif key == "listenaddress":
            port = value.rpartition(":")[2]
            if port.isdigit():
                listen_ports.append(int(port))
        elif key:
            conf[key] = value.strip()
    # ListenAddress avec port explicite prime sur Port
    conf["ports"] = sorted(set(listen_ports or ports))
    return conf


def sshd_effective_config():
    exe = find_exe("sshd")
    if not exe:
        return None
    out = run([exe, "-T"])
    if out is None:  # blocs Match : -T exige un contexte de connexion
        out = run([exe, "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"])
    return parse_sshd_t(out) if out else None


def resolve_ports(value):
    """« ssh,2222 » / « 22:25 » / « all » → ensemble d'entiers, ou "all"."""
    ports = set()
    for token in re.split(r"[\s,]+", value or ""):
        token = token.strip().lower()
        if not token:
            continue
        if token in ("all", "any", "0:65535", "1:65535"):
            return "all"
        if ":" in token:
            low, _, high = token.partition(":")
            if low.isdigit() and high.isdigit():
                ports.update(range(int(low), int(high) + 1))
            continue
        if token.isdigit():
            ports.add(int(token))
            continue
        try:
            ports.add(socket.getservbyname(token, "tcp"))
        except OSError:
            if token == "ssh":
                ports.add(22)
    return ports


def jail_ports(jail="sshd", etc="/etc/fail2ban"):
    """Ports surveillés par une jail, selon l'ordre de lecture de Fail2ban, ou None."""
    import configparser
    import glob
    files = ([os.path.join(etc, "jail.conf")]
             + sorted(glob.glob(os.path.join(etc, "jail.d", "*.conf")))
             + [os.path.join(etc, "jail.local")]
             + sorted(glob.glob(os.path.join(etc, "jail.d", "*.local"))))
    port = default = None
    for path in files:
        # default_section neutralisé : [DEFAULT] devient une section ordinaire, ce qui
        # distingue « port » propre à la jail de « port » hérité
        parser = configparser.RawConfigParser(strict=False, default_section="\0",
                                              inline_comment_prefixes=("#", ";"))
        try:
            if not parser.read(path, encoding="utf-8"):
                continue
        except (configparser.Error, UnicodeDecodeError):
            continue
        if parser.has_option(jail, "port"):
            port = parser.get(jail, "port")
        if parser.has_option("DEFAULT", "port"):
            default = parser.get("DEFAULT", "port")
    port = port or default
    return resolve_ports(port) if port else None


def firewall_dump():
    """Texte des règles du pare-feu (nftables, iptables, ipset, hosts.deny), ou None.

    None si aucun outil n'a pu être lu (absent, droits, netlink refusé) : sans
    lecture réelle, impossible d'affirmer qu'un ban manque. hosts.deny seul ne
    suffit pas à conclure, il ne fait que compléter.
    """
    parts, readable = [], False
    for cmd in (["nft", "list", "ruleset"], ["iptables-save"], ["ip6tables-save"],
                ["ipset", "list"]):
        exe = find_exe(cmd[0])
        if exe:
            out = run([exe] + cmd[1:], timeout=60)
            if out is not None:
                readable = True
                parts.append(out)
    if not readable:
        return None
    try:
        with open("/etc/hosts.deny", encoding="utf-8", errors="replace") as handle:
            parts.append(handle.read())
    except OSError:
        pass
    return "\n".join(parts)


def addresses_in(text):
    """Adresses (hôtes uniques, pas les réseaux) citées dans un texte de règles."""
    found = set()
    for token in IP_TOKEN.findall(text or ""):
        addr, _, plen = token.partition("/")
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if plen and int(plen) != ip.max_prefixlen:
            continue
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        found.add(ip)
    return found


def passwd_accounts(path="/etc/passwd"):
    """Comptes locaux → shell."""
    accounts = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                fields = line.rstrip("\n").split(":")
                if len(fields) >= 7 and fields[0]:
                    accounts[fields[0]] = fields[6]
    except OSError:
        pass
    return accounts


def db_purge_age():
    out = fail2ban_client("get", "dbpurgeage")
    match = re.search(r"(\d+)", out or "")
    return int(match.group(1)) if match else None


def db_health(db_path):
    """Taille, intégrité (quick_check), nb de bans et plus ancien ban de la base."""
    info = {"size": os.path.getsize(db_path)}
    con = sqlite3.connect("file:{}?mode=ro".format(quote(db_path)), uri=True, timeout=30)
    try:
        info["check"] = con.execute("PRAGMA quick_check").fetchone()[0]
        info["count"], info["oldest"] = con.execute(
            "SELECT COUNT(*), MIN(timeofban) FROM bans").fetchone()
    finally:
        con.close()
    return info


def fmt_size(size):
    for unit in ("o", "Kio", "Mio", "Gio"):
        if size < 1024 or unit == "Gio":
            return ("{:.0f} {}" if unit == "o" else "{:.1f} {}").format(size, unit)
        size /= 1024.0


def first_alert(findings):
    return next((text for lvl, text in findings if lvl == "alert"), None)


def worst(levels):
    return max(levels, key=LEVELS.index) if levels else "ok"


def check_ssh_logins(ctx):
    lines, source = ctx["auth"]
    if lines is None:
        return "info", "contrôle impossible : " + source, []
    accepted = ctx["events"][0]
    known = None
    if ctx["prev_state"] and "ssh_sources" in ctx["prev_state"]:
        known = set(ctx["prev_state"]["ssh_sources"])
    groups = collections.OrderedDict()
    for event in accepted:
        key = (event["user"], event["ip"], event["method"])
        group = groups.setdefault(key, {"count": 0, "last": 0})
        group["count"] += 1
        group["last"] = max(group["last"], event["ts"])
    ctx["state"]["ssh_sources"] = sources = dict((ctx["prev_state"] or {}).get("ssh_sources") or {})
    for (_, ip, _), group in groups.items():
        sources[ip] = max(sources.get(ip, 0), int(group["last"]))
    if len(sources) > STATE_MAX_ITEMS:
        keep = sorted(sources, key=sources.get, reverse=True)[:STATE_MAX_ITEMS]
        ctx["state"]["ssh_sources"] = {ip: sources[ip] for ip in keep}
    if not groups:
        return "ok", "aucune connexion réussie sur la période (source : {})".format(source), []

    rows, levels = [], []
    for (user, ip, method), group in groups.items():
        flags = []
        if ip in ctx["banned_ips"]:
            flags.append(("alert", "IP BANNIE par Fail2ban"))
        if ctx["profile"] == "lan" and not is_internal(ip):
            flags.append(("alert", "depuis Internet sur une machine LAN"))
        if method in PASSWORD_METHODS:
            flags.append(("warn" if ctx["profile"] == "vps" else "info", "par mot de passe"))
        if user == "root":
            flags.append(("info", "root"))
        if known is not None and ip not in known:
            flags.append(("warn", "source jamais vue"))
        level = worst([lvl for lvl, _ in flags])
        levels.append(level)
        rows.append((LEVELS.index(level), group["count"], "{:<34} {:<22} ×{:<4} {}{}".format(
            "{}@{}".format(user, ip), method, group["count"], fmt_ts(group["last"]),
            ("  ← " + ", ".join(label for _, label in flags)) if flags else "")))
    rows.sort(key=lambda r: (-r[0], -r[1]))
    worst_level = worst(levels)
    alerts = [r[2].split("  ← ")[0].split()[0] + " (" + r[2].split("  ← ")[1] + ")"
              for r in rows if r[0] == LEVELS.index("alert")]
    lines_out = [r[2] for r in rows[:20]]
    if len(rows) > 20:
        lines_out.append("… et {} autre(s) combinaison(s)".format(len(rows) - 20))
    ips = {ip for _, ip, _ in groups}
    summary = "{} depuis {} (source : {})".format(
        plural(sum(g["count"] for g in groups.values()), "connexion réussie",
               "connexions réussies"), plural(len(ips), "IP", "IP"), source)
    if known is None and ctx["prev_state"] is not None:
        summary += " — sources mémorisées pour les prochains rapports"
    headline = "connexion réussie de " + ", ".join(alerts[:3]) + (" …" if len(alerts) > 3 else "")
    return worst_level, summary, lines_out, headline


def password_auth_enabled(cfg):
    kbd = cfg.get("kbdinteractiveauthentication", cfg.get("challengeresponseauthentication", "no"))
    return cfg.get("passwordauthentication") == "yes" or (kbd == "yes" and cfg.get("usepam") == "yes")


def check_sshd_config(ctx):
    cfg = ctx["sshd"]
    if cfg is None:
        return "info", "contrôle impossible : « sshd -T » indisponible (sshd absent, droits)", []
    vps = ctx["profile"] == "vps"
    findings = []
    passwords = password_auth_enabled(cfg)
    root = cfg.get("permitrootlogin", "?")
    if root == "yes" and passwords:
        findings.append(("alert" if vps else "warn",
                         "PermitRootLogin yes avec mots de passe acceptés : root attaquable "
                         "par force brute → « PermitRootLogin prohibit-password »"))
    elif root == "yes":
        findings.append(("info", "PermitRootLogin yes (clé seule tant que les mots de passe "
                                 "sont refusés) → préférer « prohibit-password »"))
    if passwords:
        findings.append(("warn" if vps else "info",
                         "authentification par mot de passe acceptée : seul Fail2ban freine "
                         "la force brute → clés SSH + « PasswordAuthentication no »"))
    if cfg.get("permitemptypasswords") == "yes":
        findings.append(("alert", "PermitEmptyPasswords yes : connexion sans mot de passe possible"))
    tries = cfg.get("maxauthtries", "6")
    if tries.isdigit() and int(tries) > 6:
        findings.append(("info", "MaxAuthTries {} (> 6) : plus d'essais par connexion".format(tries)))

    ports, watched = set(cfg.get("ports") or []), ctx["jail_ports"]
    if watched is None:
        findings.append(("info", "ports de la jail sshd introuvables dans /etc/fail2ban"))
    elif watched != "all" and ports - watched:
        findings.append(("alert", "sshd écoute sur {} mais la jail sshd ne protège pas {} : "
                                  "les bans n'y bloquent rien".format(
                                      ",".join(map(str, sorted(ports))),
                                      ",".join(map(str, sorted(ports - watched))))))
    summary = "PermitRootLogin {}, mots de passe {}, port(s) {} (jail sshd : {})".format(
        root, "acceptés" if passwords else "refusés", ",".join(map(str, sorted(ports))) or "?",
        "tous" if watched == "all" else ",".join(map(str, sorted(watched or []))) or "?")
    return worst([lvl for lvl, _ in findings]), summary, [
        "[{}] {}".format(LEVEL_LABELS[lvl], text) for lvl, text in findings if lvl != "ok"
    ], first_alert(findings)


def check_firewall(ctx):
    status = ctx["status"]
    if status is None:
        return "info", "contrôle impossible : Fail2ban ne répond pas", []
    active = [(jail, ip) for jail, st in status.items() for ip in sorted(st["ips"])]
    if not active:
        return "ok", "aucun ban actif à vérifier", []
    dump = ctx["firewall"]
    if dump is None:
        return "info", "contrôle impossible : règles du pare-feu illisibles " \
                       "(nft/iptables absents ou droits insuffisants)", []
    present = addresses_in(dump)
    missing = collections.OrderedDict()
    for jail, ip in active:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr not in present:
            missing.setdefault(jail, []).append(ip)
    if not missing:
        return "ok", "{}, tous présents dans le pare-feu".format(
            plural(len(active), "ban actif", "bans actifs")), []
    count = sum(len(v) for v in missing.values())
    lines = ["{} : {}{}".format(jail, ", ".join(ips[:10]), " …" if len(ips) > 10 else "")
             for jail, ips in missing.items()]
    return "alert", "{} sur {} absent(s) du pare-feu : ces IP ne sont PAS bloquées " \
                    "(action de ban en échec, règles vidées par un rechargement ?)".format(
                        count, plural(len(active), "ban actif", "bans actifs")), lines


def check_accounts(ctx):
    lines, source = ctx["auth"]
    if lines is None:
        return "info", "contrôle impossible : " + source, []
    _, targets, invalid = ctx["events"]
    if not targets:
        return "ok", "aucune tentative d'authentification échouée journalisée", []
    accounts = ctx["accounts"]
    passwords = password_auth_enabled(ctx["sshd"] or {})
    real = sorted((u for u in targets if u in accounts and u not in invalid),
                  key=lambda u: (-len(targets[u]), u))
    fake = sorted((u for u in targets if u not in real), key=lambda u: (-len(targets[u]), u))
    interactive = [u for u in real if not accounts[u].rsplit("/", 1)[-1] in NO_LOGIN_SHELLS]
    level, out = "info", []
    if real:
        out.append("Comptes existants visés : " + ", ".join(
            "{} ({})".format(u, plural(len(targets[u]), "IP", "IP")) for u in real[:10]))
    named = [u for u in interactive if u != "root"]
    if named:
        level = "warn"
        out.append("[ATTENTION] compte(s) réel(s) non standard visé(s) : {} — nom connu "
                   "de l'attaquant (fuite, énumération) ?".format(", ".join(named[:10])))
    if interactive and passwords:
        level = "warn"
        out.append("[ATTENTION] mots de passe acceptés par sshd : ces comptes sont exposés "
                   "à la force brute")
    if fake:
        out.append("Noms inexistants les plus essayés : " + ", ".join(
            "{} ({})".format(redact_name(u) if u else "« vide »", len(targets[u]))
            for u in fake[:10]))
    summary = "{} visé(s) dont {} existant(s), {} source(s)".format(
        plural(len(targets), "nom d'utilisateur", "noms d'utilisateur"), len(real),
        len(set().union(*targets.values())))
    return level, summary, out


def check_database(ctx):
    db_path = ctx["db_path"]
    if not db_path or not os.path.exists(db_path):
        return "alert", "base introuvable ({}) : plus d'historique ni de restauration " \
                        "des bans après redémarrage".format(db_path), []
    info = db_health(db_path)
    findings = []
    if info["check"] != "ok":
        findings.append(("alert", "intégrité : " + info["check"]))
    if info["size"] > DB_SIZE_WARN:
        findings.append(("warn", "base volumineuse ({}) : réduire dbpurgeage ?".format(
            fmt_size(info["size"]))))
    purge = db_purge_age()
    if info["oldest"] and info["oldest"] > ctx["since"] + 86400:
        findings.append(("info", "l'historique ne commence que le {} : rapport partiel".format(
            fmt_ts(info["oldest"]))))
    summary = "{}, {}, intégrité {}{}".format(
        fmt_size(info["size"]), plural(info["count"] or 0, "ban", "bans"), info["check"],
        ", purge après {} j".format(purge // 86400) if purge else "")
    return worst([lvl for lvl, _ in findings]), summary, [
        "[{}] {}".format(LEVEL_LABELS[lvl], text) for lvl, text in findings], first_alert(findings)


CHECKS = collections.OrderedDict([
    ("ssh_logins", check_ssh_logins), ("sshd_config", check_sshd_config),
    ("firewall", check_firewall), ("accounts", check_accounts), ("database", check_database),
])


def run_checks(keys, since, until, profile, bans, status, prev_state, db_path):
    """Exécute les contrôles demandés → ([Check], données à mémoriser)."""
    if not keys:
        return [], {}
    active = set()
    for st in (status or {}).values():
        active |= st["ips"]
    ctx = {"since": since, "until": until, "profile": profile, "status": status,
           "prev_state": prev_state, "db_path": db_path, "state": {},
           "banned_ips": {b.ip for b in bans} | active}
    lazy = (
        ("auth", lambda: read_auth_lines(since, until), ("ssh_logins", "accounts")),
        ("sshd", sshd_effective_config, ("sshd_config", "accounts", "local_accounts")),
        ("jail_ports", jail_ports, ("sshd_config",)),
        ("firewall", firewall_dump, ("firewall",)),
        ("accounts", passwd_accounts, ("accounts",)),
    )
    for name, loader, users in lazy:
        ctx[name] = None
        if any(k in keys for k in users):
            try:
                ctx[name] = loader()
            except Exception as exc:  # noqa: BLE001 — source indisponible ≠ rapport perdu
                warn("source {} indisponible : {}".format(name, exc))
    if ctx["auth"] is None:
        ctx["auth"] = (None, "lecture des journaux impossible")
    ctx["events"] = parse_ssh_events(ctx["auth"][0] or [])
    results = []
    for key in keys:
        try:
            result = tuple(CHECKS[key](ctx))
        except Exception as exc:  # noqa: BLE001
            result = ("info", "contrôle impossible : {}".format(exc), [])
        level, summary, lines = result[:3]
        headline = (result[3] if len(result) > 3 else None) or summary
        results.append(Check(key, level, CHECK_TITLES[key], summary, lines, headline))
    return results, ctx["state"]


def parse_check_list(value):
    """« yes » / « no » / « ssh_logins,firewall » → liste ordonnée de clés, ou ValueError."""
    value = (value or "yes").strip().lower()
    if value in ("yes", "oui", "1", "true", "on", "all"):
        return list(CHECK_KEYS)
    if value in ("no", "non", "0", "false", "off", "none"):
        return []
    keys = [k for k in re.split(r"[\s,]+", value) if k]
    unknown = [k for k in keys if k not in CHECK_KEYS]
    if unknown:
        raise ValueError("contrôle(s) inconnu(s) : {} (connus : {})".format(
            ", ".join(unknown), ", ".join(CHECK_KEYS)))
    return [k for k in CHECK_KEYS if k in keys]


# ----------------------------------------------------------- contrôles niveau 2
# État du système : mises à jour, ports, comptes/clés, services, disque, heure.
# Toujours en lecture seule : les gestionnaires de paquets sont interrogés sur
# leur cache local (aucun « apt update », aucune requête réseau).
SYSTEM_FS = ("/", "/var", "/var/log", "/var/lib/fail2ban", "/boot", "/home", "/tmp")
DISK_WARN, DISK_ALERT = 90, 97
SS_PROC = re.compile(r'users:\(\("([^"]+)"')
LOGIN_SHELL_EXCLUDE = NO_LOGIN_SHELLS + ("git-shell",)


def run_rc(cmd, timeout=60):
    """(code retour, sortie standard) ; (None, "") si la commande est introuvable."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              universal_newlines=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None, ""
    return proc.returncode, proc.stdout


def pending_updates():
    """(total, dont sécurité ou None, gestionnaire) depuis le cache local, ou None."""
    exe = find_exe("apt")
    if exe:
        out = run([exe, "list", "--upgradable"], timeout=180)
        if out is None:
            return None
        lines = [l for l in out.splitlines() if "[upgradable" in l]
        return len(lines), sum(1 for l in lines if "-security" in l.split(" ")[0]), "apt"
    exe = find_exe("dnf") or find_exe("yum")
    if exe:
        rc, out = run_rc([exe, "-q", "-C", "check-update"], timeout=180)
        if rc not in (0, 100):  # cache absent : on ne télécharge rien
            return None
        total = len([l for l in out.splitlines()
                     if len(l.split()) == 3 and not l.startswith((" ", "Obsoleting"))])
        rc, sec = run_rc([exe, "-q", "-C", "updateinfo", "list", "--security"], timeout=180)
        security = len([l for l in sec.splitlines() if l.strip()]) if rc == 0 else None
        return total, security, os.path.basename(exe)
    exe = find_exe("apk")
    if exe:
        out = run([exe, "version", "-l", "<"], timeout=120)
        if out is None:
            return None
        return len([l for l in out.splitlines() if " < " in l]), None, "apk"
    return None


def in_container():
    """Conteneur (LXC, podman, docker) : le noyau est celui de l'hôte."""
    if os.path.exists("/run/.containerenv") or os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/environ", "rb") as handle:
            return b"container=" in handle.read()
    except OSError:
        return False


def reboot_required():
    """Raison pour laquelle un redémarrage est attendu, ou None."""
    if os.path.exists("/run/reboot-required") or os.path.exists("/var/run/reboot-required"):
        try:
            with open("/var/run/reboot-required.pkgs", encoding="utf-8") as handle:
                pkgs = sorted({l.strip() for l in handle if l.strip()})
            return "demandé par : " + ", ".join(pkgs[:5]) + (" …" if len(pkgs) > 5 else "")
        except OSError:
            return "/var/run/reboot-required présent"
    exe = find_exe("needs-restarting")
    if exe:
        rc, _ = run_rc([exe, "-r"])
        if rc == 1:
            return "needs-restarting -r : noyau ou bibliothèques de base mis à jour"
    if in_container():
        return None
    release = os.uname().release
    try:
        installed = os.listdir("/lib/modules")
    except OSError:
        installed = []
    if installed and release not in installed:
        return "noyau en cours {} remplacé (installés : {})".format(release, ", ".join(sorted(installed)))
    return None


def listening_sockets():
    """{« tcp/22 » : processus} des sockets en écoute hors boucle locale, ou None."""
    exe = find_exe("ss")
    if not exe:
        return None
    out = run([exe, "-Hlntup"])
    if out is None:
        out = run([exe, "-Hlntu"])  # sans -p (droits) : pas de nom de processus
    if out is None:
        return None
    found = {}
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        proto, local = cols[0], cols[4]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        if not port.isdigit():
            continue
        if addr.startswith("127.") or addr in ("::1", "localhost") or "%lo" in local:
            continue
        proc = SS_PROC.search(line)
        key = "{}/{}".format(proto, port)
        found[key] = found.get(key) or (proc.group(1) if proc else "?")
    return found


def passwd_entries(path="/etc/passwd"):
    """[(nom, uid, dossier, shell)] des comptes locaux."""
    entries = []
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                f = line.rstrip("\n").split(":")
                if len(f) >= 7 and f[0] and f[2].lstrip("-").isdigit():
                    entries.append((f[0], int(f[2]), f[5], f[6]))
    except OSError:
        pass
    return entries


def key_fingerprint(blob):
    """Empreinte OpenSSH « SHA256:… » d'une clé publique encodée en base64."""
    try:
        raw = base64.b64decode(blob.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def authorized_keys(entries, sshd_cfg=None):
    """{compte : {empreinte : type}} pour chaque fichier authorized_keys existant."""
    patterns = ((sshd_cfg or {}).get("authorizedkeysfile") or
                ".ssh/authorized_keys .ssh/authorized_keys2").split()
    result = {}
    for name, uid, home, _ in entries:
        for pattern in patterns:
            if pattern.lower() == "none":
                continue
            path = pattern.replace("%h", home).replace("%u", name).replace("%U", str(uid)) \
                .replace("%%", "%")
            if not path.startswith("/"):
                path = os.path.join(home, path)
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    lines = handle.read().splitlines()
            except OSError:
                continue
            for line in lines:
                tokens = line.strip().split()
                for i, token in enumerate(tokens[:-1]):  # options éventuelles avant le type
                    if token.startswith(("ssh-", "ecdsa-", "sk-")):
                        fp = key_fingerprint(tokens[i + 1])
                        if fp:
                            result.setdefault(name, {})[fp] = token
                        break
    return result


def failed_services():
    """Services en échec (systemd --failed / OpenRC --crashed), ou None."""
    exe = find_exe("systemctl")
    if exe and os.path.isdir("/run/systemd/system"):
        out = run([exe, "--failed", "--plain", "--no-legend", "--no-pager"])
        if out is None:
            return None
        return [l.split()[0].lstrip("●* ") for l in out.splitlines() if l.split()]
    exe = find_exe("rc-status")
    if exe:
        out = run([exe, "--crashed"])
        return [l.split()[0] for l in (out or "").splitlines() if l.split()] if out is not None else None
    return None


def disk_usage(paths=SYSTEM_FS):
    """[(point, % blocs, % inodes)] des systèmes de fichiers distincts."""
    seen, result = set(), []
    for path in paths:
        try:
            dev = os.stat(path).st_dev
            st = os.statvfs(path)
        except OSError:
            continue
        if dev in seen or not st.f_blocks:
            continue
        seen.add(dev)
        used = st.f_blocks - st.f_bfree
        pct = used * 100.0 / ((used + st.f_bavail) or 1)
        ipct = ((st.f_files - st.f_ffree) * 100.0 / st.f_files) if st.f_files else 0.0
        result.append((path, pct, ipct))
    return result


def time_sync():
    """(synchronisée : bool, source) ou None si inconnu."""
    exe = find_exe("timedatectl")
    if exe and os.path.isdir("/run/systemd/system"):
        out = run([exe, "show", "-p", "NTPSynchronized", "-p", "NTP"])
        if out:
            values = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
            if "NTPSynchronized" in values:
                return values["NTPSynchronized"] == "yes", "timedatectl (NTP {})".format(
                    "activé" if values.get("NTP") == "yes" else "désactivé")
    exe = find_exe("chronyc")
    if exe:
        out = run([exe, "-n", "tracking"])
        if out:
            match = re.search(r"Leap status\s*:\s*(.+)", out)
            if match:
                return "Not synchronised" not in match.group(1), "chronyc"
    return None


def check_updates(ctx):
    pending, reboot = pending_updates(), reboot_required()
    findings, parts = [], []
    if pending is None:
        parts.append("paquets : cache du gestionnaire illisible")
    else:
        total, security, manager = pending
        parts.append("{} en attente ({})".format(plural(total, "mise à jour", "mises à jour"),
                                                  manager))
        if security:
            findings.append(("warn", "{} de sécurité à appliquer".format(
                plural(security, "mise à jour", "mises à jour"))))
        elif total and security is None:
            findings.append(("info", "nature des mises à jour inconnue ({})".format(manager)))
    if reboot:
        findings.append(("warn", "redémarrage nécessaire : " + reboot))
    parts.append("redémarrage " + ("NÉCESSAIRE" if reboot else "non requis"))
    return worst([lvl for lvl, _ in findings]), ", ".join(parts), [
        "[{}] {}".format(LEVEL_LABELS[lvl], text) for lvl, text in findings], None


def check_ports(ctx):
    current = listening_sockets()
    if current is None:
        return "info", "contrôle impossible : « ss » indisponible", [], None
    ctx["state"]["ports"] = current
    prev = (ctx["prev_state"] or {}).get("ports")
    listing = ", ".join("{} ({})".format(k, v) for k, v in sorted(current.items(),
                                                               key=lambda kv: (kv[0][:3], int(kv[0][4:]))))
    summary = "{} hors boucle locale : {}".format(
        plural(len(current), "port en écoute", "ports en écoute"), listing or "aucun")
    if prev is None:
        return "info" if current else "ok", summary + " — mémorisés pour les prochains rapports", [], None
    new = sorted(set(current) - set(prev))
    gone = sorted(set(prev) - set(current))
    lines = ["[{}] nouveau port en écoute : {} ({})".format(
        LEVEL_LABELS["warn"], k, current[k]) for k in new]
    lines += ["[INFO] port fermé depuis le rapport précédent : {} ({})".format(k, prev[k])
              for k in gone]
    return ("warn" if new else "ok"), summary, lines, None


def check_local_accounts(ctx):
    entries = passwd_entries()
    if not entries:
        return "info", "contrôle impossible : /etc/passwd illisible", [], None
    findings = []
    uid0 = [n for n, uid, _, _ in entries if uid == 0 and n != "root"]
    if uid0:
        findings.append(("alert", "compte(s) d'UID 0 autre(s) que root : " + ", ".join(uid0)))
    login = sorted(n for n, _, _, shell in entries
                   if shell and shell.rsplit("/", 1)[-1] not in LOGIN_SHELL_EXCLUDE)
    keys = authorized_keys(entries, ctx["sshd"])
    prev = ctx["prev_state"] or {}
    if "login_accounts" in prev:
        new = sorted(set(login) - set(prev["login_accounts"]))
        if new:
            findings.append(("warn", "nouveau(x) compte(s) avec shell : " + ", ".join(new)))
    if "ssh_keys" in prev:
        for user in sorted(keys):
            added = sorted(set(keys[user]) - set(prev["ssh_keys"].get(user, [])))
            if added:
                findings.append(("alert" if user == "root" else "warn",
                                 "clé(s) SSH ajoutée(s) pour {} : {}".format(user, ", ".join(
                                     "{} {}".format(keys[user][fp], fp) for fp in added[:5]))))
        for user in sorted(prev["ssh_keys"]):
            removed = set(prev["ssh_keys"][user]) - set(keys.get(user, {}))
            if removed:
                findings.append(("info", "{} retirée(s) pour {}".format(
                    plural(len(removed), "clé SSH", "clés SSH"), user)))
    ctx["state"]["login_accounts"] = login
    ctx["state"]["ssh_keys"] = {u: sorted(v) for u, v in keys.items()}
    summary = "{} avec shell ({}), clés SSH : {}".format(
        plural(len(login), "compte", "comptes"), ", ".join(login[:8]) + (" …" if len(login) > 8 else ""),
        ", ".join("{} ({})".format(u, len(v)) for u, v in sorted(keys.items())) or "aucune")
    if "ssh_keys" not in prev and ctx["prev_state"] is not None:
        summary += " — mémorisés pour les prochains rapports"
    return worst([lvl for lvl, _ in findings]), summary, [
        "[{}] {}".format(LEVEL_LABELS[lvl], t) for lvl, t in findings], first_alert(findings)


def check_services(ctx):
    failed = failed_services()
    if failed is None:
        return "info", "contrôle impossible : ni systemd ni OpenRC interrogeable", [], None
    if not failed:
        return "ok", "aucun service en échec", [], None
    critical = [u for u in failed if re.match(r"(fail2ban|sshd?|nftables|firewalld|iptables)\b", u)]
    level = "alert" if critical else "warn"
    head = "service(s) de sécurité en échec : " + ", ".join(critical) if critical else None
    return level, "{} : {}".format(plural(len(failed), "service en échec", "services en échec"),
                                   ", ".join(failed[:10])), [], head


def check_disk(ctx):
    usage = disk_usage()
    if not usage:
        return "info", "contrôle impossible : statvfs indisponible", [], None
    findings = []
    for path, pct, ipct in usage:
        for what, value in (("espace", pct), ("inodes", ipct)):
            if value >= DISK_ALERT:
                findings.append(("alert", "{} {} plein à {:.0f} % : journaux et base Fail2ban "
                                          "ne peuvent plus s'écrire".format(path, what, value)))
            elif value >= DISK_WARN:
                findings.append(("warn", "{} {} à {:.0f} %".format(path, what, value)))
    summary = ", ".join("{} {:.0f} %".format(p, v) for p, v, _ in usage)
    return worst([lvl for lvl, _ in findings]), summary, [
        "[{}] {}".format(LEVEL_LABELS[lvl], t) for lvl, t in findings], first_alert(findings)


def check_time(ctx):
    sync = time_sync()
    if sync is None:
        return "info", "état de synchronisation inconnu (ni timedatectl ni chronyc)", [], None
    synced, source = sync
    if synced:
        return "ok", "horloge synchronisée ({})".format(source), [], None
    return "warn", "horloge NON synchronisée ({}) : horodatages des bans et des journaux " \
                   "faussés, TLS fragile".format(source), [], None


CHECKS.update([("updates", check_updates), ("ports", check_ports),
               ("local_accounts", check_local_accounts), ("services", check_services),
               ("disk", check_disk), ("time", check_time)])
CHECK_TITLES.update({
    "updates": "Mises à jour et redémarrage",
    "ports": "Ports en écoute",
    "local_accounts": "Comptes locaux et clés SSH",
    "services": "Services en échec",
    "disk": "Espace disque",
    "time": "Synchronisation de l'heure",
})
CHECK_KEYS = tuple(CHECKS)


# ------------------------------------------------------------------- masquage
# Un mot de passe tapé dans le champ « login » finit dans les journaux (« Invalid
# user P@ssw0rd2026 ») puis dans le rapport envoyé par mail : on masque les noms
# d'utilisateur qui ressemblent à un secret.
def looks_like_secret(name):
    classes = sum(bool(re.search(p, name)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return (len(name) >= 8 and classes == 4) or (len(name) >= 12 and classes >= 3) or len(name) >= 24


def redact_name(name):
    if REDACT and looks_like_secret(name):
        return "‹masqué : {} car.›".format(len(name))
    return name


REDACT = True


# ------------------------------------------------------------- mode alertes
def alert_fingerprint(text):
    """Identité stable d'une alerte : les compteurs varient, pas les IP ni les noms."""
    return re.sub(r"(?<![\d.:])\d+(?![\d.:/])", "#", text)


def alert_state_path(state_path):
    root, _ = os.path.splitext(state_path)
    return root + "-alerts.json"


def pending_alerts(alerts, sent, now, remind_days):
    """Alertes à envoyer : nouvelles, ou rappel au-delà de remind_days (0 = jamais)."""
    due = []
    for text in alerts:
        info = sent.get(alert_fingerprint(text))
        if info is None:
            due.append((text, "nouvelle"))
        elif remind_days and now - info.get("last_sent", 0) >= remind_days * 86400:
            due.append((text, "toujours en cours depuis le {}".format(fmt_ts(info["first"]))))
    return due


def updated_alert_state(alerts, sent, now, notified):
    """Ne garde que les alertes en cours : une alerte résolue qui revient sera renvoyée."""
    state = {}
    for text in alerts:
        fp = alert_fingerprint(text)
        info = dict(sent.get(fp) or {"first": int(now)})
        if notified:
            info["last_sent"] = int(now)
        info.setdefault("last_sent", 0)
        info["text"] = text[:300]
        state[fp] = info
    return state


def alert_message(host, due, alerts, checks):
    text = ["ALERTES FAIL2BAN — {}".format(host), "=" * 78]
    for alert, why in due:
        text.append("/!\\ {}  [{}]".format(alert, why))
    others = [a for a in alerts if a not in {d[0] for d in due}]
    if others:
        text += ["", "Déjà signalées, toujours en cours :"] + ["  - " + a for a in others]
    detail = [c for c in checks if c.level == "alert"]
    if detail:
        text += ["", "DÉTAIL"]
        for chk in detail:
            text.append("  {} — {}".format(chk.title, chk.summary))
            text += ["      " + line for line in chk.lines]
    text += ["", "-" * 78, "fail2ban-report {} --alert-only, {:%d/%m/%Y %H:%M}. Rapport complet : "
             "fail2ban-report --stdout --until-now".format(__version__, dt.datetime.now())]
    body = "\n".join(text) + "\n"
    html_doc = ('<!DOCTYPE html><html><body style="{}color:{}"><pre style="{}font-size:13px;'
                'white-space:pre-wrap">{}</pre></body></html>').format(FONT, INK, MONO, html.escape(body))
    return body, html_doc


# ----------------------------------------------------------------- rapport
class Report(object):
    """Agrège les bans d'une période et produit les versions texte et HTML."""

    def __init__(self, host, days, bans, prev_count, seen_before, status, alerts,
                 top_n=10, geoip=True, db_path="", profile="vps", prev_state=None,
                 period_label=None, checks=None):
        self.host = host
        self.checks = list(checks or [])
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

        for chk in self.checks:
            if chk.level == "alert":
                self.alerts.append("{} : {}".format(chk.title, chk.headline))

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

        if self.checks:
            add("CONTRÔLES DE SÉCURITÉ")
            for chk in self.checks:
                add("  {:<12} {} — {}".format("[{}]".format(LEVEL_LABELS[chk.level]),
                                               chk.title, chk.summary))
                for line in chk.lines:
                    add("               " + line)
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

        if self.checks:
            colors = {"ok": ("#dcfce7", "#166534"), "info": ("#e0e7ff", "#3730a3"),
                      "warn": ("#fef3c7", "#92400e"), "alert": ("#fee2e2", "#991b1b")}
            chk_rows = []
            for chk in self.checks:
                bg, fg = colors[chk.level]
                detail = "".join('<div style="{}font-size:12px;color:{};margin-top:3px">{}</div>'
                                 .format(MONO, MUTED, esc(line)) for line in chk.lines)
                chk_rows.append([
                    '<span style="background:{};color:{};border-radius:9px;padding:2px 8px;'
                    'font-size:11px;font-weight:700;white-space:nowrap">{}</span>'.format(
                        bg, fg, LEVEL_LABELS[chk.level]),
                    "<b>{}</b><div style=\"font-size:13px;color:{}\">{}</div>{}".format(
                        esc(chk.title), INK, esc(chk.summary), detail)])
            rows.append(self._section("Contrôles de sécurité", self._table(
                ["État", "Contrôle"], chk_rows, ["left", "left"])))

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
    parser.add_argument("--checks", metavar="LISTE",
                        help="contrôles à exécuter : yes, no ou liste parmi " + ", ".join(CHECK_KEYS)
                             + " (défaut : REPORT_CHECKS ou yes)")
    parser.add_argument("--no-checks", action="store_true", help="aucun contrôle de sécurité")
    parser.add_argument("--alert-only", action="store_true",
                        help="contrôles des dernières 24 h ; mail seulement si alerte nouvelle")
    parser.add_argument("--no-redact", action="store_true",
                        help="ne pas masquer les noms d'utilisateur ressemblant à un secret")
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
    global REDACT
    REDACT = as_bool(conf.get("REPORT_REDACT"), True) and not args.no_redact
    if args.alert_only:
        # Fenêtre glissante des dernières 24 h
        days, args.until_now, args.period = 1, True, "days"

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

    try:
        check_keys = [] if args.no_checks else parse_check_list(
            args.checks or conf.get("REPORT_CHECKS"))
    except ValueError as exc:
        warn(str(exc))
        return 2
    checks, check_state = run_checks(check_keys, since, until, profile, bans, status,
                                     prev_state, db_path)

    geoip = as_bool(conf.get("REPORT_GEOIP"), True) and not args.no_geoip
    report = Report(host, day_list, bans, prev_count, seen_before, status, alerts,
                    top_n=top_n, geoip=geoip, db_path=db_path, profile=profile,
                    prev_state=prev_state, period_label=label, checks=checks)
    text, html_doc = report.as_text(), report.as_html()

    alert_path = alert_state_path(state_path)
    now = time.time()

    def remember_alerts(notified):
        if args.no_state:
            return
        try:
            sent = {} if args.no_state else (load_state(alert_path) or {}).get("alerts", {})
            save_state(alert_path, {"version": STATE_VERSION, "alerts": updated_alert_state(
                report.alerts, sent, now, notified)})
        except OSError as exc:
            warn("mémorisation des alertes impossible ({}) : {}".format(alert_path, exc))

    if args.alert_only:
        return alert_only(args, conf, host, report, checks, alert_path, now, remember_alerts)

    def remember():
        if args.no_state:
            return
        try:
            snapshot = report.state_snapshot(since, until)
            snapshot.update(check_state)
            if "ssh_sources" not in check_state and prev_state and "ssh_sources" in prev_state:
                snapshot["ssh_sources"] = prev_state["ssh_sources"]  # contrôle désactivé
            save_state(state_path, snapshot)
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
    # Alertes contenues dans ce rapport : le mode --alert-only ne les renverra pas
    remember_alerts(True)
    return 0


def alert_only(args, conf, host, report, checks, alert_path, now, remember_alerts):
    """Envoie un mail court s'il existe une alerte nouvelle (ou un rappel dû)."""
    sent = {} if args.no_state else (load_state(alert_path) or {}).get("alerts", {})
    try:
        remind = int(conf.get("ALERT_REMIND_DAYS") or 7)
    except ValueError:
        remind = 7
    due = pending_alerts(report.alerts, sent, now, remind)
    if not due:
        if not args.quiet:
            warn("aucune alerte nouvelle ({} en cours, déjà signalée(s))".format(
                len(report.alerts)))
        if args.save_state or not (args.stdout or args.html):
            remember_alerts(False)  # oublie les alertes résolues
        return 0
    text, html_doc = alert_message(host, due, report.alerts, checks)
    prefix = conf.get("REPORT_SUBJECT_PREFIX") or "[Fail2ban]"
    subject = "{} [ALERTE] {} : {}".format(prefix, host, plural(len(due), "alerte", "alertes"))
    if args.stdout or args.html:
        if args.stdout:
            data = subject + "\n\n" + text
            out = getattr(sys.stdout, "buffer", None)
            if out is not None:
                out.write(data.encode("utf-8"))
                out.flush()
            else:
                sys.stdout.write(data)
        if args.html:
            with open(args.html, "w", encoding="utf-8") as handle:
                handle.write(html_doc)
        if args.save_state:
            remember_alerts(True)
        return 0
    recipients = [a for a in re.split(r"[\s,;]+", args.to or conf.get("REPORT_TO", "")) if a]
    if not recipients:
        warn("aucun destinataire (REPORT_TO ou --to)")
        return 2
    msg, sender = build_message(conf, recipients, subject, text, html_doc, host)
    try:
        via = send(msg, sender, conf)
    except Exception as exc:  # noqa: BLE001
        warn("échec de l'envoi des alertes : {}".format(exc))
        return 1
    if not args.quiet:
        warn("{} envoyée(s) à {} via {}".format(plural(len(due), "alerte", "alertes"),
                                                ", ".join(recipients), via))
    remember_alerts(True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
