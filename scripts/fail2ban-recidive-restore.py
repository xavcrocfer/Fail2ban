#!/usr/bin/env python3
# Source de vérité : copié dans setup.sh par scripts/embed.py (voir --check).
__version__ = "dev"
# ==== corps embarqué dans setup.sh (ne rien mettre au-dessus) ====
#
# fail2ban-recidive-restore — restaure le compteur de la jail de récidive
#
# Fail2ban garde les échecs en cours en mémoire et, au redémarrage, reprend la
# lecture de ses journaux là où il s'était arrêté : la jail « sshd-recidive »
# oublie donc les bans [sshd] déjà comptés sur sa fenêtre (30 j), et la règle
# « 3 bans → 60 jours » ne survivrait pas à un reboot ou à une mise à jour.
#
# Ce script relit ces bans dans la base SQLite de Fail2ban et les réinjecte avec
# « fail2ban-client set <jail> attempt ». Il est lancé par systemd après chaque
# démarrage de Fail2ban (ExecStartPost) et par fail2ban-setup.
#
# Déduplication PAR IP ET PAR ÉVÉNEMENT (et non plus sur le compteur global de
# la jail) : depuis le dernier « Starting Fail2ban » du journal, on relève
#   • « [sshd-recidive] Found <IP> - <date> » : bans déjà relus par la jail (la date
#     est celle de la ligne de ban d'origine → comparable à timeofban) ;
#   • les injections déjà faites par ce script pour CE démarrage (fichier d'état).
# Seuls les bans [sshd] ni relus ni déjà injectés sont réinjectés. Une IP B
# fraîchement comptée n'empêche donc plus de restaurer l'historique d'une IP A.
#
# Les IP déjà bannies par la récidive, ou ayant déjà atteint le seuil sans être
# bannies (débannies à la main), sont ignorées. Les échecs restaurés sont datés
# du redémarrage : ils expirent un peu plus tard que les originaux (choix prudent).
#
import argparse
import collections
import datetime as dt
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

STATE_FILE = "/var/lib/fail2ban-setup/recidive-restore.json"
TOLERANCE = 3  # secondes entre timeofban (base) et l'horodatage de la ligne « Ban »


def log(msg):
    print("fail2ban-recidive-restore: " + msg, file=sys.stderr)


def client(*args):
    exe = shutil.which("fail2ban-client") or "/usr/bin/fail2ban-client"
    try:
        proc = subprocess.run([exe] + list(args), stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, universal_newlines=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def last_value(out):
    """Dernière ligne/mot significatif d'une réponse « fail2ban-client get »."""
    lines = [l.strip(" `|-") for l in (out or "").splitlines() if l.strip(" `|-")]
    return lines[-1] if lines else ""


def parse_since_start(logfile, jail):
    """(marqueur du démarrage courant, {ip: [timestamps déjà relus]})."""
    start, seen = None, collections.defaultdict(list)
    found = re.compile(r"\[" + re.escape(jail) + r"\] Found (\S+) - (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")
    try:
        with open(logfile, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "Starting Fail2ban" in line:
                    start, seen = line.strip(), collections.defaultdict(list)
                    continue
                m = found.search(line)
                if m:
                    try:
                        ts = time.mktime(time.strptime(m.group(2), "%Y-%m-%d %H:%M:%S"))
                    except ValueError:
                        continue
                    seen[m.group(1)].append(ts)
    except OSError as exc:
        log("journal {} illisible ({}) : déduplication par journal impossible".format(logfile, exc))
    return start, seen


def load_state(marker):
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("start") == marker:
            return {ip: list(v) for ip, v in data.get("injected", {}).items()}
    except (OSError, ValueError, AttributeError):
        pass
    return {}


def save_state(marker, injected):
    os.makedirs(os.path.dirname(STATE_FILE), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(STATE_FILE))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"start": marker, "injected": injected}, fh)
    os.replace(tmp, STATE_FILE)


def wait_stable(jail, minimum, quiet=5, maximum=45):
    start = last_change = time.time()
    last = None
    while True:
        m = re.search(r"Total failed:\s*(\d+)", client("status", jail) or "")
        cur = m.group(1) if m else None
        now = time.time()
        if cur != last:
            last, last_change = cur, now
        if now - start >= minimum and now - last_change >= quiet:
            return
        if now - start >= maximum:
            log("compteur de {} encore instable après {} s : poursuite".format(jail, maximum))
            return
        time.sleep(1)


def already(ts, stamps):
    return any(abs(ts - s) <= TOLERANCE for s in stamps)


def main():
    parser = argparse.ArgumentParser(
        description="Restaure le compteur de la jail de récidive depuis la base Fail2ban.")
    parser.add_argument("--source", default="sshd", help="jail surveillée (défaut : sshd)")
    parser.add_argument("--recidive", default="sshd-recidive",
                        help="jail de récidive (défaut : sshd-recidive)")
    parser.add_argument("--wait", type=int, default=60,
                        help="attente maximale du démarrage de Fail2ban, en secondes")
    parser.add_argument("--logfile", help="journal Fail2ban (défaut : logtarget du serveur)")
    parser.add_argument("-n", "--dry-run", action="store_true", help="affiche sans rien injecter")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args()

    deadline = time.time() + args.wait
    while client("ping") is None:
        if time.time() > deadline:
            log("Fail2ban ne répond pas, abandon")
            return 1
        time.sleep(1)

    status = client("status", args.recidive)
    if status is None:
        log("jail {} inactive : rien à faire".format(args.recidive))
        return 0
    banned = re.search(r"Banned IP list:\s*(.*)", status)
    banned = set(banned.group(1).split()) if banned else set()
    try:
        findtime = int(last_value(client("get", args.recidive, "findtime")))
        maxretry = int(last_value(client("get", args.recidive, "maxretry")))
    except ValueError:
        log("impossible de lire findtime/maxretry de {}".format(args.recidive))
        return 1
    dbfile = re.search(r"(/\S+)\s*$", (client("get", "dbfile") or "").strip())
    if not dbfile:
        log("base de données Fail2ban désactivée : rien à restaurer")
        return 0
    logfile = args.logfile or last_value(client("get", "logtarget"))
    if not logfile.startswith("/"):
        log("logtarget « {} » n'est pas un fichier : restauration impossible sans doublons".format(logfile))
        return 1

    # La jail relit ses journaux en tâche de fond (backend polling : plusieurs
    # secondes après le démarrage). On attend que « Total failed » ne bouge plus
    # pendant 5 s (au moins 8 s, au plus 45 s) avant de comparer avec la base.
    wait_stable(args.recidive, 0 if args.dry_run else 8)
    marker, seen = parse_since_start(logfile, args.recidive)
    if marker is None:
        log("aucun « Starting Fail2ban » dans {} : abandon prudent".format(logfile))
        return 1
    injected = load_state(marker)

    con = sqlite3.connect("file:{}?mode=ro".format(quote(dbfile.group(1))), uri=True, timeout=30)
    try:
        rows = con.execute("SELECT ip, timeofban FROM bans WHERE jail = ? AND timeofban >= ? "
                           "ORDER BY timeofban", (args.source, int(time.time() - findtime))).fetchall()
    finally:
        con.close()
    history = collections.OrderedDict()
    for ip, ts in rows:
        history.setdefault(ip, []).append(ts)

    restored = events = 0
    for ip, stamps in history.items():
        if ip in banned or len(stamps) >= maxretry:
            continue
        counted = seen.get(ip, []) + injected.get(ip, [])
        todo = [ts for ts in stamps if not already(ts, counted)]
        if not todo:
            continue
        matches = ["[{}] Ban {} du {:%Y-%m-%d %H:%M:%S} (compteur restauré)".format(
            args.source, ip, dt.datetime.fromtimestamp(ts)) for ts in todo]
        if args.dry_run:
            print("{} : {} ban(s) {} à restaurer ({} déjà compté(s))".format(
                ip, len(todo), args.source, len(stamps) - len(todo)))
        elif client("set", args.recidive, "attempt", ip, *matches) is None:
            log("échec de la restauration pour {}".format(ip))
            continue
        else:
            injected.setdefault(ip, []).extend(todo)
        restored += 1
        events += len(todo)
    if not args.dry_run:
        save_state(marker, injected)
    log("{} IP / {} ban(s) {} dans {} (bans [{}] des {} derniers jours, seuil {})".format(
        restored, events, "à restaurer (simulation)" if args.dry_run else "restauré(s)",
        args.recidive, args.source, findtime // 86400, maxretry))
    return 0


if __name__ == "__main__":
    sys.exit(main())
