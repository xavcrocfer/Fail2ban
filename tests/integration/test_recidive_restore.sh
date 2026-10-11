#!/bin/bash
# shellcheck disable=SC2034  # variables lues par les fonctions de setup.sh sourcé
# Test d'intégration : restauration de la récidive dédupliquée par IP/événement.
# À lancer dans un conteneur jetable Debian/Ubuntu (root) où fail2ban est installé :
#   podman run --rm -v "$PWD:/src:ro" debian:13 bash /src/tests/integration/test_recidive_restore.sh
#
# Scénario (cassé avant 2.1.0 : un seul échec en mémoire bloquait TOUTE restauration) :
#   • base : A banni 2× par [sshd], B banni 1× ;
#   • le journal contient déjà la ligne « [sshd] Ban B » → la jail relit B toute seule ;
#   • attendu : A restauré (2), B non dupliqué ; 2e passage : rien ; 3e ban de A → A banni 60 j.
set -Eeuo pipefail
fail() { echo "ÉCHEC : $*" >&2; tail -n 40 /var/log/fail2ban.log >&2 || true; exit 1; }
ok() { echo "OK : $*"; }

if ! command -v fail2ban-server >/dev/null; then
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban python3 >/dev/null 2>&1
fi
# shellcheck source=/dev/null
source /src/setup.sh
PYTHON_BIN=$(command -v python3)
RECIDIVE_MAXRETRY=3 RECIDIVE_FINDTIME=30d RECIDIVE_BANTIME=60d
gen_restore_script >/usr/local/sbin/fail2ban-recidive-restore
chmod 0755 /usr/local/sbin/fail2ban-recidive-restore

A=203.0.113.10 B=198.51.100.20 C=192.0.2.30
now=$(date +%s)
tA1=$((now - 5 * 86400)) tA2=$((now - 3 * 86400)) tB=$((now - 2 * 86400))
fmt() { date -d "@$1" '+%Y-%m-%d %H:%M:%S,000'; }

rm -rf /etc/fail2ban/jail.d/* /var/lib/fail2ban/* /var/lib/fail2ban-setup
mkdir -p /var/run/fail2ban
LOG=/var/log/fail2ban.log
: >"$LOG"
gen_f2b_filter_recidive >/etc/fail2ban/filter.d/sshd-recidive.conf
cat >/etc/fail2ban/fail2ban.local <<EOF
[Definition]
logtarget = $LOG
dbfile = /var/lib/fail2ban/fail2ban.sqlite3
dbpurgeage = 90d
EOF
cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
banaction = dummy
banaction_allports = dummy
backend = polling
[sshd]
enabled = false
[sshd-recidive]
enabled  = true
filter   = sshd-recidive
logpath  = $LOG
maxretry = 3
findtime = 30d
bantime  = 60d
EOF
# Ban historique de B déjà présent dans le journal (relu au démarrage)
echo "$(fmt "$tB") fail2ban.actions [1]: NOTICE  [sshd] Ban $B" >>"$LOG"

fail2ban-client -x start >/dev/null 2>&1 || fail "démarrage de fail2ban"
for _ in $(seq 30); do fail2ban-client ping >/dev/null 2>&1 && break; sleep 1; done
python3 - "$A" "$B" "$tA1" "$tA2" "$tB" <<'PY'
import sqlite3, sys
a, b, t1, t2, tb = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
c = sqlite3.connect("/var/lib/fail2ban/fail2ban.sqlite3")
c.execute("INSERT OR IGNORE INTO jails(name, enabled) VALUES('sshd', 0)")
cols = [r[1] for r in c.execute("PRAGMA table_info(bans)")]
for ip, ts in ((a, t1), (a, t2), (b, tb)):
    row = {"jail": "sshd", "ip": ip, "timeofban": ts, "data": "{}"}
    if "bantime" in cols: row["bantime"] = 86400
    if "bancount" in cols: row["bancount"] = 1
    keys = ",".join(row); qs = ",".join("?" * len(row))
    c.execute("INSERT INTO bans({}) VALUES({})".format(keys, qs), list(row.values()))
c.commit()
PY
# Restauration lancée TOUT DE SUITE (comme ExecStartPost) : la jail n'a pas
# encore relu B → le script doit attendre la stabilisation, sinon B serait doublé.
/usr/local/sbin/fail2ban-recidive-restore 2>&1 | tee /tmp/r1
grep -q "\[sshd-recidive\] Found $B" "$LOG" || fail "la jail n'a pas relu le ban de B"
ok "la jail a relu B seule (Currently failed > 0 : l'ancien script n'aurait rien restauré)"
grep -q "1 IP / 2 ban(s)" /tmp/r1 || fail "premier passage : 1 IP / 2 bans attendus"
[[ $(grep -c "\[sshd-recidive\] Attempt $A" "$LOG") -eq 1 ]] || fail "une injection pour A attendue"
grep -q "\[sshd-recidive\] Attempt $B" "$LOG" && fail "B ne doit pas être réinjecté (déjà relu)"
ok "A×2 restauré, B non dupliqué malgré la course au démarrage"

dry=$(/usr/local/sbin/fail2ban-recidive-restore --dry-run 2>&1)
echo "$dry"
grep -q "0 IP / 0 ban(s)" <<<"$dry" || fail "dry-run : plus rien à restaurer attendu"
/usr/local/sbin/fail2ban-recidive-restore 2>&1 | tee /tmp/r2
grep -q "0 IP / 0 ban(s)" /tmp/r2 || fail "second passage : aucun doublon attendu"
ok "restauration idempotente (état par démarrage)"

# 3e ban de A → seuil atteint → ban de récidive ; C (1 seul ban) jamais banni
echo "$(date '+%Y-%m-%d %H:%M:%S,000') fail2ban.actions [1]: NOTICE  [sshd] Ban $A" >>"$LOG"
echo "$(date '+%Y-%m-%d %H:%M:%S,000') fail2ban.actions [1]: NOTICE  [sshd] Ban $C" >>"$LOG"
for _ in $(seq 15); do
    [[ $(fail2ban-client status sshd-recidive) == *"$A"* ]] && break
    sleep 1
done
st=$(fail2ban-client status sshd-recidive)
grep -q "Banned IP list:.*$A" <<<"$st" || fail "A aurait dû être banni par la récidive"
grep -q "Banned IP list:.*$C" <<<"$st" && fail "C ne doit pas être banni"
ok "A banni au 3e ban (2 restaurés + 1 nouveau), C non banni"

# Redémarrage : nouvel état, pas de réinjection pour A (déjà banni)
fail2ban-client restart >/dev/null 2>&1; sleep 4
/usr/local/sbin/fail2ban-recidive-restore 2>&1 | tee /tmp/r3
grep -q "Banned IP list:.*$A" <(fail2ban-client status sshd-recidive) || fail "A doit rester banni après redémarrage"
grep -q "1 IP / 1 ban(s)" /tmp/r3 || fail "après redémarrage : B (oublié en mémoire, non relu) doit être restauré une fois"
[[ $(grep -c "\[sshd-recidive\] Attempt $A" "$LOG") -eq 1 ]] || fail "A (banni) ne doit pas être réinjecté"
ok "après redémarrage : A reste banni sans réinjection, B restauré une seule fois"
fail2ban-client stop >/dev/null 2>&1 || true
echo "TOUS LES TESTS DE RÉCIDIVE SONT PASSÉS"
