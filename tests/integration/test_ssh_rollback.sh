#!/bin/bash
# shellcheck disable=SC2034  # variables lues par les fonctions de setup.sh sourcé
# Test d'intégration du changement de port SSH et de son retour arrière indépendant.
# Conteneur systemd réel requis (voir images/Containerfile.debian13) :
#   podman run -d --name f2bt --systemd=always -v "$PWD:/src:ro,Z" f2b-test-debian13
#   podman exec f2bt bash /src/tests/integration/test_ssh_rollback.sh
set -Euo pipefail
NEW=2222
fail() { echo "ÉCHEC : $*" >&2; journalctl -n 30 --no-pager >&2 2>/dev/null || true; exit 1; }
ok() { echo "OK : $*"; }
listening() { ss -Hltn "sport = :$1" | grep -q LISTEN; }
effective_ports() { sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -n | xargs; }
command -v script >/dev/null || fail "util-linux « script » requis"
# systemd (timer transitoire) ou OpenRC/autre (processus détaché setsid)
if [[ -d /run/systemd/system ]]; then
    ssh_restart() { systemctl reset-failed ssh sshd 2>/dev/null; systemctl restart ssh 2>/dev/null || systemctl restart sshd; }
    timer_armed() { [[ -n $(systemctl list-timers --all --no-legend 'fail2ban-setup-ssh-rollback-*' 2>/dev/null) ]]; }
    stop_watchdogs() { systemctl stop 'fail2ban-setup-ssh-rollback-*.timer' 2>/dev/null || true; }
else
    ssh_restart() { rc-service sshd restart >/dev/null 2>&1; }
    timer_armed() { pgrep -f 'ssh-rollback\..*/rollback\.sh' >/dev/null; }
    stop_watchdogs() { pkill -f 'ssh-rollback\..*/rollback\.sh' 2>/dev/null || true; }
fi
# stdin des pilotes maintenu ouvert par un processus reconnaissable (ne jamais
# tuer le « sleep » du watchdog ; exec -a est inopérant avec coreutils multi-appel)
hold_stdin() { exec tail -f /dev/null; }

# Pilote : reproduit main() jusqu'au changement de port
cat >/tmp/driver.sh <<'EOF'
source /src/setup.sh
install -d -m 0700 "$BACKUP_ROOT"; touch "$LOG_FILE"; LOG_READY=1
trap cleanup EXIT
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR
trap on_interrupt INT TERM HUP
detect_all >/dev/null
NEW_SSH_PORT=2222
change_ssh_port
echo "FINAL=${SSH_FINAL_PORTS}"
EOF

reset_state() {
    stop_watchdogs
    pkill -f /tmp/driver.sh 2>/dev/null || true
    pkill -f '^tail -f /dev/null' 2>/dev/null || true
    rm -f /etc/ssh/sshd_config.d/*fail2ban-setup* 2>/dev/null
    sed -i 's/^#\([[:space:]]*Port .*\)   # désactivé par fail2ban-setup.*$/\1/' /etc/ssh/sshd_config
    rm -rf /var/lib/fail2ban-setup/ssh-rollback.*
    ssh_restart; sleep 1
    [[ $(effective_ports) == 22 ]] || fail "état initial : port 22 attendu, vu $(effective_ports)"
}

wait_until() { # wait_until SECONDES commande…
    local t=$1; shift
    for ((i = 0; i < t; i++)); do "$@" && return 0; sleep 1; done
    return 1
}
# (timer_armed sans tube : avec pipefail, « … | grep -q » peut échouer par SIGPIPE)
restored() { [[ $(effective_ports) == 22 ]] && listening 22 && ! listening $NEW; }

# ── 1. SIGKILL pendant l'attente de confirmation → le watchdog systemd restaure seul
reset_state
# stdin maintenu ouvert (sinon read voit EOF et le retour arrière part tout de suite)
hold_stdin 2>/dev/null | SSH_CONFIRM_TIMEOUT=6 SSH_RB_GRACE=4 script -qfec "bash /tmp/driver.sh" /dev/null >/tmp/t1.log 2>&1 &
wait_until 30 grep -q "TEST OBLIGATOIRE" /tmp/t1.log || fail "T1 : invite de confirmation absente"
listening $NEW && listening 22 || fail "T1 : la phase de test doit écouter sur 22 ET ${NEW}"
ok "T1 : phase de test sur 22 + ${NEW}"
timer_armed || fail "T1 : timer de retour arrière non armé"
pkill -KILL -f /tmp/driver.sh; pkill -KILL -x script; pkill -f "^tail -f /dev/null" || true
ok "T1 : installateur tué par SIGKILL (aucun trap ne peut s'exécuter)"
restored && fail "T1 : rien ne devait être restauré avant l'échéance"
wait_until 25 restored || fail "T1 : le watchdog n'a pas restauré le port 22 (vu : $(effective_ports))"
ok "T1 : watchdog indépendant → port 22 restauré, ${NEW} fermé"

# ── 2. Coupure de la session (SIGHUP) → retour arrière immédiat par le trap
reset_state
hold_stdin 2>/dev/null | SSH_CONFIRM_TIMEOUT=60 script -qfec "bash /tmp/driver.sh" /dev/null >/tmp/t2.log 2>&1 &
wait_until 30 grep -q "TEST OBLIGATOIRE" /tmp/t2.log || fail "T2 : invite absente"
pkill -HUP -f "^bash /tmp/driver.sh"   # le pilote seul, pas « script »
wait_until 10 restored || fail "T2 : SIGHUP n'a pas restauré immédiatement"
timer_armed && fail "T2 : timer encore armé après restauration"
ok "T2 : SIGHUP (session coupée) → restauration immédiate, watchdog désarmé"

# ── 3. Confirmation « oui » → seul le nouveau port reste, watchdog désarmé
reset_state
( wait_until 30 grep -q "TEST OBLIGATOIRE" /tmp/t3.log; sleep 1; echo oui ) |
    SSH_CONFIRM_TIMEOUT=60 script -qfec "bash /tmp/driver.sh" /dev/null >/tmp/t3.log 2>&1
grep -q "FINAL=${NEW}" /tmp/t3.log || fail "T3 : port final ${NEW} attendu ($(tail -5 /tmp/t3.log))"
[[ $(effective_ports) == "$NEW" ]] && listening $NEW && ! listening 22 || fail "T3 : seul ${NEW} doit écouter"
timer_armed && fail "T3 : timer encore armé"
ls -d /var/lib/fail2ban-setup/ssh-rollback.* 2>/dev/null && fail "T3 : état de retour arrière non nettoyé"
ok "T3 : confirmé → port ${NEW} seul, ancien port retiré, watchdog désarmé"

# ── 4. Non interactif → les deux ports sont conservés, rien ne reviendra en arrière
reset_state
cat >/tmp/driver_ni.sh <<'EOF'
source /src/setup.sh
OPT_NONINTERACTIVE=true
install -d -m 0700 "$BACKUP_ROOT"; touch "$LOG_FILE"; LOG_READY=1
detect_all >/dev/null
NEW_SSH_PORT=2222
change_ssh_port
echo "FINAL=${SSH_FINAL_PORTS}"
EOF
SSH_CONFIRM_TIMEOUT=3 SSH_RB_GRACE=2 bash /tmp/driver_ni.sh </dev/null >/tmp/t4.log 2>&1
grep -q "FINAL=22,${NEW}" /tmp/t4.log || fail "T4 : « 22,${NEW} » attendu ($(tail -5 /tmp/t4.log))"
sleep 8
listening 22 && listening $NEW || fail "T4 : les deux ports doivent rester ouverts après l'échéance"
ok "T4 : non interactif → 22 conservé + ${NEW}, aucun retour arrière intempestif"

reset_state
echo "TOUS LES TESTS SSH SONT PASSÉS"
