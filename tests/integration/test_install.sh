#!/bin/bash
# Installation complète dans un conteneur systemd (voir images/Containerfile.debian13) :
#   podman exec f2bt bash /src/tests/integration/test_install.sh
# Couvre : refus hyperviseur (code 3) + --force-hypervisor, installation non
# interactive, relais SMTP en TLS strict, puis --no-report qui retire la planification.
set -Euo pipefail
fail() { echo "ÉCHEC : $*" >&2; tail -n 30 /var/log/fail2ban-setup*.log >&2 2>/dev/null || true; exit 1; }
ok() { echo "OK : $*"; }
S=/src/setup.sh
# Abstraction init : systemd (timer) ou OpenRC/cron (Alpine)
if [[ -d /run/systemd/system ]]; then
    f2b_active() { systemctl is-active --quiet fail2ban; }
    report_scheduled() { systemctl is-enabled --quiet fail2ban-report.timer; }
    report_calendar() { sed -n 's/^OnCalendar=//p' /etc/systemd/system/fail2ban-report.timer; }
    report_gone() { [[ ! -e /etc/systemd/system/fail2ban-report.timer ]] && ! systemctl is-active --quiet fail2ban-report.timer; }
else
    f2b_active() { rc-service fail2ban status >/dev/null 2>&1; }
    report_scheduled() { grep -qs fail2ban-report /etc/crontabs/root /etc/cron.d/fail2ban-report; }
    report_gone() { ! report_scheduled; }
    # « mm hh jour mois jsem » de la ligne cron
    report_calendar() { grep -hs fail2ban-report /etc/crontabs/root /etc/cron.d/fail2ban-report | grep -v '^#' | awk '{print $1, $2, $3, $4, $5}'; }
fi
COMMON=(-y --keep-ssh-port --ignore-ip 10.0.0.0/8)

# 1. Hyperviseur simulé (/etc/pve) → refus, rien d'installé
mkdir -p /etc/pve
out=$(bash "$S" "${COMMON[@]}" --no-report 2>&1); rc=$?
[[ $rc -eq 3 ]] || fail "code 3 attendu sur hyperviseur, obtenu ${rc}"
grep -q "Hyperviseur détecté : Proxmox VE" <<<"$out" || fail "message hyperviseur absent"
command -v fail2ban-server >/dev/null && fail "rien ne doit être installé sur un hyperviseur"
ok "hyperviseur Proxmox simulé → refus (code 3), rien installé"
out=$(bash "$S" --detect 2>&1)
grep -q "HYPERVISEUR Proxmox VE" <<<"$out" || fail "--detect doit signaler l'hyperviseur"
ok "--detect affiche l'hyperviseur sans refuser"
rmdir /etc/pve
out=$(bash "$S" --detect 2>&1)
grep -q "invité VM" <<<"$out" || fail "--detect doit afficher l'état invité"
ok "sans /etc/pve : simple invité, accepté"

# 2. Installation avec relais SMTP (TLS strict par défaut)
SMTP_PASSWORD='s3cret-test' bash "$S" "${COMMON[@]}" --email admin@example.org \
    --smtp-host smtp.example.org --smtp-port 587 --smtp-user alert@example.org \
    >/tmp/inst.log 2>&1 || fail "installation : code $? ($(tail -5 /tmp/inst.log))"
f2b_active || fail "fail2ban inactif"
fail2ban-client status sshd >/dev/null || fail "jail sshd absente"
fail2ban-client status sshd-recidive >/dev/null || fail "jail sshd-recidive absente"
ok "installation non interactive : fail2ban actif, jails sshd + sshd-recidive"
pc() { postconf -h "$1"; }
[[ $(pc smtp_tls_security_level) == secure ]] || fail "smtp_tls_security_level=secure attendu ($(pc smtp_tls_security_level))"
[[ $(pc smtp_tls_wrappermode) == no ]] || fail "wrappermode=no attendu sur 587"
[[ $(pc smtp_sasl_security_options) == *noplaintext* ]] || fail "noplaintext attendu"
[[ -n $(pc smtp_tls_CAfile) ]] || fail "CAfile attendu"
grep -rq 's3cret-test' /var/log/ 2>/dev/null && fail "mot de passe SMTP présent dans un journal"
ok "Postfix : TLS secure (certificat vérifié), SASL sans clair, secret absent des journaux"
report_scheduled || fail "rapport non planifié"
conf=/etc/fail2ban/report.conf
# Conteneur sur réseau privé (10.88.x / 10.0.2.x) : profil LAN → rapport mensuel le 1er
grep -q '^HOST_PROFILE="lan"' $conf || fail "profil lan attendu ($(grep HOST_PROFILE $conf))"
grep -q '^REPORT_PERIOD="month"' $conf || fail "période month attendue"
grep -q '^REPORT_STATE="/var/lib/fail2ban-setup/report-state.json"' $conf || fail "REPORT_STATE absent"
cal=$(report_calendar)
[[ $cal == "*-*-01 08:00:00" || $cal == "0 8 1 * *" ]] || fail "planification mensuelle attendue (« ${cal} »)"
grep -q "le 1er de chaque mois" /tmp/inst.log || fail "résumé mensuel absent"
ok "profil LAN détecté → rapport mensuel le 1er (${cal})"
[[ ! -e /var/lib/fail2ban-setup/report-state.json ]] || fail "l'aperçu (--until-now) ne doit pas mémoriser l'état"
fail2ban-report --stdout --no-geoip --save-state >/tmp/rep.txt 2>&1 || fail "fail2ban-report : code $?"
grep -q "NOUVEAUTÉS" /tmp/rep.txt || fail "section Nouveautés absente"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["version"]==1 and d["profile"]=="lan", d' \
    /var/lib/fail2ban-setup/report-state.json || fail "état du rapport invalide"
[[ $(stat -c %a /var/lib/fail2ban-setup/report-state.json) == 600 ]] || fail "état non protégé (600 attendu)"
fail2ban-report --stdout --no-geoip >/tmp/rep2.txt 2>&1 || fail "2e rapport : code $?"
grep -q "Rien de nouveau\|déjà bannie" /tmp/rep2.txt || fail "2e rapport : delta non calculé"
ok "rapport : section Nouveautés, état mémorisé (600), delta au 2e passage"

# 3. Port 25 : TLS toujours obligatoire (plus d'opportuniste « may »)
SMTP_PASSWORD='s3cret-test' bash "$S" "${COMMON[@]}" --email admin@example.org \
    --smtp-host smtp.example.org --smtp-port 25 --smtp-user alert@example.org --smtp-tls encrypt \
    --profile vps --report-period week --report-day mar \
    >/tmp/inst25.log 2>&1 || fail "réinstallation port 25 : code $?"
[[ $(pc smtp_tls_security_level) == encrypt ]] || fail "port 25 : encrypt attendu ($(pc smtp_tls_security_level))"
ok "port 25 + --smtp-tls encrypt → TLS obligatoire (jamais « may »)"
grep -q '^HOST_PROFILE="vps"' $conf && grep -q '^REPORT_PERIOD="days"' $conf || fail "--profile vps / week non appliqués"
cal=$(report_calendar)
[[ $cal == "Tue *-*-* 08:00:00" || $cal == "0 8 * * 2" ]] || fail "planification hebdo mardi attendue (« ${cal} »)"
grep -q '^HOST_PROFILE=vps' /var/lib/fail2ban-setup/answers.env || fail "profil non mémorisé"
ok "--profile vps --report-period week --report-day mar → mardi 08:00 (${cal}), mémorisé"
bash "$S" -y --profile dmz >/dev/null 2>&1 && fail "--profile dmz doit être refusé"
bash "$S" -y --report-period daily >/dev/null 2>&1 && fail "--report-period daily doit être refusé"
det=$(bash "$S" --detect 2>&1)  # pas de « | grep -q » : SIGPIPE sous pipefail
[[ $det == *"Profil détecté"*lan* ]] || fail "--detect : profil détecté absent"
ok "options invalides refusées ; --detect affiche le profil détecté"
bash "$S" -y --smtp-tls may >/dev/null 2>&1 && fail "--smtp-tls may doit être refusé"
ok "--smtp-tls may refusé"

# 4. --no-report retire réellement la planification
bash "$S" "${COMMON[@]}" --no-report >/tmp/norep.log 2>&1 || fail "--no-report : code $?"
report_gone || fail "planification du rapport toujours présente après --no-report"
grep -q "Plus aucun rapport ne sera envoyé" /tmp/norep.log || fail "message de désactivation absent"
ok "--no-report : planification désactivée et supprimée"

# 5. --force-hypervisor : installation tolérée avec avertissement
mkdir -p /etc/pve
bash "$S" "${COMMON[@]}" --no-report --force-hypervisor >/tmp/force.log 2>&1 || fail "--force-hypervisor : code $?"
grep -q "installation FORCÉE" /tmp/force.log || fail "avertissement --force-hypervisor absent"
rmdir /etc/pve
ok "--force-hypervisor : installation acceptée avec avertissement"
echo "TOUS LES TESTS D'INSTALLATION SONT PASSÉS"
