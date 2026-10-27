#!/bin/bash
# Régression d'un VPS Plesk fictif : jail.conf minimal sans les macros action_,
# 13 jails historiques actives et paquet Plesk sans actions nftables installées.
set -Euo pipefail
fail() { echo "ÉCHEC : $*" >&2; tail -n 40 /var/log/fail2ban-setup*.log >&2 2>/dev/null || true; exit 1; }
ok() { echo "OK : $*"; }
S=/src/setup.sh
COMMON=(-y --keep-ssh-port --ignore-ip "198.51.100.199" --email admin@example.org \
    --smtp-host smtp.example.org --smtp-port 587 --smtp-user alert@example.org)

. /etc/os-release
if [[ ${ID:-} != debian ]]; then
    ok "régression Plesk ciblée Debian : distribution ${ID:-inconnue} ignorée"
    exit 0
fi

# Le test est autonome : installer d'abord le paquet et Postfix dans le conteneur.
if ! command -v fail2ban-client >/dev/null; then
    SMTP_PASSWORD='s3cret-test' bash "$S" "${COMMON[@]}" >/tmp/plesk-prereq.log 2>&1 ||
        fail "préinstallation : code $?"
fi

# Base réduite fournie par Plesk : elle définit directement les actions des deux
# jails historiques, mais aucune des macros action_/action_mw du jail.conf amont.
cat >/etc/fail2ban/jail.conf <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 10m
findtime = 10m
maxretry = 5
backend = auto
enabled = false

[ssh]
filter = sshd
action = iptables[name=ssh, port=ssh]
logpath = /var/log/auth.log

[recidive]
filter = recidive
action = iptables-allports[name=recidive]
logpath = /var/log/fail2ban.log
bantime = 1w
findtime = 1d
EOF

# Les 11 jails Plesk réellement actives sur le VPS, plus ssh et recidive = 13.
cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 203.0.113.148
[ssh]
enabled = true
[recidive]
enabled = true
[plesk-proftpd]
enabled = true
[plesk-postfix]
enabled = true
[plesk-dovecot]
enabled = true
[plesk-roundcube]
enabled = true
[plesk-apache]
enabled = true
[plesk-apache-badbot]
enabled = true
[plesk-panel]
enabled = true
[plesk-wordpress]
enabled = true
[plesk-mailconfig]
enabled = true
[plesk-permanent-ban]
enabled = true
[plesk-one-week-ban]
enabled = true
EOF

# Les noms sont ceux du serveur. Des filtres/actions standards suffisent ici :
# le comportement testé est la fusion de configuration et le nombre de jails.
cat >/etc/fail2ban/jail.d/plesk.conf <<'EOF'
[plesk-proftpd]
filter = sshd
action = iptables-multiport[name=plesk-proftpd, port=ftp]
logpath = /var/log/auth.log
[plesk-postfix]
filter = sshd
action = iptables-multiport[name=plesk-postfix, port=smtp]
logpath = /var/log/auth.log
[plesk-dovecot]
filter = sshd
action = iptables-multiport[name=plesk-dovecot, port=imap]
logpath = /var/log/auth.log
[plesk-roundcube]
filter = sshd
action = iptables-multiport[name=plesk-roundcube, port=http]
logpath = /var/log/auth.log
[plesk-apache]
filter = sshd
action = iptables-multiport[name=plesk-apache, port=http]
logpath = /var/log/auth.log
[plesk-apache-badbot]
filter = sshd
action = iptables-multiport[name=plesk-apache-badbot, port=http]
logpath = /var/log/auth.log
[plesk-panel]
filter = sshd
action = iptables-multiport[name=plesk-panel, port=https]
logpath = /var/log/auth.log
[plesk-wordpress]
filter = sshd
action = iptables-multiport[name=plesk-wordpress, port=http]
logpath = /var/log/auth.log
[plesk-mailconfig]
filter = sshd
action = iptables-multiport[name=plesk-mailconfig, port=http]
logpath = /var/log/auth.log
[plesk-permanent-ban]
filter = sshd
action = iptables-allports[name=plesk-permanent-ban]
logpath = /var/log/auth.log
[plesk-one-week-ban]
filter = sshd
action = iptables-allports[name=plesk-one-week-ban]
logpath = /var/log/auth.log
EOF

touch /var/log/auth.log /var/log/fail2ban.log
# Le paquet Plesk du VPS ne déploie que les actions iptables dans /etc. Debian
# amont conserve leurs modèles sous /usr/share/doc : les recopier simule le
# contenu exact disponible sur le serveur, puis retirer les actions nftables.
if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables >/dev/null
fi
for action in iptables iptables-multiport iptables-allports; do
    src=/usr/share/doc/fail2ban/dist-config/action.d/${action}.conf
    [[ -r $src ]] && install -m 0644 "$src" "/etc/fail2ban/action.d/${action}.conf"
done
rm -f /etc/fail2ban/action.d/nftables.conf \
      /etc/fail2ban/action.d/nftables-multiport.conf \
      /etc/fail2ban/action.d/nftables-allports.conf
command -v nft >/dev/null || fail "précondition : nft doit être présent"
command -v iptables >/dev/null || fail "précondition : iptables doit être présent"
for action in iptables-multiport iptables-allports; do
    [[ -r /etc/fail2ban/action.d/${action}.conf ]] || fail "précondition : action ${action} absente"
done
for action in nftables-multiport nftables-allports; do
    [[ ! -e /etc/fail2ban/action.d/${action}.conf ]] || fail "précondition : action ${action} encore présente"
done

SMTP_PASSWORD='s3cret-test' bash "$S" "${COMMON[@]}" >/tmp/plesk-install.log 2>&1 ||
    fail "installation sur configuration Plesk : code $? ($(tail -8 /tmp/plesk-install.log))"
fail2ban-client --test >/tmp/plesk-test.log 2>&1 ||
    fail "configuration finale invalide : $(tail -8 /tmp/plesk-test.log)"

generated=/etc/fail2ban/jail.d/10-fail2ban-setup-sshd.local
! grep -q '%(action_)s' "$generated" || fail "la configuration dépend encore de la macro action_ absente"
grep -q '^banaction[[:space:]]*= iptables-multiport$' /etc/fail2ban/jail.d/00-fail2ban-setup-defaults.local ||
    fail "repli vers l'action iptables disponible non effectué"
ok "jail.conf Plesk sans action_ + actions nftables absentes → configuration valide"

status=$(fail2ban-client status)
list=${status##*Jail list:}
IFS=',' read -ra jails <<<"$list"
[[ ${#jails[@]} -eq 15 ]] || fail "15 jails attendues (13 Plesk/historiques + 2 nouvelles) : ${list}"
for jail in ssh recidive plesk-proftpd plesk-postfix plesk-dovecot plesk-roundcube \
    plesk-apache plesk-apache-badbot plesk-panel plesk-wordpress plesk-mailconfig \
    plesk-permanent-ban plesk-one-week-ban sshd sshd-recidive; do
    fail2ban-client status "$jail" >/dev/null 2>&1 || fail "jail absente : $jail"
done
ok "13 jails historiques Plesk + sshd/sshd-recidive chargées (15 au total)"

# Les actions sont initialisées au premier ban : valider leur exécution réelle,
# pas seulement leur lecture par fail2ban-client --test.
BAN_SSH=198.51.100.77
BAN_RECIDIVE=198.51.100.78
fail2ban-client set sshd banip "$BAN_SSH" >/dev/null || fail "ban réel sshd impossible"
fail2ban-client set sshd-recidive banip "$BAN_RECIDIVE" >/dev/null || fail "ban réel récidive impossible"
sleep 2
rules=$(nft list ruleset 2>/dev/null)
[[ $rules == *"f2b-sshd"* && $rules == *"dport 22"* && $rules == *"$BAN_SSH"* ]] ||
    fail "règle multiport sshd/22 absente de nftables"
[[ $rules == *"f2b-sshd-recidive"* && $rules == *"$BAN_RECIDIVE"* ]] ||
    fail "règle allports sshd-recidive absente de nftables"
fail2ban-client set sshd unbanip "$BAN_SSH" >/dev/null || fail "unban sshd impossible"
fail2ban-client set sshd-recidive unbanip "$BAN_RECIDIVE" >/dev/null || fail "unban récidive impossible"
ok "repli iptables-nft : bans sshd (port 22) et sshd-recidive (tous ports) visibles dans nftables"
