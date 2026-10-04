#!/usr/bin/env bash
#===============================================================================
#
#   Fail2ban Setup — installation & configuration multi-distribution de Fail2ban
#
#   Usage   : sudo ./setup.sh [options]            (aide : ./setup.sh --help)
#   Version : 2.0.0
#
#   Distributions prises en charge
#     • Debian, Ubuntu, Linux Mint, Raspberry Pi OS, Devuan ............ apt
#     • RHEL, Rocky, AlmaLinux, CentOS Stream, Oracle, Fedora, Amazon .. dnf/yum (+EPEL)
#     • openSUSE Leap / Tumbleweed, SLES ............................... zypper
#     • Arch, Manjaro, EndeavourOS ..................................... pacman
#     • Alpine (OpenRC ; installer bash d'abord : apk add bash) ......... apk
#
#   Ce que fait le script
#     1. Détecte la distribution, l'init, le pare-feu, SELinux et le service SSH.
#     2. Si SSH écoute sur le port 22, propose de le changer (SELinux, pare-feu,
#        socket systemd gérés) avec test de connexion et retour arrière auto.
#     3. Installe Fail2ban et configure deux jails SSH :
#          [sshd]           5 échecs en 1 h          → ban 24 h
#          [sshd-recidive]  3 bans [sshd] en 30 j    → ban 60 j, tous ports
#     4. Configure (option) Postfix en relais SMTP authentifié.
#     5. Installe un rapport hebdomadaire HTML des bans (timer systemd / cron).
#
#   Le script est idempotent : il peut être relancé pour modifier la config,
#   les réponses précédentes sont proposées par défaut.
#
#===============================================================================

# --- Garde-fous : bash >= 4.2 requis -------------------------------------------
if [ -z "${BASH_VERSION:-}" ]; then
    echo "Ce script nécessite bash (Alpine : apk add bash). Lancez : sudo bash $0" >&2
    exit 1
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
    echo "bash >= 4.2 requis (version actuelle : ${BASH_VERSION})." >&2
    exit 1
fi

set -Eeuo pipefail
umask 022
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

#===============================================================================
# 1. CONSTANTES & PARAMÈTRES
#===============================================================================
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="fail2ban-setup"
readonly MANAGED_MARK="Géré par ${SCRIPT_NAME}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
readonly RUN_ID

# Fichiers Fail2ban générés (jamais jail.conf / jail.local : on ne touche qu'à nos fichiers)
readonly F2B_ETC="/etc/fail2ban"
readonly F2B_MAIN_LOCAL="${F2B_ETC}/fail2ban.d/00-${SCRIPT_NAME}.local"
readonly F2B_JAIL_DEFAULTS="${F2B_ETC}/jail.d/00-${SCRIPT_NAME}-defaults.local"
readonly F2B_JAIL_SSH="${F2B_ETC}/jail.d/10-${SCRIPT_NAME}-sshd.local"
readonly F2B_FILTER_RECIDIVE="${F2B_ETC}/filter.d/sshd-recidive.conf"
readonly F2B_ACTION_MAIL="${F2B_ETC}/action.d/mail-recidive.conf"
readonly F2B_LOG="/var/log/fail2ban.log"
readonly RESTORE_BIN="/usr/local/sbin/fail2ban-recidive-restore"

# Rapport hebdomadaire
readonly REPORT_BIN="/usr/local/sbin/fail2ban-report"
readonly REPORT_CONF="${F2B_ETC}/report.conf"
readonly REPORT_UNIT="fail2ban-report"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly CRON_FILE="/etc/cron.d/fail2ban-report"
readonly F2B_SERVICE_DROPIN="${SYSTEMD_DIR}/fail2ban.service.d/50-${SCRIPT_NAME}-recidive.conf"

# SSH
readonly SSH_PORT_DROPIN="/etc/ssh/sshd_config.d/00-${SCRIPT_NAME}-port.conf"
readonly SSH_SOCKET_DROPIN="${SYSTEMD_DIR}/ssh.socket.d/00-${SCRIPT_NAME}-port.conf"
readonly SSH_CONFIRM_TIMEOUT=300

# Fonctionnement du script
readonly STATE_DIR="/var/lib/${SCRIPT_NAME}"
readonly STATE_FILE="${STATE_DIR}/answers.env"
readonly BACKUP_ROOT="/var/backups/${SCRIPT_NAME}"
readonly BACKUP_DIR="${BACKUP_ROOT}/${RUN_ID}"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
readonly LOCK_FILE="/run/${SCRIPT_NAME}.lock"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"   # surchargeable (tests)

# --- Paramètres des jails (surchargeables par variables d'environnement) -------
SSH_MAXRETRY="${SSH_MAXRETRY:-5}"             # échecs tolérés…
SSH_FINDTIME="${SSH_FINDTIME:-1h}"            # …dans cette fenêtre
SSH_BANTIME="${SSH_BANTIME:-24h}"             # durée du ban « classique »
SSH_MODE="${SSH_MODE:-normal}"                # normal | ddos | extra | aggressive
RECIDIVE_MAXRETRY="${RECIDIVE_MAXRETRY:-3}"   # nombre de bans [sshd]…
RECIDIVE_FINDTIME="${RECIDIVE_FINDTIME:-30d}" # …sur cette période
RECIDIVE_BANTIME="${RECIDIVE_BANTIME:-60d}"   # → ban de 2 mois, tous ports

# --- Options de ligne de commande ----------------------------------------------
ACTION="install"                 # install | detect | uninstall
OPT_NONINTERACTIVE=false
OPT_SSH_PORT=""
OPT_KEEP_SSH_PORT=false
OPT_IGNORE_IP=""
OPT_EMAIL=""
OPT_FROM=""
OPT_SMTP_HOST=""
OPT_SMTP_PORT=""
OPT_SMTP_USER=""
OPT_NO_REPORT=false
OPT_REPORT_DAY=""
OPT_REPORT_TIME=""
OPT_RECIDIVE_MAIL=true
ORIG_ARGS="$*"

# --- État détecté / décidé pendant l'exécution ----------------------------------
OS_ID="" OS_LIKE="" OS_VERSION_ID="" OS_MAJOR="" OS_PRETTY="" OS_FAMILY="" PKG_MGR=""
INIT_SYSTEM=""
FIREWALL="none" FW_POLICY_DROP=false NEED_NFTABLES=false
BANACTION="" BANACTION_ALLPORTS=""
SELINUX_MODE="absent"
SSHD_BIN="" SSH_SERVICE="" SSH_SOCKET=false SSH_ON_22=false
SSH_CONF_PORTS=() SSH_LISTEN_PORTS=()
SSH_FINAL_PORTS="22"
NEW_SSH_PORT=""
ADMIN_IP=""
HOST_FQDN="" HOST_SHORT=""
MTA_BIN="" MTA_NAME="" POSTFIX_RELAYHOST=""
PYTHON_BIN=""
F2B_BACKEND="auto" SSH_LOGPATH="" SSH_FILTER_EXTRA=""
IGNORE_EXTRA="" IGNORE_IPS=""
REPORT_ENABLED=false REPORT_TO="" REPORT_FROM="" REPORT_DAY="mon" REPORT_TIME="08:00"
MAIL_MODE="none"                 # relay | existing | none
SMTP_HOST="" SMTP_PORT="587" SMTP_USER="" SMTP_PASSWORD="${SMTP_PASSWORD:-}"
JAIL_ERRORS=0
STEP_NO=0
LOG_READY=""
TMP_FILES=()

# Réponses de l'exécution précédente (valeurs par défaut des questions)
PREV_IGNORE_IPS="" PREV_REPORT_TO="" PREV_REPORT_FROM="" PREV_REPORT_DAY="" PREV_REPORT_TIME=""
PREV_SMTP_HOST="" PREV_SMTP_PORT="" PREV_SMTP_USER=""

# Retour arrière SSH
SSH_RB_ACTIVE=false SSH_RB_DIR="" SSH_RB_SELINUX=false SSH_RB_FW=""
SSH_RB_CREATED=()

#===============================================================================
# 2. AFFICHAGE & JOURNALISATION
#===============================================================================
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
    C_RESET=$'\e[0m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m' C_RED=$'\e[31m'
    C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_BLUE=$'\e[34m' C_CYAN=$'\e[36m'
else
    C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN=""
fi

_log_file() {
    if [[ -n $LOG_READY ]]; then
        printf '%s [%-5s] %s\n' "$(date '+%F %T')" "$1" "$2" >>"$LOG_FILE"
    fi
    return 0
}
log_info()  { printf '  %s•%s %s\n' "$C_BLUE" "$C_RESET" "$*"; _log_file INFO "$*"; }
log_ok()    { printf '  %s✔%s %s\n' "$C_GREEN" "$C_RESET" "$*"; _log_file OK "$*"; }
log_warn()  { printf '  %s⚠ %s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2; _log_file WARN "$*"; }
log_error() { printf '  %s✘ %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; _log_file ERROR "$*"; }
log_step()  {
    STEP_NO=$((STEP_NO + 1))
    printf '\n%s%s[%d] %s%s\n' "$C_BOLD" "$C_CYAN" "$STEP_NO" "$*" "$C_RESET"
    _log_file STEP "$*"
}
# Largeur affichée d'une chaîne UTF-8 (printf %-Ns compte des octets, pas des caractères)
str_width() {
    local LC_ALL=C s=$1
    s=${s//[$'\x80'-$'\xbf']/}
    printf '%s' "${#s}"
}
kv() {
    local pad
    pad=$((24 - $(str_width "$1")))
    ((pad > 0)) || pad=1
    printf '    %s%s%*s%s %s\n' "$C_DIM" "$1" "$pad" "" "$C_RESET" "$2"
    _log_file INFO "$1 : $2"
}
die() { log_error "$1"; exit "${2:-1}"; }
have() { command -v "$1" >/dev/null 2>&1; }

# run "description" commande args… : exécute en journalisant la sortie ;
# en cas d'échec, affiche la fin du journal et renvoie le code d'erreur.
run() {
    local desc=$1 rc=0
    shift
    _log_file CMD "$*"
    "$@" >>"$LOG_FILE" 2>&1 || rc=$?
    if ((rc != 0)); then
        log_error "${desc} : échec (code ${rc})"
        printf '    %s── fin du journal %s ──%s\n' "$C_DIM" "$LOG_FILE" "$C_RESET" >&2
        tail -n 15 "$LOG_FILE" | sed 's/^/    │ /' >&2 || true
        return "$rc"
    fi
    return 0
}

banner() {
    local line="  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf '\n%s%s\n' "$C_BOLD" "$line"
    printf '   Fail2ban Setup v%s · installation & durcissement SSH\n' "$SCRIPT_VERSION"
    printf '%s%s\n' "$line" "$C_RESET"
}

usage() {
    cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} — installation & configuration multi-distribution de Fail2ban

Usage : sudo $0 [options]

Installation
  -y, --yes, --non-interactive  Aucune question (valeurs par défaut + options)
      --ssh-port PORT           Déplace SSH sur PORT (sans question)
      --keep-ssh-port           Ne propose jamais de changer le port SSH
      --ssh-mode MODE           Mode du filtre sshd : normal|ddos|extra|aggressive
      --ignore-ip "IP …"        IP/CIDR à ne jamais bannir (en plus de localhost)
      --email ADRESSE[,…]       Destinataire(s) du rapport hebdomadaire
      --from ADRESSE            Expéditeur des emails
      --smtp-host HÔTE          Configure Postfix en relais via HÔTE
      --smtp-port PORT          Port du relais (défaut 587 ; 465 = TLS implicite)
      --smtp-user IDENTIFIANT   Compte SMTP (mot de passe : variable SMTP_PASSWORD)
      --report-day JOUR         Jour du rapport : lun…dim / mon…sun (défaut lun)
      --report-time HH:MM       Heure du rapport (défaut 08:00)
      --no-report               N'installe pas le rapport hebdomadaire
      --no-recidive-mail        Pas d'email à chaque ban de récidive

Autres actions
      --detect                  Affiche la détection système puis quitte
      --uninstall               Supprime la configuration installée par ce script
  -h, --help                    Cette aide
  -V, --version                 Version

Variables d'environnement (valeurs par défaut entre crochets)
  SSH_MAXRETRY [5]  SSH_FINDTIME [1h]  SSH_BANTIME [24h]  SSH_MODE [normal]
  RECIDIVE_MAXRETRY [3]  RECIDIVE_FINDTIME [30d]  RECIDIVE_BANTIME [60d]
  SMTP_PASSWORD     mot de passe SMTP (évite de le saisir / de l'exposer dans ps)

Exemples
  sudo ./setup.sh
  sudo SMTP_PASSWORD='xxx' ./setup.sh -y --email admin@exemple.fr \\
       --smtp-host smtp.exemple.fr --smtp-user alertes@exemple.fr --ssh-port 49222
  curl -fsSL https://exemple.fr/setup.sh | sudo bash
EOF
}

#===============================================================================
# 3. UTILITAIRES : QUESTIONS, VALIDATIONS, FICHIERS
#===============================================================================

# Une question n'est posée que si un terminal est disponible (fonctionne aussi
# avec « curl … | sudo bash » : on lit /dev/tty et non stdin).
has_tty() {
    [[ $OPT_NONINTERACTIVE == false ]] && { : </dev/tty; } 2>/dev/null
}

# ask VARIABLE "question" "défaut" [fonction_de_validation]
ask() {
    local __var=$1 __q=$2 __def=${3-} __check=${4-} __ans
    if ! has_tty; then
        if [[ -n $__check ]] && ! "$__check" "$__def"; then
            die "Valeur invalide ou manquante pour « ${__q} » : '${__def}' (mode non interactif : utilisez les options)."
        fi
        printf -v "$__var" '%s' "$__def"
        return 0
    fi
    while :; do
        if [[ -n $__def ]]; then
            printf '  %s?%s %s %s[%s]%s : ' "$C_CYAN" "$C_RESET" "$__q" "$C_DIM" "$__def" "$C_RESET" >/dev/tty
        else
            printf '  %s?%s %s : ' "$C_CYAN" "$C_RESET" "$__q" >/dev/tty
        fi
        IFS= read -r __ans </dev/tty || __ans=""
        __ans=${__ans:-$__def}
        __ans="${__ans#"${__ans%%[![:space:]]*}"}"   # trim gauche
        __ans="${__ans%"${__ans##*[![:space:]]}"}"   # trim droite
        if [[ -z $__check ]] || "$__check" "$__ans"; then
            break
        fi
        printf '    %sValeur invalide, recommencez.%s\n' "$C_RED" "$C_RESET" >/dev/tty
    done
    printf -v "$__var" '%s' "$__ans"
    _log_file ASK "${__q} → ${__ans}"
}

# ask_yn "question" o|n   → code retour 0 = oui
ask_yn() {
    local q=$1 def=${2:-n} hint ans
    if [[ $def == o ]]; then hint="O/n"; else hint="o/N"; fi
    if ! has_tty; then
        if [[ $def == o ]]; then return 0; else return 1; fi
    fi
    while :; do
        printf '  %s?%s %s %s[%s]%s : ' "$C_CYAN" "$C_RESET" "$q" "$C_DIM" "$hint" "$C_RESET" >/dev/tty
        IFS= read -r ans </dev/tty || ans=""
        ans=${ans:-$def}
        case ${ans,,} in
            o | oui | y | yes) _log_file ASK "${q} → oui"; return 0 ;;
            n | non | no)      _log_file ASK "${q} → non"; return 1 ;;
        esac
    done
}

# ask_secret VARIABLE "question"  (saisie masquée, jamais journalisée)
ask_secret() {
    local __var=$1 __q=$2 __ans=""
    if has_tty; then
        printf '  %s?%s %s : ' "$C_CYAN" "$C_RESET" "$__q" >/dev/tty
        IFS= read -rs __ans </dev/tty || __ans=""
        printf '\n' >/dev/tty
    fi
    printf -v "$__var" '%s' "$__ans"
}

is_port()       { [[ $1 =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }
is_uint()       { [[ $1 =~ ^[0-9]+$ ]] && ((10#$1 >= 1)); }
is_email()      { [[ $1 =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; }
is_email_loose() { [[ $1 =~ ^[^@[:space:]]+@[^@[:space:]]+$ ]]; }
is_hostname()   { [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; }
is_hhmm()       { [[ $1 =~ ^([01]?[0-9]|2[0-3]):[0-5][0-9]$ ]]; }
is_ssh_mode()   { [[ $1 =~ ^(normal|ddos|extra|aggressive)$ ]]; }
is_day()        { [[ -n $(normalize_day "$1") ]]; }

is_email_list() {
    local IFS=$', \t' e n=0
    for e in $1; do
        is_email "$e" || return 1
        n=$((n + 1))
    done
    ((n > 0))
}

is_ip_or_cidr() {
    local v=$1 ip mask="" o
    ip=${v%%/*}
    if [[ $v == */* ]]; then mask=${v#*/}; fi
    if [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for o in "${BASH_REMATCH[@]:1}"; do ((10#$o <= 255)) || return 1; done
        [[ -z $mask ]] || { [[ $mask =~ ^[0-9]{1,2}$ ]] && ((10#$mask <= 32)); }
        return
    fi
    if [[ $ip == *:* && $ip =~ ^[0-9A-Fa-f:.]+$ ]]; then
        [[ -z $mask ]] || { [[ $mask =~ ^[0-9]{1,3}$ ]] && ((10#$mask <= 128)); }
        return
    fi
    return 1
}

is_ip_list_or_empty() {
    local IFS=$', \t' v
    for v in $1; do is_ip_or_cidr "$v" || return 1; done
    return 0
}

# Jour → mon…sun (accepte français et anglais). Chaîne vide si invalide.
normalize_day() {
    case ${1,,} in
        mon | monday | lun | lundi) echo mon ;;
        tue | tuesday | mar | mardi) echo tue ;;
        wed | wednesday | mer | mercredi) echo wed ;;
        thu | thursday | jeu | jeudi) echo thu ;;
        fri | friday | ven | vendredi) echo fri ;;
        sat | saturday | sam | samedi) echo sat ;;
        sun | sunday | dim | dimanche) echo sun ;;
        *) echo "" ;;
    esac
}
day_fr() {
    case $1 in
        mon) echo lundi ;; tue) echo mardi ;; wed) echo mercredi ;; thu) echo jeudi ;;
        fri) echo vendredi ;; sat) echo samedi ;; sun) echo dimanche ;;
    esac
}
day_cron() {
    case $1 in
        sun) echo 0 ;; mon) echo 1 ;; tue) echo 2 ;; wed) echo 3 ;; thu) echo 4 ;; fri) echo 5 ;; sat) echo 6 ;;
    esac
}

# Durée Fail2ban (30, 10m, 24h, 60d, 1w, 2mo…) → secondes ; vide si invalide.
to_seconds() {
    local v=${1,,} n u
    if [[ ! $v =~ ^([0-9]+)[[:space:]]*(s|sec|m|min|h|d|w|mo|y)?$ ]]; then
        echo ""
        return 0
    fi
    n=$((10#${BASH_REMATCH[1]}))
    u=${BASH_REMATCH[2]:-s}
    case $u in
        s | sec) echo "$n" ;;
        m | min) echo $((n * 60)) ;;
        h) echo $((n * 3600)) ;;
        d) echo $((n * 86400)) ;;
        w) echo $((n * 604800)) ;;
        mo) echo $((n * 2629800)) ;;
        y) echo $((n * 31557600)) ;;
    esac
}

# Supprime les doublons d'une liste séparée par des espaces (ordre conservé)
dedupe_words() {
    local w out=" "
    for w in $1; do
        [[ $out == *" $w "* ]] || out+="$w "
    done
    out=${out# }
    printf '%s' "${out% }"
}

# Copie un fichier dans le répertoire de sauvegarde de l'exécution (une seule fois)
backup_file() {
    local f=$1
    [[ -e $f || -L $f ]] || return 0
    [[ ! -e ${BACKUP_DIR}${f} ]] || return 0
    mkdir -p "${BACKUP_DIR}$(dirname "$f")"
    cp -a "$f" "${BACKUP_DIR}${f}"
    _log_file BACKUP "$f → ${BACKUP_DIR}${f}"
}

# write_file CHEMIN [MODE] < contenu  — écriture atomique avec sauvegarde
write_file() {
    local dst=$1 mode=${2:-0644} dir tmp
    dir=$(dirname "$dst")
    [[ -d $dir ]] || mkdir -p "$dir"
    backup_file "$dst"
    tmp=$(mktemp "${dir}/.${SCRIPT_NAME}.XXXXXX")
    TMP_FILES+=("$tmp")
    cat >"$tmp"
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$dst"
    if have restorecon; then restorecon -F "$dst" >/dev/null 2>&1 || true; fi
    _log_file WRITE "$dst (mode $mode)"
}

# En-tête placé dans chaque fichier généré
managed_header() {
    printf '# ==============================================================================\n'
    printf '# %s v%s — %s\n' "$MANAGED_MARK" "$SCRIPT_VERSION" "$(date '+%F %T')"
    printf '# Fichier régénéré à chaque exécution du script : mettez vos personnalisations\n'
    printf '# dans un autre fichier (ex. /etc/fail2ban/jail.d/99-local.local).\n'
    printf '# ==============================================================================\n'
}

# Ports TCP en écoute (un par ligne)
listening_tcp_ports() {
    local out="" f laddr st rest
    # /proc/net/tcp{,6} : état 0A = LISTEN, port local en hexadécimal
    for f in /proc/net/tcp /proc/net/tcp6; do
        [[ -r $f ]] || continue
        while read -r _ laddr _ st rest; do
            if [[ $st == 0A && $laddr == *:* ]]; then out+="$((16#${laddr##*:}))"$'\n'; fi
        done <"$f"
    done
    if [[ -n $out ]]; then
        sort -un <<<"$out" | grep -E '^[0-9]+$' || true
        return 0
    fi
    if have ss; then
        out=$(ss -tln 2>/dev/null | awk '{print $4}' || true)
    elif have netstat; then
        out=$(netstat -tln 2>/dev/null | awk '{print $4}' || true)
    fi
    [[ -n $out ]] || return 0
    awk -F'[:.]' '{print $NF}' <<<"$out" | grep -E '^[0-9]+$' | sort -un || true
}

# in_list VALEUR élément… → 0 si VALEUR fait partie de la liste
in_list() {
    local needle=$1 item
    shift
    for item in "$@"; do
        if [[ $item == "$needle" ]]; then return 0; fi
    done
    return 1
}

port_in_use() {
    local ports
    ports=$(listening_tcp_ports)
    grep -qx -- "$1" <<<"$ports"
}

wait_for_port() {
    local port=$1 timeout=${2:-15} i
    for ((i = 0; i < timeout; i++)); do
        if port_in_use "$port"; then return 0; fi
        sleep 1
    done
    return 1
}

# Port aléatoire libre, hors plage éphémère et hors ports « classiques » de repli
suggest_port() {
    local low=10000 high=32767 range p i
    range=$(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || true)
    if [[ $range =~ ^([0-9]+) ]] && ((BASH_REMATCH[1] > low + 1000)); then
        high=$((BASH_REMATCH[1] - 1))
    fi
    for ((i = 0; i < 50; i++)); do
        p=$((low + RANDOM % (high - low)))
        if ! port_in_use "$p"; then echo "$p"; return 0; fi
    done
    echo 22222
}

primary_ip() {
    local ip=""
    if have ip; then
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null |
            awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}' || true)
    fi
    if [[ -z $ip ]]; then ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true); fi
    printf '%s' "${ip:-IP_DU_SERVEUR}"
}

#===============================================================================
# 4. DÉTECTION DE L'ENVIRONNEMENT
#===============================================================================
detect_os() {
    [[ -r $OS_RELEASE_FILE ]] || die "${OS_RELEASE_FILE} introuvable : distribution non prise en charge."
    eval "$(
        # shellcheck disable=SC1090,SC1091
        . "$OS_RELEASE_FILE"
        printf 'OS_ID=%q OS_LIKE=%q OS_VERSION_ID=%q OS_PRETTY=%q' \
            "${ID:-unknown}" "${ID_LIKE:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-${ID:-Linux}}"
    )"
    OS_MAJOR=${OS_VERSION_ID%%.*}

    case " ${OS_ID} ${OS_LIKE} " in
        *" alpine "*) OS_FAMILY=alpine ;;
        *" arch "* | *" archlinux "*) OS_FAMILY=arch ;;
        *" suse "* | *" opensuse "* | *" sles "* | *" opensuse-leap "* | *" opensuse-tumbleweed "*) OS_FAMILY=suse ;;
        *" fedora "* | *" rhel "* | *" centos "* | *" rocky "* | *" almalinux "* | *" ol "* | *" amzn "*) OS_FAMILY=rhel ;;
        *" debian "* | *" ubuntu "* | *" devuan "* | *" raspbian "*) OS_FAMILY=debian ;;
        *) die "Distribution non prise en charge : ${OS_PRETTY} (ID=${OS_ID}, ID_LIKE=${OS_LIKE})." ;;
    esac

    case $OS_FAMILY in
        debian) PKG_MGR=apt-get ;;
        rhel) if have dnf; then PKG_MGR=dnf; else PKG_MGR=yum; fi ;;
        suse) PKG_MGR=zypper ;;
        arch) PKG_MGR=pacman ;;
        alpine) PKG_MGR=apk ;;
    esac
    have "$PKG_MGR" || die "Gestionnaire de paquets ${PKG_MGR} introuvable."
}

detect_init() {
    if [[ -d /run/systemd/system ]]; then
        INIT_SYSTEM=systemd
    elif have rc-service; then
        INIT_SYSTEM=openrc
    else
        INIT_SYSTEM=sysv
    fi
}

detect_firewall() {
    local out="" drop_re='hook input[^;]*;[[:space:]]*policy drop'
    FIREWALL=none
    FW_POLICY_DROP=false
    NEED_NFTABLES=false

    if have firewall-cmd && [[ $(LC_ALL=C firewall-cmd --state 2>/dev/null || true) == running ]]; then
        FIREWALL=firewalld
    elif have ufw && out=$(LC_ALL=C ufw status 2>/dev/null) && [[ $out == *"Status: active"* ]]; then
        FIREWALL=ufw
    elif have nft; then
        FIREWALL=nftables
        out=$(nft list ruleset 2>/dev/null || true)
        if [[ $out =~ $drop_re ]]; then FW_POLICY_DROP=true; fi
    elif have iptables; then
        FIREWALL=iptables
        out=$(iptables -S INPUT 2>/dev/null || true)
        if [[ $out == *"-P INPUT DROP"* ]]; then FW_POLICY_DROP=true; fi
    fi

    # Action de ban : firewalld natif, sinon nftables (table dédiée, coexiste avec
    # ufw/iptables-nft), sinon iptables. Rien d'installé → on installe nftables.
    if [[ $FIREWALL == firewalld ]]; then
        BANACTION=firewallcmd-rich-rules
        BANACTION_ALLPORTS=firewallcmd-allports
    elif have nft; then
        BANACTION=nftables-multiport
        BANACTION_ALLPORTS=nftables-allports
    elif have iptables; then
        BANACTION=iptables-multiport
        BANACTION_ALLPORTS=iptables-allports
    else
        BANACTION=nftables-multiport
        BANACTION_ALLPORTS=nftables-allports
        NEED_NFTABLES=true
    fi
}

detect_selinux() {
    SELINUX_MODE=absent
    if have getenforce; then
        SELINUX_MODE=$(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
        [[ -n $SELINUX_MODE ]] || SELINUX_MODE=absent
    fi
}
selinux_active() { [[ $SELINUX_MODE == enforcing || $SELINUX_MODE == permissive ]]; }

# Fichiers de configuration sshd (principal + drop-ins)
sshd_config_files() {
    local f
    [[ -e /etc/ssh/sshd_config ]] && printf '%s\n' /etc/ssh/sshd_config
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [[ -e $f ]] && printf '%s\n' "$f"
    done
    return 0
}

# /etc/ssh/sshd_config.d/ est-il inclus ? (openSUSE Tumbleweed : config fournie dans
# /usr/etc/ssh, /etc/ssh/sshd_config peut ne pas exister)
sshd_includes_dropins() {
    local f
    for f in /etc/ssh/sshd_config /usr/etc/ssh/sshd_config; do
        [[ -r $f ]] || continue
        if grep -qiE '^[[:space:]]*Include[[:space:]]+(/etc/ssh/)?sshd_config\.d/' "$f"; then return 0; fi
    done
    return 1
}

sshd_test_config() {
    # Debian/Ubuntu : sshd -t/-T exige le répertoire de séparation de privilèges
    if [[ $OS_FAMILY == debian && ! -d /run/sshd ]]; then install -d -m 0755 /run/sshd; fi
    "$SSHD_BIN" -t >>"$LOG_FILE" 2>&1
}

# Ports configurés (configuration effective via sshd -T, sinon lecture des fichiers)
sshd_config_ports() {
    local out=""
    if [[ $OS_FAMILY == debian && ! -d /run/sshd ]]; then install -d -m 0755 /run/sshd 2>/dev/null || true; fi
    out=$("$SSHD_BIN" -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -un || true)
    if [[ -z $out ]]; then
        out=$(sshd_config_files | xargs cat 2>/dev/null |
            awk 'tolower($1) == "port" {print $2}' | sort -un || true)
    fi
    printf '%s\n' "${out:-22}"
}

detect_ssh() {
    local p conf_ports listening
    SSHD_BIN=$(command -v sshd 2>/dev/null || true)
    if [[ -z $SSHD_BIN ]]; then
        for p in /usr/sbin/sshd /usr/local/sbin/sshd; do
            if [[ -x $p ]]; then SSHD_BIN=$p; break; fi
        done
    fi
    [[ -n $SSHD_BIN ]] || return 0

    case $INIT_SYSTEM in
        systemd)
            if systemctl is-active --quiet ssh.socket 2>/dev/null; then SSH_SOCKET=true; fi
            if systemctl cat ssh.service >/dev/null 2>&1; then SSH_SERVICE=ssh; else SSH_SERVICE=sshd; fi
            ;;
        *)
            if [[ -e /etc/init.d/ssh && ! -e /etc/init.d/sshd ]]; then SSH_SERVICE=ssh; else SSH_SERVICE=sshd; fi
            ;;
    esac

    # Ubuntu >= 22.10 : sshd activé par socket systemd → c'est ssh.socket qui écoute
    if [[ $SSH_SOCKET == true ]]; then
        conf_ports=$(systemctl show -p Listen --value ssh.socket 2>/dev/null |
            grep -oE ':[0-9]+ \(Stream\)' | tr -dc '0-9\n' | sort -un || true)
    else
        conf_ports=$(sshd_config_ports)
    fi
    [[ -n $conf_ports ]] || conf_ports=22
    mapfile -t SSH_CONF_PORTS <<<"$conf_ports"

    listening=$(listening_tcp_ports)
    SSH_LISTEN_PORTS=()
    for p in "${SSH_CONF_PORTS[@]}"; do
        if grep -qx -- "$p" <<<"$listening"; then SSH_LISTEN_PORTS+=("$p"); fi
    done
    SSH_ON_22=false
    for p in ${SSH_LISTEN_PORTS[@]+"${SSH_LISTEN_PORTS[@]}"}; do
        if [[ $p == 22 ]]; then SSH_ON_22=true; fi
    done
    SSH_FINAL_PORTS=$(
        IFS=,
        echo "${SSH_CONF_PORTS[*]}"
    )
}

detect_mta() {
    local c
    MTA_BIN="" MTA_NAME="" POSTFIX_RELAYHOST=""
    for c in /usr/sbin/sendmail /usr/bin/sendmail /usr/lib/sendmail; do
        if [[ -x $c ]]; then MTA_BIN=$c; break; fi
    done
    [[ -n $MTA_BIN ]] || return 0
    if have postconf; then
        MTA_NAME=postfix
        POSTFIX_RELAYHOST=$(postconf -h relayhost 2>/dev/null || true)
    elif have exim4 || have exim; then
        MTA_NAME=exim
    elif have msmtp; then
        MTA_NAME=msmtp
    elif have ssmtp; then
        MTA_NAME=ssmtp
    else
        MTA_NAME=sendmail
    fi
}

# IP de l'administrateur connecté (pour la liste blanche) : SSH_CONNECTION est
# perdu avec sudo, on se rabat alors sur « who -m » via le terminal.
detect_admin_ip() {
    local c=${SSH_CONNECTION:-${SSH_CLIENT:-}}
    ADMIN_IP=""
    if [[ -n $c ]]; then
        ADMIN_IP=${c%% *}
    elif have who && { : </dev/tty; } 2>/dev/null; then
        ADMIN_IP=$(who -m </dev/tty 2>/dev/null | sed -n 's/.*(\([^)]*\)).*/\1/p' | head -n 1 || true)
    fi
    ADMIN_IP=${ADMIN_IP#::ffff:}
    if [[ -n $ADMIN_IP ]] && ! is_ip_or_cidr "$ADMIN_IP"; then ADMIN_IP=""; fi
    if [[ $ADMIN_IP == 127.* || $ADMIN_IP == ::1 ]]; then ADMIN_IP=""; fi
    return 0
}

detect_all() {
    log_step "Détection de l'environnement"
    detect_os
    detect_init
    detect_firewall
    detect_selinux
    detect_ssh
    detect_mta
    detect_admin_ip
    HOST_FQDN=$(hostname -f 2>/dev/null || hostname 2>/dev/null || uname -n)
    [[ -n $HOST_FQDN && $HOST_FQDN != "(none)" ]] || HOST_FQDN=$(uname -n)
    HOST_SHORT=${HOST_FQDN%%.*}

    local fw_desc=$FIREWALL listen_desc="aucun"
    [[ $FW_POLICY_DROP == true ]] && fw_desc+=" (politique INPUT = DROP)"
    if ((${#SSH_LISTEN_PORTS[@]})); then listen_desc="${SSH_LISTEN_PORTS[*]}"; fi

    kv "Système" "${OS_PRETTY} (famille ${OS_FAMILY}, ${PKG_MGR})"
    kv "Init" "$INIT_SYSTEM"
    kv "Hôte" "$HOST_FQDN"
    kv "Pare-feu" "$fw_desc"
    kv "Action de ban" "${BANACTION} / ${BANACTION_ALLPORTS}"
    kv "SELinux" "$SELINUX_MODE"
    if [[ -n $SSHD_BIN ]]; then
        kv "Service SSH" "${SSH_SERVICE}$([[ $SSH_SOCKET == true ]] && echo ' (activé par ssh.socket)')"
        kv "Ports SSH" "configurés : ${SSH_CONF_PORTS[*]} — en écoute : ${listen_desc}"
    else
        kv "Service SSH" "OpenSSH server introuvable"
    fi
    kv "Serveur mail" "${MTA_NAME:-aucun}${POSTFIX_RELAYHOST:+ (relayhost ${POSTFIX_RELAYHOST})}"
    kv "IP admin" "${ADMIN_IP:-non détectée}"
    if have fail2ban-client; then
        kv "Fail2ban" "$(fail2ban-client --version 2>/dev/null | head -n 1 || echo installé)"
    else
        kv "Fail2ban" "non installé"
    fi
}

#===============================================================================
# 5. PAQUETS & SERVICES
#===============================================================================
pkg_refresh() {
    case $PKG_MGR in
        apt-get) run "Mise à jour de l'index APT" env DEBIAN_FRONTEND=noninteractive apt-get update -q ;;
        dnf | yum) run "Mise à jour du cache ${PKG_MGR}" "$PKG_MGR" -q -y makecache ;;
        zypper) run "Rafraîchissement des dépôts zypper" zypper --non-interactive --quiet refresh ;;
        apk) run "Mise à jour de l'index apk" apk update ;;
        pacman) : ;; # synchronisé à l'installation (pas de -Sy partiel sur Arch)
    esac
}

pkg_install() {
    case $PKG_MGR in
        apt-get)
            env DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
                -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
            ;;
        dnf | yum) "$PKG_MGR" install -y -q "$@" ;;
        zypper) zypper --non-interactive --quiet install --no-recommends "$@" ;;
        pacman) pacman -S --needed --noconfirm "$@" || pacman -Syu --needed --noconfirm "$@" ;;
        apk) apk add --no-progress "$@" ;;
    esac
}

pkg_remove() {
    case $PKG_MGR in
        apt-get) env DEBIAN_FRONTEND=noninteractive apt-get purge -y -q "$@" ;;
        dnf | yum) "$PKG_MGR" remove -y -q "$@" ;;
        zypper) zypper --non-interactive remove "$@" ;;
        pacman) pacman -Rns --noconfirm "$@" ;;
        apk) apk del "$@" ;;
    esac
}

enable_epel() {
    [[ $OS_FAMILY == rhel && $OS_ID != fedora ]] || return 0
    local repos
    repos=$("$PKG_MGR" repolist enabled 2>/dev/null || true)
    if grep -qiE '^!?epel([[:space:]/]|$)' <<<"$repos"; then
        log_ok "Dépôt EPEL déjà actif"
        return 0
    fi
    case $OS_ID in
        rhel) run "Installation du dépôt EPEL" "$PKG_MGR" install -y \
            "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_MAJOR}.noarch.rpm" ;;
        ol) run "Installation du dépôt EPEL (Oracle)" "$PKG_MGR" install -y "oracle-epel-release-el${OS_MAJOR}" ;;
        amzn)
            if [[ $OS_MAJOR == 2 ]] && have amazon-linux-extras; then
                run "Activation d'EPEL (Amazon Linux 2)" amazon-linux-extras install -y epel
            else
                log_warn "Amazon Linux ${OS_VERSION_ID} : pas d'EPEL officiel, tentative via les dépôts natifs."
            fi
            ;;
        *) run "Installation du dépôt EPEL" "$PKG_MGR" install -y epel-release ;;
    esac
}

svc_enable() {
    local s=$1 out
    case $INIT_SYSTEM in
        systemd) run "Activation de ${s}" systemctl enable --now "$s" ;;
        openrc)
            out=$(rc-update show default 2>/dev/null || true)
            if ! grep -qE "^[[:space:]]*${s}[[:space:]]" <<<"$out"; then
                run "Activation de ${s}" rc-update add "$s" default
            fi
            if ! rc-service "$s" status >/dev/null 2>&1; then run "Démarrage de ${s}" rc-service "$s" start; fi
            ;;
        *)
            if have update-rc.d; then
                run "Activation de ${s}" update-rc.d "$s" defaults || true
            elif have chkconfig; then
                run "Activation de ${s}" chkconfig "$s" on || true
            fi
            if ! service "$s" status >/dev/null 2>&1; then run "Démarrage de ${s}" service "$s" start; fi
            ;;
    esac
}

svc_restart() {
    case $INIT_SYSTEM in
        systemd) run "Redémarrage de ${1}" systemctl restart "$1" ;;
        openrc) run "Redémarrage de ${1}" rc-service "$1" restart ;;
        *) run "Redémarrage de ${1}" service "$1" restart ;;
    esac
}

svc_stop_disable() {
    case $INIT_SYSTEM in
        systemd) run "Arrêt de ${1}" systemctl disable --now "$1" || true ;;
        openrc) rc-service "$1" stop >>"$LOG_FILE" 2>&1 || true
                rc-update del "$1" default >>"$LOG_FILE" 2>&1 || true ;;
        *) service "$1" stop >>"$LOG_FILE" 2>&1 || true ;;
    esac
}

svc_is_active() {
    case $INIT_SYSTEM in
        systemd) systemctl is-active --quiet "$1" 2>/dev/null ;;
        openrc) rc-service "$1" status >/dev/null 2>&1 ;;
        *) service "$1" status >/dev/null 2>&1 ;;
    esac
}

install_packages() {
    log_step "Installation des paquets"
    local -a pkgs=() optional=()
    local p

    case $OS_FAMILY in
        debian)
            pkgs=(fail2ban iproute2)
            [[ $INIT_SYSTEM == systemd ]] && pkgs+=(python3-systemd)
            [[ $INIT_SYSTEM != systemd && $REPORT_ENABLED == true ]] && pkgs+=(cron)
            ;;
        rhel)
            enable_epel
            pkgs=(fail2ban-server iproute)
            [[ $INIT_SYSTEM == systemd ]] && pkgs+=(python3-systemd)
            ;;
        suse)
            pkgs=(fail2ban iproute2)
            [[ $INIT_SYSTEM == systemd ]] && pkgs+=(python3-systemd)
            ;;
        arch)
            pkgs=(fail2ban iproute2)
            [[ $INIT_SYSTEM == systemd ]] && pkgs+=(python-systemd)
            [[ $INIT_SYSTEM != systemd && $REPORT_ENABLED == true ]] && pkgs+=(cronie)
            ;;
        alpine)
            pkgs=(fail2ban iproute2 python3)
            ;;
    esac
    optional+=(whois)
    [[ $NEED_NFTABLES == true ]] && pkgs+=(nftables)

    # SELinux : semanage est indispensable pour autoriser sshd sur un autre port
    if [[ -n $NEW_SSH_PORT ]] && selinux_active && ! have semanage; then
        if [[ $OS_FAMILY == rhel && ${OS_MAJOR:-0} -le 7 && $OS_ID != fedora && $OS_ID != amzn ]]; then
            pkgs+=(policycoreutils-python)
        else
            pkgs+=(policycoreutils-python-utils)
        fi
    fi

    # Relais SMTP
    if [[ $MAIL_MODE == relay ]]; then
        pkgs+=(postfix ca-certificates)
        case $OS_FAMILY in
            debian)
                pkgs+=(libsasl2-modules)
                debconf-set-selections <<EOF
postfix postfix/main_mailer_type select Satellite system
postfix postfix/mailname string ${HOST_FQDN}
postfix postfix/relayhost string [${SMTP_HOST}]:${SMTP_PORT}
EOF
                ;;
            rhel | suse) pkgs+=(cyrus-sasl-plain) ;;
            alpine) optional+=(cyrus-sasl cyrus-sasl-login) ;;
        esac
    fi

    pkg_refresh
    log_info "Paquets : ${pkgs[*]}"
    if ! run "Installation des paquets" pkg_install "${pkgs[@]}"; then
        if [[ $OS_FAMILY == rhel ]]; then
            log_warn "Nouvel essai avec le paquet « fail2ban » (au lieu de fail2ban-server)…"
            pkgs=("${pkgs[@]/#fail2ban-server/fail2ban}")
            run "Installation des paquets" pkg_install "${pkgs[@]}" || die "Installation impossible."
        else
            die "Installation des paquets impossible (voir ${LOG_FILE})."
        fi
    fi
    for p in "${optional[@]}"; do
        pkg_install "$p" >>"$LOG_FILE" 2>&1 || log_warn "Paquet optionnel indisponible : ${p}"
    done

    have fail2ban-client || die "fail2ban-client introuvable après installation."
    log_ok "$(fail2ban-client --version 2>/dev/null | head -n 1 || echo Fail2ban) installé"
}

# Interpréteur Python utilisé par Fail2ban (même interpréteur pour le rapport)
detect_python() {
    local server line cand="" w
    local -a parts=()
    PYTHON_BIN=""
    server=$(command -v fail2ban-server 2>/dev/null || true)
    if [[ -n $server ]] && IFS= read -r line <"$server" && [[ $line == '#!'* ]]; then
        read -r -a parts <<<"${line#\#!}"
        if [[ ${parts[0]##*/} == env ]]; then
            for w in "${parts[@]:1}"; do
                [[ $w == -* ]] && continue
                cand=$(command -v "$w" 2>/dev/null || true)
                break
            done
        else
            cand=${parts[0]}
        fi
        [[ -n $cand && -x $cand ]] && PYTHON_BIN=$cand
    fi
    if [[ -z $PYTHON_BIN ]]; then
        for cand in python3 /usr/libexec/platform-python; do
            cand=$(command -v "$cand" 2>/dev/null || true)
            if [[ -n $cand ]]; then PYTHON_BIN=$cand; break; fi
        done
    fi
    [[ -n $PYTHON_BIN ]] || die "Interpréteur Python 3 introuvable."
    "$PYTHON_BIN" -c 'import sqlite3, email, json, ipaddress' >/dev/null 2>&1 ||
        die "${PYTHON_BIN} : modules Python standard manquants (sqlite3…)."
    _log_file INFO "Python : ${PYTHON_BIN}"
}

# Lecture des logs : journald si possible (indispensable sur Debian 12+ sans
# rsyslog), sinon fichiers texte.
decide_backend() {
    SSH_LOGPATH="" SSH_FILTER_EXTRA=""
    if [[ $INIT_SYSTEM == systemd ]] && "$PYTHON_BIN" -c 'import systemd.journal' >/dev/null 2>&1; then
        F2B_BACKEND=systemd
        log_ok "Lecture des journaux : journald (backend systemd)"
        return 0
    fi
    F2B_BACKEND=auto
    [[ $INIT_SYSTEM == systemd ]] && log_warn "Module Python « systemd » indisponible : lecture des fichiers de log."
    case $OS_FAMILY in
        debian | arch) SSH_LOGPATH=/var/log/auth.log ;;
        rhel) SSH_LOGPATH=/var/log/secure ;;
        suse) SSH_LOGPATH=/var/log/messages ;;
        alpine)
            SSH_LOGPATH=/var/log/messages
            # syslogd BusyBox insère « facility.niveau » après le nom d'hôte
            # (ex. « host auth.info sshd[42]: … ») : on l'accepte via __vserver.
            SSH_FILTER_EXTRA=', __vserver="(?:@vserver_\S+|[a-z0-9]+\.[a-z]+)"'
            ;;
    esac
    if [[ ! -e $SSH_LOGPATH ]]; then
        die "Journal SSH ${SSH_LOGPATH} introuvable : installez/activez un démon syslog (rsyslog, syslogd…)."
    fi
    log_ok "Lecture des journaux : ${SSH_LOGPATH}"
}

#===============================================================================
# 6. QUESTIONS
#===============================================================================
load_previous_answers() {
    [[ -r $STATE_FILE ]] || return 0
    local k v
    while IFS='=' read -r k v; do
        case $k in
            IGNORE_IPS | REPORT_TO | REPORT_FROM | REPORT_DAY | REPORT_TIME | SMTP_HOST | SMTP_PORT | SMTP_USER)
                printf -v "PREV_${k}" '%s' "$v"
                ;;
        esac
    done <"$STATE_FILE"
    log_info "Réponses de l'exécution précédente rechargées (${STATE_FILE})."
}

save_answers() {
    install -d -m 0700 "$STATE_DIR"
    write_file "$STATE_FILE" 0600 <<EOF
# Réponses de la dernière exécution de ${SCRIPT_NAME} ($(date '+%F %T'))
# Réutilisées comme valeurs par défaut. Aucun mot de passe n'est stocké ici.
IGNORE_IPS=${IGNORE_EXTRA}
REPORT_TO=${REPORT_TO}
REPORT_FROM=${REPORT_FROM}
REPORT_DAY=${REPORT_DAY}
REPORT_TIME=${REPORT_TIME}
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_USER=${SMTP_USER}
EOF
}

validate_new_ssh_port() {
    local p=$1
    if ! is_port "$p"; then log_warn "Port invalide (1-65535)."; return 1; fi
    p=$((10#$p))
    if ((p == 22)); then log_warn "Choisissez un port différent de 22."; return 1; fi
    if port_in_use "$p"; then log_warn "Le port ${p} est déjà utilisé par un autre service."; return 1; fi
    return 0
}

questions_ssh_port() {
    NEW_SSH_PORT=""
    [[ -n $SSHD_BIN ]] || return 0

    if [[ -n $OPT_SSH_PORT ]]; then
        if in_list "$((10#$OPT_SSH_PORT))" "${SSH_CONF_PORTS[@]}"; then
            log_ok "SSH utilise déjà le port ${OPT_SSH_PORT}."
            return 0
        fi
        validate_new_ssh_port "$OPT_SSH_PORT" || die "Port SSH refusé : ${OPT_SSH_PORT}"
        NEW_SSH_PORT=$((10#$OPT_SSH_PORT))
        return 0
    fi

    if [[ $SSH_ON_22 != true ]]; then
        if ((${#SSH_LISTEN_PORTS[@]})); then
            log_ok "SSH écoute sur le port ${SSH_LISTEN_PORTS[*]} : pas de changement proposé."
        else
            log_info "sshd ne semble pas en écoute : pas de changement de port proposé."
        fi
        return 0
    fi

    log_warn "SSH écoute sur le port 22, scanné en permanence par les robots."
    if [[ $OPT_KEEP_SSH_PORT == true ]] || ! has_tty; then
        log_info "Port 22 conservé (--keep-ssh-port ou mode non interactif)."
        return 0
    fi
    log_info "Changer de port ne remplace pas une bonne config (clés, pas de root…),"
    log_info "mais élimine l'essentiel du bruit des scans automatiques."
    if ask_yn "Voulez-vous modifier le port SSH ?" n; then
        ask NEW_SSH_PORT "Nouveau port SSH" "$(suggest_port)" validate_new_ssh_port
        NEW_SSH_PORT=$((10#$NEW_SSH_PORT))
    fi
}

questions_ignoreip() {
    local extra=${OPT_IGNORE_IP:-$PREV_IGNORE_IPS} existing=""
    # Première exécution : reprise des ignoreip déjà configurés (jail.local…)
    if [[ -z $PREV_IGNORE_IPS && -z $OPT_IGNORE_IP ]] && have fail2ban-client; then
        existing=$(fail2ban-client -d 2>/dev/null |
            sed -n "s/.*'addignoreip', '\([^']*\)'.*/\1/p" | sort -u | tr '\n' ' ' || true)
        extra="${extra} ${existing}"
    fi
    if [[ -n $ADMIN_IP && " $extra " != *" $ADMIN_IP "* ]]; then
        log_info "Vous êtes connecté depuis ${ADMIN_IP}."
        if ask_yn "Ajouter ${ADMIN_IP} à la liste blanche (jamais bannie) ?" o; then
            extra="${extra} ${ADMIN_IP}"
        fi
    fi
    extra=$(dedupe_words "${extra//,/ }")
    extra=$(dedupe_words "$(printf '%s' "$extra" | tr ' ' '\n' | grep -vxE '127\.0\.0\.1(/8)?|::1' | tr '\n' ' ' || true)")
    ask IGNORE_EXTRA "IP/réseaux à ne jamais bannir (espaces, vide = aucun)" "$extra" is_ip_list_or_empty
    IGNORE_EXTRA=$(dedupe_words "${IGNORE_EXTRA//,/ }")
    IGNORE_IPS=$(dedupe_words "127.0.0.1/8 ::1 ${IGNORE_EXTRA}")
}

questions_relay() {
    MAIL_MODE=relay
    [[ $MTA_NAME == exim ]] && log_warn "Postfix remplacera Exim."
    log_info "Exemples : smtp.gmail.com:587 (mot de passe d'application), ssl0.ovh.net:465,"
    log_info "smtp.office365.com:587, smtp-relay.brevo.com:587…"
    ask SMTP_HOST "Serveur SMTP relais" "${OPT_SMTP_HOST:-$PREV_SMTP_HOST}" is_hostname
    ask SMTP_PORT "Port SMTP (587 STARTTLS, 465 TLS, 25)" "${OPT_SMTP_PORT:-${PREV_SMTP_PORT:-587}}" is_port
    ask SMTP_USER "Identifiant SMTP (vide = sans authentification)" "${OPT_SMTP_USER:-$PREV_SMTP_USER}"
    if [[ -n $SMTP_USER && -z $SMTP_PASSWORD ]]; then
        ask_secret SMTP_PASSWORD "Mot de passe SMTP (saisie masquée)"
        [[ -n $SMTP_PASSWORD ]] || die "Mot de passe SMTP requis (saisie ou variable SMTP_PASSWORD)."
    fi
    if [[ $SMTP_PASSWORD == *$'\n'* ]]; then die "Le mot de passe SMTP ne peut pas contenir de retour à la ligne."; fi
}

questions_mail_transport() {
    if [[ -n $OPT_SMTP_HOST ]]; then
        questions_relay
    elif [[ $MTA_NAME == postfix && -n $POSTFIX_RELAYHOST ]]; then
        log_ok "Postfix est déjà configuré en relais (${POSTFIX_RELAYHOST})."
        if ask_yn "Reconfigurer le relais SMTP ?" n; then questions_relay; else MAIL_MODE=existing; fi
    elif [[ -n $MTA_BIN ]]; then
        log_info "Serveur mail local détecté : ${MTA_NAME} (${MTA_BIN})."
        if ask_yn "Configurer plutôt un relais SMTP authentifié (Postfix) ?" n; then
            questions_relay
        else
            MAIL_MODE=existing
        fi
    else
        log_warn "Aucun serveur mail (sendmail) : sans relais, les emails ne partiront pas."
        if ! has_tty; then
            MAIL_MODE=none
            log_warn "Mode non interactif sans --smtp-host : rapport installé mais non envoyable."
        elif ask_yn "Installer Postfix comme relais SMTP authentifié ?" o; then
            questions_relay
        else
            MAIL_MODE=none
        fi
    fi
}

questions_report() {
    REPORT_ENABLED=false
    [[ $OPT_NO_REPORT == true ]] && return 0
    local def_to=${OPT_EMAIL:-$PREV_REPORT_TO} def_from day
    if [[ -z $def_to ]] && ! has_tty; then
        log_warn "Aucune adresse (--email) : rapport hebdomadaire non installé."
        return 0
    fi
    ask_yn "Installer le rapport hebdomadaire des bans par email ?" o || return 0
    REPORT_ENABLED=true

    ask REPORT_TO "Destinataire(s) du rapport (séparés par des virgules)" "$def_to" is_email_list
    REPORT_TO=$(tr -s ' ,;' ',' <<<"$REPORT_TO" | sed 's/^,//; s/,$//')
    ask day "Jour d'envoi (lun…dim)" "$(day_fr "$(normalize_day "${OPT_REPORT_DAY:-${PREV_REPORT_DAY:-mon}}")")" is_day
    REPORT_DAY=$(normalize_day "$day")
    ask REPORT_TIME "Heure d'envoi (HH:MM)" "${OPT_REPORT_TIME:-${PREV_REPORT_TIME:-08:00}}" is_hhmm
    REPORT_TIME=$(printf '%02d:%02d' "$((10#${REPORT_TIME%%:*}))" "$((10#${REPORT_TIME##*:}))")

    questions_mail_transport

    # Beaucoup de relais exigent que l'expéditeur soit le compte authentifié
    if [[ -n $OPT_FROM ]]; then
        def_from=$OPT_FROM
    elif [[ -n $SMTP_USER ]] && is_email "$SMTP_USER"; then
        def_from=$SMTP_USER
    else
        def_from=${PREV_REPORT_FROM:-fail2ban@${HOST_FQDN}}
    fi
    ask REPORT_FROM "Adresse expéditrice" "$def_from" is_email_loose
}

questions() {
    log_step "Configuration"
    questions_ssh_port
    questions_ignoreip
    questions_report
}

validate_parameters() {
    local s_ban s_rfind
    is_ssh_mode "$SSH_MODE" || die "SSH_MODE invalide : ${SSH_MODE} (normal|ddos|extra|aggressive)."
    is_uint "$SSH_MAXRETRY" || die "SSH_MAXRETRY invalide : ${SSH_MAXRETRY}"
    is_uint "$RECIDIVE_MAXRETRY" || die "RECIDIVE_MAXRETRY invalide : ${RECIDIVE_MAXRETRY}"
    local v
    for v in SSH_FINDTIME SSH_BANTIME RECIDIVE_FINDTIME RECIDIVE_BANTIME; do
        [[ -n $(to_seconds "${!v}") ]] || die "${v} invalide : '${!v}' (ex. 10m, 24h, 60d)."
    done
    # 3 bans de 24 h ne peuvent pas tenir dans une fenêtre trop courte
    s_ban=$(to_seconds "$SSH_BANTIME")
    s_rfind=$(to_seconds "$RECIDIVE_FINDTIME")
    if ((s_rfind <= (RECIDIVE_MAXRETRY - 1) * s_ban)); then
        log_warn "RECIDIVE_FINDTIME (${RECIDIVE_FINDTIME}) trop court : ${RECIDIVE_MAXRETRY} bans de ${SSH_BANTIME} ne peuvent pas y tenir."
    fi
}

show_plan() {
    log_step "Récapitulatif"
    local ssh_desc rep_desc mail_desc
    if [[ -n $NEW_SSH_PORT ]]; then
        ssh_desc="port ${SSH_CONF_PORTS[*]} → ${NEW_SSH_PORT} (test + retour arrière auto)"
    else
        ssh_desc="port ${SSH_FINAL_PORTS} (inchangé)"
    fi
    if [[ $REPORT_ENABLED == true ]]; then
        rep_desc="chaque $(day_fr "$REPORT_DAY") à ${REPORT_TIME} → ${REPORT_TO}"
        case $MAIL_MODE in
            relay) mail_desc="Postfix → relais [${SMTP_HOST}]:${SMTP_PORT}${SMTP_USER:+ (compte ${SMTP_USER})}" ;;
            existing) mail_desc="MTA existant (${MTA_NAME})" ;;
            *) mail_desc="aucun (emails non envoyables)" ;;
        esac
    else
        rep_desc="non"
        mail_desc="-"
    fi
    kv "SSH" "$ssh_desc"
    kv "Jail sshd" "${SSH_MAXRETRY} échecs / ${SSH_FINDTIME} → ban ${SSH_BANTIME} (mode ${SSH_MODE})"
    kv "Jail sshd-recidive" "${RECIDIVE_MAXRETRY} bans sshd / ${RECIDIVE_FINDTIME} → ban ${RECIDIVE_BANTIME}, tous ports"
    kv "Action de ban" "${BANACTION} / ${BANACTION_ALLPORTS}"
    kv "Liste blanche" "$IGNORE_IPS"
    kv "Rapport hebdo" "$rep_desc"
    kv "Envoi des emails" "$mail_desc"
    if [[ $OPT_RECIDIVE_MAIL == true && $REPORT_ENABLED == true && $MAIL_MODE != none ]]; then
        kv "Notif. récidive" "oui (email à chaque ban de ${RECIDIVE_BANTIME})"
    else
        kv "Notif. récidive" "non"
    fi
    echo
    if ! ask_yn "Appliquer cette configuration ?" o; then
        log_warn "Abandon : aucune modification effectuée."
        exit 0
    fi
}

#===============================================================================
# 7. RELAIS SMTP (POSTFIX)
#===============================================================================
gen_test_mail() {
    cat <<EOF
From: Fail2ban ${HOST_SHORT} <${REPORT_FROM}>
To: ${REPORT_TO}
Subject: [Fail2ban] Test d'envoi depuis ${HOST_FQDN}
Date: $(LC_ALL=C date -R)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Auto-Submitted: auto-generated

Bonjour,

Ce message confirme que ${HOST_FQDN} sait envoyer des emails.
Le rapport Fail2ban sera envoyé chaque $(day_fr "$REPORT_DAY") à ${REPORT_TIME}.

--
${SCRIPT_NAME} v${SCRIPT_VERSION}
EOF
}

send_test_mail() {
    if [[ -z $MTA_BIN ]]; then
        log_warn "Aucune commande sendmail : test d'envoi impossible."
        return 0
    fi
    log_info "Envoi d'un email de test à ${REPORT_TO}…"
    if ! gen_test_mail | "$MTA_BIN" -t -oi -f "$REPORT_FROM" >>"$LOG_FILE" 2>&1; then
        log_warn "La commande sendmail a échoué (voir ${LOG_FILE})."
        return 0
    fi
    have postqueue || { log_ok "Email de test transmis au MTA."; return 0; }

    local i queue=""
    for ((i = 0; i < 20; i++)); do
        queue=$(postqueue -p 2>/dev/null || true)
        [[ $queue == *"Mail queue is empty"* ]] && break
        sleep 1
    done
    if [[ $queue == *"Mail queue is empty"* ]]; then
        log_ok "Email de test remis au relais : vérifiez la réception (et les spams)."
    else
        log_warn "L'email de test est encore en file d'attente. Raison probable :"
        grep -E '^[[:space:]]*\(' <<<"$queue" | head -n 3 | sed 's/^/      /' >&2 || true
        log_info "Diagnostic : postqueue -p ; journalctl -u postfix ou /var/log/mail.log"
    fi
}

configure_postfix_relay() {
    log_step "Relais SMTP : Postfix → [${SMTP_HOST}]:${SMTP_PORT}"
    have postconf || die "postconf introuvable : installation de Postfix incomplète."
    local main_cf=/etc/postfix/main.cf dbtype tls_level wrapper cafile="" proto=all c
    local -a params

    if [[ ! -s $main_cf && -f /usr/share/postfix/main.cf.debian ]]; then
        cp /usr/share/postfix/main.cf.debian "$main_cf"
    fi
    backup_file "$main_cf"

    # Un autre MTA occuperait le port 25 local (sendmail sur RHEL…)
    for c in sendmail exim exim4; do
        if svc_is_active "$c"; then svc_stop_disable "$c"; fi
    done
    if have alternatives && [[ -x /usr/sbin/sendmail.postfix ]]; then
        alternatives --set mta /usr/sbin/sendmail.postfix >>"$LOG_FILE" 2>&1 || true
    fi

    dbtype=$(postconf -h default_database_type 2>/dev/null || true)
    dbtype=${dbtype:-hash}
    case $SMTP_PORT in
        465) tls_level=encrypt wrapper=yes ;;  # TLS implicite (SMTPS)
        25) tls_level=may wrapper=no ;;        # STARTTLS opportuniste
        *) tls_level=encrypt wrapper=no ;;     # STARTTLS obligatoire (587)
    esac
    for c in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
        if [[ -r $c ]]; then cafile=$c; break; fi
    done
    [[ -e /proc/net/if_inet6 ]] || proto=ipv4

    params=(
        "relayhost = [${SMTP_HOST}]:${SMTP_PORT}"
        "inet_interfaces = loopback-only"
        "inet_protocols = ${proto}"
        "default_transport = smtp"
        "relay_transport = relay"
        "smtp_tls_security_level = ${tls_level}"
        "smtp_tls_wrappermode = ${wrapper}"
        "smtp_tls_loglevel = 1"
        "sender_canonical_maps = static:${REPORT_FROM}"
    )
    [[ -n $cafile ]] && params+=("smtp_tls_CAfile = ${cafile}")

    if [[ -n $SMTP_USER ]]; then
        write_file /etc/postfix/sasl_passwd 0600 <<<"[${SMTP_HOST}]:${SMTP_PORT} ${SMTP_USER}:${SMTP_PASSWORD}"
        run "Génération de la table d'authentification SMTP" postmap "${dbtype}:/etc/postfix/sasl_passwd"
        chmod 0600 /etc/postfix/sasl_passwd.* 2>/dev/null || true
        params+=(
            "smtp_sasl_auth_enable = yes"
            "smtp_sasl_password_maps = ${dbtype}:/etc/postfix/sasl_passwd"
            "smtp_sasl_security_options = noanonymous"
            "smtp_sasl_tls_security_options = noanonymous"
        )
    else
        params+=("smtp_sasl_auth_enable = no")
    fi
    run "Paramétrage de main.cf" postconf -e "${params[@]}"
    if have newaliases; then newaliases >>"$LOG_FILE" 2>&1 || true; fi
    run "Vérification de Postfix" postfix check || log_warn "postfix check signale des avertissements."
    svc_enable postfix
    svc_restart postfix
    log_ok "Postfix configuré (écoute locale uniquement, identifiants en 600 dans /etc/postfix/sasl_passwd)."
    detect_mta
    send_test_mail
}

#===============================================================================
# 8. CHANGEMENT DU PORT SSH (avec retour arrière)
#===============================================================================
ssh_socket_generator_present() {
    [[ -x /usr/lib/systemd/system-generators/sshd-socket-generator ||
        -x /lib/systemd/system-generators/sshd-socket-generator ]]
}

ssh_reload_service() {
    if [[ $SSH_SOCKET == true ]]; then
        run "systemd : rechargement" systemctl daemon-reload
        run "Redémarrage de ssh.socket" systemctl restart ssh.socket
    else
        svc_restart "$SSH_SERVICE"
    fi
}

# Mémorise l'état d'un fichier avant modification (copie ou « à supprimer »)
ssh_rb_save() {
    local f=$1
    if [[ -e $f ]]; then
        if [[ ! -e ${SSH_RB_DIR}${f} ]]; then
            mkdir -p "${SSH_RB_DIR}$(dirname "$f")"
            cp -a "$f" "${SSH_RB_DIR}${f}"
        fi
        backup_file "$f"
    else
        SSH_RB_CREATED+=("$f")
    fi
}

ssh_rollback() {
    [[ $SSH_RB_ACTIVE == true ]] || return 0
    SSH_RB_ACTIVE=false
    local f err_trap
    err_trap=$(trap -p ERR)
    trap - ERR
    set +e
    log_warn "Retour arrière de la configuration SSH…"
    for f in ${SSH_RB_CREATED[@]+"${SSH_RB_CREATED[@]}"}; do rm -f -- "$f"; done
    if [[ -d $SSH_RB_DIR ]]; then
        while IFS= read -r f; do
            f=${f#.}
            cp -a "${SSH_RB_DIR}${f}" "$f"
        done < <(cd "$SSH_RB_DIR" && find . -type f)
    fi
    if [[ $SSH_RB_SELINUX == true ]]; then
        semanage port -d -t ssh_port_t -p tcp "$NEW_SSH_PORT" >>"$LOG_FILE" 2>&1
    fi
    case $SSH_RB_FW in
        firewalld)
            firewall-cmd --permanent --remove-port="${NEW_SSH_PORT}/tcp" >>"$LOG_FILE" 2>&1
            firewall-cmd --reload >>"$LOG_FILE" 2>&1
            ;;
        ufw) ufw --force delete allow "${NEW_SSH_PORT}/tcp" >>"$LOG_FILE" 2>&1 ;;
    esac
    ssh_reload_service
    if sshd_test_config; then
        log_ok "Configuration SSH d'origine restaurée (port ${SSH_CONF_PORTS[*]})."
    else
        log_error "sshd -t échoue après restauration : vérifiez /etc/ssh (sauvegardes : ${BACKUP_DIR})."
    fi
    rm -rf "$SSH_RB_DIR"
    NEW_SSH_PORT=""
    set -e
    if [[ -n $err_trap ]]; then eval "$err_trap"; fi
    return 0
}

ssh_open_firewall() {
    local port=$1
    case $FIREWALL in
        firewalld)
            run "firewalld : ouverture de ${port}/tcp" firewall-cmd --permanent --add-port="${port}/tcp"
            run "firewalld : rechargement" firewall-cmd --reload
            SSH_RB_FW=firewalld
            ;;
        ufw)
            run "ufw : ouverture de ${port}/tcp" ufw allow "${port}/tcp" comment "SSH (${SCRIPT_NAME})"
            SSH_RB_FW=ufw
            ;;
        nftables | iptables)
            if [[ $FW_POLICY_DROP == true ]]; then
                log_warn "Pare-feu ${FIREWALL} en politique DROP : ses règles sont propres à votre"
                log_warn "installation, ouvrez ${port}/tcp vous-même AVANT de continuer."
                if ! ask_yn "Le port ${port}/tcp est-il autorisé dans le pare-feu ?" n; then
                    return 1
                fi
            fi
            ;;
    esac
    log_warn "Pensez au pare-feu de l'hébergeur (Security Group AWS/Azure/GCP, Scaleway, Hetzner, OVH…) : ${port}/tcp."
    return 0
}

ssh_offer_close_old_port() {
    local out
    case $FIREWALL in
        firewalld)
            if firewall-cmd --permanent --query-service=ssh >/dev/null 2>&1 &&
                ask_yn "Fermer l'ancien port 22 dans firewalld (service « ssh ») ?" o; then
                run "firewalld : fermeture du service ssh" firewall-cmd --permanent --remove-service=ssh
                run "firewalld : rechargement" firewall-cmd --reload
            fi
            ;;
        ufw)
            out=$(LC_ALL=C ufw status 2>/dev/null || true)
            if grep -qE '^(22(/tcp)?|OpenSSH)[[:space:]]+ALLOW' <<<"$out" &&
                ask_yn "Supprimer les règles ufw autorisant l'ancien port 22 ?" o; then
                ufw --force delete allow 22/tcp >>"$LOG_FILE" 2>&1 || true
                ufw --force delete allow 22 >>"$LOG_FILE" 2>&1 || true
                ufw --force delete allow OpenSSH >>"$LOG_FILE" 2>&1 || true
                log_ok "ufw : port 22 fermé."
            fi
            ;;
    esac
    return 0
}

change_ssh_port() {
    local port=$NEW_SSH_PORT f selinux_ports ans="" user
    log_step "Changement du port SSH : ${SSH_CONF_PORTS[*]} → ${port}"

    # ListenAddress avec port explicite : la directive Port y est ignorée
    if sshd_config_files | xargs grep -qiE '^[[:space:]]*ListenAddress[[:space:]]+(\[[^]]+\]|[^:[:space:]]+):[0-9]+' 2>/dev/null; then
        log_warn "ListenAddress avec port explicite détecté dans /etc/ssh : changement manuel requis."
        NEW_SSH_PORT=""
        return 0
    fi
    # Créer /etc/ssh/sshd_config masquerait la configuration fournie par la distribution
    if ! sshd_includes_dropins && [[ ! -f /etc/ssh/sshd_config ]]; then
        log_warn "Ni /etc/ssh/sshd_config ni sshd_config.d inclus : changement de port à faire à la main."
        NEW_SSH_PORT=""
        return 0
    fi

    SSH_RB_DIR=$(mktemp -d "/tmp/${SCRIPT_NAME}-ssh.XXXXXX")
    SSH_RB_CREATED=()
    while IFS= read -r f; do ssh_rb_save "$f"; done < <(sshd_config_files)
    ssh_rb_save "$SSH_PORT_DROPIN"
    ssh_rb_save "$SSH_SOCKET_DROPIN"
    SSH_RB_ACTIVE=true

    # 1. Neutralise les directives Port existantes (elles sont cumulatives)
    while IFS= read -r f; do
        if grep -qiE '^[[:space:]]*Port[[:space:]]' "$f"; then
            sed -i "s/^\([[:space:]]*[Pp][Oo][Rr][Tt][[:space:]].*\)$/#\1   # désactivé par ${SCRIPT_NAME} ${RUN_ID}/" "$f"
        fi
    done < <(sshd_config_files)

    # 2. Nouveau port : drop-in si sshd_config.d est inclus, sinon en tête de fichier
    if sshd_includes_dropins; then
        write_file "$SSH_PORT_DROPIN" 0644 <<EOF
$(managed_header)
Port ${port}
EOF
    else
        local tmp
        tmp=$(mktemp)
        TMP_FILES+=("$tmp")
        { printf '# Port SSH défini par %s (%s)\nPort %s\n\n' "$SCRIPT_NAME" "$RUN_ID" "$port"
          cat /etc/ssh/sshd_config; } >"$tmp"
        cat "$tmp" >/etc/ssh/sshd_config   # « cat > » conserve droits et contexte SELinux
    fi

    # 3. Socket systemd sans générateur (Ubuntu 22.10 – 23.10) : drop-in ListenStream
    if [[ $SSH_SOCKET == true ]] && ! ssh_socket_generator_present; then
        write_file "$SSH_SOCKET_DROPIN" 0644 <<EOF
$(managed_header)
[Socket]
ListenStream=
ListenStream=${port}
EOF
    fi

    # 4. SELinux : sshd ne peut se lier qu'aux ports étiquetés ssh_port_t
    if selinux_active; then
        if ! have semanage; then
            log_error "SELinux actif mais semanage absent : impossible d'autoriser le port ${port}."
            ssh_rollback
            return 0
        fi
        selinux_ports=$(semanage port -l 2>/dev/null | awk '$1 == "ssh_port_t" && $2 == "tcp"' || true)
        if [[ ! $selinux_ports =~ [[:space:],]${port}(,|[[:space:]]|$) ]]; then
            if ! semanage port -a -t ssh_port_t -p tcp "$port" >>"$LOG_FILE" 2>&1; then
                run "SELinux : réétiquetage du port ${port}" semanage port -m -t ssh_port_t -p tcp "$port"
            fi
            SSH_RB_SELINUX=true
            log_ok "SELinux : port ${port}/tcp autorisé pour sshd (ssh_port_t)."
        fi
    fi

    # 5. Pare-feu local
    if ! ssh_open_firewall "$port"; then
        ssh_rollback
        return 0
    fi

    # 6. Validation puis application
    if ! sshd_test_config; then
        log_error "sshd -t refuse la nouvelle configuration."
        ssh_rollback
        return 0
    fi
    ssh_reload_service
    if ! wait_for_port "$port" 15; then
        log_error "sshd n'écoute pas sur le port ${port} après redémarrage."
        ssh_rollback
        return 0
    fi
    log_ok "sshd écoute sur le port ${port} (les sessions ouvertes restent actives)."

    # 7. Test de connexion par l'utilisateur, sinon retour arrière automatique
    if has_tty; then
        user=${SUDO_USER:-$(logname 2>/dev/null || echo root)}
        {
            printf '\n  %s┌─ TEST OBLIGATOIRE ─────────────────────────────────────────────%s\n' "$C_YELLOW" "$C_RESET"
            printf '  %s│%s NE FERMEZ PAS cette session. Dans un AUTRE terminal, lancez :\n' "$C_YELLOW" "$C_RESET"
            printf '  %s│%s     %sssh -p %s %s@%s%s\n' "$C_YELLOW" "$C_RESET" "$C_BOLD" "$port" "$user" "$(primary_ip)" "$C_RESET"
            printf '  %s│%s Puis revenez ici. Sans « oui » sous %d s : retour au port %s.\n' "$C_YELLOW" "$C_RESET" "$SSH_CONFIRM_TIMEOUT" "${SSH_CONF_PORTS[*]}"
            printf '  %s└────────────────────────────────────────────────────────────────%s\n' "$C_YELLOW" "$C_RESET"
            printf '  %s?%s La connexion sur le port %s fonctionne-t-elle ? (oui/non) : ' "$C_CYAN" "$C_RESET" "$port"
        } >/dev/tty
        IFS= read -r -t "$SSH_CONFIRM_TIMEOUT" ans </dev/tty || { ans=""; printf '\n' >/dev/tty; }
        case ${ans,,} in
            o | oui | y | yes) _log_file ASK "Test SSH port ${port} → confirmé" ;;
            *)
                log_warn "Connexion non confirmée."
                ssh_rollback
                return 0
                ;;
        esac
    else
        log_warn "Mode non interactif : testez immédiatement « ssh -p ${port} … » depuis un autre poste."
    fi

    SSH_RB_ACTIVE=false
    rm -rf "$SSH_RB_DIR"
    SSH_FINAL_PORTS=$port
    log_ok "Port SSH changé : ${port}"
    ssh_offer_close_old_port
}

#===============================================================================
# 9. CONFIGURATION FAIL2BAN
#===============================================================================
gen_f2b_main_local() {
    local purge_s purge_d
    # La base doit conserver les bans plus longtemps que le ban de récidive,
    # sinon ils ne sont pas restaurés après un redémarrage (défaut Fail2ban : 1 j).
    purge_s=$(($(to_seconds "$RECIDIVE_BANTIME") + 30 * 86400))
    if ((purge_s < 90 * 86400)); then purge_s=$((90 * 86400)); fi
    purge_d="$(((purge_s + 86399) / 86400))d"
    managed_header
    cat <<EOF
[Definition]
loglevel   = INFO
# La jail de récidive lit ce fichier : il doit rester un fichier texte.
logtarget  = ${F2B_LOG}
# Historique des bans conservé ${purge_d} (> ban de récidive de ${RECIDIVE_BANTIME}) :
# restauration des bans longs après redémarrage + historique du rapport hebdo.
dbpurgeage = ${purge_d}
EOF
}

gen_f2b_jail_defaults() {
    managed_header
    cat <<EOF
[DEFAULT]
# Adresses / réseaux jamais bannis (séparés par des espaces)
ignoreip   = ${IGNORE_IPS}
ignoreself = true

# Action de bannissement adaptée au pare-feu détecté (${FIREWALL})
banaction          = ${BANACTION}
banaction_allports = ${BANACTION_ALLPORTS}

# Paramètres email (utilisés par les actions de notification)
destemail  = ${REPORT_TO:-root@localhost}
sender     = ${REPORT_FROM:-root@${HOST_FQDN}}
sendername = Fail2ban ${HOST_SHORT}
mta        = sendmail
EOF
}

gen_f2b_jail_sshd() {
    local backend_block recidive_action=""
    if [[ $F2B_BACKEND == systemd ]]; then
        # _COMM=sshd-session / sshd-auth : OpenSSH >= 9.8 sépare le démon en plusieurs binaires
        backend_block="backend      = systemd
journalmatch = _SYSTEMD_UNIT=sshd.service + _SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session + _COMM=sshd-auth"
    else
        backend_block="backend      = auto
logpath      = ${SSH_LOGPATH}"
    fi
    if [[ $OPT_RECIDIVE_MAIL == true && $REPORT_ENABLED == true && $MAIL_MODE != none ]]; then
        recidive_action='action    = %(action_)s
            mail-recidive[name=%(__name__)s, dest="%(destemail)s", sender="%(sender)s", sendername="%(sendername)s"]'
    fi

    managed_header
    cat <<EOF
#
# Protection SSH en deux étages
# ─────────────────────────────
#  1. [sshd]           ${SSH_MAXRETRY} échecs en ${SSH_FINDTIME}               → ban ${SSH_BANTIME} sur le(s) port(s) SSH
#  2. [sshd-recidive]  ${RECIDIVE_MAXRETRY} bans [sshd] en ${RECIDIVE_FINDTIME}           → ban ${RECIDIVE_BANTIME} sur TOUS les ports
#
# Commandes utiles
#   fail2ban-client status sshd
#   fail2ban-client status sshd-recidive
#   fail2ban-client set sshd unbanip <IP>
#   fail2ban-client set sshd-recidive unbanip <IP>

[sshd]
enabled      = true
port         = ${SSH_FINAL_PORTS}
mode         = ${SSH_MODE}
# _daemon élargi : OpenSSH >= 9.8 journalise sous « sshd-session » / « sshd-auth »
filter       = sshd[mode=%(mode)s, _daemon="sshd(?:-session|-auth)?"${SSH_FILTER_EXTRA}]
${backend_block}
maxretry     = ${SSH_MAXRETRY}
findtime     = ${SSH_FINDTIME}
bantime      = ${SSH_BANTIME}

[sshd-recidive]
enabled   = true
# Compte les lignes « [sshd] Ban <IP> » du journal de Fail2ban lui-même
filter    = sshd-recidive[_watched="sshd"]
backend   = auto
logpath   = ${F2B_LOG}
banaction = %(banaction_allports)s
maxretry  = ${RECIDIVE_MAXRETRY}
findtime  = ${RECIDIVE_FINDTIME}
bantime   = ${RECIDIVE_BANTIME}
${recidive_action}
EOF
}

gen_f2b_filter_recidive() {
    managed_header
    cat <<'EOF'
#
# Filtre de récidive restreint à certaines jails (le filtre « recidive » fourni
# avec Fail2ban compte les bans de TOUTES les jails). Les lignes « Restore Ban »
# émises au redémarrage ne sont pas comptées.
#
# Surveiller plusieurs jails : filter = sshd-recidive[_watched="sshd|nginx-.*"]

[INCLUDES]
before = common.conf

[Definition]
_daemon  = (?:fail2ban(?:-server|\.actions)\s*)
_watched = sshd

failregex = ^%(__prefix_line)s(?:\s*fail2ban\.actions\s*%(__pid_re)s?:\s+)?NOTICE\s+\[(?:%(_watched)s)\]\s+Ban\s+<HOST>\s*$

ignoreregex =

datepattern = ^{DATE}

journalmatch = _SYSTEMD_UNIT=fail2ban.service PRIORITY=5
EOF
}

gen_f2b_action_mail() {
    managed_header
    cat <<'EOF'
#
# Email envoyé à chaque ban de récidive (événement rare donc utile), en français,
# avec un extrait whois. Aucun email au démarrage / à l'arrêt des jails.

[INCLUDES]
before = sendmail-common.conf

[Definition]
actionstart =
actionstop  =
norestored  = 1

actionban = printf %%b "Subject: [Fail2ban] <fq-hostname>: recidive - <ip> bannie $(( <bantime> / 86400 )) jours
            Date: `LC_ALL=C date +"%%a, %%d %%h %%Y %%T %%z"`
            From: <sendername> <<sender>>
            To: <dest>
            MIME-Version: 1.0
            Content-Type: text/plain; charset=UTF-8
            Content-Transfer-Encoding: 8bit
            Auto-Submitted: auto-generated\n
            Bonjour,\n
            L'adresse <ip> vient d'être bannie pour $(( <bantime> / 86400 )) jours, sur TOUS
            les ports, par la jail <name> : elle a déjà été bannie <failures> fois par SSH.\n
            Whois :
            $( (timeout 15 whois <ip> 2>/dev/null || true) | grep -iE '^(country|netname|org-?name|descr|abuse-mailbox|orgabuseemail):' | head -n 8 )\n
            Pour la débannir : fail2ban-client set <name> unbanip <ip>\n
            -- \n
            Fail2ban sur <fq-hostname>" | <mailcmd>

[Init]
name = recidive
EOF
}

gen_restore_script() {
    printf '#!%s\n' "$PYTHON_BIN"
    managed_header
    printf '__version__ = "%s"\n' "$SCRIPT_VERSION"
    cat <<'PYEOF'
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
# Les IP ayant déjà atteint le seuil sans être bannies (débannies à la main) sont
# ignorées. Les échecs restaurés sont datés du redémarrage : ils expirent donc un
# peu plus tard que les originaux (choix volontairement prudent).
#
import argparse
import collections
import datetime as dt
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from urllib.parse import quote


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


def main():
    parser = argparse.ArgumentParser(
        description="Restaure le compteur de la jail de récidive depuis la base Fail2ban.")
    parser.add_argument("--source", default="sshd", help="jail surveillée (défaut : sshd)")
    parser.add_argument("--recidive", default="sshd-recidive",
                        help="jail de récidive (défaut : sshd-recidive)")
    parser.add_argument("--wait", type=int, default=60,
                        help="attente maximale du démarrage de Fail2ban, en secondes")
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
    failed = re.search(r"Currently failed:\s*(\d+)", status)
    if failed and int(failed.group(1)) > 0:
        # La jail a déjà relu ses journaux (premier démarrage, rotation…) : pas de doublon
        log("compteur déjà alimenté, rien à restaurer")
        return 0
    banned = re.search(r"Banned IP list:\s*(.*)", status)
    banned = set(banned.group(1).split()) if banned else set()
    try:
        findtime = int((client("get", args.recidive, "findtime") or "").strip())
        maxretry = int((client("get", args.recidive, "maxretry") or "").strip())
    except ValueError:
        log("impossible de lire findtime/maxretry de {}".format(args.recidive))
        return 1
    dbfile = re.search(r"(/\S+)\s*$", (client("get", "dbfile") or "").strip())
    if not dbfile:
        log("base de données Fail2ban désactivée : rien à restaurer")
        return 0

    con = sqlite3.connect("file:{}?mode=ro".format(quote(dbfile.group(1))), uri=True, timeout=30)
    try:
        rows = con.execute("SELECT ip, timeofban FROM bans WHERE jail = ? AND timeofban >= ? "
                           "ORDER BY timeofban", (args.source, int(time.time() - findtime))).fetchall()
    finally:
        con.close()
    history = collections.OrderedDict()
    for ip, ts in rows:
        history.setdefault(ip, []).append(ts)

    restored = 0
    for ip, stamps in history.items():
        if ip in banned or len(stamps) >= maxretry:
            continue
        matches = ["[{}] Ban {} du {:%Y-%m-%d %H:%M:%S} (compteur restauré)".format(
            args.source, ip, dt.datetime.fromtimestamp(ts)) for ts in stamps]
        if args.dry_run:
            print("{} : {} ban(s) {}".format(ip, len(stamps), args.source))
        elif client("set", args.recidive, "attempt", ip, *matches) is None:
            log("échec de la restauration pour {}".format(ip))
            continue
        restored += 1
    log("{} IP restaurée(s) dans {} (bans [{}] des {} derniers jours, seuil {})".format(
        restored, args.recidive, args.source, findtime // 86400, maxretry))
    return 0


if __name__ == "__main__":
    sys.exit(main())
PYEOF
}

gen_f2b_service_dropin() {
    managed_header
    cat <<EOF
# Après chaque démarrage, restaure le compteur de la jail de récidive
# (sinon un redémarrage oublierait les bans [sshd] déjà comptés).
[Service]
ExecStartPost=-${RESTORE_BIN}
EOF
}

write_fail2ban_config() {
    log_step "Configuration de Fail2ban"
    write_file "$F2B_MAIN_LOCAL" 0644 < <(gen_f2b_main_local)
    write_file "$F2B_JAIL_DEFAULTS" 0644 < <(gen_f2b_jail_defaults)
    write_file "$F2B_FILTER_RECIDIVE" 0644 < <(gen_f2b_filter_recidive)
    write_file "$F2B_ACTION_MAIL" 0644 < <(gen_f2b_action_mail)
    write_file "$F2B_JAIL_SSH" 0644 < <(gen_f2b_jail_sshd)
    write_file "$RESTORE_BIN" 0755 < <(gen_restore_script)
    if [[ $INIT_SYSTEM == systemd ]]; then
        write_file "$F2B_SERVICE_DROPIN" 0644 < <(gen_f2b_service_dropin)
        run "systemd : rechargement" systemctl daemon-reload
    fi
    log_ok "Jails écrites : ${F2B_JAIL_SSH}"
    if [[ -f ${F2B_ETC}/jail.local ]]; then
        log_info "jail.local existe : les fichiers jail.d/*.local ci-dessus sont prioritaires sur lui."
    fi
}

start_fail2ban() {
    log_step "Validation et démarrage de Fail2ban"
    local help st i jail banned
    [[ -e $F2B_LOG ]] || install -m 0640 /dev/null "$F2B_LOG"

    help=$(fail2ban-client --help 2>&1 || true)
    if [[ $help == *"--test"* ]]; then
        run "Test de la configuration" fail2ban-client --test ||
            die "Configuration Fail2ban invalide (sauvegardes : ${BACKUP_DIR})."
    else
        run "Contrôle de la configuration" fail2ban-client -d ||
            die "Configuration Fail2ban invalide (sauvegardes : ${BACKUP_DIR})."
    fi
    log_ok "Configuration valide"

    svc_enable fail2ban
    svc_restart fail2ban
    for ((i = 0; i < 30; i++)); do
        if fail2ban-client ping >/dev/null 2>&1; then sleep 2; break; fi
        sleep 1
    done
    if ! fail2ban-client ping >/dev/null 2>&1; then
        log_error "Fail2ban ne répond pas après redémarrage."
        if [[ $INIT_SYSTEM == systemd ]]; then
            journalctl -u fail2ban -n 20 --no-pager 2>/dev/null | sed 's/^/    │ /' >&2 || true
        fi
        tail -n 20 "$F2B_LOG" 2>/dev/null | sed 's/^/    │ /' >&2 || true
        die "Démarrage de Fail2ban impossible."
    fi

    if [[ $INIT_SYSTEM != systemd ]]; then
        run "Restauration du compteur de récidive" "$RESTORE_BIN" || true
    fi
    for jail in sshd sshd-recidive; do
        if st=$(fail2ban-client status "$jail" 2>/dev/null); then
            banned=$(sed -n 's/.*Currently banned:[[:space:]]*\([0-9]*\).*/\1/p' <<<"$st" || true)
            log_ok "Jail ${jail} active (${banned:-0} IP bannie(s) actuellement)"
        else
            log_error "Jail ${jail} inactive : consultez ${F2B_LOG}"
            JAIL_ERRORS=$((JAIL_ERRORS + 1))
        fi
    done
}

#===============================================================================
# 10. RAPPORT HEBDOMADAIRE
#===============================================================================
gen_report_conf() {
    managed_header
    cat <<EOF
# Configuration lue par ${REPORT_BIN} (syntaxe CLÉ=valeur)

REPORT_TO="${REPORT_TO}"
REPORT_FROM="${REPORT_FROM}"
REPORT_FROM_NAME="Fail2ban ${HOST_SHORT}"
REPORT_HOSTNAME="${HOST_FQDN}"
REPORT_SUBJECT_PREFIX="[Fail2ban]"
# Période couverte (jours) et taille des classements
REPORT_DAYS=7
REPORT_TOP=10
# Pays des IP via whois (yes/no)
REPORT_GEOIP=yes
# Jails dont l'absence déclenche une alerte dans le rapport
EXPECTED_JAILS="sshd sshd-recidive"
# Détectés automatiquement si vides :
F2B_DB=""
SENDMAIL=""
EOF
}

gen_report_service() {
    managed_header
    cat <<EOF
[Unit]
Description=Rapport hebdomadaire Fail2ban (bans de la semaine par email)
After=network-online.target fail2ban.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${REPORT_BIN}
Nice=10
IOSchedulingClass=idle
PrivateTmp=true
EOF
}

gen_report_timer() {
    local dow=$1 hhmm=$2
    managed_header
    cat <<EOF
[Unit]
Description=Planification du rapport hebdomadaire Fail2ban

[Timer]
OnCalendar=${dow} *-*-* ${hhmm}:00
RandomizedDelaySec=5min
# Rattrape l'envoi si le serveur était éteint à l'heure prévue
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

install_report_schedule() {
    local dow_sd dow_cron hh mm tab=/etc/crontabs/root tmp
    dow_sd=${REPORT_DAY^}
    dow_cron=$(day_cron "$REPORT_DAY")
    hh=$((10#${REPORT_TIME%%:*}))
    mm=$((10#${REPORT_TIME##*:}))

    if [[ $INIT_SYSTEM == systemd ]]; then
        write_file "${SYSTEMD_DIR}/${REPORT_UNIT}.service" 0644 < <(gen_report_service)
        write_file "${SYSTEMD_DIR}/${REPORT_UNIT}.timer" 0644 < <(gen_report_timer "$dow_sd" "$REPORT_TIME")
        run "systemd : rechargement" systemctl daemon-reload
        run "Activation du timer ${REPORT_UNIT}.timer" systemctl enable "${REPORT_UNIT}.timer"
        run "Démarrage du timer ${REPORT_UNIT}.timer" systemctl restart "${REPORT_UNIT}.timer"
        rm -f "$CRON_FILE"
        log_ok "Timer systemd : chaque $(day_fr "$REPORT_DAY") à ${REPORT_TIME} (systemctl list-timers ${REPORT_UNIT})"
    elif [[ $OS_FAMILY == alpine ]]; then
        backup_file "$tab"
        tmp=$(mktemp)
        TMP_FILES+=("$tmp")
        { grep -v 'fail2ban-report' "$tab" 2>/dev/null || true
          printf '%d %d * * %s %s 2>&1 | logger -t fail2ban-report  # %s\n' \
              "$mm" "$hh" "$dow_cron" "$REPORT_BIN" "$MANAGED_MARK"; } >"$tmp"
        cat "$tmp" >"$tab"
        svc_enable crond
        log_ok "Crontab root : chaque $(day_fr "$REPORT_DAY") à ${REPORT_TIME}"
    else
        write_file "$CRON_FILE" 0644 <<EOF
$(managed_header)
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${mm} ${hh} * * ${dow_cron} root ${REPORT_BIN} 2>&1 | logger -t fail2ban-report
EOF
        log_ok "Cron : chaque $(day_fr "$REPORT_DAY") à ${REPORT_TIME} (${CRON_FILE})"
    fi
}

install_report() {
    log_step "Rapport hebdomadaire des bans"
    write_file "$REPORT_BIN" 0755 < <(gen_report_script)
    write_file "$REPORT_CONF" 0640 < <(gen_report_conf)
    install_report_schedule

    if run "Test de génération du rapport" "$REPORT_BIN" --stdout --no-geoip; then
        log_ok "Générateur de rapport opérationnel (aperçu : ${REPORT_BIN} --stdout)"
    else
        log_warn "Le test du rapport a échoué : lancez « ${REPORT_BIN} --stdout » pour diagnostiquer."
        return 0
    fi
    if [[ $MAIL_MODE != none ]] && ask_yn "Envoyer un premier rapport maintenant (aperçu) ?" o; then
        run "Envoi du rapport" "$REPORT_BIN" --until-now &&
            log_ok "Rapport envoyé à ${REPORT_TO}"
    fi
    return 0
}

#===============================================================================
# 11. GÉNÉRATEUR DU RAPPORT (Python 3.6+, bibliothèque standard uniquement)
#===============================================================================
gen_report_script() {
    printf '#!%s\n' "$PYTHON_BIN"
    managed_header
    printf '__version__ = "%s"\n' "$SCRIPT_VERSION"
    cat <<'PYEOF'
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
import time
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from urllib.parse import quote

DEFAULT_CONF = "/etc/fail2ban/report.conf"
DEFAULT_DB = "/var/lib/fail2ban/fail2ban.sqlite3"
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
                 top_n=10, geoip=True, db_path=""):
        self.host = host
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
        countries = lookup_countries([ip for ip, _ in top]) if geoip else {}
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

    # -- libellés -------------------------------------------------------------
    def period_label(self):
        return "Du {} au {} ({})".format(fmt_date(self.days[0]), fmt_date(self.days[-1]),
                                         plural(len(self.days), "jour"))

    def trend(self):
        """(texte, couleur) de l'évolution par rapport à la période précédente."""
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

    # Période : jours calendaires complets, se terminant hier soir à minuit
    # (ou maintenant avec --until-now). Bornes calculées en heure locale.
    today = dt.date.today()
    if args.until_now:
        first = today - dt.timedelta(days=days - 1)
        until = time.time()
    else:
        first = today - dt.timedelta(days=days)
        until = time.mktime(today.timetuple())
    day_list = [first + dt.timedelta(days=i) for i in range(days)]
    since = time.mktime(first.timetuple())
    prev_since = time.mktime((first - dt.timedelta(days=days)).timetuple())

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
                    top_n=top_n, geoip=geoip, db_path=db_path)
    text, html_doc = report.as_text(), report.as_html()

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
PYEOF
}

#===============================================================================
# 12. DÉSINSTALLATION
#===============================================================================
uninstall() {
    log_step "Désinstallation de la configuration ${SCRIPT_NAME}"
    if has_tty && ! ask_yn "Supprimer la configuration Fail2ban installée par ce script ?" n; then
        log_info "Abandon."
        return 0
    fi
    local f
    if [[ $INIT_SYSTEM == systemd ]]; then
        systemctl disable --now "${REPORT_UNIT}.timer" >>"$LOG_FILE" 2>&1 || true
    fi
    for f in "$F2B_MAIN_LOCAL" "$F2B_JAIL_DEFAULTS" "$F2B_JAIL_SSH" "$F2B_FILTER_RECIDIVE" \
        "$F2B_ACTION_MAIL" "$REPORT_BIN" "$REPORT_CONF" "$CRON_FILE" "$RESTORE_BIN" "$F2B_SERVICE_DROPIN" \
        "${SYSTEMD_DIR}/${REPORT_UNIT}.service" "${SYSTEMD_DIR}/${REPORT_UNIT}.timer"; do
        if [[ -f $f ]] && grep -q "$MANAGED_MARK" "$f"; then
            backup_file "$f"
            rm -f -- "$f"
            log_ok "Supprimé : $f"
        fi
    done
    if [[ -f /etc/crontabs/root ]] && grep -q 'fail2ban-report' /etc/crontabs/root; then
        backup_file /etc/crontabs/root
        sed -i '/fail2ban-report/d' /etc/crontabs/root
        log_ok "Entrée retirée de /etc/crontabs/root"
    fi
    if [[ $INIT_SYSTEM == systemd ]]; then systemctl daemon-reload >>"$LOG_FILE" 2>&1 || true; fi

    if have fail2ban-client; then
        if ask_yn "Désinstaller aussi le paquet Fail2ban ?" n; then
            svc_stop_disable fail2ban
            local pkg=fail2ban
            [[ $OS_FAMILY == rhel ]] && pkg=fail2ban-server
            run "Suppression du paquet ${pkg}" pkg_remove "$pkg" || true
        elif svc_is_active fail2ban; then
            svc_restart fail2ban ||
                log_warn "Fail2ban ne redémarre pas avec la configuration d'origine de la distribution : vérifiez ${F2B_ETC}/jail.d/."
        fi
    fi
    log_info "Non modifiés : port SSH, Postfix, pare-feu (sauvegardes : ${BACKUP_ROOT})."
    log_ok "Désinstallation terminée."
}

#===============================================================================
# 13. RÉSUMÉ FINAL
#===============================================================================
final_summary() {
    log_step "Terminé"
    local rep="non installé"
    if [[ $REPORT_ENABLED == true ]]; then
        rep="chaque $(day_fr "$REPORT_DAY") à ${REPORT_TIME} → ${REPORT_TO}"
    fi
    kv "Port SSH" "$SSH_FINAL_PORTS"
    kv "Jail sshd" "${SSH_MAXRETRY} échecs / ${SSH_FINDTIME} → ${SSH_BANTIME}"
    kv "Jail sshd-recidive" "${RECIDIVE_MAXRETRY} bans / ${RECIDIVE_FINDTIME} → ${RECIDIVE_BANTIME} (tous ports)"
    kv "Rapport" "$rep"
    kv "Journal du script" "$LOG_FILE"
    kv "Sauvegardes" "$BACKUP_DIR"
    printf '\n  %sCommandes utiles%s\n' "$C_BOLD" "$C_RESET"
    printf '    fail2ban-client status sshd              # état + IP bannies\n'
    printf '    fail2ban-client status sshd-recidive\n'
    printf '    fail2ban-client set sshd unbanip <IP>    # débannir (idem sshd-recidive)\n'
    printf '    tail -f %s\n' "$F2B_LOG"
    if [[ $REPORT_ENABLED == true ]]; then
        printf '    %s --stdout --until-now   # aperçu du rapport\n' "$REPORT_BIN"
    fi
    if ((JAIL_ERRORS > 0)); then
        log_warn "${JAIL_ERRORS} jail(s) en erreur : voir ${F2B_LOG}"
    else
        printf '\n  %s✔ Fail2ban est opérationnel.%s\n\n' "$C_GREEN" "$C_RESET"
    fi
    return 0
}

#===============================================================================
# 14. POINT D'ENTRÉE
#===============================================================================
parse_args() {
    local opt val
    while (($#)); do
        opt=$1
        val=""
        if [[ $opt == --*=* ]]; then
            val=${opt#*=}
            opt=${opt%%=*}
        fi
        case $opt in
            -h | --help) usage; exit 0 ;;
            -V | --version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION}"; exit 0 ;;
            -y | --yes | --non-interactive) OPT_NONINTERACTIVE=true ;;
            --detect) ACTION=detect ;;
            --uninstall) ACTION=uninstall ;;
            --keep-ssh-port) OPT_KEEP_SSH_PORT=true ;;
            --no-report) OPT_NO_REPORT=true ;;
            --no-recidive-mail) OPT_RECIDIVE_MAIL=false ;;
            --ssh-port | --ssh-mode | --ignore-ip | --email | --from | --smtp-host | --smtp-port | \
                --smtp-user | --report-day | --report-time)
                if [[ -z $val ]]; then
                    (($# >= 2)) || die "L'option ${opt} attend une valeur."
                    val=$2
                    shift
                fi
                case $opt in
                    --ssh-port) OPT_SSH_PORT=$val ;;
                    --ssh-mode) SSH_MODE=$val ;;
                    --ignore-ip) OPT_IGNORE_IP=$val ;;
                    --email) OPT_EMAIL=$val ;;
                    --from) OPT_FROM=$val ;;
                    --smtp-host) OPT_SMTP_HOST=$val ;;
                    --smtp-port) OPT_SMTP_PORT=$val ;;
                    --smtp-user) OPT_SMTP_USER=$val ;;
                    --report-day) OPT_REPORT_DAY=$val ;;
                    --report-time) OPT_REPORT_TIME=$val ;;
                esac
                ;;
            *) die "Option inconnue : $1 (voir --help)" ;;
        esac
        shift
    done
    if [[ -n $OPT_REPORT_DAY ]] && ! is_day "$OPT_REPORT_DAY"; then die "--report-day invalide : ${OPT_REPORT_DAY}"; fi
    if [[ -n $OPT_REPORT_TIME ]] && ! is_hhmm "$OPT_REPORT_TIME"; then die "--report-time invalide : ${OPT_REPORT_TIME}"; fi
    if [[ -n $OPT_SSH_PORT ]] && ! is_port "$OPT_SSH_PORT"; then die "--ssh-port invalide : ${OPT_SSH_PORT}"; fi
    if [[ -n $OPT_IGNORE_IP ]] && ! is_ip_list_or_empty "$OPT_IGNORE_IP"; then die "--ignore-ip invalide : ${OPT_IGNORE_IP}"; fi
    return 0
}

cleanup() {
    local f
    for f in ${TMP_FILES[@]+"${TMP_FILES[@]}"}; do
        [[ -e $f ]] && rm -f -- "$f"
    done
    return 0
}

on_error() {
    local rc=$? line=$1 cmd=$2
    trap - ERR
    log_error "Erreur inattendue (code ${rc}) ligne ${line} : ${cmd}"
    ssh_rollback
    log_error "Détails : ${LOG_FILE} — sauvegardes : ${BACKUP_DIR}"
    exit "$rc"
}

on_interrupt() {
    trap - ERR INT TERM
    printf '\n' >&2
    log_warn "Interruption demandée."
    ssh_rollback
    exit 130
}

main() {
    parse_args "$@"
    [[ $EUID -eq 0 ]] || die "Ce script doit être exécuté en root (sudo)."

    install -d -m 0700 "$BACKUP_ROOT"
    touch "$LOG_FILE" && chmod 0600 "$LOG_FILE"
    LOG_READY=1
    _log_file START "${SCRIPT_NAME} v${SCRIPT_VERSION} — action=${ACTION} — args : ${ORIG_ARGS}"

    trap cleanup EXIT
    trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR
    trap on_interrupt INT TERM

    if have flock; then
        exec 9>"$LOCK_FILE"
        flock -n 9 || die "Une autre exécution de ${SCRIPT_NAME} est en cours."
    fi

    banner
    detect_all

    case $ACTION in
        detect) exit 0 ;;
        uninstall) uninstall; exit 0 ;;
    esac

    [[ -n $SSHD_BIN ]] || die "OpenSSH server n'est pas installé : ce script protège SSH, installez-le d'abord."
    validate_parameters
    load_previous_answers
    questions
    show_plan

    install_packages
    detect_python
    decide_backend
    if [[ $MAIL_MODE == relay ]]; then configure_postfix_relay; fi
    if [[ -n $NEW_SSH_PORT ]]; then change_ssh_port; fi
    write_fail2ban_config
    start_fail2ban
    if [[ $REPORT_ENABLED == true ]]; then install_report; fi
    save_answers
    final_summary
    if ((JAIL_ERRORS > 0)); then exit 1; fi
}

# Exécution directe ou via « curl … | bash » ; rien n'est lancé si le fichier est sourcé (tests).
if [[ ${BASH_SOURCE[0]:-$0} == "$0" ]]; then
    main "$@"
fi
