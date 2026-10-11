# Fail2ban Setup

Script d'installation et de configuration **multi-distribution** de Fail2ban, orienté
protection SSH, avec **rapport périodique des bans par email** (hebdomadaire sur un VPS,
mensuel sur un réseau interne) qui met en avant **ce qui a changé** depuis l'envoi précédent.

```bash
sudo ./setup.sh            # interactif
sudo ./setup.sh --help     # toutes les options
```

## Fonctionnalités

- **Détection automatique** : distribution, init (systemd / OpenRC / SysV), pare-feu
  (firewalld, ufw, nftables, iptables), SELinux, service SSH (y compris `ssh.socket` d'Ubuntu ≥ 22.10).
- **Deux jails SSH** :

  | Jail             | Déclencheur                         | Sanction                         |
  |------------------|-------------------------------------|----------------------------------|
  | `sshd`           | 5 échecs en 1 h                     | ban **24 h** sur le(s) port(s) SSH |
  | `sshd-recidive`  | **3 bans `sshd`** en 30 jours       | ban **60 jours** sur **tous** les ports |

- **Changement assisté du port SSH** si sshd écoute sur le port 22 : SELinux (`semanage`),
  firewalld / ufw, socket systemd, validation `sshd -t`, **test de connexion obligatoire et
  retour arrière automatique** si la connexion n'est pas confirmée sous 5 minutes. Ce retour
  arrière est **indépendant du script** (timer systemd transitoire, ou processus détaché sans
  systemd) : il a lieu même si l'installateur est tué ou la session SSH coupée.
- **Refus des hyperviseurs** : Proxmox VE, hôte KVM/libvirt, Xen dom0, LXD/Incus, VirtualBox
  hôte → arrêt (code 3) avant toute modification. Les VM et VPS invités restent pris en charge.
- **Profil VPS / LAN détecté automatiquement** (adresse IPv4 publique, fournisseur cloud,
  session SSH depuis Internet ; sans requête réseau) — modifiable avec `--profile`.
- **Rapport HTML + texte** (timer systemd ou cron), hebdomadaire en VPS, mensuel (le 1er) en
  LAN : bans par jour, par jail, top des IP avec pays, réseaux /24 les plus actifs, récidives,
  comparaison avec la période précédente, alertes si une jail est tombée.
- **Section « Nouveautés »** : grâce à une mémoire entre deux rapports, seules les évolutions
  ressortent — jail disparue/ajoutée, nouveau pays, nouveau réseau actif, IP qui reviennent.
- **Profil LAN** : tout ban d'une IP interne (RFC 1918, CGNAT, ULA…) est signalé comme
  anomalie (poste compromis, scan interne, liste blanche incomplète).
- **Email à chaque récidive** (en français, avec extrait whois).
- **Relais SMTP authentifié via Postfix** (Gmail, OVH, Office 365, Brevo…) avec email de test
  et contrôle de la file d'attente. **TLS toujours obligatoire** (y compris port 25) et
  certificat du relais **vérifié** par défaut : les identifiants ne partent jamais en clair.
- **Robuste** : idempotent (relançable, réponses précédentes proposées par défaut), sauvegarde
  de chaque fichier modifié, journal complet, verrou anti-exécution concurrente, mode
  non interactif, compatible `curl … | sudo bash`, désinstallation propre.

![Exemple de rapport hebdomadaire](docs/rapport-exemple.png)

## Distributions prises en charge

| Famille | Distributions | Paquets |
|---------|---------------|---------|
| Debian  | Debian, Ubuntu, Linux Mint, Raspberry Pi OS, Devuan | apt |
| Red Hat | RHEL, Rocky, AlmaLinux, CentOS Stream, Oracle Linux, Fedora, Amazon Linux 2 | dnf/yum + EPEL |
| SUSE    | openSUSE Leap / Tumbleweed, SLES | zypper |
| Arch    | Arch Linux, Manjaro, EndeavourOS | pacman |
| Alpine  | Alpine Linux (OpenRC) — installer bash d'abord : `apk add bash` | apk |

## Utilisation

### Interactif

```bash
git clone https://github.com/xavcrocfer/Fail2ban.git && cd Fail2ban
sudo ./setup.sh
```

Le script pose ses questions (port SSH, liste blanche, rapport, relais SMTP), affiche un
récapitulatif, puis applique la configuration après confirmation.

### Non interactif (Ansible, cloud-init…)

```bash
sudo SMTP_PASSWORD='mot-de-passe' ./setup.sh -y \
     --email admin@exemple.fr \
     --smtp-host smtp.exemple.fr --smtp-port 587 --smtp-user alertes@exemple.fr \
     --ignore-ip "203.0.113.10 198.51.100.0/24" \
     --ssh-port 49222
```

> En mode non interactif, le port SSH n'est modifié que si `--ssh-port` est fourni
> (aucun test de connexion possible : vérifiez immédiatement l'accès).

### Options

| Option | Rôle |
|--------|------|
| `-y`, `--non-interactive` | aucune question |
| `--ssh-port PORT` / `--keep-ssh-port` | déplacer SSH / ne jamais le proposer |
| `--ssh-mode MODE` | `normal` (défaut), `ddos`, `extra`, `aggressive` |
| `--ignore-ip "IP …"` | IP/CIDR jamais bannies |
| `--email`, `--from` | destinataire(s) / expéditeur |
| `--smtp-host`, `--smtp-port`, `--smtp-user` | relais Postfix (mot de passe : `SMTP_PASSWORD`) |
| `--smtp-tls NIVEAU` | `secure` (défaut : TLS + certificat vérifié) ou `encrypt` (relais interne auto-signé) |
| `--profile vps\|lan` | profil de la machine (défaut : détecté) |
| `--report-period week\|month` | rapport hebdomadaire ou mensuel le 1er (défaut : week en VPS, month en LAN) |
| `--report-day`, `--report-time` | jour (hebdo) et heure (défaut : lundi 08:00) |
| `--no-report`, `--no-recidive-mail` | pas de rapport (retire aussi une planification existante) / pas d'email de récidive |
| `--force-hypervisor` | installer malgré la détection d'un hyperviseur (déconseillé) |
| `--detect` | afficher la détection et quitter |
| `--uninstall` | supprimer la configuration installée |

Les seuils se règlent par variables d'environnement :
`SSH_MAXRETRY` (5), `SSH_FINDTIME` (1h), `SSH_BANTIME` (24h),
`RECIDIVE_MAXRETRY` (3), `RECIDIVE_FINDTIME` (30d), `RECIDIVE_BANTIME` (60d).

```bash
sudo SSH_MAXRETRY=3 RECIDIVE_BANTIME=90d ./setup.sh
```

Délais du changement de port : `SSH_CONFIRM_TIMEOUT` (300 s) et `SSH_RB_GRACE` (120 s, marge
du retour arrière indépendant). Codes de retour : `0` succès, `1` erreur, `3` hyperviseur
détecté, `130` interruption.

## Fichiers installés

Le script ne modifie jamais `jail.conf` ni `jail.local` : il écrit ses propres fichiers,
régénérés à chaque exécution (personnalisations → `jail.d/99-local.local`).

| Fichier | Contenu |
|---------|---------|
| `/etc/fail2ban/fail2ban.d/00-fail2ban-setup.local` | log fichier + `dbpurgeage` (90 j) |
| `/etc/fail2ban/jail.d/00-fail2ban-setup-defaults.local` | liste blanche, action de ban, emails |
| `/etc/fail2ban/jail.d/10-fail2ban-setup-sshd.local` | jails `sshd` et `sshd-recidive` |
| `/etc/fail2ban/filter.d/sshd-recidive.conf` | filtre de récidive limité à la jail `sshd` |
| `/etc/fail2ban/action.d/mail-recidive.conf` | email de récidive |
| `/usr/local/sbin/fail2ban-recidive-restore` | restauration du compteur de récidive |
| `/etc/systemd/system/fail2ban.service.d/50-fail2ban-setup-recidive.conf` | lancement de la restauration au démarrage |
| `/usr/local/sbin/fail2ban-report` + `/etc/fail2ban/report.conf` | rapport périodique |
| `/var/lib/fail2ban-setup/report-state.json` | mémoire du rapport (nouveautés), mode 600 |
| `/etc/systemd/system/fail2ban-report.{service,timer}` (ou cron) | planification |
| `/etc/ssh/sshd_config.d/00-fail2ban-setup-port.conf` | port SSH (si modifié) |

Journal : `/var/log/fail2ban-setup.log` — sauvegardes : `/var/backups/fail2ban-setup/<date>/`.

## Détails techniques

- **Récidive** : `sshd-recidive` lit `/var/log/fail2ban.log` et compte les lignes
  `[sshd] Ban <IP>` (les `Restore Ban` du redémarrage sont ignorées). Le filtre `recidive`
  fourni avec Fail2ban compte les bans de *toutes* les jails ; celui-ci est restreint
  (`filter = sshd-recidive[_watched="sshd|nginx-.*"]` pour l'élargir).
- **Persistance des bans** : `dbpurgeage` passe de 1 jour (défaut) à 90 jours, sinon les bans
  de 60 jours ne seraient pas restaurés après un redémarrage.
- **Persistance du compteur de récidive** : Fail2ban garde les échecs en mémoire et reprend ses
  journaux là où il s'était arrêté ; sans précaution, un reboot entre deux bans « effacerait »
  les bans déjà comptés (limite de la jail `recidive` standard). `fail2ban-recidive-restore`,
  lancé par systemd après chaque démarrage (`ExecStartPost`), relit ces bans dans la base et
  les réinjecte (`fail2ban-client set sshd-recidive attempt`). La déduplication se fait **par
  IP et par ban** : il attend que la jail ait fini de relire le journal, ignore les bans déjà
  relus (lignes `[sshd-recidive] Found <IP> - <date>`) et ceux déjà injectés depuis ce
  démarrage (`/var/lib/fail2ban-setup/recidive-restore.json`). `--dry-run` montre ce qui
  serait restauré. Sans systemd (Alpine, Devuan),
  il est exécuté par le script d'installation ; après un redémarrage manuel :
  `fail2ban-recidive-restore`.
- **OpenSSH ≥ 9.8** journalise sous `sshd-session` : le filtre et le `journalmatch` sont
  élargis en conséquence (le filtre d'origine de Fail2ban 1.0 ne les détecte pas).
- **journald** est utilisé dès que possible (obligatoire sur Debian 12+ sans rsyslog).
- **Action de ban** : `firewallcmd-*` si firewalld est actif, sinon `nftables` (table dédiée
  qui coexiste avec ufw/iptables-nft), sinon `iptables`.

## Rapport

```bash
fail2ban-report --stdout --until-now   # aperçu texte, inclut aujourd'hui
fail2ban-report --html /tmp/r.html     # version HTML
fail2ban-report --days 30 --to moi@exemple.fr
fail2ban-report --period month --stdout  # mois calendaire précédent
fail2ban-report --profile lan --stdout   # forcer le profil
systemctl list-timers fail2ban-report  # prochaine exécution
```

**Mémoire entre rapports.** Après chaque envoi réussi, `fail2ban-report` enregistre dans
`/var/lib/fail2ban-setup/report-state.json` (écriture atomique, root seul) les IP de la période,
les réseaux /24 et pays déjà vus et la liste des jails. Le rapport suivant en déduit la section
« Nouveautés ». Un aperçu (`--stdout`, `--html`, `--until-now`) ne modifie **jamais** cette
référence, sauf avec `--save-state` ; `--no-state` l'ignore complètement. Un fichier absent ou
corrompu est simplement ignoré (le rapport l'indique comme « premier rapport »).
Les pays déjà résolus y sont mis en cache, ce qui évite de relancer `whois` à chaque rapport.

Les données viennent de la base SQLite de Fail2ban (90 jours d'historique) et de
`fail2ban-client`. Le pays des IP est obtenu par `whois` (désactivable : `REPORT_GEOIP=no`).
Une IP débannie manuellement est retirée de la base par Fail2ban et n'apparaît donc plus
dans l'historique.

## Commandes utiles

```bash
fail2ban-client status sshd
fail2ban-client status sshd-recidive
fail2ban-client set sshd unbanip 1.2.3.4
fail2ban-client set sshd-recidive unbanip 1.2.3.4
fail2ban-regex /var/log/auth.log sshd    # tester un filtre
tail -f /var/log/fail2ban.log
```

## Dépannage

- **Emails non reçus** : `postqueue -p` affiche la raison du blocage ; beaucoup de relais
  exigent que l'expéditeur soit le compte authentifié (Gmail : mot de passe d'application).
- **Port SSH injoignable** : pensez au pare-feu de l'hébergeur (Security Group AWS/Azure/GCP,
  pare-feu réseau OVH, Scaleway, Hetzner…), le script ne gère que le pare-feu local.
- **Amazon Linux 2023** : pas d'EPEL officiel, Fail2ban peut y être indisponible.

## Tests

Tests d'intégration en conteneurs jetables (podman ou docker, systemd/OpenRC réels) :

```bash
tests/integration/run.sh            # Debian 13, Rocky 9, Alpine 3.22
tests/integration/run.sh debian13   # une seule distribution
```

Ils couvrent : refus hyperviseur et `--force-hypervisor`, installation non interactive,
Postfix TLS strict, `--no-report`, profil LAN/VPS et planification hebdo/mensuelle, mémoire
du rapport, retour arrière SSH (SIGKILL de l'installateur, coupure de session, confirmation,
mode non interactif) et restauration de la récidive.

Les scripts Python installés vivent dans `scripts/` (source de vérité, testables
directement) et sont **embarqués** dans `setup.sh`, qui reste un fichier unique autonome :

```bash
python3 -m unittest discover -s tests/unit -v   # tests unitaires du rapport (sans fail2ban)
scripts/embed.py            # recopie scripts/*.py dans setup.sh après modification
scripts/embed.py --check    # échoue si setup.sh n'est pas synchronisé
```

## Désinstallation

```bash
sudo ./setup.sh --uninstall
```

Supprime les fichiers générés (le paquet Fail2ban sur demande). Le port SSH, Postfix et le
pare-feu ne sont pas modifiés.
