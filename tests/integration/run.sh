#!/bin/bash
# Lance les tests d'intégration dans des conteneurs jetables (podman ou docker).
#   tests/integration/run.sh [debian13|rocky9|alpine322 …]
# Chaque distribution : image construite depuis images/Containerfile.<nom>, conteneur
# avec init réel (systemd ou OpenRC), dépôt monté en lecture seule sur /src.
set -Euo pipefail
cd "$(dirname "$0")/../.." || exit 1
ENGINE=$(command -v podman || command -v docker) || { echo "podman ou docker requis" >&2; exit 1; }
DISTROS=("$@")
((${#DISTROS[@]})) || DISTROS=(debian13 rocky9 alpine322)
TESTS=(test_ssh_rollback.sh test_install.sh test_recidive_restore.sh)
failed=()

for d in "${DISTROS[@]}"; do
    img=f2b-test-$d name=f2b-test-$d-$$
    echo "════ ${d}"
    "$ENGINE" build -q -t "$img" -f "tests/integration/images/Containerfile.$d" tests/integration/images >/dev/null ||
        { failed+=("$d:build"); continue; }
    run_opts=(-d --name "$name" -v "$PWD:/src:ro,Z")
    [[ $d != alpine* && $(basename "$ENGINE") == podman ]] && run_opts+=(--systemd=always)
    "$ENGINE" run "${run_opts[@]}" "$img" >/dev/null || { failed+=("$d:run"); continue; }
    sleep 5
    for t in "${TESTS[@]}"; do
        # Le test de récidive pilote son propre fail2ban : arrêter le service installé
        if [[ $t == test_recidive_restore.sh ]]; then
            "$ENGINE" exec "$name" sh -c 'systemctl stop fail2ban 2>/dev/null || rc-service fail2ban stop 2>/dev/null; true' >/dev/null
        fi
        if "$ENGINE" exec "$name" timeout 600 bash "/src/tests/integration/$t" >"${TMPDIR:-/tmp}/$name-$t.log" 2>&1; then
            grep -E '^(OK|TOUS)' "${TMPDIR:-/tmp}/$name-$t.log"
        else
            grep -E '^(OK|ÉCHEC)' "${TMPDIR:-/tmp}/$name-$t.log"
            echo "  → journal : ${TMPDIR:-/tmp}/$name-$t.log"
            failed+=("$d:$t")
        fi
    done
    "$ENGINE" rm -f -t 1 "$name" >/dev/null
done

if ((${#failed[@]})); then
    echo "ÉCHECS : ${failed[*]}" >&2
    exit 1
fi
echo "Tous les tests sont passés (${DISTROS[*]})."
