#!/usr/bin/env python3
"""Synchronise les générateurs Python de scripts/ avec leur copie embarquée dans setup.sh.

setup.sh doit rester autonome (curl … | sudo bash) : il embarque le corps de chaque
script entre « cat <<'PYEOF' » et « PYEOF » dans sa fonction gen_*. La source de
vérité est scripts/<nom>.py ; seul ce qui suit la ligne EMBED_MARK est copié
(le shebang, l'en-tête et __version__ sont produits par setup.sh).

    scripts/embed.py           met à jour setup.sh
    scripts/embed.py --check   échoue (code 1) si setup.sh n'est pas synchronisé
    scripts/embed.py --extract (amorçage) recopie setup.sh → scripts/
"""
import argparse
import difflib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP = os.path.join(ROOT, "setup.sh")
EMBED_MARK = "# ==== corps embarqué dans setup.sh (ne rien mettre au-dessus) ===="
# fonction de setup.sh → fichier source
TARGETS = {
    "gen_report_script": "scripts/fail2ban-report.py",
    "gen_restore_script": "scripts/fail2ban-recidive-restore.py",
}
DEV_HEADER = '''#!/usr/bin/env python3
# Source de vérité : copié dans setup.sh par scripts/embed.py (voir --check).
__version__ = "dev"
'''


def block_re(func):
    return re.compile(r"(^{}\(\) \{{\n(?:.*\n)*?    cat <<'PYEOF'\n)((?:.*\n)*?)(^PYEOF\n)".format(
        re.escape(func)), re.M)


def body_of(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if EMBED_MARK not in text:
        sys.exit("{} : marqueur d'embarquement absent".format(path))
    return text.split(EMBED_MARK + "\n", 1)[1]


def main():
    parser = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--extract", action="store_true")
    args = parser.parse_args()

    with open(SETUP, encoding="utf-8") as fh:
        setup = fh.read()
    new, dirty = setup, []
    for func, rel in TARGETS.items():
        path = os.path.join(ROOT, rel)
        match = block_re(func).search(new)
        if not match:
            sys.exit("setup.sh : bloc PYEOF de {}() introuvable".format(func))
        if args.extract:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(DEV_HEADER + EMBED_MARK + "\n" + match.group(2))
            os.chmod(path, 0o755)
            print("extrait : {}() → {}".format(func, rel))
            continue
        body = body_of(path)
        if body != match.group(2):
            dirty.append(rel)
            if args.check:
                sys.stdout.writelines(difflib.unified_diff(
                    match.group(2).splitlines(True), body.splitlines(True),
                    "setup.sh:" + func, rel, n=1))
            new = new[:match.start(2)] + body + new[match.end(2):]
    if args.extract:
        return 0
    if args.check:
        if dirty:
            print("\nsetup.sh désynchronisé ({}) : lancez scripts/embed.py".format(", ".join(dirty)))
            return 1
        print("setup.sh synchronisé avec scripts/ ({} scripts)".format(len(TARGETS)))
        return 0
    if new != setup:
        with open(SETUP, "w", encoding="utf-8") as fh:
            fh.write(new)
        print("setup.sh mis à jour : " + ", ".join(dirty))
    else:
        print("setup.sh déjà synchronisé")
    return 0


if __name__ == "__main__":
    sys.exit(main())
