#!/usr/bin/env bash
# TP4 - Audit lecture seule des 8 controles sudo / systemd / SELinux.
# Usage : sudo bash audit_advanced.sh
# Sortie : 0 = 8/8 ; 1 = controle(s) non valide(s) ; 2 = erreur d'execution.
set -Eeuo pipefail
export LC_ALL=C

REPORT=/tmp/audit_report_tp4.txt
USER_TP=tp4demo
SUDO_FILE=/etc/sudoers.d/40-tp4ops
APP_UNIT=tp4app.service
WEB_DIR=/srv/tp4web
FCONTEXT='/srv/tp4web(/.*)?'
TOTAL=8
PASSED=0
FAILED=()
BODY=''

say() { BODY+="$1"$'\n'; printf '%s\n' "$1"; }
check() {
  local id=$1 mission=$2 title=$3 status=$4 details=$5
  if [[ $status == PASS ]]; then
    PASSED=$((PASSED + 1))
  else
    FAILED+=("$id")
  fi
  say "[$status] $id $mission -- $title"
  say "        -> $details"
}
fail_preflight() { printf '[ERREUR] %s\n' "$*" >&2; exit 2; }
require() { command -v "$1" >/dev/null 2>&1 || fail_preflight "Commande absente : $1"; }

[[ $(id -u) -eq 0 ]] || fail_preflight 'Lancer avec sudo.'
for command_name in sudo visudo systemctl semanage getenforce stat sha256sum; do
  require "$command_name"
done
[[ -f /root/tp4_sse_lab/.initialized ]] || fail_preflight 'Executer d abord init_lab_advanced.sh.'
[[ -f $SUDO_FILE && -f /etc/systemd/system/tp4app.service && -d $WEB_DIR ]] \
  || fail_preflight 'Objets TP4 absents ou supprimes.'
visudo -cf /etc/sudoers >/dev/null 2>&1 || fail_preflight 'Configuration sudoers invalide.'
[[ $(getenforce) == Enforcing ]] || fail_preflight 'SELinux doit rester en mode Enforcing.'

say '============================================================'
say ' AUDIT TP4 -- sudo, systemd, SELinux'
say '============================================================'
say " Date       : $(date '+%F %T %Z')"
say " Machine    : $(hostname)"
say " Operateur  : ${SUDO_USER:-root}"
say '------------------------------------------------------------'

# 01 : aucune autorisation de lancer le pager interactif en root.
if sudo -u "$USER_TP" sudo -n -l /usr/bin/less /var/lib/tp4lab/events.log >/dev/null 2>&1; then
  check 01 M4.1 'Pager root dangereux retire' FAIL 'tp4demo peut encore executer sudo less.'
else
  check 01 M4.1 'Pager root dangereux retire' PASS 'sudo less refuse.'
fi

# 02 : delegation UNIQUE de systemctl status, sans restart ni wildcard.
# Eviter de valider une configuration qui autorise aussi des commandes non testees.
expected_sudo_rule='%tp4ops ALL=(root) NOPASSWD: /usr/bin/systemctl status tp4app.service --no-pager'
real_sudo_rules=$(grep -Ev '^[[:space:]]*(#|$|Defaults:)' "$SUDO_FILE" || true)
if [[ $real_sudo_rules == "$expected_sudo_rule" ]] \
   && sudo -u "$USER_TP" sudo -n -l /usr/bin/systemctl status tp4app.service --no-pager >/dev/null 2>&1 \
   && ! sudo -u "$USER_TP" sudo -n -l /usr/bin/systemctl restart tp4app.service >/dev/null 2>&1 \
   && ! sudo -u "$USER_TP" sudo -n -l /usr/bin/systemctl status sshd.service --no-pager >/dev/null 2>&1 \
   && ! sudo -u "$USER_TP" sudo -n -l /usr/bin/systemctl status tp4app.service >/dev/null 2>&1 \
   && ! sudo -u "$USER_TP" sudo -n -l /usr/bin/sh >/dev/null 2>&1; then
  check 02 M4.2 'Delegation systemctl strictement limitee' PASS 'status tp4app --no-pager autorise ; restart et autres commandes refuses.'
else
  check 02 M4.2 'Delegation systemctl strictement limitee' FAIL 'Regle attendue : status tp4app.service --no-pager, et aucune autre commande.'
fi

# 03 : interdiction de privilege escalation via exec.
nnp=$(systemctl show "$APP_UNIT" --value -p NoNewPrivileges 2>/dev/null || true)
if [[ $nnp == yes ]]; then
  check 03 M5.1 'NoNewPrivileges' PASS 'NoNewPrivileges=yes'
else
  check 03 M5.1 'NoNewPrivileges' FAIL "Valeur actuelle : ${nnp:-absente} (attendu yes)."
fi

# 04 : isolement temporaire du service.
privtmp=$(systemctl show "$APP_UNIT" --value -p PrivateTmp 2>/dev/null || true)
if [[ $privtmp == yes ]]; then
  check 04 M5.2 'PrivateTmp' PASS 'PrivateTmp=yes'
else
  check 04 M5.2 'PrivateTmp' FAIL "Valeur actuelle : ${privtmp:-absente} (attendu yes)."
fi

# 05 : OS en lecture seule + exception explicite + service fonctionnel.
protect=$(systemctl show "$APP_UNIT" --value -p ProtectSystem 2>/dev/null || true)
rwpaths=$(systemctl show "$APP_UNIT" --value -p ReadWritePaths 2>/dev/null || true)
active=$(systemctl is-active "$APP_UNIT" 2>/dev/null || true)
if [[ $protect == strict && $rwpaths == /var/lib/tp4app \
   && $active == active && -f /var/lib/tp4app/probe.txt ]]; then
  check 05 M5.3 'ProtectSystem strict + exception d ecriture' PASS 'ProtectSystem=strict, ReadWritePaths=/var/lib/tp4app, service actif.'
else
  check 05 M5.3 'ProtectSystem strict + exception d ecriture' FAIL \
    "ProtectSystem=${protect:-absent}; ReadWritePaths=${rwpaths:-absent}; service=${active:-inconnu}."
fi

# 06-07 : types SELinux effectifs pour repertoire et document.
sel_type() { stat -c %C -- "$1" 2>/dev/null || true; }
directory_type=$(sel_type "$WEB_DIR")
file_type=$(sel_type "$WEB_DIR/index.html")
if [[ $directory_type == *:httpd_sys_content_t:* ]]; then
  check 06 M6.1 'Repertoire avec label web' PASS "$directory_type"
else
  check 06 M6.1 'Repertoire avec label web' FAIL "${directory_type:-label absent} (attendu httpd_sys_content_t)."
fi
if [[ $file_type == *:httpd_sys_content_t:* ]]; then
  check 07 M6.2 'Fichier avec label web' PASS "$file_type"
else
  check 07 M6.2 'Fichier avec label web' FAIL "${file_type:-label absent} (attendu httpd_sys_content_t)."
fi

# 08 : regle fcontext persistante, pas seulement chcon.
local_rules=$(semanage fcontext -l -C 2>/dev/null || true)
if printf '%s\n' "$local_rules" | grep -F -- "$FCONTEXT" | grep -q 'httpd_sys_content_t'; then
  check 08 M6.3 'Regle fcontext locale persistante' PASS "$FCONTEXT -> httpd_sys_content_t"
else
  check 08 M6.3 'Regle fcontext locale persistante' FAIL 'Aucune regle fcontext locale pour /srv/tp4web(/.*)?.'
fi

say ''
say "SELinux    : $(getenforce) (information non notee, Enforcing requis pour le TP)"
say '------------------------------------------------------------'
pct=$((PASSED * 100 / TOTAL))
say " Score de conformite TP4 : $PASSED/$TOTAL ($pct %)"
if (( PASSED == TOTAL )); then
  say ' Verdict : [EXCELLENT]'
elif (( pct >= 70 )); then
  say " Verdict : [PARTIEL] echecs : ${FAILED[*]}"
else
  say " Verdict : [CRITIQUE] echecs : ${FAILED[*]}"
fi
fingerprint=$(printf '%s' "$BODY" | sha256sum | cut -c1-16)
say " Empreinte du rapport : $fingerprint"
say '============================================================'

if [[ -e $REPORT ]]; then
  cp -p -- "$REPORT" "$REPORT.$(date '+%Y%m%d-%H%M%S')" || fail_preflight 'Sauvegarde du rapport precedent impossible.'
fi
if ! printf '%s' "$BODY" > "$REPORT"; then
  fail_preflight "Ecriture du rapport impossible : $REPORT"
fi
chmod 0644 "$REPORT" || fail_preflight 'chmod du rapport impossible.'
printf '\nRapport : %s\n' "$REPORT"
(( PASSED == TOTAL )) && exit 0
exit 1
