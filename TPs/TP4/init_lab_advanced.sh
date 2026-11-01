#!/usr/bin/env bash
# TP4 - Preparation du laboratoire sudo, systemd et SELinux (AlmaLinux 9.8).
# ATTENTION : cette preparation installe volontairement une regle sudo dangereuse.
# VM de TP jetable avec snapshot uniquement. Ne jamais lancer en production.
# Usage : sudo bash init_lab_advanced.sh [--restore]
set -Eeuo pipefail
export LC_ALL=C

USER_TP=tp4demo
GROUP_TP=tp4ops
SUDO_FILE=/etc/sudoers.d/40-tp4ops
UNIT_FILE=/etc/systemd/system/tp4app.service
DROPIN_DIR=/etc/systemd/system/tp4app.service.d
STATE_DIR=/root/tp4_sse_lab
MARKER=$STATE_DIR/.initialized
APP_DIR=/var/lib/tp4app
LOG_DIR=/var/lib/tp4lab
WEB_DIR=/srv/tp4web
FCONTEXT='/srv/tp4web(/.*)?'

say() { printf '[TP4] %s\n' "$*"; }
die() { printf '[ERREUR] %s\n' "$*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "Commande absente : $1"; }

[[ $(id -u) -eq 0 ]] || die 'Executer avec sudo sur la VM de TP.'
[[ $# -le 1 ]] || die 'Usage : init_lab_advanced.sh [--restore]'

if [[ ${1:-} == --restore ]]; then
  [[ -f $MARKER ]] || die 'Aucun marqueur TP4 : nettoyage refuse.'
  say 'Suppression des objets reserves au TP4...'
  systemctl stop tp4app.service >/dev/null 2>&1 || true
  rm -f -- "$SUDO_FILE" "$UNIT_FILE"
  rm -rf -- "$DROPIN_DIR"
  systemctl daemon-reload >/dev/null 2>&1 || true
  if command -v semanage >/dev/null 2>&1; then
    if semanage fcontext -l -C 2>/dev/null | grep -Fq -- "$FCONTEXT"; then
      semanage fcontext -d "$FCONTEXT" || say 'Verifier manuellement le retrait de la regle fcontext.'
    fi
  fi
  rm -rf -- "$APP_DIR" "$LOG_DIR" "$WEB_DIR"
  if id "$USER_TP" >/dev/null 2>&1; then
    userdel -r "$USER_TP" >/dev/null 2>&1 || say "Suppression de $USER_TP incomplete."
  fi
  if getent group "$GROUP_TP" >/dev/null 2>&1; then
    groupdel "$GROUP_TP" >/dev/null 2>&1 || say "Suppression de $GROUP_TP incomplete."
  fi
  rm -f -- "$MARKER"
  rmdir "$STATE_DIR" >/dev/null 2>&1 || true
  say 'Nettoyage termine. Le snapshot reste la solution de restauration privilegiee.'
  exit 0
fi
[[ $# -eq 0 ]] || die 'Option inconnue (seule option : --restore).'

for cmd in sudo visudo less systemctl semanage restorecon chcon getenforce useradd userdel groupadd groupdel; do
  need "$cmd"
done
[[ $(getenforce) == Enforcing ]] || die 'SELinux doit etre Enforcing (verifier getenforce).'
[[ ! -e $MARKER ]] || die 'TP4 deja initialise. Restaurer le snapshot ou utiliser --restore.'
for p in "$SUDO_FILE" "$UNIT_FILE" "$DROPIN_DIR" "$APP_DIR" "$LOG_DIR" "$WEB_DIR"; do
  [[ ! -e $p ]] || die "Objet deja present (aucun ecrasement) : $p"
done
id "$USER_TP" >/dev/null 2>&1 && die "Compte deja present : $USER_TP"
getent group "$GROUP_TP" >/dev/null 2>&1 && die "Groupe deja present : $GROUP_TP"
[[ -x /usr/bin/less && -x /usr/bin/systemctl ]] || die 'Binaires less et systemctl absents.'
[[ -d /etc/sudoers.d ]] || die '/etc/sudoers.d absent.'
if semanage fcontext -l -C | grep -Fq -- "$FCONTEXT"; then
  die 'Une regle fcontext existante cible deja /srv/tp4web : laboratoire refuse.'
fi

cat <<'WARNING'
==================================================================
 TP4 - LABORATOIRE VULNERABLE : SUDO / SYSTEMD / SELINUX
 Cette operation cree une delegation sudo DANGEREUSE pour tp4demo.
 VM isolee et snapshot obligatoires. Aucun service reseau ajoute.
 Les objets TP3 (myapp, webops, etc.) ne sont pas modifies.
==================================================================
WARNING
printf 'Tapez OUI pour preparer la VM : '
read -r confirmation
[[ $confirmation == OUI ]] || { say 'Annule.'; exit 0; }

# Marqueur AVANT les modifications pour permettre --restore apres echec partiel.
mkdir -p -m 0700 "$STATE_DIR"
printf 'Date: %s\n' "$(date -Is)" > "$MARKER"
chmod 0600 "$MARKER"

groupadd "$GROUP_TP"
useradd -m -s /sbin/nologin -G "$GROUP_TP" "$USER_TP"
passwd -l "$USER_TP" >/dev/null 2>&1 || true
install -d -m 0755 "$LOG_DIR"
printf 'Journal fictif : laboratoire TP4\n' > "$LOG_DIR/events.log"
chmod 0640 "$LOG_DIR/events.log"

# Defauts 01-02 : pager interactif root + wildcard systemctl.
cat > "$SUDO_FILE" <<'SUDOERS'
Defaults:%tp4ops use_pty
%tp4ops ALL=(root) NOPASSWD: /usr/bin/less /var/lib/tp4lab/events.log, /usr/bin/systemctl *
SUDOERS
chmod 0440 "$SUDO_FILE"
visudo -cf /etc/sudoers >/dev/null || die 'Erreur sudoers. Utiliser --restore.'
say '[01-02] Sudoers volontairement trop permissif : less et systemctl *.'

# Defauts 03-05 : service sans confinement, mais isolé des TP precedents.
install -d -m 0750 -o "$USER_TP" -g "$GROUP_TP" "$APP_DIR"
cat > "$UNIT_FILE" <<'UNIT'
[Unit]
Description=TP4 - Service fictif pour les essais de confinement

[Service]
Type=oneshot
RemainAfterExit=yes
User=tp4demo
Group=tp4ops
ExecStart=/usr/bin/sh -c 'echo TP4-OK > /var/lib/tp4app/probe.txt'
UNIT
chmod 0644 "$UNIT_FILE"
systemctl daemon-reload
systemctl restart tp4app.service || die 'tp4app ne demarre pas : voir systemctl status tp4app.'
say '[03-05] tp4app.service sans NoNewPrivileges, PrivateTmp ni ProtectSystem.'

# Defauts 06-08 : etiquettes de demonstration incorrectes, sans toucher a la politique globale.
install -d -m 0755 "$WEB_DIR"
printf 'Page de demonstration TP4\n' > "$WEB_DIR/index.html"
chmod 0644 "$WEB_DIR/index.html"
restorecon -R "$WEB_DIR" >/dev/null 2>&1 || true
chcon -R -t user_home_t "$WEB_DIR" || die 'Impossible de poser le type SELinux incorrect.'
say '[06-08] Repertoire et fichier mal etiquetes, aucune regle fcontext locale.'

say 'Preparation terminee. Attendu : score initial 0/8.'
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ -f $SCRIPT_DIR/audit_advanced.sh ]]; then
  bash "$SCRIPT_DIR/audit_advanced.sh" || true
else
  say 'Executer ensuite : sudo bash ./audit_advanced.sh'
fi
