#!/usr/bin/env bash
# =============================================================================
#  init_lab_perms.sh — Préparation de la VM du TP2 (partie 1), semaine 4
#  Cours « Sécurité des Systèmes d'Exploitation » — ENSA Agadir
#  Cible : AlmaLinux 9.x (RHEL 9 et dérivés)
#
#  Installe sur une VM NEUVE les 7 défauts de permissions du scénario
#  (dossier partagé sans SGID, sticky bit absent, service sans UMask, ACL
#  cachée, masque restrictif, binaires SUID inutiles, serveur en SUID root).
#  C'est l'état de départ du TP : audit_perms.sh doit ensuite afficher 0/8,
#  et l'étudiant corrige jusqu'à 8/8.
#
#  Les modifications sont LOCALES et limitées à des fichiers de démonstration
#  sous /srv, /shared, /opt/legacy, /usr/local/bin et /var/lib/myapp. Les
#  « binaires SUID » sont des copies inoffensives de /usr/bin/true et de
#  /usr/bin/sleep. Aucun service réseau n'est ouvert, aucun accès distant
#  n'est créé, les comptes de démonstration n'ont pas de mot de passe.
#
#  ATTENTION : à n'exécuter que sur une VM de TP jetable, jamais sur une
#  machine de production ni sur un poste personnel.
#
#  Usage :
#    sudo bash init_lab_perms.sh            # demande une confirmation
#    sudo bash init_lab_perms.sh --yes      # sans confirmation
#    sudo bash init_lab_perms.sh --force    # ré-exécution (VM déjà préparée)
#    sudo bash init_lab_perms.sh --restore  # supprime tout ce que le script a créé
#  Code de sortie : 0 = VM prête, 1 = erreur, 2 = exécution impossible.
# =============================================================================

set -u
export LC_ALL=C

ROOT="${LAB_ROOT:-}"                       # racine alternative (tests hors VM)
STATE="$ROOT/root/labo_perms_s4"           # marqueur
MARKER="$STATE/.prepare"
PASSWD="$ROOT/etc/passwd"
GROUPF="$ROOT/etc/group"

TEAM_GROUP="webops"
LAB_USERS=(ana bilal stagiaire)

ASSUME_YES=0; FORCE=0; ACTION=prepare
for a in "$@"; do
  case "$a" in
    -y|--yes)   ASSUME_YES=1 ;;
    -f|--force) FORCE=1 ;;
    --restore)  ACTION=restore ;;
    -h|--help)  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Option inconnue : $a (voir --help)" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  C_OK=$'\e[32m'; C_KO=$'\e[31m'; C_W=$'\e[33m'; C_0=$'\e[0m'
else
  C_OK=""; C_KO=""; C_W=""; C_0=""
fi
step() { printf '%s[%s]%s %s\n' "$C_OK" "$1" "$C_0" "$2"; }
warn() { printf '%s[!]%s %s\n' "$C_W" "$C_0" "$1"; }
die()  { printf '%s[x]%s %s\n' "$C_KO" "$C_0" "$1" >&2; exit "${2:-1}"; }

R=(); [ -n "$ROOT" ] && R=(--root "$ROOT")
has() { command -v "$1" >/dev/null 2>&1; }

[ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ] && die "à exécuter en root : sudo bash init_lab_perms.sh" 2
[ -r "$PASSWD" ] || die "lecture impossible de $PASSWD" 2
for c in useradd userdel groupadd groupdel setfacl getfacl chmod chown cp install; do
  has "$c" || die "commande manquante : $c (paquets shadow-utils, acl, coreutils)" 2
done
has setcap || warn "setcap absent (paquet libcap) : nécessaire pour la mission 3"

user_exists()  { awk -F: -v u="$1" '$1==u {f=1} END{exit !f}' "$PASSWD"; }
group_exists() { awk -F: -v g="$1" '$1==g {f=1} END{exit !f}' "$GROUPF"; }
uid_of() { awk -F: -v u="$1" '$1==u {print $3}' "$PASSWD"; }
gid_of() { awk -F: -v g="$1" '$1==g {print $3}' "$GROUPF"; }
# chown résolu depuis $ROOT (numérique : fonctionne aussi dans l'arborescence de test)
own() { chown "$(uid_of "$1"):$(gid_of "$2")" "${@:3}"; }
live() { [ -z "$ROOT" ] && has systemctl; }

LAB_FILES=("$ROOT/srv/teamshare" "$ROOT/shared" "$ROOT/srv/secure" "$ROOT/srv/app"
           "$ROOT/opt/legacy" "$ROOT/usr/local/bin/legacy-helper" "$ROOT/usr/local/bin/myserver"
           "$ROOT/var/lib/myapp" "$ROOT/etc/systemd/system/myapp.service"
           "$ROOT/etc/systemd/system/myserver.service")

# ----------------------------------------------------------------- remise à zéro
if [ "$ACTION" = restore ]; then
  if live; then
    systemctl stop myapp myserver >/dev/null 2>&1
  fi
  rm -rf -- "${LAB_FILES[@]}" "$ROOT/etc/systemd/system/myapp.service.d"
  live && systemctl daemon-reload >/dev/null 2>&1
  for u in "${LAB_USERS[@]}"; do
    user_exists "$u" && userdel "${R[@]}" -r "$u" >/dev/null 2>&1
  done
  group_exists "$TEAM_GROUP" && groupdel "${R[@]}" "$TEAM_GROUP" >/dev/null 2>&1
  rm -f "$MARKER"
  step "OK" "objets de démonstration, comptes ${LAB_USERS[*]} et groupe $TEAM_GROUP supprimés"
  exit 0
fi

# ----------------------------------------------------------------- garde-fous
cat <<EOF
==============================================================
 PRÉPARATION DE LA VM — TP2 (partie 1), semaine 4
==============================================================
 Ce script introduit volontairement 7 défauts de permissions
 sur CETTE machine : dossier partagé, sticky bit, UMask d'un
 service, ACL cachée, masque ACL, binaires SUID inutiles et
 serveur en SUID root.

 Fichiers de démonstration uniquement (/srv, /shared, /opt/legacy,
 /usr/local/bin). À n'exécuter que sur la VM de TP (snapshot
 recommandé avant). Aucun accès distant n'est créé.
EOF
if [ -z "$ROOT" ]; then
  if ! grep -qiE 'almalinux|rhel|centos|rocky|fedora' "$ROOT/etc/os-release" 2>/dev/null; then
    warn "système non RHEL : le script est prévu pour AlmaLinux 9."
  fi
fi
if [ -e "$MARKER" ] && [ "$FORCE" -eq 0 ]; then
  die "VM déjà préparée le $(cat "$MARKER"). Relancer avec --force, ou --restore, ou repartir du snapshot."
fi
if [ "$ASSUME_YES" -eq 0 ]; then
  printf '\nTapez OUI pour préparer cette machine : '
  read -r ans
  [ "$ans" = "OUI" ] || die "annulé." 0
fi
mkdir -p "$STATE"; chmod 0700 "$STATE"

# ----------------------------------------------------------------- comptes du scénario
group_exists "$TEAM_GROUP" || groupadd "${R[@]}" "$TEAM_GROUP"
for u in "${LAB_USERS[@]}"; do
  user_exists "$u" || useradd "${R[@]}" -m -s /bin/bash "$u" >/dev/null 2>&1 || warn "création de $u incomplète"
done
usermod "${R[@]}" -aG "$TEAM_GROUP" ana   >/dev/null 2>&1
usermod "${R[@]}" -aG "$TEAM_GROUP" bilal >/dev/null 2>&1
step "--" "comptes du scénario : ana et bilal (groupe $TEAM_GROUP), stagiaire (sans groupe)"

# =============================================================================
#  Les 7 défauts (numérotés comme les contrôles de audit_perms.sh)
# =============================================================================

# 01 — dossier partagé sans SGID (M1.1) ; 03 est le service (M1.3)
mkdir -p "$ROOT/srv/teamshare"
own root "$TEAM_GROUP" "$ROOT/srv/teamshare"
chmod 0770 "$ROOT/srv/teamshare"
step "01" "/srv/teamshare en 0770, sans SGID : les fichiers prennent le groupe de leur auteur"

# 02 — dossier world-writable sans sticky bit (M1.2)
mkdir -p "$ROOT/shared/tmp"
chmod 0755 "$ROOT/shared"
chmod 0777 "$ROOT/shared/tmp"
step "02" "/shared/tmp en 0777, sans sticky bit"

# 03 — service sans UMask (M1.3)
mkdir -p "$ROOT/etc/systemd/system" "$ROOT/var/lib/myapp"
cat > "$ROOT/etc/systemd/system/myapp.service" <<'EOF'
[Unit]
Description=Application de demonstration (TP securite, semaine 4)

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'rm -f /var/lib/myapp/out.txt && touch /var/lib/myapp/out.txt'
EOF
if live; then
  systemctl daemon-reload >/dev/null 2>&1
  systemctl restart myapp >/dev/null 2>&1 || warn "démarrage de myapp impossible (vérifier : systemctl status myapp)"
fi
step "03" "myapp.service sans directive UMask : fichiers créés en 0644"

# 04 — ACL cachée sur un fichier sensible (M2.1)
mkdir -p "$ROOT/srv/secure"
printf 'donnees confidentielles (TP)\n' > "$ROOT/srv/secure/fichier_sensible"
chmod 0755 "$ROOT/srv/secure"
chmod 0640 "$ROOT/srv/secure/fichier_sensible"
own root root "$ROOT/srv/secure/fichier_sensible"
setfacl -m "u:$(uid_of stagiaire):rwx" "$ROOT/srv/secure/fichier_sensible" 2>/dev/null \
  || warn "ACL non posée sur fichier_sensible (système de fichiers sans ACL ?)"
step "04" "fichier_sensible : mode 0640 mais ACL cachée donnant rwx à stagiaire"

# 05 — masque ACL restrictif (M2.2)
mkdir -p "$ROOT/srv/app"
chmod 0755 "$ROOT/srv/app"
printf '#!/bin/sh\necho "release en cours"\n' > "$ROOT/srv/app/release.sh"
own root root "$ROOT/srv/app/release.sh"
chmod 0750 "$ROOT/srv/app/release.sh"
setfacl -m "g:$(gid_of "$TEAM_GROUP"):rwx" "$ROOT/srv/app/release.sh" 2>/dev/null
setfacl -m m::r "$ROOT/srv/app/release.sh" 2>/dev/null \
  || warn "ACL non posée sur release.sh (système de fichiers sans ACL ?)"
step "05" "release.sh : group:$TEAM_GROUP:rwx mais mask::r-- (droits effectifs : r--)"

# 06 — binaires SUID inutiles (M3.1)
mkdir -p "$ROOT/usr/local/bin" "$ROOT/opt/legacy"
for b in "$ROOT/usr/local/bin/legacy-helper" "$ROOT/opt/legacy/old-report-gen"; do
  install -m 0755 -o root -g root "$ROOT/usr/bin/true" "$b" 2>/dev/null || cp "$ROOT/usr/bin/true" "$b"
  chmod 4755 "$b"
done
step "06" "legacy-helper et old-report-gen : copies de /usr/bin/true en SUID root (4755)"

# 07 — serveur en SUID root au lieu d'une capability (M3.2)
install -m 0755 -o root -g root "$ROOT/usr/bin/sleep" "$ROOT/usr/local/bin/myserver" 2>/dev/null \
  || cp "$ROOT/usr/bin/sleep" "$ROOT/usr/local/bin/myserver"
chmod 4755 "$ROOT/usr/local/bin/myserver"
cat > "$ROOT/etc/systemd/system/myserver.service" <<'EOF'
[Unit]
Description=Serveur de demonstration (TP securite, semaine 4)

[Service]
User=nobody
ExecStart=/usr/local/bin/myserver infinity
EOF
if live; then
  systemctl daemon-reload >/dev/null 2>&1
  systemctl restart myserver >/dev/null 2>&1 || warn "démarrage de myserver impossible (vérifier : systemctl status myserver)"
fi
step "07" "myserver : copie de /usr/bin/sleep en SUID root, lancée par myserver.service"

printf '%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" > "$MARKER"

# ----------------------------------------------------------------- fin
echo
echo "=============================================================="
echo " VM préparée : 7 défauts en place."
echo " Remise en état : snapshot de la VM, ou bash init_lab_perms.sh --restore"
echo " Les comptes ana, bilal et stagiaire n'ont pas de mot de passe :"
echo " utilisez sudo -u <compte> pour tester."
echo "=============================================================="

DIR=$(cd "$(dirname "$0")" && pwd)
if [ -z "$ROOT" ] && [ -r "$DIR/audit_perms.sh" ]; then
  echo
  echo "--- Audit initial (audit_perms.sh) ---"
  bash "$DIR/audit_perms.sh"
  echo
  echo "Rapport initial disponible : /tmp/audit_report_v2.txt"
else
  echo
  echo "Étape suivante : sudo bash ./audit_perms.sh   (8 [FAIL] attendus)"
fi
exit 0
