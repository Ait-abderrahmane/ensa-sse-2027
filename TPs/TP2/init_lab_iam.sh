#!/usr/bin/env bash
# =============================================================================
#  init_lab_iam.sh — Préparation de la VM du TP1, semaine 3
#  Cours « Sécurité des Systèmes d'Exploitation » — ENSA Agadir
#  Cible : AlmaLinux 9.x (RHEL 9 et dérivés)
#
#  Rejoue sur une VM NEUVE les 11 erreurs de configuration IAM accumulées par
#  « l'équipe précédente ». C'est l'état de départ du TP : le script
#  audi_iam.sh doit ensuite afficher 0/11, et l'étudiant corrige jusqu'à 11/11.
#
#  Toutes les modifications sont LOCALES et portent uniquement sur les comptes
#  et la configuration IAM. Aucun service réseau n'est ouvert, aucun accès
#  distant n'est créé : les comptes de démonstration reçoivent un mot de passe
#  aléatoire qui n'est affiché nulle part et n'est conservé nulle part.
#
#  ATTENTION : à n'exécuter que sur une VM de TP jetable, jamais sur une
#  machine de production ni sur un poste personnel.
#
#  Usage :
#    sudo bash init_lab_iam.sh            # demande une confirmation
#    sudo bash init_lab_iam.sh --yes      # sans confirmation
#    sudo bash init_lab_iam.sh --force    # ré-exécution (VM déjà préparée)
#    sudo bash init_lab_iam.sh --restore  # remet les fichiers sauvegardés
#  Code de sortie : 0 = VM prête, 1 = erreur, 2 = exécution impossible.
# =============================================================================

set -u
export LC_ALL=C

ROOT="${LAB_ROOT:-}"                       # racine alternative (tests hors VM)
STATE="$ROOT/root/labo_iam_s3"             # sauvegardes et marqueur
MARKER="$STATE/.prepare"
PASSWD="$ROOT/etc/passwd"
LOGINDEFS="$ROOT/etc/login.defs"
FAILLOCK_CONF="$ROOT/etc/security/faillock.conf"
PWQ_CONF="$ROOT/etc/security/pwquality.conf"

ASSUME_YES=0; FORCE=0; ACTION=prepare
for a in "$@"; do
  case "$a" in
    -y|--yes)   ASSUME_YES=1 ;;
    -f|--force) FORCE=1 ;;
    --restore)  ACTION=restore ;;
    -h|--help)  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# commandes shadow-utils, redirigées vers $ROOT pendant les tests
R=(); [ -n "$ROOT" ] && R=(--root "$ROOT")
has() { command -v "$1" >/dev/null 2>&1; }

[ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ] && die "à exécuter en root : sudo bash init_lab_iam.sh" 2
[ -r "$PASSWD" ] || die "lecture impossible de $PASSWD" 2
for c in useradd usermod groupadd chage chpasswd tar; do
  has "$c" || die "commande manquante : $c (paquet shadow-utils)" 2
done

user_exists()  { awk -F: -v u="$1" '$1==u {f=1} END{exit !f}' "$PASSWD"; }
group_exists() { awk -F: -v g="$1" '$1==g {f=1} END{exit !f}' "$ROOT/etc/group"; }
rand_pw()      { tr -dc 'A-Za-z0-9!@#%+=' < /dev/urandom 2>/dev/null | head -c 24 || echo "Lab-$RANDOM$RANDOM-S3"; }
# mot de passe aléatoire, jamais affiché ni conservé (le compte doit seulement
# apparaître « actif » : champ 2 de shadow rempli)
set_random_pw() {
  local u="$1" pw h=""
  pw=$(rand_pw)
  if printf '%s:%s\n' "$u" "$pw" | chpasswd "${R[@]}" 2>/dev/null; then return 0; fi
  has openssl && h=$(openssl passwd -6 "$pw" 2>/dev/null)
  if [ -n "$h" ] && usermod "${R[@]}" -p "$h" "$u" 2>/dev/null; then return 0; fi
  warn "mot de passe de $u non défini (chpasswd indisponible)"
}

# clé = valeur dans un fichier de configuration (ajoutée si absente)
set_conf() {  # fichier clé valeur
  local f="$1" k="$2" v="$3"
  [ -e "$f" ] || { mkdir -p "$(dirname "$f")"; : > "$f"; }
  if grep -Eq "^[[:space:]]*${k}[[:space:]]*=" "$f"; then
    sed -i -E "s|^[[:space:]]*${k}[[:space:]]*=.*|$k = $v|" "$f"
  else
    printf '%s = %s\n' "$k" "$v" >> "$f"
  fi
}
set_defs() {  # login.defs : CLE valeur
  local k="$1" v="$2"
  if grep -Eq "^[[:space:]]*${k}[[:space:]]+" "$LOGINDEFS"; then
    sed -i -E "s|^[[:space:]]*${k}[[:space:]]+.*|$k\t$v|" "$LOGINDEFS"
  else
    printf '%s\t%s\n' "$k" "$v" >> "$LOGINDEFS"
  fi
}

BACKUP_FILES=(etc/passwd etc/shadow etc/group etc/gshadow etc/login.defs
              etc/security/faillock.conf etc/security/pwquality.conf)

# ----------------------------------------------------------------- restauration
if [ "$ACTION" = restore ]; then
  last=$(find "$STATE" -maxdepth 1 -name 'backup-*.tar.gz' 2>/dev/null | sort | tail -n1)
  [ -n "$last" ] || die "aucune sauvegarde dans $STATE (restaurez le snapshot de la VM)"
  tar xzf "$last" -C "${ROOT:-/}" || die "restauration impossible"
  rm -f "$MARKER"
  step "OK" "fichiers restaurés depuis $last"
  warn "les comptes créés par le script ne sont pas supprimés (userdel -r si besoin)"
  exit 0
fi

# ----------------------------------------------------------------- garde-fous
cat <<EOF
==============================================================
 PRÉPARATION DE LA VM — TP1 semaine 3 (IAM)
==============================================================
 Ce script introduit volontairement 11 défauts de configuration
 IAM sur CETTE machine : permissions de /etc/shadow, entrée
 corrompue dans /etc/passwd, comptes de service avec shell,
 comptes mal gérés, groupes, vieillissement, PAM.

 À n'exécuter que sur la VM de TP (snapshot recommandé avant).
 Aucun accès distant n'est créé.
EOF
if [ -z "$ROOT" ]; then
  if ! grep -qiE 'almalinux|rhel|centos|rocky|fedora' "$ROOT/etc/os-release" 2>/dev/null; then
    warn "système non RHEL : le script est prévu pour AlmaLinux 9."
  fi
fi
if [ -e "$MARKER" ] && [ "$FORCE" -eq 0 ]; then
  die "VM déjà préparée le $(cat "$MARKER"). Relancer avec --force, ou repartir du snapshot."
fi
if [ "$ASSUME_YES" -eq 0 ]; then
  printf '\nTapez OUI pour préparer cette machine : '
  read -r ans
  [ "$ans" = "OUI" ] || die "annulé." 0
fi

# ----------------------------------------------------------------- sauvegarde
mkdir -p "$STATE"; chmod 0700 "$STATE"
STAMP=$(date +%Y%m%d-%H%M%S)
TARGET="$STATE/backup-$STAMP.tar.gz"
EXIST=()
for f in "${BACKUP_FILES[@]}"; do [ -e "${ROOT:-}/$f" ] && EXIST+=("$f"); done
if tar czf "$TARGET" -C "${ROOT:-/}" "${EXIST[@]}" 2>/dev/null; then
  step "00" "sauvegarde des fichiers d'origine : $TARGET"
else
  warn "sauvegarde incomplète : la remise en état passera par le snapshot"
fi

# ----------------------------------------------------------------- comptes du scénario
if ! group_exists devteam; then groupadd "${R[@]}" devteam; fi
if ! group_exists docker;  then groupadd "${R[@]}" docker;  fi

for u in alice bob_old contractor1 backup_ops; do
  if ! user_exists "$u"; then
    useradd "${R[@]}" -m -s /bin/bash "$u" >/dev/null 2>&1 || warn "création de $u incomplète"
    set_random_pw "$u"
  fi
done
usermod "${R[@]}" -c "Alice Dev"        alice       >/dev/null 2>&1
usermod "${R[@]}" -c "Bob (parti)"      bob_old     >/dev/null 2>&1
usermod "${R[@]}" -c "Prestataire"      contractor1 >/dev/null 2>&1
usermod "${R[@]}" -c "Operateur backup" backup_ops  >/dev/null 2>&1
step "--" "comptes du scénario : alice, bob_old, contractor1, backup_ops"

# =============================================================================
#  Les 11 défauts (numérotés comme les contrôles de audi_iam.sh)
# =============================================================================

# 01 — permissions de /etc/shadow (M1.1)
chmod 0644 "$ROOT/etc/shadow"
chown root:root "$ROOT/etc/shadow" 2>/dev/null
step "01" "/etc/shadow laissé en 0644 (lisible par tous)"

# 02 — entrée corrompue dans /etc/passwd (M1.2)
if ! awk -F: '$1=="ghost"' "$PASSWD" | grep -q .; then
  GID_FREE=$(awk -F: '$3>=1000 && $3<60000 {m=($3>m)?$3:m} END{print m+1}' "$PASSWD")
  printf 'ghost:x:%s:%s::/home/ghost\n' "$GID_FREE" "$GID_FREE" >> "$PASSWD"
fi
step "02" "entrée 'ghost' malformée ajoutée à /etc/passwd (6 champs au lieu de 7)"

# 03 — comptes de service avec shell interactif (M2.1)
for s in svc_app svc_report; do
  user_exists "$s" || useradd "${R[@]}" -r -M -d /var/lib/"$s" -s /bin/bash "$s" >/dev/null 2>&1
  usermod "${R[@]}" -s /bin/bash "$s" >/dev/null 2>&1
done
step "03" "comptes de service svc_app et svc_report dotés de /bin/bash"

# 04 — ancien collaborateur laissé actif (M2.2)
set_random_pw bob_old                                   # mot de passe non verrouillé
usermod "${R[@]}" -U bob_old >/dev/null 2>&1
usermod "${R[@]}" -s /bin/bash bob_old >/dev/null 2>&1
chage  "${R[@]}" -E -1 bob_old >/dev/null 2>&1          # aucune expiration
HOME_BOB=$(awk -F: '$1=="bob_old"{print $6}' "$PASSWD")
if [ -n "$HOME_BOB" ] && [ -d "$ROOT$HOME_BOB" ]; then
  printf 'notes de passation - ne pas supprimer\n' > "$ROOT$HOME_BOB/passation.txt"
  chown bob_old "$ROOT$HOME_BOB/passation.txt" 2>/dev/null
fi
step "04" "bob_old : compte actif, shell interactif, sans expiration (home conservé)"

# 05 — alice sort de devteam (M3.1) : l'erreur usermod -G sans -a
usermod "${R[@]}" -aG devteam alice >/dev/null 2>&1
usermod "${R[@]}" -G docker   alice >/dev/null 2>&1     # remplace la liste
if ! awk -F: '$1=="devteam"{print $4}' "$ROOT/etc/group" | grep -q 'bob_old'; then
  usermod "${R[@]}" -aG devteam bob_old >/dev/null 2>&1
fi
step "05" "alice retirée de devteam par un 'usermod -G docker' sans -a"

# 06 — intrus dans le groupe wheel (M3.2)
group_exists wheel || groupadd "${R[@]}" -g 10 wheel
usermod "${R[@]}" -aG wheel backup_ops >/dev/null 2>&1
step "06" "backup_ops ajouté au groupe wheel"

# 07 — prestataire sans date de fin (M4.1)
chage "${R[@]}" -E -1 contractor1 >/dev/null 2>&1
step "07" "contractor1 sans date d'expiration"

# 08 — politique de renouvellement absente (M4.2)
set_defs PASS_MAX_DAYS 99999
set_defs PASS_MIN_DAYS 0
set_defs PASS_WARN_AGE 7
step "08" "PASS_MAX_DAYS remis à 99999 dans /etc/login.defs"

# 09 — backup_ops : mot de passe jamais renouvelé (M4.3)
set_random_pw backup_ops
chage "${R[@]}" -d 2024-01-15 -M 99999 backup_ops >/dev/null 2>&1
step "09" "backup_ops : mot de passe inchangé depuis 2024, aucune rotation"

# 10 — faillock absent de la pile et seuil permissif (M5)
if [ -z "$ROOT" ] && has authselect; then
  if authselect current 2>/dev/null | grep -q 'with-faillock'; then
    authselect disable-feature with-faillock >/dev/null 2>&1 \
      && warn "feature authselect with-faillock désactivée"
  fi
fi
set_conf "$FAILLOCK_CONF" deny 10
set_conf "$FAILLOCK_CONF" fail_interval 900
set_conf "$FAILLOCK_CONF" unlock_time 600
step "10" "faillock hors de la pile PAM, deny = 10 (seuil trop permissif)"

# 11 — qualité des mots de passe affaiblie (M5)
set_conf "$PWQ_CONF" minlen 6
set_conf "$PWQ_CONF" minclass 1
step "11" "pwquality : minlen = 6, minclass = 1"

printf '%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" > "$MARKER"

# ----------------------------------------------------------------- vérifications
ADMIN=$(awk -F: '$3==1000 {print $1}' "$PASSWD")
if [ -z "$ADMIN" ]; then
  warn "aucun compte d'UID 1000 : lancez l'audit avec WHEEL_ALLOWED=\"votre_compte\"."
fi

echo
echo "=============================================================="
echo " VM préparée : 11 défauts en place."
echo " Sauvegarde  : $TARGET
 Remise en état : snapshot de la VM, ou bash init_lab_iam.sh --restore
 Les comptes créés ont un mot de passe aléatoire, ni affiché ni conservé."
echo "=============================================================="

DIR=$(cd "$(dirname "$0")" && pwd)
if [ -z "$ROOT" ] && [ -r "$DIR/audi_iam.sh" ]; then
  echo
  echo "--- Audit initial (audi_iam.sh) ---"
  bash "$DIR/audi_iam.sh"
  echo
  echo "Rapport initial disponible : /tmp/audit_report.txt"
else
  echo
  echo "Étape suivante : sudo bash ./audi_iam.sh   (11 [FAIL] attendus)"
fi
exit 0
