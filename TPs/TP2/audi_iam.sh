#!/usr/bin/env bash
# =============================================================================
#  audi_iam.sh — Audit IAM, semaine 3 (TP1 : Incident Response & Durcissement IAM)
#  Cours « Sécurité des Systèmes d'Exploitation » — ENSA Agadir
#  Cible : AlmaLinux 9.x (RHEL 9 et dérivés)
#
#  Vérifie les 11 contrôles des missions 1 à 5 du TP et écrit le rapport dans
#  /tmp/audit_report.txt (l'ancien rapport est conservé avec un horodatage).
#  Le script est en LECTURE SEULE : il ne modifie jamais le système audité.
#
#  Usage   : sudo bash audi_iam.sh
#  Réglages (variables d'environnement, facultatives) :
#    WHEEL_ALLOWED="admin ops"   comptes autorisés dans wheel
#                                (défaut : le premier compte humain, UID = UID_MIN)
#    SVC_SHELL_ALLOWED="postgres" comptes système autorisés à garder un shell
#    AUDIT_REPORT=/chemin        fichier de rapport (défaut /tmp/audit_report.txt)
#    AUDIT_ROOT=/chemin          racine alternative (tests hors VM uniquement)
#  Code de sortie : 0 = 11/11, 1 = au moins un échec, 2 = exécution impossible.
# =============================================================================

set -u
export LC_ALL=C

ROOT="${AUDIT_ROOT:-}"
REPORT="${AUDIT_REPORT:-/tmp/audit_report.txt}"
PASSWD="$ROOT/etc/passwd"
SHADOW="$ROOT/etc/shadow"
GROUP="$ROOT/etc/group"
LOGINDEFS="$ROOT/etc/login.defs"
SHELLS="$ROOT/etc/shells"
PAMDIR="$ROOT/etc/pam.d"
FAILLOCK_CONF="$ROOT/etc/security/faillock.conf"
PWQ_CONF="$ROOT/etc/security/pwquality.conf"
PWQ_DIR="$ROOT/etc/security/pwquality.conf.d"

# Comptes du scénario (VM compromise du TP)
OLD_USER="bob_old"
DEV_USER="alice";  DEV_GROUP="devteam"
CONTRACTOR="contractor1"
BACKUP_USER="backup_ops"
MAX_DAYS_POLICY=90
MINLEN_POLICY=12
DENY_MAX=5

TOTAL=11
PASSED=0
FAILED_IDS=()
BODY=""

# ----------------------------------------------------------------- affichage
if [ -t 1 ]; then
  C_OK=$'\e[32m'; C_KO=$'\e[31m'; C_IN=$'\e[36m'; C_B=$'\e[1m'; C_0=$'\e[0m'
else
  C_OK=""; C_KO=""; C_IN=""; C_B=""; C_0=""
fi

out()  { BODY+="$1"$'\n'; printf '%s\n' "$2"; }        # $1 texte brut, $2 texte coloré
line() { out "$1" "$1"; }

result() {   # result ID MISSION TITRE STATUT DETAIL
  local id="$1" mission="$2" title="$3" status="$4" detail="$5"
  if [ "$status" = PASS ]; then
    PASSED=$((PASSED + 1))
    out "[PASS] $id  $mission  $title" "${C_OK}[PASS]${C_0} $id  $mission  $title"
  else
    FAILED_IDS+=("$id")
    out "[FAIL] $id  $mission  $title" "${C_KO}${C_B}[FAIL]${C_0} $id  $mission  $title"
  fi
  while IFS= read -r d; do
    [ -n "$d" ] && out "         -> $d" "         -> $d"
  done <<< "$detail"
}

info() { out "[INFO] $1" "${C_IN}[INFO]${C_0} $1"; }

# ----------------------------------------------------------------- utilitaires
today_days() { echo $(( $(date +%s) / 86400 )); }
eoy_days()   { echo $(( $(date -u -d "$(date +%Y)-12-31" +%s) / 86400 )); }
days2date()  { date -u -d "@$(( $1 * 86400 ))" +%Y-%m-%d; }

# dernière valeur d'une clé « CLE valeur » (login.defs)
defs_get() { awk -v k="$1" '$1==k {v=$2} END{print v}' "$LOGINDEFS" 2>/dev/null; }

# dernière valeur d'une clé « cle = valeur » dans un ou plusieurs fichiers
conf_get() {
  local key="$1"; shift
  local f v=""
  for f in "$@"; do
    [ -r "$f" ] || continue
    local x
    x=$(sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*\([0-9-]*\).*/\1/p" "$f" | tail -n1)
    [ -n "$x" ] && v="$x"
  done
  echo "$v"
}

# lignes PAM actives (sans commentaires) d'un fichier
pam_active() { [ -r "$1" ] && grep -Ev '^[[:space:]]*(#|$)' "$1"; }

shadow_field() {  # utilisateur, numéro de champ
  awk -F: -v u="$1" -v n="$2" '$1==u {print $n; found=1} END{exit !found}' "$SHADOW"
}
user_exists() { awk -F: -v u="$1" '$1==u {f=1} END{exit !f}' "$PASSWD"; }
passwd_field() { awk -F: -v u="$1" -v n="$2" '$1==u {print $n}' "$PASSWD"; }

is_interactive_shell() {
  local s="$1"
  case "$s" in
    */nologin|*/false|"") return 1 ;;
  esac
  if [ -r "$SHELLS" ]; then
    grep -qxF "$s" "$SHELLS" && return 0
  fi
  case "$s" in
    */bash|*/sh|*/zsh|*/ksh|*/csh|*/tcsh|*/fish|*/dash) return 0 ;;
  esac
  return 1
}

# membres d'un groupe : liste secondaire + comptes dont c'est le groupe primaire
group_members() {
  local g="$1" gid
  gid=$(awk -F: -v g="$g" '$1==g {print $3}' "$GROUP")
  {
    awk -F: -v g="$g" '$1==g {n=split($4,a,","); for(i=1;i<=n;i++) if(a[i]!="") print a[i]}' "$GROUP"
    [ -n "$gid" ] && awk -F: -v gid="$gid" '$4==gid {print $1}' "$PASSWD"
  } | sort -u
}

# ----------------------------------------------------------------- pré-requis
if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
  echo "audi_iam.sh : à exécuter en root (sudo bash audi_iam.sh)." >&2
  exit 2
fi
for f in "$PASSWD" "$SHADOW" "$GROUP"; do
  if [ ! -r "$f" ]; then echo "audi_iam.sh : lecture impossible de $f" >&2; exit 2; fi
done

UID_MIN=$(defs_get UID_MIN); UID_MIN=${UID_MIN:-1000}
TODAY=$(today_days)
EOY=$(eoy_days)

line "=============================================================="
line " AUDIT IAM — Semaine 3 (TP1)                 audi_iam.sh v1.0"
line "=============================================================="
line " Machine   : $(hostname 2>/dev/null || echo inconnue)"
# shellcheck source=/dev/null
line " Système   : $( (. "$ROOT/etc/os-release" 2>/dev/null && echo "$PRETTY_NAME") || echo inconnu)"
line " Date      : $(date '+%Y-%m-%d %H:%M:%S %Z')"
line " Opérateur : ${SUDO_USER:-$(id -un)}"
line "--------------------------------------------------------------"

# =============================================================================
#  MISSION 1 — Fichiers IAM critiques & intégrité
# =============================================================================

# 01 — Permissions de /etc/shadow
c01() {
  local mode owner grp d=""
  mode=$(stat -c '%a' "$SHADOW"); owner=$(stat -c '%U' "$SHADOW"); grp=$(stat -c '%G' "$SHADOW")
  local m=$((8#$mode)) ok=1
  (( m & 8#007 )) && { ok=0; d+="mode $(printf '%04o' "$m") : « autres » ont des droits sur les empreintes"$'\n'; }
  (( m & 8#030 )) && { ok=0; d+="mode $(printf '%04o' "$m") : le groupe peut écrire ou exécuter"$'\n'; }
  (( m & 8#100 )) && { ok=0; d+="mode $(printf '%04o' "$m") : bit d'exécution inutile pour le propriétaire"$'\n'; }
  (( m & 8#7000 )) && { ok=0; d+="mode $(printf '%04o' "$m") : bits spéciaux (setuid/setgid/sticky) présents"$'\n'; }
  [ "$owner" != root ] && { ok=0; d+="propriétaire $owner (attendu root)"$'\n'; }
  [ "$grp" != root ] && { ok=0; d+="groupe $grp (attendu root)"$'\n'; }
  if [ $ok -eq 1 ]; then
    result 01 "M1.1" "Permissions de /etc/shadow" PASS "mode $(printf '%04o' "$m"), $owner:$grp"
  else
    result 01 "M1.1" "Permissions de /etc/shadow" FAIL "${d}attendu : 0000 (défaut AlmaLinux ; 0600 ou 0640 tolérés), root:root"
  fi
}

# 02 — Intégrité de /etc/passwd
c02() {
  local d
  d=$(awk -F: '
    /^[[:space:]]*$/ { printf "ligne %d vide\n", NR; next }
    NF != 7          { printf "ligne %d : %d champs au lieu de 7 (%s)\n", NR, NF, $1; next }
    $1 == ""         { printf "ligne %d : nom de compte vide\n", NR }
    $3 !~ /^[0-9]+$/ { printf "ligne %d (%s) : UID non numérique\n", NR, $1 }
    $4 !~ /^[0-9]+$/ { printf "ligne %d (%s) : GID non numérique\n", NR, $1 }
    $2 != "x"        { printf "%s : champ 2 = \"%s\" (attendu x, empreinte hors de shadow)\n", $1, $2 }
    $3 == "0" && $1 != "root" { printf "%s : UID 0 (second compte root)\n", $1 }
    { if (seen_n[$1]++) printf "%s : nom de compte dupliqué\n", $1
      if ($3 ~ /^[0-9]+$/) { if ($3 in seen_u) printf "UID %s dupliqué (%s et %s)\n", $3, seen_u[$3], $1; else seen_u[$3]=$1 } }
  ' "$PASSWD")
  # cohérence passwd -> shadow
  local u miss=""
  while IFS=: read -r u _; do
    [ -z "$u" ] && continue
    awk -F: -v u="$u" '$1==u {f=1} END{exit !f}' "$SHADOW" || miss+="$u "
  done < "$PASSWD"
  [ -n "$miss" ] && d+=$'\n'"sans entrée dans shadow : ${miss% }"
  d=$(printf '%s\n' "$d" | sed '/^$/d')
  if [ -z "$d" ]; then
    result 02 "M1.2" "Intégrité de /etc/passwd" PASS "7 champs par ligne, noms et UID uniques, un seul UID 0"
  else
    result 02 "M1.2" "Intégrité de /etc/passwd" FAIL "$d"$'\n'"contrôle natif : pwck -r ; corriger avec usermod/userdel ou vipw"
  fi
}

# =============================================================================
#  MISSION 2 — Surface d'attaque & comptes
# =============================================================================

# 03 — Comptes de service avec un shell interactif
c03() {
  local bad="" name uid shell
  while IFS=: read -r name _ uid _ _ _ shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [ "$name" = root ] && continue
    if [ "$uid" -lt "$UID_MIN" ] || [ "$uid" -ge 65534 ]; then
      case " ${SVC_SHELL_ALLOWED:-} " in *" $name "*) continue ;; esac
      is_interactive_shell "$shell" && bad+="$name (UID $uid, $shell)"$'\n'
    fi
  done < "$PASSWD"
  if [ -z "$bad" ]; then
    result 03 "M2.1" "Comptes de service sans shell interactif" PASS "aucun compte système (UID < $UID_MIN) avec un shell de connexion"
  else
    result 03 "M2.1" "Comptes de service sans shell interactif" FAIL "${bad}attendu : /usr/sbin/nologin pour les comptes de service"
  fi
}

# 04 — Ancien collaborateur neutralisé sans destruction
c04() {
  local d="" ok=1
  if ! user_exists "$OLD_USER"; then
    result 04 "M2.2" "Compte $OLD_USER neutralisé, home conservé" FAIL "compte supprimé : le home et les preuves ne sont plus garantis (désactiver, ne pas supprimer)"
    return
  fi
  local pw shell exp home
  pw=$(shadow_field "$OLD_USER" 2); exp=$(shadow_field "$OLD_USER" 8)
  shell=$(passwd_field "$OLD_USER" 7); home=$(passwd_field "$OLD_USER" 6)
  case "$pw" in '!'*|'*'*) ;; *) ok=0; d+="mot de passe non verrouillé (champ 2 de shadow sans « ! »)"$'\n' ;; esac
  is_interactive_shell "$shell" && { ok=0; d+="shell interactif : $shell"$'\n'; }
  if [[ ! "$exp" =~ ^[0-9]+$ ]] || [ "$exp" -gt "$TODAY" ]; then
    ok=0; d+="compte non expiré (champ 8 de shadow : « ${exp:-vide} »), les clés SSH restent utilisables"$'\n'
  fi
  [ -d "$ROOT$home" ] || { ok=0; d+="répertoire $home absent : espace de travail détruit"$'\n'; }
  if [ $ok -eq 1 ]; then
    result 04 "M2.2" "Compte $OLD_USER neutralisé, home conservé" PASS "verrouillé, shell $shell, expiré, $home présent"
  else
    result 04 "M2.2" "Compte $OLD_USER neutralisé, home conservé" FAIL "${d}attendu : verrou + nologin + expiration, sans userdel"
  fi
}

# =============================================================================
#  MISSION 3 — Stratégie des groupes
# =============================================================================

# 05 — alice a retrouvé devteam
c05() {
  if ! user_exists "$DEV_USER"; then
    result 05 "M3.1" "$DEV_USER membre de $DEV_GROUP" FAIL "compte $DEV_USER introuvable"; return
  fi
  if group_members "$DEV_GROUP" | grep -qxF "$DEV_USER"; then
    result 05 "M3.1" "$DEV_USER membre de $DEV_GROUP" PASS "$DEV_USER figure dans $DEV_GROUP"
  else
    result 05 "M3.1" "$DEV_USER membre de $DEV_GROUP" FAIL "$DEV_USER absente de $DEV_GROUP (usermod -G sans -a ?)"$'\n'"vérifier avec : id $DEV_USER"
  fi
}

# 06 — Pas d'intrus dans wheel
c06() {
  local allowed="${WHEEL_ALLOWED:-}"
  if [ -z "$allowed" ]; then
    allowed=$(awk -F: -v m="$UID_MIN" '$3==m {print $1}' "$PASSWD")
  fi
  local intruders="" u
  while read -r u; do
    [ -z "$u" ] && continue
    case " $allowed " in *" $u "*) continue ;; esac
    intruders+="$u "
  done < <(group_members wheel)
  if [ -z "$intruders" ]; then
    result 06 "M3.2" "Groupe wheel limité aux administrateurs" PASS "membres autorisés : ${allowed:-aucun}"
  else
    result 06 "M3.2" "Groupe wheel limité aux administrateurs" FAIL "membre(s) non autorisé(s) : ${intruders% }"$'\n'"autorisé(s) : ${allowed:-aucun} (variable WHEEL_ALLOWED)"
  fi
}

# =============================================================================
#  MISSION 4 — Politique de mots de passe
# =============================================================================

# 07 — Expiration datée du prestataire
c07() {
  if ! user_exists "$CONTRACTOR"; then
    result 07 "M4.1" "Expiration de $CONTRACTOR avant la fin d'année" FAIL "compte $CONTRACTOR introuvable"; return
  fi
  local exp; exp=$(shadow_field "$CONTRACTOR" 8)
  if [[ "$exp" =~ ^[0-9]+$ ]] && [ "$exp" -le "$EOY" ]; then
    result 07 "M4.1" "Expiration de $CONTRACTOR avant la fin d'année" PASS "expiration du compte : $(days2date "$exp")"
  else
    result 07 "M4.1" "Expiration de $CONTRACTOR avant la fin d'année" FAIL "champ 8 de shadow : « ${exp:-vide} » (aucune date ou date après le $(days2date "$EOY"))"
  fi
}

# 08 — PASS_MAX_DAYS pour les futurs comptes
c08() {
  local v; v=$(defs_get PASS_MAX_DAYS)
  if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le "$MAX_DAYS_POLICY" ]; then
    result 08 "M4.2" "PASS_MAX_DAYS <= $MAX_DAYS_POLICY dans login.defs" PASS "PASS_MAX_DAYS $v"
  else
    result 08 "M4.2" "PASS_MAX_DAYS <= $MAX_DAYS_POLICY dans login.defs" FAIL "PASS_MAX_DAYS « ${v:-absent} » dans /etc/login.defs"$'\n'"rappel : ne vaut que pour les comptes créés ensuite"
  fi
}

# 09 — backup_ops doit changer son mot de passe à la prochaine connexion
c09() {
  if ! user_exists "$BACKUP_USER"; then
    result 09 "M4.3" "Changement forcé pour $BACKUP_USER" FAIL "compte $BACKUP_USER introuvable"; return
  fi
  local last; last=$(shadow_field "$BACKUP_USER" 3)
  if [ "$last" = "0" ]; then
    result 09 "M4.3" "Changement forcé pour $BACKUP_USER" PASS "date de dernier changement = 0 : changement exigé à la connexion"
  else
    local when="$last"; [[ "$last" =~ ^[0-9]+$ ]] && when="$last ($(days2date "$last"))"
    result 09 "M4.3" "Changement forcé pour $BACKUP_USER" FAIL "champ 3 de shadow : $when, aucun changement n'est exigé"
  fi
}

# =============================================================================
#  MISSION 5 — Confinement PAM anti-bruteforce
# =============================================================================

# 10 — faillock actif et seuil raisonnable
c10() {
  local d="" ok=1 f
  for f in system-auth password-auth; do
    local act; act=$(pam_active "$PAMDIR/$f")
    grep -Eq '^auth.*pam_faillock\.so.*preauth' <<< "$act" || { ok=0; d+="$f : pas de pam_faillock preauth"$'\n'; }
    grep -Eq '^auth.*pam_faillock\.so.*authfail' <<< "$act" || { ok=0; d+="$f : pas de pam_faillock authfail"$'\n'; }
  done
  local deny
  deny=$(conf_get deny "$FAILLOCK_CONF")
  local argdeny
  argdeny=$(cat "$PAMDIR/system-auth" "$PAMDIR/password-auth" 2>/dev/null | grep -Ev '^[[:space:]]*#' \
            | grep -o 'pam_faillock\.so.*deny=[0-9]*' | sed 's/.*deny=//' | tail -n1)
  [ -n "$argdeny" ] && deny="$argdeny"
  deny=${deny:-3}
  if [ "$deny" -eq 0 ] 2>/dev/null; then ok=0; d+="deny = 0 : aucun verrouillage"$'\n'
  elif [ "$deny" -gt "$DENY_MAX" ] 2>/dev/null; then ok=0; d+="deny = $deny : seuil trop permissif (maximum $DENY_MAX)"$'\n'
  fi
  local unlock; unlock=$(conf_get unlock_time "$FAILLOCK_CONF")
  if [ $ok -eq 1 ]; then
    result 10 "M5" "faillock actif (system-auth et password-auth)" PASS "deny = $deny, unlock_time = ${unlock:-600 (défaut)}"
  else
    result 10 "M5" "faillock actif (system-auth et password-auth)" FAIL "${d}attendu : feature authselect with-faillock, réglages dans faillock.conf"
  fi
}

# 11 — pwquality présent et minlen >= 12
c11() {
  local d="" ok=1
  local act; act=$(pam_active "$PAMDIR/system-auth")
  grep -Eq '^password.*pam_pwquality\.so' <<< "$act" || { ok=0; d+="system-auth : pam_pwquality absent de la pile password"$'\n'; }
  local files=("$PWQ_CONF")
  if [ -d "$PWQ_DIR" ]; then
    local x; for x in "$PWQ_DIR"/*.conf; do [ -e "$x" ] && files+=("$x"); done
  fi
  local minlen; minlen=$(conf_get minlen "${files[@]}")
  local argmin
  argmin=$(grep -o 'pam_pwquality\.so.*minlen=[0-9]*' <<< "$act" | sed 's/.*minlen=//' | tail -n1)
  [ -n "$argmin" ] && minlen="$argmin"
  minlen=${minlen:-8}
  if [ "$minlen" -lt "$MINLEN_POLICY" ] 2>/dev/null; then ok=0; d+="minlen effectif = $minlen (attendu >= $MINLEN_POLICY)"$'\n'; fi
  if [ $ok -eq 1 ]; then
    result 11 "M5" "pwquality actif, minlen >= $MINLEN_POLICY" PASS "minlen = $minlen"
  else
    result 11 "M5" "pwquality actif, minlen >= $MINLEN_POLICY" FAIL "${d}réglage dans /etc/security/pwquality.conf (ou pwquality.conf.d/)"
  fi
}

line ""
line "--- Mission 1 : fichiers IAM critiques"
c01; c02
line ""
line "--- Mission 2 : surface d'attaque et comptes"
c03; c04
line ""
line "--- Mission 3 : stratégie des groupes"
c05; c06
line ""
line "--- Mission 4 : politique de mots de passe"
c07; c08; c09
line ""
line "--- Mission 5 : confinement PAM"
c10; c11

# ----------------------------------------------------------------- informations (non notées)
line ""
line "--- Informations (non notées)"
leftover=$(awk -F: '$1 ~ /^tp_/ {printf "%s ", $1}' "$PASSWD")
[ -n "$leftover" ] && info "comptes de test du bonus encore présents : $leftover(nettoyage demandé)"
[ -e "$ROOT/etc/skel/.politique" ] && info "/etc/skel/.politique encore présent (nettoyage du bonus)"
if [ -z "$ROOT" ] && command -v authselect >/dev/null 2>&1; then
  info "authselect : $(authselect current 2>/dev/null | head -n1 | sed 's/^Profile ID: /profil /')"
  if ! authselect check >/dev/null 2>&1; then
    info "authselect check : configuration PAM modifiée hors authselect"
  fi
fi
if [ -r "$ROOT/etc/gshadow" ]; then
  gm=$(printf '%04o' "$((8#$(stat -c '%a' "$ROOT/etc/gshadow")))")
  go=$(stat -c '%U:%G' "$ROOT/etc/gshadow")
  if [ "$gm" != 0000 ] || [ "$go" != root:root ]; then
    info "/etc/gshadow : $gm $go (attendu 0000 root:root)"
  fi
fi

# ----------------------------------------------------------------- synthèse
PCT=$(( PASSED * 100 / TOTAL ))
line ""
line "=============================================================="
line " Score de hardening : $PASSED/$TOTAL ($PCT %)"
if [ "$PASSED" -eq "$TOTAL" ]; then
  out " Verdict : [EXCELLENT] système totalement durci" " Verdict : ${C_OK}${C_B}[EXCELLENT]${C_0} système totalement durci"
elif [ "$PCT" -ge 70 ]; then
  out " Verdict : [PARTIEL] contrôles en échec : ${FAILED_IDS[*]}" " Verdict : ${C_KO}[PARTIEL]${C_0} contrôles en échec : ${FAILED_IDS[*]}"
else
  out " Verdict : [CRITIQUE] contrôles en échec : ${FAILED_IDS[*]}" " Verdict : ${C_KO}${C_B}[CRITIQUE]${C_0} contrôles en échec : ${FAILED_IDS[*]}"
fi
line "=============================================================="

# ----------------------------------------------------------------- rapport
MID=$(cat "$ROOT/etc/machine-id" 2>/dev/null || hostname)
SUM=$(printf '%s%s' "$BODY" "$MID" | sha256sum | cut -c1-16)
line " Empreinte du rapport : $SUM"

if [ -e "$REPORT" ]; then
  cp -p "$REPORT" "$REPORT.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
fi
if printf '%s' "$BODY" > "$REPORT" 2>/dev/null; then
  chmod 0644 "$REPORT" 2>/dev/null || true
  printf '\nRapport écrit dans %s\n' "$REPORT"
else
  printf '\nImpossible d'"'"'écrire %s\n' "$REPORT" >&2
fi

[ "$PASSED" -eq "$TOTAL" ] && exit 0 || exit 1
