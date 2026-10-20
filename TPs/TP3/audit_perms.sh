#!/usr/bin/env bash
# =============================================================================
#  audit_perms.sh — Audit des permissions, semaine 4 (TP2, partie 1)
#  Cours « Sécurité des Systèmes d'Exploitation » — ENSA Agadir
#  Cible : AlmaLinux 9.x (RHEL 9 et dérivés)
#
#  Vérifie les 8 contrôles des missions 1 à 3 du TP (DAC et bits spéciaux, ACL,
#  SUID et capabilities) et écrit le rapport dans /tmp/audit_report_v2.txt
#  (l'ancien rapport est conservé avec un horodatage).
#  Le script est en LECTURE SEULE : il ne modifie jamais le système audité.
#
#  Usage   : sudo bash audit_perms.sh
#  Réglages (variables d'environnement, facultatives) :
#    AUDIT_REPORT=/chemin   fichier de rapport (défaut /tmp/audit_report_v2.txt)
#    AUDIT_ROOT=/chemin     racine alternative (tests hors VM uniquement)
#  Code de sortie : 0 = 8/8, 1 = au moins un échec, 2 = exécution impossible.
# =============================================================================

set -u
export LC_ALL=C

ROOT="${AUDIT_ROOT:-}"
REPORT="${AUDIT_REPORT:-/tmp/audit_report_v2.txt}"

# Objets du scénario (créés par init_lab_perms.sh)
TEAMSHARE="$ROOT/srv/teamshare";          TEAM_GROUP="webops"
SHARED_TMP="$ROOT/shared/tmp"
UNIT_APP="myapp"
SENSITIVE="$ROOT/srv/secure/fichier_sensible"
RELEASE="$ROOT/srv/app/release.sh"
LEGACY_BINS=("$ROOT/usr/local/bin/legacy-helper" "$ROOT/opt/legacy/old-report-gen")
SERVER_BIN="$ROOT/usr/local/bin/myserver"
UNIT_DIRS=("$ROOT/etc/systemd/system" "$ROOT/usr/lib/systemd/system")

TOTAL=8
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
has()  { command -v "$1" >/dev/null 2>&1; }
mode() { printf '%04o' "$((8#$(stat -c '%a' "$1")))"; }     # mode octal sur 4 chiffres

# nom du groupe propriétaire (lu dans group : indépendant du NSS de la machine d'audit)
gname() { awk -F: -v g="$(stat -c '%g' "$1")" '$3==g {print $1; f=1} END{if(!f) print g}' "$ROOT/etc/group"; }
gid_of() { awk -F: -v g="$1" '$1==g {print $3}' "$ROOT/etc/group"; }

# ACL d'un fichier, sans commentaires d'en-tête (getfacl absent : sortie vide)
acl_of() { has getfacl && getfacl -p ${ROOT:+-n} "$1" 2>/dev/null | grep -v '^#[[:space:]]*\(file\|owner\|group\|flags\):' ; }

# valeur UMask effective de l'unité (systemctl en VM, sinon lecture des fichiers)
unit_umask() {
  local u="$1" v="" f d
  if [ -z "$ROOT" ] && has systemctl; then
    v=$(systemctl show "$u" -p UMask --value 2>/dev/null)
    [ -n "$v" ] && { echo "$v"; return; }
  fi
  for d in "${UNIT_DIRS[@]}"; do
    for f in "$d/$u.service" "$d/$u.service.d"/*.conf; do
      [ -r "$f" ] || continue
      local x
      x=$(sed -n 's/^[[:space:]]*UMask[[:space:]]*=[[:space:]]*\([0-7]*\).*/\1/p' "$f" | tail -n1)
      [ -n "$x" ] && v="$x"
    done
  done
  echo "${v:-0022}"
}

# ----------------------------------------------------------------- pré-requis
if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
  echo "audit_perms.sh : à exécuter en root (sudo bash audit_perms.sh)." >&2
  exit 2
fi
if ! has getfacl; then
  echo "audit_perms.sh : getfacl introuvable (paquet acl : sudo dnf install acl)." >&2
  exit 2
fi
if ! has getcap; then
  echo "audit_perms.sh : getcap introuvable (paquet libcap : sudo dnf install libcap)." >&2
  exit 2
fi

line "=============================================================="
line " AUDIT PERMISSIONS — Semaine 4 (TP2, partie 1)  audit_perms.sh v1.0"
line "=============================================================="
line " Machine   : $(hostname 2>/dev/null || echo inconnue)"
# shellcheck source=/dev/null
line " Système   : $( (. "$ROOT/etc/os-release" 2>/dev/null && echo "$PRETTY_NAME") || echo inconnu)"
line " Date      : $(date '+%Y-%m-%d %H:%M:%S %Z')"
line " Opérateur : ${SUDO_USER:-$(id -un)}"
line "--------------------------------------------------------------"

# =============================================================================
#  MISSION 1 — DAC et bits spéciaux
# =============================================================================

# 01 — SGID sur le dossier partagé
c01() {
  local t="Dossier partagé : SGID et groupe $TEAM_GROUP"
  if [ ! -d "$TEAMSHARE" ]; then
    result 01 "M1.1" "$t" FAIL "$TEAMSHARE introuvable"; return
  fi
  local m grp d="" ok=1
  m=$((8#$(stat -c '%a' "$TEAMSHARE"))); grp=$(gname "$TEAMSHARE")
  (( m & 8#2000 )) || { ok=0; d+="bit SGID absent (mode $(mode "$TEAMSHARE")) : les fichiers créés prennent le groupe de leur auteur"$'\n'; }
  [ "$grp" = "$TEAM_GROUP" ] || { ok=0; d+="groupe $grp (attendu $TEAM_GROUP)"$'\n'; }
  (( m & 8#007 )) && { ok=0; d+="« autres » ont des droits (mode $(mode "$TEAMSHARE")) : dossier d'équipe ouvert au monde"$'\n'; }
  (( (m & 8#070) == 8#070 )) || { ok=0; d+="le groupe n'a pas rwx (mode $(mode "$TEAMSHARE"))"$'\n'; }
  if [ $ok -eq 1 ]; then
    result 01 "M1.1" "$t" PASS "mode $(mode "$TEAMSHARE"), groupe $grp"
  else
    result 01 "M1.1" "$t" FAIL "${d}attendu : chown root:$TEAM_GROUP et chmod 2770"
  fi
}

# 02 — sticky bit sur le dossier world-writable
c02() {
  local t="Sticky bit sur /shared/tmp"
  if [ ! -d "$SHARED_TMP" ]; then
    result 02 "M1.2" "$t" FAIL "$SHARED_TMP introuvable" ; return
  fi
  local m; m=$((8#$(stat -c '%a' "$SHARED_TMP")))
  if (( m & 8#1000 )); then
    result 02 "M1.2" "$t" PASS "mode $(mode "$SHARED_TMP")"
  else
    result 02 "M1.2" "$t" FAIL "mode $(mode "$SHARED_TMP") : tout utilisateur peut supprimer les fichiers des autres"$'\n'"attendu : sticky bit (chmod 1777)"
  fi
}

# 03 — umask du service
c03() {
  local t="umask du service $UNIT_APP (UMask=)"
  local v; v=$(unit_umask "$UNIT_APP")
  local n=$((8#$v))
  if (( (n & 8#027) == 8#027 )); then
    result 03 "M1.3" "$t" PASS "UMask = $v"
  else
    result 03 "M1.3" "$t" FAIL "UMask effectif = $v : fichiers créés lisibles par le groupe en écriture ou par tous"$'\n'"attendu : UMask=0027 (au moins) dans la section [Service], puis daemon-reload et restart"
  fi
}

# =============================================================================
#  MISSION 2 — ACL
# =============================================================================

# 04 — aucune ACL cachée sur le fichier sensible
c04() {
  local t="Fichier sensible sans ACL cachée"
  if [ ! -e "$SENSITIVE" ]; then
    result 04 "M2.1" "$t" FAIL "$SENSITIVE introuvable (supprimé : à restaurer)"; return
  fi
  local extra
  extra=$(acl_of "$SENSITIVE" | grep -E '^(user|group):[^:]+:' )
  if [ -z "$extra" ]; then
    result 04 "M2.1" "$t" PASS "aucune entrée nommée, mode $(mode "$SENSITIVE")"
  else
    result 04 "M2.1" "$t" FAIL "entrée(s) ACL nommée(s) :"$'\n'"$(printf '%s\n' "$extra" | sed 's/[[:space:]]*#.*//')"$'\n'"attendu : retirer l'entrée avec setfacl -x (ls -l signale ces ACL par un +)"
  fi
}

# 05 — masque : les droits accordés à webops sont effectifs
c05() {
  local t="Masque ACL de release.sh cohérent"
  if [ ! -e "$RELEASE" ]; then
    result 05 "M2.2" "$t" FAIL "$RELEASE introuvable"; return
  fi
  local l granted eff tg
  tg=$(gid_of "$TEAM_GROUP")
  l=$(acl_of "$RELEASE" | grep -E "^group:($TEAM_GROUP${tg:+|$tg}):")
  if [ -z "$l" ]; then
    result 05 "M2.2" "$t" FAIL "entrée group:$TEAM_GROUP absente (l'ACL a été supprimée au lieu d'être corrigée)"; return
  fi
  granted=$(sed -E "s/^group:[^:]+:([rwx-]{3}).*/\1/" <<< "$l")
  eff=$(sed -nE 's/.*#effective:([rwx-]{3}).*/\1/p' <<< "$l")
  eff=${eff:-$granted}
  if [ "$granted" = "$eff" ] && [[ "$eff" == *x* ]]; then
    result 05 "M2.2" "$t" PASS "group:$TEAM_GROUP:$granted, effectif $eff"
  else
    result 05 "M2.2" "$t" FAIL "accordé $granted mais effectif $eff : le masque plafonne l'entrée"$'\n'"attendu : setfacl -m m::rwx (puis relire getfacl)"
  fi
}

# =============================================================================
#  MISSION 3 — SUID et capabilities
# =============================================================================

# 06 — binaires obsolètes sans SUID
c06() {
  local t="Binaires obsolètes sans SUID"
  local bad="" ok_list="" b
  for b in "${LEGACY_BINS[@]}"; do
    if [ ! -e "$b" ]; then ok_list+="${b#"$ROOT"} (supprimé) "; continue; fi
    if (( 8#$(stat -c '%a' "$b") & 8#4000 )); then
      bad+="${b#"$ROOT"} : SUID root toujours actif (mode $(mode "$b"))"$'\n'
    else
      ok_list+="${b#"$ROOT"} "
    fi
  done
  if [ -z "$bad" ]; then
    result 06 "M3.1" "$t" PASS "${ok_list% }"
  else
    result 06 "M3.1" "$t" FAIL "${bad}attendu : chmod u-s (ou suppression après analyse)"
  fi
}

# 07 — myserver : capability à la place du SUID
c07() {
  local t="myserver : capability à la place du SUID"
  if [ ! -e "$SERVER_BIN" ]; then
    result 07 "M3.2" "$t" FAIL "$SERVER_BIN introuvable"; return
  fi
  local d="" ok=1 caps names
  (( 8#$(stat -c '%a' "$SERVER_BIN") & 8#6000 )) && { ok=0; d+="bit SUID/SGID encore présent (mode $(mode "$SERVER_BIN"))"$'\n'; }
  caps=$(getcap "$SERVER_BIN" 2>/dev/null)
  if [ -z "$caps" ]; then
    ok=0; d+="aucune capability sur le binaire (getcap vide)"$'\n'
  else
    names=$(grep -o 'cap_[a-z_]*' <<< "${caps#* }" | sort -u | tr '\n' ' ')
    grep -q 'cap_net_bind_service' <<< "$names" || { ok=0; d+="cap_net_bind_service absente (présent : ${names:-rien})"$'\n'; }
    [ "$(wc -w <<< "$names")" -gt 1 ] && { ok=0; d+="capabilities en trop : ${names% } (seule cap_net_bind_service est nécessaire)"$'\n'; }
    grep -Eq '[=+][ip]*e' <<< "${caps#* }" || { ok=0; d+="flag e absent : le binaire ne l'activera pas de lui-même"$'\n'; }
  fi
  if [ $ok -eq 1 ]; then
    result 07 "M3.2" "$t" PASS "${caps#"$ROOT"}"
  else
    result 07 "M3.2" "$t" FAIL "${d}attendu : chmod u-s puis setcap cap_net_bind_service=ep"
  fi
}

# 08 — aucun SUID/SGID résiduel hors paquets
c08() {
  local t="Aucun SUID/SGID hors paquets (/usr/local, /opt)"
  local found=""
  local dirs=() p
  for p in "$ROOT/usr/local" "$ROOT/opt"; do [ -d "$p" ] && dirs+=("$p"); done
  [ ${#dirs[@]} -gt 0 ] && found=$(find "${dirs[@]}" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sed "s|^$ROOT||")
  if [ -z "$found" ]; then
    result 08 "M3.3" "$t" PASS "inventaire vide"
  else
    result 08 "M3.3" "$t" FAIL "$(printf '%s\n' "$found" | while read -r f; do printf '%s (%s)\n' "$f" "$(mode "$ROOT$f")"; done)"$'\n'"attendu : aucun binaire hors paquet avec SUID/SGID (ou justification documentée)"
  fi
}

line ""
line "--- Mission 1 : DAC et bits spéciaux"
c01; c02; c03
line ""
line "--- Mission 2 : ACL"
c04; c05
line ""
line "--- Mission 3 : SUID et capabilities"
c06; c07; c08

# ----------------------------------------------------------------- informations (non notées)
line ""
line "--- Informations (non notées)"
if [ -z "$ROOT" ]; then
  ww=$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | grep -v '^/proc' | head -n 5 | tr '\n' ' ')
  [ -n "$ww" ] && info "dossier(s) modifiable(s) par tous sans sticky : $ww"
  orph=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -n 3 | tr '\n' ' ')
  [ -n "$orph" ] && info "fichier(s) sans propriétaire ou sans groupe : $orph"
  suid_n=$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l)
  info "binaires SUID du système : $suid_n (inventaire détaillé : bonus C.4)"
fi
if [ -e "$ROOT/usr/bin/ping" ]; then
  if (( 8#$(stat -c '%a' "$ROOT/usr/bin/ping") & 8#4000 )); then
    info "ping : SUID root actif (bonus C.2 : constater ce choix)"
  else
    pc=$(getcap "$ROOT/usr/bin/ping" 2>/dev/null | sed 's/^[^ ]* //')
    info "ping : pas de SUID, capability : ${pc:-aucune}"
  fi
fi
ls "$ROOT"/root/suid-baseline-*.txt >/dev/null 2>&1 \
  && info "baseline SUID datée présente (bonus C.4)"

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

[ "$PASSED" -eq "$TOTAL" ] && exit 0
exit 1
