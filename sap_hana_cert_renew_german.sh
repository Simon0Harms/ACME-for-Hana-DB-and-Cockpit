#!/bin/sh
# =============================================================================
# sap_hana_cert_renew.sh
#
# Deployt ACME-Zertifikate (acme.sh) in die In-Database-PSEs einer
# SAP-HANA-MDC-Installation (SystemDB + Tenants) und verifiziert das
# Ergebnis anschliessend direkt am SQL-Port. Schreibt ein CheckMK-Spool-File
# mit dem Ergebnis pro Datenbank.
#
# Verbindungskonzept: EIN hdbuserstore-Key (ACME_RENEW) gegen den
# SystemDB-Port 3<nn>13; die Zieldatenbank wird per Nameserver-Routing
# ("hdbsql -d <DBNAME>") ausgewaehlt. Voraussetzung: der User ACME_RENEW
# existiert in jeder Datenbank MIT DEMSELBEN PASSWORT.
#
# SID, FQDN, Instanznummer und Datenbank-Liste werden automatisch ermittelt;
# jede Groesse kann im Konfigurationsblock fest gesetzt werden, um die
# Ermittlung zu uebersteuern.
#
# Aufrufmodi:
#   sap_hana_cert_renew.sh deploy   Zertifikat in alle DBs deployen + verify
#   sap_hana_cert_renew.sh verify   Nur Port-Verifikation + Spool-Update
#   sap_hana_cert_renew.sh deploy --force
#                                   Deploy auch, wenn Fingerprint unveraendert
#
# Integration mit acme.sh (als <sid>adm ausfuehren):
#   acme.sh --install-cert -d "$(hostname -f)" \
#       --key-file       "/usr/sap/${SAPSYSTEMNAME}/home/certs/host.key" \
#       --fullchain-file "/usr/sap/${SAPSYSTEMNAME}/home/certs/host.fullchain.pem" \
#       --reloadcmd      "/usr/sap/${SAPSYSTEMNAME}/home/bin/sap_hana_cert_renew.sh deploy"
#
# Cron (taeglich, haelt das CheckMK-Spool-File frisch):
#   15 6 * * *  /usr/sap/<SID>/home/bin/sap_hana_cert_renew.sh verify
#
# Voraussetzungen (einmalig, siehe hana_acme_setup.sql):
#   - User ACME_RENEW in SystemDB und jedem Tenant, gleiches Passwort,
#     mit CERTIFICATE ADMIN + SSL ADMIN; in der SystemDB zusaetzlich
#     CATALOG READ (fuer die automatische Tenant-Ermittlung)
#   - PSE (Name siehe PSE_NAME) mit PURPOSE SSL in jeder DB
#   - EIN hdbuserstore-Key gegen die SystemDB:
#       hdbuserstore SET ACME_RENEW "<host>:3<nn>13" ACME_RENEW "<pw>"
#
# Exit-Codes:
#   0 = alle DBs OK, 1 = mindestens eine DB fehlgeschlagen,
#   2 = Vorbedingung nicht erfuellt (Config/Dateien/Lock/Ermittlung)
#
# -----------------------------------------------------------------------------
# LICENSE
# -----------------------------------------------------------------------------
# GNU General Public License v3.0 or later. See the LICENSE file in the
# repository root, or <https://www.gnu.org/licenses/gpl-3.0.html>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
# applicable law.
# =============================================================================

set -u

# --------------------------- Konfiguration ----------------------------------
# Leer lassen ("") = automatische Ermittlung. Setzen = Uebersteuern.
SID=""              # sonst aus $SAPSYSTEMNAME (<sid>adm-Umgebung)
FQDN=""             # sonst aus "hostname -f"
INSTANCE=""         # sonst aus /usr/sap/<SID>/HDB<nn>
KEY_FILE=""         # sonst /usr/sap/<SID>/home/certs/host.key
CHAIN_FILE=""       # sonst /usr/sap/<SID>/home/certs/host.fullchain.pem

# Optional: Root-CA-PEM als MANUELLER Override. Leer lassen = die Kette wird
# automatisch bis zur self-signed Root vervollstaendigt (System-Truststore,
# sonst AIA-Download mit lokalem Cache). Nur setzen, wenn die automatische
# Vervollstaendigung nicht moeglich ist (offline und Root nicht im Truststore).
ROOT_CA_FILE=""

# Datenbanken als "<DBNAME>:<SQL-Port>"-Liste (whitespace-getrennt).
# Leer lassen = automatische Ermittlung ueber SYS_DATABASES.M_SERVICES.
DATABASES=""

# Name der In-Database-PSE (muss in jeder DB existieren, PURPOSE SSL)
PSE_NAME="ACME_SSL"

# Der eine hdbuserstore-Key (zeigt auf den SystemDB-Port)
USTORE_KEY="ACME_RENEW"

# CheckMK-Spool
SPOOL_DIR="/var/lib/check_mk_agent/spool"
SPOOL_MAX_AGE=90000                    # 25h -- "verify" laeuft taeglich per Cron
# Schwellwerte fuer die Restlaufzeit (Metrik lifetime_remaining, Sekunden).
# acme.sh erneuert nach 60 von 90 Tagen -> normal sind ~30 Tage Rest;
# weniger als WARN_DAYS heisst: mindestens ein Renewal-Zyklus ist ausgefallen.
CERT_WARN_DAYS=20
CERT_CRIT_DAYS=10

# Arbeitsverzeichnis fuer Log, Lock und Deploy-State
STATE_DIR="${HOME}/.sap_hana_cert_renew"
LOG_FILE="${STATE_DIR}/renew.log"
LOCK_DIR="${STATE_DIR}/lock"

HDBSQL="hdbsql"
OPENSSL="openssl"

# --------------------------- Site-Konfiguration -----------------------------
# Optionale externe Konfiguration: ueberschreibt die Defaults oben mit
# standortspezifischen Werten (Mailadresse, XSA-Org, Schwellwerte ...).
# Gesucht wird $SITE_CONF, sonst site.conf neben diesem Skript.
# ACHTUNG: Die Datei wird als Shell-Code gesourct und laeuft mit den Rechten
# dieses Skripts -- gleiche Schutzanforderungen wie fuer das Skript selbst
# (Owner root, Mode 644, NICHT gruppen-/weltschreibbar).
# Hinweis: Wird STATE_DIR in der Conf geaendert, muessen LOG_FILE (und ggf.
# LOCK_DIR/MARKER) dort ebenfalls gesetzt werden -- sie werden oben abgeleitet.
SITE_CONF="${SITE_CONF:-$(dirname "$0")/site.conf}"
if [ -r "$SITE_CONF" ]; then
    # shellcheck disable=SC1090
    . "$SITE_CONF"
fi

# --------------------------- Hilfsfunktionen --------------------------------
log() {
    printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$$" "$1" >> "$LOG_FILE"
}

die() {
    log "FATAL: $1"
    printf 'FATAL: %s\n' "$1" >&2
    write_spool 2 "$1"
    exit 2
}

# CheckMK-Local-Check-Spool-File atomar schreiben
# $1 = Status (0/1/2 oder P), $2 = Meldung, $3 = Perfdata (optional, Default "-")
write_spool() {
    [ -d "$SPOOL_DIR" ] || return 0
    if [ ! -w "$SPOOL_DIR" ]; then
        log "WARNUNG: ${SPOOL_DIR} nicht beschreibbar fuer $(id -un) -- Spool-Update uebersprungen (chgrp sapsys + chmod g+ws auf dem Verzeichnis noetig)"
        return 0
    fi
    _sid="${SID:-NA}"
    _spool_file="${SPOOL_DIR}/${SPOOL_MAX_AGE}_sap_hana_cert_renew_${_sid}"
    _spool_tmp="${_spool_file}.$$"
    {
        printf '<<<local:sep(0)>>>\n'
        printf '%s SAP_HANA_cert_%s %s %s\n' "$1" "$_sid" "${3:--}" "$2"
    } > "$_spool_tmp" 2>/dev/null && mv "$_spool_tmp" "$_spool_file" 2>/dev/null \
        || log "WARNUNG: Spool-File ${_spool_file} konnte nicht geschrieben werden"
}

cleanup() {
    [ -n "${PEM_TMP:-}" ] && rm -f "$PEM_TMP"
    [ -n "${SQL_TMP:-}" ] && rm -f "$SQL_TMP"
    [ -n "${CHAIN_WORK:-}" ] && rm -f "$CHAIN_WORK"
    rm -f "${STATE_DIR}/lastcert.$$" "${STATE_DIR}/aia_dl.$$" 2>/dev/null
    [ -n "${HAVE_LOCK:-}" ] && rmdir "$LOCK_DIR" 2>/dev/null
}

# ---- Automatische Vervollstaendigung der Zertifikatskette -------------------
# HANA verlangt bei SET OWN CERTIFICATE die Kette bis zur SELF-SIGNED Root;
# ACME-Fullchains enden beim Intermediate bzw. bei cross-signierten Roots
# (Fehler 5645 "Incomplete certificate chain"). Die fehlenden Glieder werden
# CA-unabhaengig ermittelt: zuerst aus dem System-Truststore (/etc/ssl/certs,
# Hash-Symlinks), sonst per AIA-URL ("CA Issuers") aus dem Zertifikat geladen
# und in ${STATE_DIR}/ca_cache gecacht, damit Renewals nicht von der
# Erreichbarkeit der CA-Webserver abhaengen.

# Letztes Zertifikat einer PEM-Datei extrahieren -> stdout
last_cert() {
    awk '/-----BEGIN CERTIFICATE-----/{buf=""; inb=1}
         inb{buf=buf $0 "\n"}
         /-----END CERTIFICATE-----/{inb=0; last=buf}
         END{printf "%s", last}' "$1"
}

# self-signed? (subject_hash == issuer_hash)
is_self_signed() {
    [ "$("$OPENSSL" x509 -in "$1" -noout -subject_hash 2>/dev/null)" = \
      "$("$OPENSSL" x509 -in "$1" -noout -issuer_hash 2>/dev/null)" ]
}

# Aussteller-Zertifikat fuer $1 beschaffen -> Pfad auf stdout, RC!=0 sonst
fetch_issuer() {
    _ih=$("$OPENSSL" x509 -in "$1" -noout -issuer_hash 2>/dev/null)
    _want=$("$OPENSSL" x509 -in "$1" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    [ -n "$_ih" ] || return 1

    # 1) System-Truststore (Hash-Symlinks von update-ca-certificates)
    for _c in /etc/ssl/certs/"${_ih}".[0-9]*; do
        [ -r "$_c" ] || continue
        _subj=$("$OPENSSL" x509 -in "$_c" -noout -subject 2>/dev/null | sed 's/^subject=//')
        if [ "$_subj" = "$_want" ]; then
            log "Kette: Aussteller im System-Truststore gefunden: ${_c}"
            printf '%s\n' "$_c"
            return 0
        fi
    done

    # 2) Cache frueherer AIA-Downloads
    if [ -r "${CA_CACHE}/${_ih}.pem" ]; then
        printf '%s\n' "${CA_CACHE}/${_ih}.pem"
        return 0
    fi

    # 3) AIA-Download ("CA Issuers"-URL aus dem Zertifikat)
    _url=$("$OPENSSL" x509 -in "$1" -noout -ext authorityInfoAccess 2>/dev/null \
        | sed -n 's/.*CA Issuers - URI://p' | head -n1)
    if [ -z "$_url" ]; then
        log "Kette: keine AIA-URL im Zertifikat (issuer: ${_want})"
        return 1
    fi

    _dl="${STATE_DIR}/aia_dl.$$"
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 30 -o "$_dl" "$_url" 2>> "$LOG_FILE" || { rm -f "$_dl"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 30 -O "$_dl" "$_url" 2>> "$LOG_FILE" || { rm -f "$_dl"; return 1; }
    else
        log "Kette: weder curl noch wget fuer AIA-Download verfuegbar"
        return 1
    fi

    # DER, PEM oder PKCS7 -> reines PEM normalisieren
    if "$OPENSSL" x509 -inform DER -in "$_dl" 2>/dev/null > "${_dl}.pem" \
       || "$OPENSSL" x509 -inform PEM -in "$_dl" 2>/dev/null > "${_dl}.pem" \
       || "$OPENSSL" pkcs7 -inform DER -in "$_dl" -print_certs 2>/dev/null > "${_dl}.pem" \
       || "$OPENSSL" pkcs7 -inform PEM -in "$_dl" -print_certs 2>/dev/null > "${_dl}.pem"; then
        sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
            "${_dl}.pem" > "${CA_CACHE}/${_ih}.pem"
        rm -f "$_dl" "${_dl}.pem"
        if [ -s "${CA_CACHE}/${_ih}.pem" ]; then
            log "Kette: Aussteller per AIA geladen und gecacht: ${_url}"
            printf '%s\n' "${CA_CACHE}/${_ih}.pem"
            return 0
        fi
    fi
    rm -f "$_dl" "${_dl}.pem"
    log "Kette: AIA-Download nicht als Zertifikat lesbar: ${_url}"
    return 1
}

# Kette aus $1 vervollstaendigen (max. 4 Glieder anfuegen) -> $2
complete_chain() {
    cp "$1" "$2" || return 1
    _depth=0
    _last="${STATE_DIR}/lastcert.$$"
    while [ "$_depth" -lt 4 ]; do
        last_cert "$2" > "$_last"
        if is_self_signed "$_last"; then
            rm -f "$_last"
            return 0
        fi
        _iss=$(fetch_issuer "$_last") || { rm -f "$_last"; return 1; }
        cat "$_iss" >> "$2" || { rm -f "$_last"; return 1; }
        _depth=$((_depth + 1))
    done
    rm -f "$_last"
    log "Kette: nach ${_depth} Gliedern keine self-signed Root erreicht"
    return 1
}

# SHA256-Fingerprint des lokal vorliegenden Leaf-Zertifikats
local_fingerprint() {
    "$OPENSSL" x509 -in "$CHAIN_FILE" -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/^.*=//'
}

# SHA256-Fingerprint des am Port ausgelieferten Zertifikats
# $1 = Port
served_fingerprint() {
    printf '' | "$OPENSSL" s_client -connect "${FQDN}:$1" \
        -servername "$FQDN" 2>/dev/null \
        | "$OPENSSL" x509 -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/^.*=//'
}

# Deploy in eine Datenbank per Nameserver-Routing
# $1 = Datenbankname; nutzt $SQL_TMP
# -E 1: hdbsql bricht bei SQL-Fehlern ab und liefert Exit-Code != 0
# (Default waere: Fehler nur auf stderr, Exit-Code 0!)
deploy_db() {
    "$HDBSQL" -U "$USTORE_KEY" -d "$1" -x -E 1 -I "$SQL_TMP" >> "$LOG_FILE" 2>&1
}

# --------------------------- Vorbedingungen ---------------------------------
MODE="${1:-}"
FORCE="no"
[ "${2:-}" = "--force" ] && FORCE="yes"

case "$MODE" in
    deploy|verify) ;;
    *) printf 'Usage: %s deploy [--force] | verify\n' "$0" >&2; exit 2 ;;
esac

umask 077
mkdir -p "$STATE_DIR" || { printf 'Cannot create %s\n' "$STATE_DIR" >&2; exit 2; }
CA_CACHE="${STATE_DIR}/ca_cache"
mkdir -p "$CA_CACHE" || { printf 'Cannot create %s\n' "$CA_CACHE" >&2; exit 2; }
trap cleanup EXIT INT TERM

# Lock (mkdir ist atomar und POSIX)
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "Lock ${LOCK_DIR} existiert, anderer Lauf aktiv -- Abbruch"
    exit 2
fi
HAVE_LOCK="yes"

# SAP-Umgebung sicherstellen: unter Cron/reloadcmd fehlt das <sid>adm-Profil
# (kein Login-Shell-Sourcing), daher sind hdbsql nicht im PATH und
# SAPSYSTEMNAME leer. Das interaktive .sapenv.sh laesst sich hier NICHT
# zuverlaessig sourcen -- es ruft "tset" auf, das ohne Terminal abbricht und
# den ganzen Lauf killt. Statt zu sourcen, setzen wir die zwei benoetigten
# Groessen direkt: SAPSYSTEMNAME (aus dem Instanzpfad) und den HANA-Client-
# PATH (exe-Verzeichnis der Instanz).
if [ -z "${SAPSYSTEMNAME:-}" ]; then
    # /usr/sap/<SID>/HDB<nn> -> SID aus dem Pfad ziehen
    for _d in /usr/sap/[A-Z][A-Z0-9][A-Z0-9]/HDB[0-9][0-9]; do
        [ -d "$_d" ] || continue
        SAPSYSTEMNAME=$(printf '%s' "$_d" | sed 's#/usr/sap/\([^/]*\)/.*#\1#')
        export SAPSYSTEMNAME
        break
    done
fi
if ! command -v "$HDBSQL" >/dev/null 2>&1; then
    # hdbsql liegt im exe-Verzeichnis der Instanz; per Glob finden
    for _exe in /usr/sap/"${SAPSYSTEMNAME:-*}"/HDB[0-9][0-9]/exe/hdbsql \
                /usr/sap/"${SAPSYSTEMNAME:-*}"/SYS/exe/hdb/hdbsql; do
        _cand=$(ls -1 $_exe 2>/dev/null | head -n1)
        if [ -n "$_cand" ] && [ -x "$_cand" ]; then
            PATH="$(dirname "$_cand"):$PATH"
            export PATH
            log "hdbsql gefunden: ${_cand}"
            break
        fi
    done
fi

command -v "$HDBSQL"  >/dev/null 2>&1 || die "hdbsql nicht im PATH (Instanz-exe-Verzeichnis nicht gefunden -- HDBSQL im Skript auf vollen Pfad setzen)"
command -v "$OPENSSL" >/dev/null 2>&1 || die "openssl nicht im PATH"

# --------------------------- Automatische Ermittlung ------------------------
# SID aus der <sid>adm-Umgebung
if [ -z "$SID" ]; then
    SID="${SAPSYSTEMNAME:-}"
    [ -n "$SID" ] || die "SID nicht ermittelbar: SAPSYSTEMNAME leer -- als <sid>adm ausfuehren oder SID im Skript setzen"
fi

# FQDN vom System; Plausibilitaetspruefung: muss einen Punkt enthalten
if [ -z "$FQDN" ]; then
    FQDN=$(hostname -f 2>/dev/null)
    case "$FQDN" in
        *.*) ;;
        *) die "hostname -f liefert keinen FQDN ('${FQDN}') -- FQDN im Skript setzen" ;;
    esac
fi

# Instanznummer aus dem Instanzverzeichnis
if [ -z "$INSTANCE" ]; then
    set -- /usr/sap/"$SID"/HDB[0-9][0-9]
    [ -d "$1" ] || die "Kein Instanzverzeichnis /usr/sap/${SID}/HDB<nn> gefunden -- INSTANCE im Skript setzen"
    [ $# -eq 1 ] || die "Mehrere Instanzverzeichnisse unter /usr/sap/${SID} gefunden -- INSTANCE im Skript setzen"
    INSTANCE="${1##*HDB}"
fi
SYSDB_PORT="3${INSTANCE}13"

# Zertifikatspfade, falls nicht uebersteuert
[ -n "$KEY_FILE" ]   || KEY_FILE="/usr/sap/${SID}/home/certs/host.key"
[ -n "$CHAIN_FILE" ] || CHAIN_FILE="/usr/sap/${SID}/home/certs/host.fullchain.pem"

# Datenbank-Liste: SystemDB + alle Tenants mit SQL-Port.
# Benoetigt CATALOG READ fuer ACME_RENEW in der SystemDB.
if [ -z "$DATABASES" ]; then
    DATABASES=$("$HDBSQL" -U "$USTORE_KEY" -d SYSTEMDB -x -a -j \
        "SELECT DATABASE_NAME || ':' || SQL_PORT \
         FROM SYS_DATABASES.M_SERVICES \
         WHERE SQL_PORT <> 0 \
           AND SERVICE_NAME IN ('nameserver','indexserver') \
           AND COORDINATOR_TYPE = 'MASTER' \
         ORDER BY DATABASE_NAME" 2>> "$LOG_FILE" \
        | tr -d '"' | tr '\n' ' ')
    case "$DATABASES" in
        *"SYSTEMDB:${SYSDB_PORT}"*) ;;
        *) die "Auto-Discovery der Datenbanken fehlgeschlagen (hdbuserstore-Key ${USTORE_KEY} vorhanden? CATALOG READ vorhanden?) -- DATABASES im Skript setzen" ;;
    esac
fi

log "Kontext: SID=${SID} INSTANCE=${INSTANCE} FQDN=${FQDN} DATABASES=${DATABASES}"

[ -r "$CHAIN_FILE" ] || die "Fullchain-Datei fehlt/unlesbar: $CHAIN_FILE"
LOCAL_FP=$(local_fingerprint)
[ -n "$LOCAL_FP" ] || die "Konnte Fingerprint aus $CHAIN_FILE nicht ermitteln"

# =============================================================================
# Modus: deploy
# =============================================================================
if [ "$MODE" = "deploy" ]; then
    [ -r "$KEY_FILE" ] || die "Key-Datei fehlt/unlesbar: $KEY_FILE"

    # Sanity-Check: passt der Key zum Zertifikat?
    PUB_CERT=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -pubkey 2>/dev/null)
    PUB_KEY=$("$OPENSSL" pkey -in "$KEY_FILE" -pubout 2>/dev/null)
    if [ -z "$PUB_CERT" ] || [ "$PUB_CERT" != "$PUB_KEY" ]; then
        die "Key ${KEY_FILE} passt nicht zum Zertifikat ${CHAIN_FILE}"
    fi

    log "Deploy startet, Zertifikat-Fingerprint: ${LOCAL_FP}"

    # PEM fuer HANA bauen: privater Schluessel, dann die VOLLSTAENDIGE Kette
    # (Leaf + Intermediates + Root). Der Key wird per "openssl pkey"
    # normalisiert (PKCS#8): acme.sh-ECC-Keys enthalten einen vorangestellten
    # "EC PARAMETERS"-Block, den der HANA-Parser nicht versteht.
    # umask 077 ist gesetzt, mktemp-Dateien sind nur fuer uns lesbar.
    PEM_TMP=$(mktemp "${STATE_DIR}/pem.XXXXXX") || die "mktemp fehlgeschlagen"
    "$OPENSSL" pkey -in "$KEY_FILE" > "$PEM_TMP" 2>> "$LOG_FILE" \
        || die "Key-Normalisierung (openssl pkey) fehlgeschlagen"

    CHAIN_WORK="${STATE_DIR}/chainwork.$$"
    if [ -n "$ROOT_CA_FILE" ]; then
        [ -r "$ROOT_CA_FILE" ] || die "ROOT_CA_FILE nicht lesbar: $ROOT_CA_FILE"
        cat "$CHAIN_FILE" "$ROOT_CA_FILE" > "$CHAIN_WORK" \
            || die "PEM-Bau (Root-CA-Override) fehlgeschlagen"
    else
        complete_chain "$CHAIN_FILE" "$CHAIN_WORK" \
            || die "Zertifikatskette konnte nicht bis zur Root vervollstaendigt werden (Truststore/AIA, siehe Log) -- ROOT_CA_FILE im Skript setzen"
    fi
    cat "$CHAIN_WORK" >> "$PEM_TMP" || die "PEM-Bau fehlgeschlagen"

    # SQL-Datei bauen (PEM enthaelt keine Single Quotes, Literal ist sicher)
    SQL_TMP=$(mktemp "${STATE_DIR}/sql.XXXXXX") || die "mktemp fehlgeschlagen"
    {
        printf 'ALTER PSE %s SET OWN CERTIFICATE\n' "$PSE_NAME"
        printf "'"
        cat "$PEM_TMP"
        printf "';\n"
    } > "$SQL_TMP"

    FAILED=""
    OK=""
    for ENTRY in $DATABASES; do
        DB_NAME="${ENTRY%%:*}"
        MARKER="${STATE_DIR}/deployed.${DB_NAME}"

        if [ "$FORCE" = "no" ] && [ -f "$MARKER" ] \
           && [ "$(cat "$MARKER")" = "$LOCAL_FP" ]; then
            log "${DB_NAME}: Fingerprint unveraendert, uebersprungen"
            OK="${OK} ${DB_NAME}(skip)"
            continue
        fi

        if deploy_db "$DB_NAME"; then
            printf '%s' "$LOCAL_FP" > "$MARKER"
            log "${DB_NAME}: Deploy OK"
            OK="${OK} ${DB_NAME}"
        else
            log "${DB_NAME}: Deploy FEHLGESCHLAGEN (siehe Log)"
            FAILED="${FAILED} ${DB_NAME}"
        fi
    done

    rm -f "$PEM_TMP" "$SQL_TMP" "$CHAIN_WORK"
    PEM_TMP=""; SQL_TMP=""; CHAIN_WORK=""

    if [ -n "$FAILED" ]; then
        write_spool 2 "Deploy fehlgeschlagen fuer:${FAILED} | OK:${OK:- -}"
        log "Deploy beendet mit Fehlern:${FAILED}"
        exit 1
    fi
    log "Deploy in alle Datenbanken erfolgreich:${OK}"
fi

# =============================================================================
# Verifikation am Port (laeuft nach deploy und im Modus verify)
# Sonderfall Erstinbetriebnahme: Ist die PSE in einer DB noch nicht auf
# PURPOSE SSL (activate steht aus), liefert der Port zwangslaeufig nicht das
# neue Zertifikat -- das ist "ausstehend" (WARN, Exit 0), kein Fehler.
# =============================================================================
V_OK=""
V_FAIL=""
V_PEND=""

for ENTRY in $DATABASES; do
    DB_NAME="${ENTRY%%:*}"
    PORT="${ENTRY#*:}"

    SERVED_FP=$(served_fingerprint "$PORT")
    if [ "$SERVED_FP" = "$LOCAL_FP" ] && [ -n "$SERVED_FP" ]; then
        log "${DB_NAME}: Port ${PORT} liefert aktuelles Zertifikat"
        V_OK="${V_OK} ${DB_NAME}"
        continue
    fi

    # Port liefert nicht das neue Zertifikat -- ist die PSE ueberhaupt aktiv?
    PURPOSE=$("$HDBSQL" -U "$USTORE_KEY" -d "$DB_NAME" -x -a -j \
        "SELECT IFNULL(PURPOSE,'') FROM SYS.PSES WHERE NAME = '${PSE_NAME}'" \
        2>> "$LOG_FILE" | head -n1 | tr -d '"')
    if [ "$PURPOSE" != "SSL" ]; then
        log "${DB_NAME}: PSE ${PSE_NAME} noch nicht PURPOSE SSL -- Aktivierung ausstehend"
        V_PEND="${V_PEND} ${DB_NAME}"
    elif [ -z "$SERVED_FP" ]; then
        log "${DB_NAME}: Port ${PORT} nicht erreichbar oder kein TLS"
        V_FAIL="${V_FAIL} ${DB_NAME}:${PORT}(unreachable)"
    else
        log "${DB_NAME}: Port ${PORT} liefert ALTES Zertifikat (${SERVED_FP})"
        V_FAIL="${V_FAIL} ${DB_NAME}:${PORT}(stale)"
    fi
done

EXPIRY=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -enddate 2>/dev/null \
    | sed 's/^notAfter=//')

# Restlaufzeit als CheckMK-Metrik (Sekunden). Metrikname wie bei den
# eingebauten Cert-Checks -- nur dafuer liefert CheckMK ein Perf-O-Meter.
# Die WARN/CRIT-Bewertung rechnet das Skript selbst (Konvention wie beim
# SAPSSLC-Localcheck), die Schwellwerte in der Perfdata sind informativ.
PERF="-"
DAYS_TXT=""
CERT_STATE=0
END_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
if [ -n "$END_EPOCH" ]; then
    REMAIN=$((END_EPOCH - $(date +%s)))
    [ "$REMAIN" -lt 0 ] && REMAIN=0
    WARN_S=$((CERT_WARN_DAYS * 86400))
    CRIT_S=$((CERT_CRIT_DAYS * 86400))
    PERF="certificate_remaining_validity=${REMAIN};${WARN_S};${CRIT_S}"
    DAYS_TXT=" ($((REMAIN / 86400)) Tage verbleibend)"
    [ "$REMAIN" -le "$WARN_S" ] && CERT_STATE=1
    [ "$REMAIN" -le "$CRIT_S" ] && CERT_STATE=2
fi

# Zeitpunkt des letzten erfolgreichen Deploys (mtime des neuesten Markers)
DEPLOY_TXT=""
LAST_MARKER=$(ls -t "${STATE_DIR}"/deployed.* 2>/dev/null | head -n1)
if [ -n "$LAST_MARKER" ]; then
    DEPLOY_TXT=" | letzter Deploy: $(date -r "$LAST_MARKER" '+%Y-%m-%d %H:%M')"
fi

if [ -n "$V_FAIL" ]; then
    write_spool 2 "Zertifikat nicht aktiv auf:${V_FAIL} | OK:${V_OK:- -} | expires: ${EXPIRY}${DAYS_TXT}" "$PERF"
    exit 1
fi

if [ -n "$V_PEND" ]; then
    write_spool 1 "Deployt, Aktivierung ausstehend (sap_hana_cert_setup.sh activate):${V_PEND} | OK:${V_OK:- -} | expires: ${EXPIRY}${DAYS_TXT}" "$PERF"
    log "Verifikation: Aktivierung ausstehend fuer:${V_PEND}"
    exit 0
fi

if [ "$CERT_STATE" -gt 0 ]; then
    write_spool "$CERT_STATE" "Zertifikat aktiv, aber Restlaufzeit unterschreitet Schwellwert -- Renewal-Kette pruefen! | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT} | DBs:${V_OK}" "$PERF"
else
    write_spool 0 "Zertifikat aktiv auf allen DBs:${V_OK} | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT}" "$PERF"
fi
log "Verifikation OK:${V_OK}${DAYS_TXT}"
exit 0
