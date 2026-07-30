#!/bin/sh
# =============================================================================
# sap_hana_cert_setup.sh
#
# Interaktive ERSTEINRICHTUNG fuer die ACME-Zertifikatsautomatisierung auf
# einer SAP-HANA-MDC-Installation.
#
# Modi:
#   setup     Ermittelt SID/Instanz/FQDN und alle aktiven Datenbanken,
#             fragt Passwoerter interaktiv ab und richtet in JEDER Datenbank
#             (SystemDB + Tenants) ein:
#               - User ACME_RENEW (CERTIFICATE ADMIN + SSL ADMIN,
#                 in der SystemDB zusaetzlich CATALOG READ)
#               - PSE ACME_SSL
#               - optional: Root-CA als Trust-Anker in der PSE
#             legt den hdbuserstore-Key ACME_RENEW an und bietet an,
#             das erste Deployment (deploy --force) auszufuehren.
#
#   activate  Setzt die PSE je Datenbank nach Rueckfrage auf PURPOSE SSL
#             und prueft unmittelbar danach per openssl s_client, ob der
#             SQL-Port ein Zertifikat liefert. Schlaegt die Pruefung fehl,
#             stoppt das Skript VOR der naechsten Datenbank.
#
# Reihenfolge: setup  ->  sap_hana_cert_renew.sh deploy --force  ->  activate
# (activate erst nach erfolgreichem Deploy -- eine aktive SSL-PSE ohne
# eigenes Zertifikat wird so verhindert.)
#
# Idempotenz: Existierende User/PSEs/Zertifikate werden erkannt und nicht
# doppelt angelegt; ein erneuter Lauf richtet nur Fehlendes ein (z. B. fuer
# einen neuen Tenant).
#
# Passwort-Handling: Alle Passwoerter werden ohne Echo abgefragt bzw. per
# stdin an "hdbuserstore -i" uebergeben -- nichts davon erscheint in der
# Prozessliste. Der temporaere Admin-Key wird beim Beenden geloescht.
#
# Aufruf als <sid>adm:  ./sap_hana_cert_setup.sh setup|activate
# =============================================================================

set -u

# --------------------------- Konfiguration ----------------------------------
# Leer lassen ("") = automatische Ermittlung. Setzen = Uebersteuern.
SID=""
FQDN=""
INSTANCE=""

ACME_USER="ACME_RENEW"
PSE_NAME="ACME_SSL"
USTORE_KEY="ACME_RENEW"
CA_CERT_NAME="ACME_ROOT_CA"

HDBSQL="hdbsql"
OPENSSL="openssl"
TMP_KEY_BASE="ACME_SETUP_TMP"   # temporaere hdbuserstore-Keys (werden geloescht)

STATE_DIR="${HOME}/.sap_hana_cert_renew"
LOG_FILE="${STATE_DIR}/setup.log"

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

msg() {
    printf '%s\n' "$1"
    log "$1"
}

die() {
    log "FATAL: $1"
    printf 'FATAL: %s\n' "$1" >&2
    exit 2
}

cleanup() {
    # Alle temporaeren Admin-Keys und Temp-Dateien entfernen
    for _k in $TMP_KEYS; do
        hdbuserstore DELETE "$_k" >/dev/null 2>&1
    done
    [ -n "${SQL_TMP:-}" ] && rm -f "$SQL_TMP"
    [ -n "${OUT_TMP:-}" ] && rm -f "$OUT_TMP"
    stty echo 2>/dev/null
}

# Passwort ohne Echo einlesen: prompt_secret "Prompt" VARNAME
prompt_secret() {
    printf '%s: ' "$1"
    stty -echo 2>/dev/null
    read -r _secret
    stty echo 2>/dev/null
    printf '\n'
    eval "$2=\$_secret"
    unset _secret
}

# Ja/Nein-Frage: confirm "Frage" -> Returncode 0 bei ja
confirm() {
    printf '%s [j/N]: ' "$1"
    read -r _answer
    case "$_answer" in
        j|J|ja|Ja|JA|y|Y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

# Alphanumerisches Passwort erzeugen (24 Zeichen, garantiert Gross/Klein/Ziffer)
gen_password() {
    while :; do
        _pw=$(tr -dc 'A-Za-z0-9' < /dev/urandom | dd bs=1 count=24 2>/dev/null)
        printf '%s' "$_pw" | grep -q '[A-Z]' || continue
        printf '%s' "$_pw" | grep -q '[a-z]' || continue
        printf '%s' "$_pw" | grep -q '[0-9]' || continue
        printf '%s' "$_pw"
        return 0
    done
}

# Temporaeren Admin-Key anlegen: make_tmp_key KEYNAME USER (Passwort via stdin)
# Aufruf:  printf '%s\n' "$PW" | make_tmp_key KEY USER
make_tmp_key() {
    hdbuserstore -i SET "$1" "${FQDN}:${SYSDB_PORT}" "$2" >> "$LOG_FILE" 2>&1 \
        || return 1
    TMP_KEYS="${TMP_KEYS} $1"
}

# SQL ausfuehren: run_sql KEY DBNAME SQL ; Ausgabe in $OUT_TMP
run_sql() {
    printf '%s\n' "$3" > "$SQL_TMP"
    # -E 1: hdbsql bricht bei SQL-Fehlern ab und liefert Exit-Code != 0
    "$HDBSQL" -U "$1" -d "$2" -x -a -j -E 1 -I "$SQL_TMP" > "$OUT_TMP" 2>> "$LOG_FILE"
}

# Skalaren Wert abfragen: query_scalar KEY DBNAME SQL
query_scalar() {
    run_sql "$1" "$2" "$3" || return 1
    head -n1 "$OUT_TMP" | tr -d '"'
}

# Admin-Key fuer eine DB sicherstellen (fragt bei abweichendem Passwort nach).
# Setzt $ADMIN_KEY. Returncode != 0, wenn keine Verbindung moeglich.
ensure_admin() {
    _db="$1"
    ADMIN_KEY="$TMP_KEY_BASE"
    run_sql "$ADMIN_KEY" "$_db" "SELECT 1 FROM DUMMY" && return 0

    msg "${_db}: Anmeldung als ${ADMIN_USER} mit dem SystemDB-Passwort fehlgeschlagen"
    prompt_secret "${_db}: abweichendes Passwort fuer ${ADMIN_USER} (leer = ueberspringen)" _dbpw
    [ -n "$_dbpw" ] || return 1

    ADMIN_KEY="${TMP_KEY_BASE}_${_db}"
    printf '%s\n' "$_dbpw" | make_tmp_key "$ADMIN_KEY" "$ADMIN_USER" || return 1
    unset _dbpw
    run_sql "$ADMIN_KEY" "$_db" "SELECT 1 FROM DUMMY"
}

# Fingerprint-/Handshake-Pruefung am Port: serves_certificate PORT
serves_certificate() {
    printf '' | "$OPENSSL" s_client -connect "${FQDN}:$1" \
        -servername "$FQDN" 2>/dev/null \
        | "$OPENSSL" x509 -noout -fingerprint -sha256 2>/dev/null \
        | grep -q '='
}

# --------------------------- Start ------------------------------------------
MODE="${1:-}"
case "$MODE" in
    setup|activate) ;;
    *) printf 'Usage: %s setup|activate\n' "$0" >&2; exit 2 ;;
esac

umask 077
mkdir -p "$STATE_DIR" || { printf 'Cannot create %s\n' "$STATE_DIR" >&2; exit 2; }
TMP_KEYS=""
trap cleanup EXIT INT TERM

SQL_TMP=$(mktemp "${STATE_DIR}/setup_sql.XXXXXX") || die "mktemp fehlgeschlagen"
OUT_TMP=$(mktemp "${STATE_DIR}/setup_out.XXXXXX") || die "mktemp fehlgeschlagen"

command -v "$HDBSQL"    >/dev/null 2>&1 || die "hdbsql nicht im PATH (als <sid>adm ausfuehren)"
command -v hdbuserstore >/dev/null 2>&1 || die "hdbuserstore nicht im PATH"
command -v "$OPENSSL"   >/dev/null 2>&1 || die "openssl nicht im PATH"

# --------------------------- Automatische Ermittlung ------------------------
if [ -z "$SID" ]; then
    SID="${SAPSYSTEMNAME:-}"
    [ -n "$SID" ] || die "SID nicht ermittelbar: SAPSYSTEMNAME leer -- als <sid>adm ausfuehren"
fi

if [ -z "$FQDN" ]; then
    FQDN=$(hostname -f 2>/dev/null)
    case "$FQDN" in
        *.*) ;;
        *) die "hostname -f liefert keinen FQDN ('${FQDN}')" ;;
    esac
fi

if [ -z "$INSTANCE" ]; then
    set -- /usr/sap/"$SID"/HDB[0-9][0-9]
    [ -d "$1" ] || die "Kein Instanzverzeichnis /usr/sap/${SID}/HDB<nn> gefunden"
    [ $# -eq 1 ] || die "Mehrere Instanzverzeichnisse unter /usr/sap/${SID} -- INSTANCE im Skript setzen"
    INSTANCE="${1##*HDB}"
fi
SYSDB_PORT="3${INSTANCE}13"
# Renewal-Skript liegt im selben Verzeichnis wie dieses Skript (z. B. NFS-Share)
RENEW_SCRIPT="$(dirname "$0")/sap_hana_cert_renew.sh"

printf '\n=== ACME-Ersteinrichtung SAP HANA (%s) ===\n' "$MODE"
printf 'System:   SID=%s  Instanz=%s  FQDN=%s  SystemDB-Port=%s\n\n' \
    "$SID" "$INSTANCE" "$FQDN" "$SYSDB_PORT"
log "Modus=${MODE} Kontext: SID=${SID} INSTANCE=${INSTANCE} FQDN=${FQDN}"

# --------------------------- Admin-Verbindung + Discovery -------------------
printf 'Admin-User fuer die Einrichtung (Default: SYSTEM): '
read -r ADMIN_USER
[ -n "$ADMIN_USER" ] || ADMIN_USER="SYSTEM"

prompt_secret "Passwort fuer ${ADMIN_USER} (SystemDB)" ADMIN_PW
[ -n "$ADMIN_PW" ] || die "Kein Admin-Passwort eingegeben"
printf '%s\n' "$ADMIN_PW" | make_tmp_key "$TMP_KEY_BASE" "$ADMIN_USER" \
    || die "Temporaerer hdbuserstore-Key konnte nicht angelegt werden"
unset ADMIN_PW

run_sql "$TMP_KEY_BASE" SYSTEMDB "SELECT 1 FROM DUMMY" \
    || die "Verbindung zur SystemDB als ${ADMIN_USER} fehlgeschlagen (Passwort? Port?)"
msg "Verbindung zur SystemDB als ${ADMIN_USER} OK"

run_sql "$TMP_KEY_BASE" SYSTEMDB \
    "SELECT DATABASE_NAME FROM SYS.M_DATABASES WHERE ACTIVE_STATUS = 'YES' ORDER BY DATABASE_NAME" \
    || die "Datenbank-Ermittlung fehlgeschlagen"
DB_LIST=$(tr -d '"' < "$OUT_TMP" | tr '\n' ' ')
case "$DB_LIST" in
    *SYSTEMDB*) ;;
    *) die "Unerwartetes Discovery-Ergebnis: '${DB_LIST}'" ;;
esac
printf '\nGefundene aktive Datenbanken: %s\n\n' "$DB_LIST"

# =============================================================================
# Modus: activate
# =============================================================================
if [ "$MODE" = "activate" ]; then
    printf 'ACHTUNG: Die Aktivierung schaltet die TLS-Konfiguration der jeweiligen\n'
    printf 'Datenbank auf die PSE %s um. Clients mit sslValidateCertificate\n' "$PSE_NAME"
    printf '(hdbsql, ODBC/JDBC der Appserver, CheckMK mk_sap_hana) muessen der neuen\n'
    printf 'CA-Kette vertrauen. Zweite Session offen halten!\n\n'

    # Ports je Datenbank ermitteln
    run_sql "$TMP_KEY_BASE" SYSTEMDB \
        "SELECT DATABASE_NAME || ':' || SQL_PORT \
         FROM SYS_DATABASES.M_SERVICES \
         WHERE SQL_PORT <> 0 \
           AND SERVICE_NAME IN ('nameserver','indexserver') \
           AND COORDINATOR_TYPE = 'MASTER' \
         ORDER BY DATABASE_NAME" \
        || die "Port-Ermittlung fehlgeschlagen"
    DB_PORTS=$(tr -d '"' < "$OUT_TMP" | tr '\n' ' ')

    # ---- sslclientpki-Vorpruefung (Fehler 5657) -----------------------------
    # In neueren Revisionen ist sslclientpki=on WERKSDEFAULT und blockiert
    # SET PURPOSE SSL instanzweit. Das Skript prueft das selbst, zeigt die
    # X.509-Nutzung an und bietet die Korrektur (SYSTEM-Layer, online) an.
    PKI_EFF=$(query_scalar "$TMP_KEY_BASE" SYSTEMDB \
        "SELECT LOWER(VALUE) FROM SYS.M_INIFILE_CONTENTS \
         WHERE LOWER(KEY) = 'sslclientpki' \
         ORDER BY MAP(LAYER_NAME,'HOST',3,'DATABASE',2,'SYSTEM',1,'DEFAULT',0,0) DESC \
         LIMIT 1")
    if [ "${PKI_EFF:-off}" = "on" ]; then
        printf '\nHINWEIS: ini-Parameter sslclientpki=on blockiert PURPOSE SSL (Fehler 5657).\n'
        printf 'Pruefe automatisch, ob X.509-Client-Logon auf dieser Instanz genutzt wird ...\n\n'

        # Befunde sammeln (leer = keine Hinweise auf X.509-Nutzung)
        FINDINGS=""

        # 1) In-Database-Provider und User-Mappings, je Datenbank
        for ENTRY in $DB_PORTS; do
            _pdb="${ENTRY%%:*}"
            if ! ensure_admin "$_pdb"; then
                FINDINGS="${FINDINGS}\n  - ${_pdb}: nicht pruefbar (keine Admin-Verbindung)"
                continue
            fi
            _prov=$(query_scalar "$ADMIN_KEY" "$_pdb" \
                "SELECT COUNT(*) FROM SYS.X509_PROVIDERS") || _prov="?"
            _map=$(query_scalar "$ADMIN_KEY" "$_pdb" \
                "SELECT COUNT(*) FROM SYS.X509_USER_MAPPINGS") || _map="?"
            [ "$_prov" = "0" ] || FINDINGS="${FINDINGS}\n  - ${_pdb}: X509_PROVIDERS = ${_prov}"
            [ "$_map"  = "0" ] || FINDINGS="${FINDINGS}\n  - ${_pdb}: X509_USER_MAPPINGS = ${_map}"
        done

        # 2) Dateibasierter Client-Trust-Store: ohne sapcli.pse in $SECUDIR ist
        #    dateibasiertes X.509-Client-Logon technisch unmoeglich -- die
        #    ABWESENHEIT der Datei ist damit ein belastbarer Negativ-Beweis.
        SEC_DIR="${SECUDIR:-/usr/sap/${SID}/HDB${INSTANCE}/$(hostname)/sec}"
        if [ -f "${SEC_DIR}/sapcli.pse" ]; then
            FINDINGS="${FINDINGS}\n  - dateibasierter Client-Trust-Store vorhanden: ${SEC_DIR}/sapcli.pse"
        fi

        if [ -z "$FINDINGS" ]; then
            printf 'Ergebnis: KEINE Hinweise auf X.509-Client-Logon.\n'
            printf '(0 Provider und 0 User-Mappings in allen Datenbanken, kein sapcli.pse\n'
            printf 'unter %s -- dateibasiertes Client-Zertifikat-Logon ist damit ausgeschlossen.)\n\n' "$SEC_DIR"
            log "sslclientpki-Pruefung: keine X.509-Nutzung gefunden"
        else
            printf 'ACHTUNG -- Hinweise auf moegliche X.509-Nutzung gefunden:%b\n\n' "$FINDINGS"
            printf 'Das Abschalten wuerde diese Anmeldungen brechen. Nur nach manueller\n'
            printf 'Pruefung der genannten Punkte bestaetigen!\n\n'
            log "sslclientpki-Pruefung: Befunde:${FINDINGS}"
        fi

        if confirm "sslclientpki jetzt instanzweit auf 'off' setzen (ALTER SYSTEM, online, alle DBs)?"; then
            run_sql "$TMP_KEY_BASE" SYSTEMDB \
                "ALTER SYSTEM ALTER CONFIGURATION ('global.ini','SYSTEM') SET ('communication','sslclientpki') = 'off' WITH RECONFIGURE;" \
                && msg "sslclientpki=off gesetzt (global.ini, SYSTEM-Layer, WITH RECONFIGURE)" \
                || die "Parameter konnte nicht gesetzt werden (INIFILE ADMIN vorhanden? Log: ${LOG_FILE})"
        else
            msg "sslclientpki nicht geaendert -- betroffene Datenbanken werden uebersprungen"
        fi
    fi

    for ENTRY in $DB_PORTS; do
        DB="${ENTRY%%:*}"
        PORT="${ENTRY#*:}"

        ensure_admin "$DB" || { msg "${DB}: uebersprungen (keine Admin-Verbindung)"; continue; }

        # Vorbedingung: PSE hat ein eigenes Zertifikat?
        HAS_OWN=$(query_scalar "$ADMIN_KEY" "$DB" \
            "SELECT COUNT(*) FROM SYS.PSE_CERTIFICATES WHERE PSE_NAME = '${PSE_NAME}' AND CERTIFICATE_USAGE = 'OWN'")
        if [ "$HAS_OWN" = "0" ]; then
            msg "${DB}: PSE ${PSE_NAME} hat KEIN eigenes Zertifikat -- erst 'sap_hana_cert_renew.sh deploy --force' ausfuehren. Uebersprungen."
            continue
        fi

        # Restpruefung je DB: effektiver Wert (oberster Layer gewinnt) --
        # die DEFAULT-Zeile bleibt nach einem SYSTEM-Override sichtbar und
        # darf nicht als "noch aktiv" gewertet werden
        PKI_EFF=$(query_scalar "$ADMIN_KEY" "$DB" \
            "SELECT LOWER(VALUE) FROM SYS.M_INIFILE_CONTENTS \
             WHERE LOWER(KEY) = 'sslclientpki' \
             ORDER BY MAP(LAYER_NAME,'HOST',3,'DATABASE',2,'SYSTEM',1,'DEFAULT',0,0) DESC \
             LIMIT 1")
        if [ "${PKI_EFF:-off}" = "on" ]; then
            msg "${DB}: uebersprungen -- sslclientpki=on wirkt hier effektiv noch (DATABASE-/HOST-Layer-Override? M_INIFILE_CONTENTS pruefen)"
            continue
        fi

        PURPOSE=$(query_scalar "$ADMIN_KEY" "$DB" \
            "SELECT IFNULL(PURPOSE,'') FROM SYS.PSES WHERE NAME = '${PSE_NAME}'")
        if [ "$PURPOSE" = "SSL" ]; then
            msg "${DB}: PSE ${PSE_NAME} ist bereits PURPOSE SSL"
            continue
        fi

        confirm "${DB}: PSE ${PSE_NAME} jetzt auf PURPOSE SSL setzen?" || {
            msg "${DB}: uebersprungen"
            continue
        }

        run_sql "$ADMIN_KEY" "$DB" "SET PSE ${PSE_NAME} PURPOSE SSL;" \
            || die "${DB}: SET PSE fehlgeschlagen -- STOP (Log: ${LOG_FILE})"
        msg "${DB}: PURPOSE SSL aktiviert, pruefe Port ${PORT} ..."

        sleep 2
        if serves_certificate "$PORT"; then
            msg "${DB}: Port ${PORT} liefert ein Zertifikat -- OK"
        else
            die "${DB}: Port ${PORT} liefert nach der Aktivierung KEIN Zertifikat -- STOP vor der naechsten Datenbank. Sofort pruefen: SELECT * FROM SYS.PSE_CERTIFICATES / indexserver-Trace."
        fi
    done

    printf '\n=== activate abgeschlossen ===\n'
    printf 'Abschlusspruefung: sap_hana_cert_renew.sh verify\n'
    exit 0
fi

# =============================================================================
# Modus: setup
# =============================================================================
printf 'Passwort fuer den technischen User %s (in ALLEN Datenbanken identisch).\n' "$ACME_USER"
printf 'Enter = automatisch generieren (24 Zeichen, alphanumerisch).\n'
prompt_secret "Passwort fuer ${ACME_USER}" ACME_PW
if [ -z "$ACME_PW" ]; then
    ACME_PW=$(gen_password)
    printf '\nGeneriertes Passwort fuer %s (JETZT im Passwort-Safe ablegen!):\n\n' "$ACME_USER"
    printf '    %s\n\n' "$ACME_PW"
    confirm "Passwort ist gesichert -- weiter?" || die "Abbruch durch Benutzer"
else
    prompt_secret "Wiederholung" ACME_PW2
    [ "$ACME_PW" = "$ACME_PW2" ] || die "Passwoerter stimmen nicht ueberein"
    unset ACME_PW2
    [ ${#ACME_PW} -ge 12 ] || die "Passwort zu kurz (min. 12 Zeichen)"
    case "$ACME_PW" in
        *[!A-Za-z0-9]*) msg "WARNUNG: Passwort enthaelt Sonderzeichen -- auf Shell-/SQL-Vertraeglichkeit achten" ;;
    esac
fi

printf '\nPfad zur Root-CA-PEM-Datei als Trust-Anker (leer = ueberspringen): '
read -r CA_FILE
if [ -n "$CA_FILE" ]; then
    [ -r "$CA_FILE" ] || die "CA-Datei nicht lesbar: $CA_FILE"
    grep -q 'BEGIN CERTIFICATE' "$CA_FILE" || die "CA-Datei ${CA_FILE} enthaelt kein PEM-Zertifikat"
fi

confirm "Einrichtung in ALLEN gefundenen Datenbanken (${DB_LIST}) durchfuehren?" \
    || die "Abbruch durch Benutzer"

# Pruef-Key mit dem ACME-Passwort: erlaubt bei existierenden Usern den Test,
# ob das eingegebene Passwort bereits gilt (vermeidet ALTER USER und damit
# den Policy-Fehler 413 "last n passwords can not be reused")
CHK_KEY="${TMP_KEY_BASE}_CHK"
printf '%s\n' "$ACME_PW" | make_tmp_key "$CHK_KEY" "$ACME_USER" \
    || die "Temporaerer Pruef-Key konnte nicht angelegt werden"

FAILED=""
for DB in $DB_LIST; do
    printf '\n--- %s ---\n' "$DB"
    DB_OK="yes"

    ensure_admin "$DB" || { msg "${DB}: keine Admin-Verbindung -- uebersprungen"; FAILED="${FAILED} ${DB}"; continue; }

    # 1) User anlegen oder Passwort vereinheitlichen
    EXISTS=$(query_scalar "$ADMIN_KEY" "$DB" \
        "SELECT COUNT(*) FROM SYS.USERS WHERE USER_NAME = '${ACME_USER}'")
    if [ "$EXISTS" = "0" ]; then
        if run_sql "$ADMIN_KEY" "$DB" "CREATE USER ${ACME_USER} PASSWORD \"${ACME_PW}\" NO FORCE_FIRST_PASSWORD_CHANGE;
ALTER USER ${ACME_USER} DISABLE PASSWORD LIFETIME;"; then
            msg "${DB}: User ${ACME_USER} angelegt"
        else
            msg "${DB}: FEHLER beim Anlegen von ${ACME_USER}"; DB_OK="no"
        fi
    else
        msg "${DB}: User ${ACME_USER} existiert bereits"
        if "$HDBSQL" -U "$CHK_KEY" -d "$DB" -x -a -j "SELECT 1 FROM DUMMY" \
             >/dev/null 2>> "$LOG_FILE"; then
            msg "${DB}: eingegebenes Passwort ist bereits gueltig -- keine Aenderung noetig"
        elif confirm "${DB}: Passwort von ${ACME_USER} auf das eingegebene setzen (noetig fuers Ein-Key-Konzept)?"; then
            printf 'ALTER USER %s PASSWORD "%s" NO FORCE_FIRST_PASSWORD_CHANGE;\nALTER USER %s DISABLE PASSWORD LIFETIME;\n' \
                "$ACME_USER" "$ACME_PW" "$ACME_USER" > "$SQL_TMP"
            if "$HDBSQL" -U "$ADMIN_KEY" -d "$DB" -x -a -j -I "$SQL_TMP" \
                 > /dev/null 2> "$OUT_TMP"; then
                msg "${DB}: Passwort gesetzt"
            else
                cat "$OUT_TMP" >> "$LOG_FILE"
                if grep -q 'can not be reused' "$OUT_TMP"; then
                    msg "${DB}: Passwort-Policy (Fehler 413): fruehere Passwoerter duerfen nicht wiederverwendet werden"
                    if confirm "${DB}: User ${ACME_USER} droppen und mit diesem Passwort neu anlegen (setzt die Passwort-Historie zurueck)?"; then
                        if run_sql "$ADMIN_KEY" "$DB" "DROP USER ${ACME_USER};" \
                           && run_sql "$ADMIN_KEY" "$DB" "CREATE USER ${ACME_USER} PASSWORD \"${ACME_PW}\" NO FORCE_FIRST_PASSWORD_CHANGE;
ALTER USER ${ACME_USER} DISABLE PASSWORD LIFETIME;"; then
                            msg "${DB}: User neu angelegt (Berechtigungen folgen im naechsten Schritt)"
                        else
                            msg "${DB}: DROP/CREATE fehlgeschlagen -- besitzt der User Objekte, manuell pruefen (ggf. DROP USER ${ACME_USER} CASCADE); Details im Log"
                            DB_OK="no"
                        fi
                    else
                        msg "${DB}: uebersprungen -- Alternativen: NEUES Passwort waehlen (setup fuer ALLE DBs erneut ausfuehren) oder Usergroup mit last_used_passwords=0"
                        DB_OK="no"
                    fi
                else
                    msg "${DB}: FEHLER beim Passwort-Setzen (siehe Log)"
                    DB_OK="no"
                fi
            fi
        fi
    fi

    # 2) Berechtigungen (GRANT auf bereits Vorhandenes ist unkritisch)
    run_sql "$ADMIN_KEY" "$DB" "GRANT CERTIFICATE ADMIN TO ${ACME_USER};" || DB_OK="no"
    run_sql "$ADMIN_KEY" "$DB" "GRANT SSL ADMIN TO ${ACME_USER};"         || DB_OK="no"
    if [ "$DB" = "SYSTEMDB" ]; then
        run_sql "$ADMIN_KEY" "$DB" "GRANT CATALOG READ TO ${ACME_USER};"  || DB_OK="no"
    fi
    [ "$DB_OK" = "yes" ] && msg "${DB}: Berechtigungen OK"

    # 3) PSE anlegen
    EXISTS=$(query_scalar "$ADMIN_KEY" "$DB" \
        "SELECT COUNT(*) FROM SYS.PSES WHERE NAME = '${PSE_NAME}'")
    if [ "$EXISTS" = "0" ]; then
        run_sql "$ADMIN_KEY" "$DB" "CREATE PSE ${PSE_NAME};" \
            && msg "${DB}: PSE ${PSE_NAME} angelegt" \
            || { msg "${DB}: FEHLER beim Anlegen der PSE"; DB_OK="no"; }
    else
        msg "${DB}: PSE ${PSE_NAME} existiert bereits"
    fi

    # Objektprivileg auf die PSE: CERTIFICATE ADMIN/SSL ADMIN reichen NICHT,
    # um eine fremde PSE zu aendern -- ACME_RENEW braucht ALTER auf der PSE
    # des Admin-Users, sonst scheitert das Deploy mit "insufficient privilege"
    if [ "$DB_OK" = "yes" ]; then
        run_sql "$ADMIN_KEY" "$DB" "GRANT ALTER ON PSE ${PSE_NAME} TO ${ACME_USER};" \
            && msg "${DB}: ALTER ON PSE ${PSE_NAME} an ${ACME_USER} vergeben" \
            || { msg "${DB}: FEHLER bei GRANT ALTER ON PSE"; DB_OK="no"; }
    fi

    # 4) Root-CA als Trust-Anker (optional)
    if [ -n "$CA_FILE" ] && [ "$DB_OK" = "yes" ]; then
        EXISTS=$(query_scalar "$ADMIN_KEY" "$DB" \
            "SELECT COUNT(*) FROM SYS.CERTIFICATES WHERE CERTIFICATE_NAME = '${CA_CERT_NAME}'")
        if [ "$EXISTS" = "0" ]; then
            {
                printf 'CREATE CERTIFICATE %s FROM\n' "$CA_CERT_NAME"
                printf "'"
                cat "$CA_FILE"
                printf "';\n"
                printf 'ALTER PSE %s ADD CERTIFICATE %s;\n' "$PSE_NAME" "$CA_CERT_NAME"
            } > "$SQL_TMP"
            if "$HDBSQL" -U "$ADMIN_KEY" -d "$DB" -x -a -j -I "$SQL_TMP" \
                 > "$OUT_TMP" 2>> "$LOG_FILE"; then
                msg "${DB}: Root-CA ${CA_CERT_NAME} hinterlegt und der PSE zugeordnet"
            else
                msg "${DB}: FEHLER beim Hinterlegen der Root-CA"; DB_OK="no"
            fi
        else
            msg "${DB}: Zertifikat ${CA_CERT_NAME} existiert bereits"
        fi
    fi

    [ "$DB_OK" = "yes" ] || FAILED="${FAILED} ${DB}"
done

if [ -n "$FAILED" ]; then
    printf '\n'
    msg "FEHLER in folgenden Datenbanken:${FAILED} -- Details in ${LOG_FILE}"
    die "Einrichtung unvollstaendig -- nach Korrektur 'setup' erneut ausfuehren (idempotent)"
fi

# --------------------------- hdbuserstore-Key -------------------------------
printf '\n'
printf '%s\n' "$ACME_PW" | hdbuserstore -i SET "$USTORE_KEY" \
    "${FQDN}:${SYSDB_PORT}" "$ACME_USER" >> "$LOG_FILE" 2>&1 \
    || die "hdbuserstore-Key ${USTORE_KEY} konnte nicht angelegt werden"
unset ACME_PW
msg "hdbuserstore-Key ${USTORE_KEY} -> ${FQDN}:${SYSDB_PORT} angelegt"

# Verbindungstest mit dem neuen Key in jede DB
for DB in $DB_LIST; do
    "$HDBSQL" -U "$USTORE_KEY" -d "$DB" -x -a -j "SELECT 1 FROM DUMMY" \
        >/dev/null 2>> "$LOG_FILE" \
        && msg "Verbindungstest ${ACME_USER} -> ${DB}: OK" \
        || die "Verbindungstest als ${ACME_USER} in ${DB} fehlgeschlagen"
done

# --------------------------- Erstes Deployment ------------------------------
printf '\n'
CHAIN_DEFAULT="/usr/sap/${SID}/home/certs/host.fullchain.pem"
if [ ! -r "$CHAIN_DEFAULT" ]; then
    msg "Noch kein Zertifikat unter ${CHAIN_DEFAULT} -- erst per acme.sh ausstellen und installieren:"
    printf '\n'
    printf '  mkdir -p /usr/sap/%s/home/certs\n' "$SID"
    printf '  "$HOME"/.acme.sh/acme.sh --issue --standalone \\\n'
    printf '      --server '\''<acme-directory-url>'\'' \\\n'
    printf '      -d "%s"\n' "$FQDN"
    printf '  "$HOME"/.acme.sh/acme.sh --install-cert -d "%s" \\\n' "$FQDN"
    printf '      --key-file       /usr/sap/%s/home/certs/host.key \\\n' "$SID"
    printf '      --fullchain-file /usr/sap/%s/home/certs/host.fullchain.pem \\\n' "$SID"
    printf '      --reloadcmd      "%s deploy"\n\n' "$RENEW_SCRIPT"
    printf '  (--install-cert ruft den reloadcmd direkt auf und deployt damit bereits.)\n\n'
    msg "Danach: $0 activate"
elif [ -x "$RENEW_SCRIPT" ]; then
    if confirm "Jetzt das erste Deployment ausfuehren (${RENEW_SCRIPT} deploy --force)?"; then
        "$RENEW_SCRIPT" deploy --force \
            && msg "Erstes Deployment erfolgreich -- naechster Schritt: $0 activate" \
            || die "Deployment fehlgeschlagen (Log: ${STATE_DIR}/renew.log) -- 'activate' NICHT ausfuehren"
    else
        msg "Deployment uebersprungen -- vor 'activate' manuell ausfuehren: ${RENEW_SCRIPT} deploy --force"
    fi
else
    msg "Hinweis: ${RENEW_SCRIPT} nicht gefunden/ausfuehrbar -- Deployment uebersprungen"
fi

printf '\n=== setup abgeschlossen ===\n'
printf 'Naechste Schritte: 1) ggf. deploy --force  2) %s activate\n' "$0"
printf '3) acme.sh verdrahten + verify-Cron (siehe README). Log: %s\n' "$LOG_FILE"
exit 0
