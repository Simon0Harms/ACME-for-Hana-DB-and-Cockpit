#!/bin/sh
# =============================================================================
# sap_hana_cert_setup.sh
#
# Interactive FIRST-TIME SETUP for the ACME certificate automation on a
# SAP HANA MDC installation.
#
# Modes:
#   setup     Determines SID, instance and FQDN plus all active databases,
#             asks for passwords interactively and creates, in EVERY database
#             (SystemDB + tenants):
#               - the user ACME_RENEW (CERTIFICATE ADMIN + SSL ADMIN, plus
#                 CATALOG READ in the SystemDB) including the object privilege
#                 ALTER on the PSE
#               - the PSE ACME_SSL
#               - optionally a root CA as a trust anchor inside the PSE
#             It then creates the hdbuserstore key ACME_RENEW and offers to run
#             the first deployment (deploy --force).
#
#   activate  Sets the PSE to PURPOSE SSL per database after confirmation and
#             immediately checks with openssl s_client whether the SQL port
#             serves a certificate. If that check fails, the script stops
#             BEFORE touching the next database.
#
# Order: setup  ->  sap_hana_cert_renew.sh deploy --force  ->  activate
# (activate only after a successful deploy -- this prevents an active SSL PSE
# that has no certificate of its own.)
#
# Idempotence: existing users, PSEs and certificates are detected and not
# created twice; a repeated run only adds what is missing (for example for a
# newly created tenant).
#
# Password handling: all passwords are read without echo and passed to
# "hdbuserstore -i" through stdin, so none of them appears in the process list.
# The temporary admin key is removed on exit.
#
# Run as <sid>adm:  ./sap_hana_cert_setup.sh setup|activate
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

# --------------------------- Configuration ----------------------------------
# Empty ("") = derive automatically. Set a value to override.
SID=""
FQDN=""
INSTANCE=""

ACME_USER="ACME_RENEW"
PSE_NAME="ACME_SSL"
USTORE_KEY="ACME_RENEW"
CA_CERT_NAME="ACME_ROOT_CA"

HDBSQL="hdbsql"
OPENSSL="openssl"
TMP_KEY_BASE="ACME_SETUP_TMP"   # temporary hdbuserstore keys (deleted on exit)

STATE_DIR="${HOME}/.sap_hana_cert_renew"
LOG_FILE="${STATE_DIR}/setup.log"

# --------------------------- Site configuration -----------------------------
# Optional external configuration: overrides the defaults above with
# site-specific values (mail address, XSA org, thresholds, ...).
#
# Search order:
#   1. $SITE_CONF, if set and readable
#   2. site.conf in the directory this script lives in (symlinks resolved,
#      works for relative and PATH invocations too)
#   3. site.conf in each directory listed in $SITE_CONF_DIRS / SITE_CONF_DIRS
#      below -- useful when a script is copied elsewhere (the cockpit script
#      lives in the <sid>adm home) but the conf stays on the shared directory
#
# CAUTION: the file is sourced as shell code and runs with this script's
# privileges -- it needs the same protection as the script itself
# (owner root, mode 644, never group- or world-writable).
# Note: if you override STATE_DIR here, also set LOG_FILE (and LOCK_DIR /
# MARKER where present) in the conf -- they are derived above.

# Extra directories searched after the script directory (whitespace separated).
SITE_CONF_DIRS="${SITE_CONF_DIRS:-}"

# Resolve the directory this script lives in.
_self="$0"
case "$_self" in
    */*) ;;
    *) _self=$(command -v "$_self" 2>/dev/null) || _self="$0" ;;
esac
if [ -L "$_self" ]; then
    _target=$(readlink "$_self" 2>/dev/null) || _target=""
    if [ -n "$_target" ]; then
        case "$_target" in
            /*) _self="$_target" ;;
            *)  _self="$(dirname "$_self")/$_target" ;;
        esac
    fi
fi
SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$_self")" 2>/dev/null && pwd -P) || SCRIPT_DIR="."

SITE_CONF_LOADED=""
if [ -n "${SITE_CONF:-}" ] && [ -r "${SITE_CONF:-}" ]; then
    SITE_CONF_LOADED="$SITE_CONF"
else
    for _d in "$SCRIPT_DIR" $SITE_CONF_DIRS; do
        if [ -r "${_d}/site.conf" ]; then
            SITE_CONF_LOADED="${_d}/site.conf"
            break
        fi
    done
fi
if [ -n "$SITE_CONF_LOADED" ]; then
    # shellcheck disable=SC1090
    . "$SITE_CONF_LOADED"
fi

# --------------------------- Helper functions -------------------------------
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
    # remove all temporary admin keys and temp files
    for _k in $TMP_KEYS; do
        hdbuserstore DELETE "$_k" >/dev/null 2>&1
    done
    [ -n "${SQL_TMP:-}" ] && rm -f "$SQL_TMP"
    [ -n "${OUT_TMP:-}" ] && rm -f "$OUT_TMP"
    stty echo 2>/dev/null
}

# Read a password without echo: prompt_secret "Prompt" VARNAME
prompt_secret() {
    printf '%s: ' "$1"
    stty -echo 2>/dev/null
    read -r _secret
    stty echo 2>/dev/null
    printf '\n'
    eval "$2=\$_secret"
    unset _secret
}

# Yes/no question: confirm "Question" -> return code 0 on yes
confirm() {
    printf '%s [y/N]: ' "$1"
    read -r _answer
    case "$_answer" in
        y|Y|yes|Yes|YES|j|J|ja) return 0 ;;
        *) return 1 ;;
    esac
}

# Generate an alphanumeric password (24 characters, guaranteed upper/lower/digit)
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

# Create a temporary admin key: make_tmp_key KEYNAME USER (password via stdin)
# Usage:  printf '%s\n' "$PW" | make_tmp_key KEY USER
make_tmp_key() {
    hdbuserstore -i SET "$1" "${FQDN}:${SYSDB_PORT}" "$2" >> "$LOG_FILE" 2>&1 \
        || return 1
    TMP_KEYS="${TMP_KEYS} $1"
}

# Execute SQL: run_sql KEY DBNAME SQL ; output goes to $OUT_TMP
run_sql() {
    printf '%s\n' "$3" > "$SQL_TMP"
    # -E 1: makes hdbsql abort on SQL errors and return a non-zero exit code
    "$HDBSQL" -U "$1" -d "$2" -x -a -j -E 1 -I "$SQL_TMP" > "$OUT_TMP" 2>> "$LOG_FILE"
}

# Query a scalar value: query_scalar KEY DBNAME SQL
query_scalar() {
    run_sql "$1" "$2" "$3" || return 1
    head -n1 "$OUT_TMP" | tr -d '"'
}

# Make sure an admin connection exists for a database (asks for a different
# password if needed). Sets $ADMIN_KEY. Return code != 0 if no connection.
ensure_admin() {
    _db="$1"
    ADMIN_KEY="$TMP_KEY_BASE"
    run_sql "$ADMIN_KEY" "$_db" "SELECT 1 FROM DUMMY" && return 0

    msg "${_db}: logon as ${ADMIN_USER} with the SystemDB password failed"
    prompt_secret "${_db}: different password for ${ADMIN_USER} (empty = skip)" _dbpw
    [ -n "$_dbpw" ] || return 1

    ADMIN_KEY="${TMP_KEY_BASE}_${_db}"
    printf '%s\n' "$_dbpw" | make_tmp_key "$ADMIN_KEY" "$ADMIN_USER" || return 1
    unset _dbpw
    run_sql "$ADMIN_KEY" "$_db" "SELECT 1 FROM DUMMY"
}

# Handshake check at a port: serves_certificate PORT
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

SQL_TMP=$(mktemp "${STATE_DIR}/setup_sql.XXXXXX") || die "mktemp failed"
OUT_TMP=$(mktemp "${STATE_DIR}/setup_out.XXXXXX") || die "mktemp failed"

command -v "$HDBSQL"    >/dev/null 2>&1 || die "hdbsql not in PATH (run as <sid>adm)"
command -v hdbuserstore >/dev/null 2>&1 || die "hdbuserstore not in PATH"
command -v "$OPENSSL"   >/dev/null 2>&1 || die "openssl not in PATH"

# --------------------------- Automatic detection ----------------------------
if [ -z "$SID" ]; then
    SID="${SAPSYSTEMNAME:-}"
    [ -n "$SID" ] || die "cannot determine SID: SAPSYSTEMNAME is empty -- run as <sid>adm"
fi

if [ -z "$FQDN" ]; then
    FQDN=$(hostname -f 2>/dev/null)
    case "$FQDN" in
        *.*) ;;
        *) die "hostname -f does not return an FQDN ('${FQDN}')" ;;
    esac
fi

if [ -z "$INSTANCE" ]; then
    set -- /usr/sap/"$SID"/HDB[0-9][0-9]
    [ -d "$1" ] || die "no instance directory /usr/sap/${SID}/HDB<nn> found"
    [ $# -eq 1 ] || die "several instance directories under /usr/sap/${SID} -- set INSTANCE in this script"
    INSTANCE="${1##*HDB}"
fi
SYSDB_PORT="3${INSTANCE}13"
# The renewal script is expected next to this one (e.g. on a shared directory)
RENEW_SCRIPT="$(dirname "$0")/sap_hana_cert_renew.sh"

printf '\n=== ACME first-time setup for SAP HANA (%s) ===\n' "$MODE"
printf 'System:   SID=%s  instance=%s  FQDN=%s  SystemDB port=%s\n\n' \
    "$SID" "$INSTANCE" "$FQDN" "$SYSDB_PORT"
log "mode=${MODE} context: SID=${SID} INSTANCE=${INSTANCE} FQDN=${FQDN} conf=${SITE_CONF_LOADED:-none}"

# --------------------------- Admin connection and discovery -----------------
printf 'Admin user for the setup (default: SYSTEM): '
read -r ADMIN_USER
[ -n "$ADMIN_USER" ] || ADMIN_USER="SYSTEM"

prompt_secret "Password for ${ADMIN_USER} (SystemDB)" ADMIN_PW
[ -n "$ADMIN_PW" ] || die "no admin password entered"
printf '%s\n' "$ADMIN_PW" | make_tmp_key "$TMP_KEY_BASE" "$ADMIN_USER" \
    || die "could not create the temporary hdbuserstore key"
unset ADMIN_PW

run_sql "$TMP_KEY_BASE" SYSTEMDB "SELECT 1 FROM DUMMY" \
    || die "connection to the SystemDB as ${ADMIN_USER} failed (password? port?)"
msg "connection to the SystemDB as ${ADMIN_USER} ok"

run_sql "$TMP_KEY_BASE" SYSTEMDB \
    "SELECT DATABASE_NAME FROM SYS.M_DATABASES WHERE ACTIVE_STATUS = 'YES' ORDER BY DATABASE_NAME" \
    || die "database discovery failed"
DB_LIST=$(tr -d '"' < "$OUT_TMP" | tr '\n' ' ')
case "$DB_LIST" in
    *SYSTEMDB*) ;;
    *) die "unexpected discovery result: '${DB_LIST}'" ;;
esac
printf '\nActive databases found: %s\n\n' "$DB_LIST"

# =============================================================================
# Mode: activate
# =============================================================================
if [ "$MODE" = "activate" ]; then
    printf 'CAUTION: activation switches the TLS configuration of each database\n'
    printf 'to the PSE %s. Clients using sslValidateCertificate (hdbsql,\n' "$PSE_NAME"
    printf 'ODBC/JDBC on the application servers, monitoring plugins) must trust the\n'
    printf 'new CA chain. Keep a second session open!\n\n'

    # Determine the port of every database
    run_sql "$TMP_KEY_BASE" SYSTEMDB \
        "SELECT DATABASE_NAME || ':' || SQL_PORT \
         FROM SYS_DATABASES.M_SERVICES \
         WHERE SQL_PORT <> 0 \
           AND SERVICE_NAME IN ('nameserver','indexserver') \
           AND COORDINATOR_TYPE = 'MASTER' \
         ORDER BY DATABASE_NAME" \
        || die "port discovery failed"
    DB_PORTS=$(tr -d '"' < "$OUT_TMP" | tr '\n' ' ')

    # ---- sslclientpki pre-check (error 5657) --------------------------------
    # In newer revisions sslclientpki=on is the FACTORY DEFAULT and blocks
    # SET PURPOSE SSL instance-wide. The script resolves the effective value,
    # reports any X.509 usage it can detect and offers the correction
    # (SYSTEM layer, online).
    PKI_EFF=$(query_scalar "$TMP_KEY_BASE" SYSTEMDB \
        "SELECT LOWER(VALUE) FROM SYS.M_INIFILE_CONTENTS \
         WHERE LOWER(KEY) = 'sslclientpki' \
         ORDER BY MAP(LAYER_NAME,'HOST',3,'DATABASE',2,'SYSTEM',1,'DEFAULT',0,0) DESC \
         LIMIT 1")
    if [ "${PKI_EFF:-off}" = "on" ]; then
        printf '\nNOTE: the ini parameter sslclientpki=on blocks PURPOSE SSL (error 5657).\n'
        printf 'Checking automatically whether X.509 client logon is used on this instance ...\n\n'

        # Collect findings (empty = no indication of X.509 usage)
        FINDINGS=""

        # 1) in-database providers and user mappings, per database
        for ENTRY in $DB_PORTS; do
            _pdb="${ENTRY%%:*}"
            if ! ensure_admin "$_pdb"; then
                FINDINGS="${FINDINGS}\n  - ${_pdb}: cannot be checked (no admin connection)"
                continue
            fi
            _prov=$(query_scalar "$ADMIN_KEY" "$_pdb" \
                "SELECT COUNT(*) FROM SYS.X509_PROVIDERS") || _prov="?"
            _map=$(query_scalar "$ADMIN_KEY" "$_pdb" \
                "SELECT COUNT(*) FROM SYS.X509_USER_MAPPINGS") || _map="?"
            [ "$_prov" = "0" ] || FINDINGS="${FINDINGS}\n  - ${_pdb}: X509_PROVIDERS = ${_prov}"
            [ "$_map"  = "0" ] || FINDINGS="${FINDINGS}\n  - ${_pdb}: X509_USER_MAPPINGS = ${_map}"
        done

        # 2) file-based client trust store: without sapcli.pse in $SECUDIR,
        #    file-based X.509 client logon is technically impossible -- so the
        #    ABSENCE of that file is solid negative evidence.
        SEC_DIR="${SECUDIR:-/usr/sap/${SID}/HDB${INSTANCE}/$(hostname)/sec}"
        if [ -f "${SEC_DIR}/sapcli.pse" ]; then
            FINDINGS="${FINDINGS}\n  - file-based client trust store present: ${SEC_DIR}/sapcli.pse"
        fi

        if [ -z "$FINDINGS" ]; then
            printf 'Result: NO indication of X.509 client logon.\n'
            printf '(0 providers and 0 user mappings in all databases, no sapcli.pse\n'
            printf 'under %s -- file-based client certificate logon is therefore ruled out.)\n\n' "$SEC_DIR"
            log "sslclientpki check: no X.509 usage found"
        else
            printf 'CAUTION -- indications of possible X.509 usage found:%b\n\n' "$FINDINGS"
            printf 'Turning it off would break those logons. Confirm only after checking\n'
            printf 'the points listed above manually!\n\n'
            log "sslclientpki check: findings:${FINDINGS}"
        fi

        if confirm "set sslclientpki to 'off' instance-wide now (ALTER SYSTEM, online, all databases)?"; then
            run_sql "$TMP_KEY_BASE" SYSTEMDB \
                "ALTER SYSTEM ALTER CONFIGURATION ('global.ini','SYSTEM') SET ('communication','sslclientpki') = 'off' WITH RECONFIGURE;" \
                && msg "sslclientpki=off set (global.ini, SYSTEM layer, WITH RECONFIGURE)" \
                || die "could not set the parameter (is INIFILE ADMIN granted? log: ${LOG_FILE})"
        else
            msg "sslclientpki unchanged -- affected databases will be skipped"
        fi
    fi

    for ENTRY in $DB_PORTS; do
        DB="${ENTRY%%:*}"
        PORT="${ENTRY#*:}"

        ensure_admin "$DB" || { msg "${DB}: skipped (no admin connection)"; continue; }

        # Precondition: does the PSE hold its own certificate?
        HAS_OWN=$(query_scalar "$ADMIN_KEY" "$DB" \
            "SELECT COUNT(*) FROM SYS.PSE_CERTIFICATES WHERE PSE_NAME = '${PSE_NAME}' AND CERTIFICATE_USAGE = 'OWN'")
        if [ "$HAS_OWN" = "0" ]; then
            msg "${DB}: PSE ${PSE_NAME} has NO own certificate -- run 'sap_hana_cert_renew.sh deploy --force' first. Skipped."
            continue
        fi

        # Per-database re-check: the effective value wins (the DEFAULT row stays
        # visible after a SYSTEM override and must not be read as "still active")
        PKI_EFF=$(query_scalar "$ADMIN_KEY" "$DB" \
            "SELECT LOWER(VALUE) FROM SYS.M_INIFILE_CONTENTS \
             WHERE LOWER(KEY) = 'sslclientpki' \
             ORDER BY MAP(LAYER_NAME,'HOST',3,'DATABASE',2,'SYSTEM',1,'DEFAULT',0,0) DESC \
             LIMIT 1")
        if [ "${PKI_EFF:-off}" = "on" ]; then
            msg "${DB}: skipped -- sslclientpki=on is still effective here (DATABASE or HOST layer override? check M_INIFILE_CONTENTS)"
            continue
        fi

        PURPOSE=$(query_scalar "$ADMIN_KEY" "$DB" \
            "SELECT IFNULL(PURPOSE,'') FROM SYS.PSES WHERE NAME = '${PSE_NAME}'")
        if [ "$PURPOSE" = "SSL" ]; then
            msg "${DB}: PSE ${PSE_NAME} is already PURPOSE SSL"
            continue
        fi

        confirm "${DB}: set PSE ${PSE_NAME} to PURPOSE SSL now?" || {
            msg "${DB}: skipped"
            continue
        }

        run_sql "$ADMIN_KEY" "$DB" "SET PSE ${PSE_NAME} PURPOSE SSL;" \
            || die "${DB}: SET PSE failed -- STOP (log: ${LOG_FILE})"
        msg "${DB}: PURPOSE SSL activated, checking port ${PORT} ..."

        sleep 2
        if serves_certificate "$PORT"; then
            msg "${DB}: port ${PORT} serves a certificate -- ok"
        else
            die "${DB}: port ${PORT} serves NO certificate after activation -- STOP before the next database. Check immediately: SELECT * FROM SYS.PSE_CERTIFICATES and the indexserver trace."
        fi
    done

    printf '\n=== activate finished ===\n'
    printf 'Final check: sap_hana_cert_renew.sh verify\n'
    exit 0
fi

# =============================================================================
# Mode: setup
# =============================================================================
printf 'Password for the technical user %s (identical in ALL databases).\n' "$ACME_USER"
printf 'Press Enter to generate one automatically (24 alphanumeric characters).\n'
prompt_secret "Password for ${ACME_USER}" ACME_PW
if [ -z "$ACME_PW" ]; then
    ACME_PW=$(gen_password)
    printf '\nGenerated password for %s (store it in your password safe NOW!):\n\n' "$ACME_USER"
    printf '    %s\n\n' "$ACME_PW"
    confirm "password stored -- continue?" || die "aborted by the user"
else
    prompt_secret "Repeat" ACME_PW2
    [ "$ACME_PW" = "$ACME_PW2" ] || die "passwords do not match"
    unset ACME_PW2
    [ ${#ACME_PW} -ge 12 ] || die "password too short (minimum 12 characters)"
    case "$ACME_PW" in
        *[!A-Za-z0-9]*) msg "WARNING: the password contains special characters -- watch out for shell and SQL compatibility" ;;
    esac
fi

printf '\nPath to a root CA PEM file to use as a trust anchor (empty = skip): '
read -r CA_FILE
if [ -n "$CA_FILE" ]; then
    [ -r "$CA_FILE" ] || die "CA file not readable: $CA_FILE"
    grep -q 'BEGIN CERTIFICATE' "$CA_FILE" || die "CA file ${CA_FILE} contains no PEM certificate"
fi

confirm "run the setup in ALL databases found (${DB_LIST})?" \
    || die "aborted by the user"

# A check key holding the ACME password: for existing users this lets us test
# whether the entered password is already in effect, which avoids an ALTER USER
# and therefore the policy error 413 "last n passwords can not be reused"
CHK_KEY="${TMP_KEY_BASE}_CHK"
printf '%s\n' "$ACME_PW" | make_tmp_key "$CHK_KEY" "$ACME_USER" \
    || die "could not create the temporary check key"

FAILED=""
for DB in $DB_LIST; do
    printf '\n--- %s ---\n' "$DB"
    DB_OK="yes"

    ensure_admin "$DB" || { msg "${DB}: no admin connection -- skipped"; FAILED="${FAILED} ${DB}"; continue; }

    # 1) create the user, or align its password
    EXISTS=$(query_scalar "$ADMIN_KEY" "$DB" \
        "SELECT COUNT(*) FROM SYS.USERS WHERE USER_NAME = '${ACME_USER}'")
    if [ "$EXISTS" = "0" ]; then
        if run_sql "$ADMIN_KEY" "$DB" "CREATE USER ${ACME_USER} PASSWORD \"${ACME_PW}\" NO FORCE_FIRST_PASSWORD_CHANGE;
ALTER USER ${ACME_USER} DISABLE PASSWORD LIFETIME;"; then
            msg "${DB}: user ${ACME_USER} created"
        else
            msg "${DB}: ERROR creating ${ACME_USER}"; DB_OK="no"
        fi
    else
        msg "${DB}: user ${ACME_USER} already exists"
        if "$HDBSQL" -U "$CHK_KEY" -d "$DB" -x -a -j "SELECT 1 FROM DUMMY" \
             >/dev/null 2>> "$LOG_FILE"; then
            msg "${DB}: the entered password is already valid -- no change needed"
        elif confirm "${DB}: set the password of ${ACME_USER} to the entered one (required for the single-key model)?"; then
            printf 'ALTER USER %s PASSWORD "%s" NO FORCE_FIRST_PASSWORD_CHANGE;\nALTER USER %s DISABLE PASSWORD LIFETIME;\n' \
                "$ACME_USER" "$ACME_PW" "$ACME_USER" > "$SQL_TMP"
            if "$HDBSQL" -U "$ADMIN_KEY" -d "$DB" -x -a -j -I "$SQL_TMP" \
                 > /dev/null 2> "$OUT_TMP"; then
                msg "${DB}: password set"
            else
                cat "$OUT_TMP" >> "$LOG_FILE"
                if grep -q 'can not be reused' "$OUT_TMP"; then
                    msg "${DB}: password policy (error 413): previous passwords may not be reused"
                    if confirm "${DB}: drop user ${ACME_USER} and recreate it with this password (resets the password history)?"; then
                        if run_sql "$ADMIN_KEY" "$DB" "DROP USER ${ACME_USER};" \
                           && run_sql "$ADMIN_KEY" "$DB" "CREATE USER ${ACME_USER} PASSWORD \"${ACME_PW}\" NO FORCE_FIRST_PASSWORD_CHANGE;
ALTER USER ${ACME_USER} DISABLE PASSWORD LIFETIME;"; then
                            msg "${DB}: user recreated (privileges follow in the next step)"
                        else
                            msg "${DB}: DROP/CREATE failed -- does the user own objects? check manually (possibly DROP USER ${ACME_USER} CASCADE); details in the log"
                            DB_OK="no"
                        fi
                    else
                        msg "${DB}: skipped -- alternatives: pick a NEW password (rerun setup for ALL databases) or use a user group with last_used_passwords=0"
                        DB_OK="no"
                    fi
                else
                    msg "${DB}: ERROR setting the password (see log)"
                    DB_OK="no"
                fi
            fi
        fi
    fi

    # 2) privileges (granting something that already exists is harmless)
    run_sql "$ADMIN_KEY" "$DB" "GRANT CERTIFICATE ADMIN TO ${ACME_USER};" || DB_OK="no"
    run_sql "$ADMIN_KEY" "$DB" "GRANT SSL ADMIN TO ${ACME_USER};"         || DB_OK="no"
    if [ "$DB" = "SYSTEMDB" ]; then
        run_sql "$ADMIN_KEY" "$DB" "GRANT CATALOG READ TO ${ACME_USER};"  || DB_OK="no"
    fi
    [ "$DB_OK" = "yes" ] && msg "${DB}: privileges ok"

    # 3) create the PSE
    EXISTS=$(query_scalar "$ADMIN_KEY" "$DB" \
        "SELECT COUNT(*) FROM SYS.PSES WHERE NAME = '${PSE_NAME}'")
    if [ "$EXISTS" = "0" ]; then
        run_sql "$ADMIN_KEY" "$DB" "CREATE PSE ${PSE_NAME};" \
            && msg "${DB}: PSE ${PSE_NAME} created" \
            || { msg "${DB}: ERROR creating the PSE"; DB_OK="no"; }
    else
        msg "${DB}: PSE ${PSE_NAME} already exists"
    fi

    # Object privilege on the PSE: CERTIFICATE ADMIN and SSL ADMIN are NOT
    # sufficient to modify a PSE owned by someone else -- ACME_RENEW needs
    # ALTER on the admin user's PSE, otherwise the deploy fails with
    # "insufficient privilege" (error 258)
    if [ "$DB_OK" = "yes" ]; then
        run_sql "$ADMIN_KEY" "$DB" "GRANT ALTER ON PSE ${PSE_NAME} TO ${ACME_USER};" \
            && msg "${DB}: ALTER ON PSE ${PSE_NAME} granted to ${ACME_USER}" \
            || { msg "${DB}: ERROR on GRANT ALTER ON PSE"; DB_OK="no"; }
    fi

    # 4) root CA as a trust anchor (optional)
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
                msg "${DB}: root CA ${CA_CERT_NAME} stored and added to the PSE"
            else
                msg "${DB}: ERROR storing the root CA"; DB_OK="no"
            fi
        else
            msg "${DB}: certificate ${CA_CERT_NAME} already exists"
        fi
    fi

    [ "$DB_OK" = "yes" ] || FAILED="${FAILED} ${DB}"
done

if [ -n "$FAILED" ]; then
    printf '\n'
    msg "ERRORS in these databases:${FAILED} -- details in ${LOG_FILE}"
    die "setup incomplete -- fix the cause and rerun 'setup' (it is idempotent)"
fi

# --------------------------- hdbuserstore key -------------------------------
printf '\n'
printf '%s\n' "$ACME_PW" | hdbuserstore -i SET "$USTORE_KEY" \
    "${FQDN}:${SYSDB_PORT}" "$ACME_USER" >> "$LOG_FILE" 2>&1 \
    || die "could not create the hdbuserstore key ${USTORE_KEY}"
unset ACME_PW
msg "hdbuserstore key ${USTORE_KEY} -> ${FQDN}:${SYSDB_PORT} created"

# Connection test with the new key against every database
for DB in $DB_LIST; do
    "$HDBSQL" -U "$USTORE_KEY" -d "$DB" -x -a -j "SELECT 1 FROM DUMMY" \
        >/dev/null 2>> "$LOG_FILE" \
        && msg "connection test ${ACME_USER} -> ${DB}: ok" \
        || die "connection test as ${ACME_USER} in ${DB} failed"
done

# --------------------------- First deployment -------------------------------
printf '\n'
CHAIN_DEFAULT="/usr/sap/${SID}/home/certs/host.fullchain.pem"
if [ ! -r "$CHAIN_DEFAULT" ]; then
    msg "no certificate at ${CHAIN_DEFAULT} yet -- issue and install one with acme.sh first:"
    printf '\n'
    printf '  mkdir -p /usr/sap/%s/home/certs\n' "$SID"
    printf '  "$HOME"/.acme.sh/acme.sh --issue --standalone \\\n'
    printf '      --server '\''<acme-directory-url>'\'' \\\n'
    printf '      -d "%s"\n' "$FQDN"
    printf '  "$HOME"/.acme.sh/acme.sh --install-cert -d "%s" \\\n' "$FQDN"
    printf '      --key-file       /usr/sap/%s/home/certs/host.key \\\n' "$SID"
    printf '      --fullchain-file /usr/sap/%s/home/certs/host.fullchain.pem \\\n' "$SID"
    printf '      --reloadcmd      "%s deploy"\n\n' "$RENEW_SCRIPT"
    printf '  (--install-cert calls the reload command directly and therefore already deploys.)\n\n'
    msg "then run: $0 activate"
elif [ -x "$RENEW_SCRIPT" ]; then
    if confirm "run the first deployment now (${RENEW_SCRIPT} deploy --force)?"; then
        "$RENEW_SCRIPT" deploy --force \
            && msg "first deployment succeeded -- next step: $0 activate" \
            || die "deployment failed (log: ${STATE_DIR}/renew.log) -- do NOT run 'activate'"
    else
        msg "deployment skipped -- run it manually before 'activate': ${RENEW_SCRIPT} deploy --force"
    fi
else
    msg "note: ${RENEW_SCRIPT} not found or not executable -- deployment skipped"
fi

printf '\n=== setup finished ===\n'
printf 'Next steps: 1) deploy --force if it was skipped  2) %s activate\n' "$0"
printf '3) wire up acme.sh and the verify cron (see the documentation). Log: %s\n' "$LOG_FILE"
exit 0
