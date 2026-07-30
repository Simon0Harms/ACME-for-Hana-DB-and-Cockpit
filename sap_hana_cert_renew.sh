#!/bin/sh
# =============================================================================
# sap_hana_cert_renew.sh
#
# Deploys ACME certificates (acme.sh) into the in-database PSEs of a SAP HANA
# MDC installation (SystemDB + tenants) and then verifies the result directly
# at the SQL port. Writes a Checkmk spool file with the per-database result.
#
# Connection model: ONE hdbuserstore key (ACME_RENEW) against the SystemDB
# port 3<nn>13; the target database is selected through nameserver routing
# ("hdbsql -d <DBNAME>"). Prerequisite: the ACME_RENEW user must exist in
# every database WITH THE SAME PASSWORD.
#
# SID, FQDN, instance number and database list are derived automatically;
# every value can be pinned in the configuration block below to override the
# automatic detection.
#
# Modes:
#   sap_hana_cert_renew.sh deploy   deploy into all databases, then verify
#   sap_hana_cert_renew.sh verify   port verification and spool update only
#   sap_hana_cert_renew.sh deploy --force
#                                   deploy even if the fingerprint is unchanged
#
# Integration with acme.sh (run as <sid>adm):
#   acme.sh --install-cert -d "$(hostname -f)" \
#       --key-file       "$HOME/certs/host.key" \
#       --fullchain-file "$HOME/certs/host.fullchain.pem" \
#       --reloadcmd      "/opt/sap-acme/sap_hana_cert_renew.sh deploy"
#
# Cron (daily, keeps the Checkmk spool file fresh):
#   15 1 * * *  /opt/sap-acme/sap_hana_cert_renew.sh verify >/dev/null 2>&1
#
# Prerequisites (one-off, see hana_acme_setup.sql):
#   - User ACME_RENEW in the SystemDB and in every tenant, same password,
#     holding CERTIFICATE ADMIN + SSL ADMIN, plus the object privilege
#     ALTER on the PSE; in the SystemDB additionally CATALOG READ (needed
#     for automatic tenant discovery)
#   - A PSE (see PSE_NAME) with PURPOSE SSL in every database
#   - ONE hdbuserstore key pointing at the SystemDB:
#       hdbuserstore SET ACME_RENEW "<host>:3<nn>13" ACME_RENEW "<pw>"
#
# Exit codes:
#   0 = all databases ok, 1 = at least one database failed,
#   2 = precondition not met (config, files, lock, discovery)
# =============================================================================

set -u

# --------------------------- Configuration ----------------------------------
# Empty ("") = derive automatically. Set a value to override.
SID=""              # otherwise from $SAPSYSTEMNAME (<sid>adm environment)
FQDN=""             # otherwise from "hostname -f"
INSTANCE=""         # otherwise from /usr/sap/<SID>/HDB<nn>
KEY_FILE=""         # otherwise $HOME/certs/host.key
CHAIN_FILE=""       # otherwise $HOME/certs/host.fullchain.pem

# Optional root CA PEM as a MANUAL override. Leave empty to have the chain
# completed automatically up to the self-signed root (system trust store,
# otherwise AIA download with a local cache). Only set this when automatic
# completion is impossible (offline and the root is not in the trust store).
ROOT_CA_FILE=""

# Databases as a whitespace-separated list of "<DBNAME>:<SQL port>".
# Empty = derive automatically from SYS_DATABASES.M_SERVICES.
DATABASES=""

# Name of the in-database PSE (must exist in every database, PURPOSE SSL)
PSE_NAME="ACME_SSL"

# The single hdbuserstore key (points at the SystemDB port)
USTORE_KEY="ACME_RENEW"

# Checkmk spool
SPOOL_DIR="/var/lib/check_mk_agent/spool"
SPOOL_MAX_AGE=90000                    # 25h -- "verify" runs daily from cron
# Thresholds for the remaining lifetime (metric certificate_remaining_validity,
# in seconds). acme.sh renews after 60 of 90 days, so ~30 days left is normal;
# less than WARN_DAYS means at least one renewal cycle was missed.
CERT_WARN_DAYS=20
CERT_CRIT_DAYS=10

# Working directory for log, lock and deploy state
STATE_DIR="${HOME}/.sap_hana_cert_renew"
LOG_FILE="${STATE_DIR}/renew.log"
LOCK_DIR="${STATE_DIR}/lock"

HDBSQL="hdbsql"
OPENSSL="openssl"

# --------------------------- Site configuration -----------------------------
# Optional external configuration: overrides the defaults above with
# site-specific values (mail address, XSA org, thresholds, ...).
# The script looks at $SITE_CONF, otherwise at site.conf next to itself.
# CAUTION: the file is sourced as shell code and runs with this script's
# privileges -- it needs the same protection as the script itself
# (owner root, mode 644, never group- or world-writable).
# Note: if you override STATE_DIR here, also set LOG_FILE (and LOCK_DIR /
# MARKER where present) in the conf -- they are derived above.
SITE_CONF="${SITE_CONF:-$(dirname "$0")/site.conf}"
if [ -r "$SITE_CONF" ]; then
    # shellcheck disable=SC1090
    . "$SITE_CONF"
fi

# --------------------------- Helper functions -------------------------------
log() {
    printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$$" "$1" >> "$LOG_FILE"
}

die() {
    log "FATAL: $1"
    printf 'FATAL: %s\n' "$1" >&2
    write_spool 2 "$1"
    exit 2
}

# Write the Checkmk local check spool file atomically.
# $1 = state (0/1/2), $2 = message, $3 = perfdata (optional, defaults to "-")
write_spool() {
    [ -d "$SPOOL_DIR" ] || return 0
    if [ ! -w "$SPOOL_DIR" ]; then
        log "WARNING: ${SPOOL_DIR} is not writable for $(id -un) -- spool update skipped (the directory needs chgrp sapsys + chmod g+ws)"
        return 0
    fi
    _sid="${SID:-NA}"
    _spool_file="${SPOOL_DIR}/${SPOOL_MAX_AGE}_sap_hana_cert_renew_${_sid}"
    _spool_tmp="${_spool_file}.$$"
    {
        printf '<<<local:sep(0)>>>\n'
        printf '%s SAP_HANA_cert_%s %s %s\n' "$1" "$_sid" "${3:--}" "$2"
    } > "$_spool_tmp" 2>/dev/null && mv "$_spool_tmp" "$_spool_file" 2>/dev/null \
        || log "WARNING: could not write spool file ${_spool_file}"
}

cleanup() {
    [ -n "${PEM_TMP:-}" ] && rm -f "$PEM_TMP"
    [ -n "${SQL_TMP:-}" ] && rm -f "$SQL_TMP"
    [ -n "${CHAIN_WORK:-}" ] && rm -f "$CHAIN_WORK"
    rm -f "${STATE_DIR}/lastcert.$$" "${STATE_DIR}/aia_dl.$$" 2>/dev/null
    [ -n "${HAVE_LOCK:-}" ] && rmdir "$LOCK_DIR" 2>/dev/null
}

# ---- Automatic certificate chain completion ---------------------------------
# For SET OWN CERTIFICATE, HANA requires the chain up to the SELF-SIGNED root.
# ACME full chains end at the intermediate, and cross-signed roots never become
# self-signed (error 5645 "Incomplete certificate chain"). The missing links
# are resolved CA-agnostically: first from the system trust store
# (/etc/ssl/certs hash symlinks), otherwise downloaded via the AIA "CA Issuers"
# URL from the certificate and cached in ${STATE_DIR}/ca_cache so that renewals
# do not depend on the CA web servers being reachable.

# Extract the last certificate of a PEM file -> stdout
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

# Obtain the issuer certificate for $1 -> path on stdout, RC != 0 otherwise
fetch_issuer() {
    _ih=$("$OPENSSL" x509 -in "$1" -noout -issuer_hash 2>/dev/null)
    _want=$("$OPENSSL" x509 -in "$1" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    [ -n "$_ih" ] || return 1

    # 1) system trust store (hash symlinks created by update-ca-certificates)
    for _c in /etc/ssl/certs/"${_ih}".[0-9]*; do
        [ -r "$_c" ] || continue
        _subj=$("$OPENSSL" x509 -in "$_c" -noout -subject 2>/dev/null | sed 's/^subject=//')
        if [ "$_subj" = "$_want" ]; then
            log "chain: issuer found in system trust store: ${_c}"
            printf '%s\n' "$_c"
            return 0
        fi
    done

    # 2) cache of earlier AIA downloads
    if [ -r "${CA_CACHE}/${_ih}.pem" ]; then
        printf '%s\n' "${CA_CACHE}/${_ih}.pem"
        return 0
    fi

    # 3) AIA download ("CA Issuers" URL taken from the certificate)
    _url=$("$OPENSSL" x509 -in "$1" -noout -ext authorityInfoAccess 2>/dev/null \
        | sed -n 's/.*CA Issuers - URI://p' | head -n1)
    if [ -z "$_url" ]; then
        log "chain: no AIA URL in the certificate (issuer: ${_want})"
        return 1
    fi

    _dl="${STATE_DIR}/aia_dl.$$"
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 30 -o "$_dl" "$_url" 2>> "$LOG_FILE" || { rm -f "$_dl"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 30 -O "$_dl" "$_url" 2>> "$LOG_FILE" || { rm -f "$_dl"; return 1; }
    else
        log "chain: neither curl nor wget available for the AIA download"
        return 1
    fi

    # normalise DER, PEM or PKCS7 into plain PEM
    if "$OPENSSL" x509 -inform DER -in "$_dl" 2>/dev/null > "${_dl}.pem" \
       || "$OPENSSL" x509 -inform PEM -in "$_dl" 2>/dev/null > "${_dl}.pem" \
       || "$OPENSSL" pkcs7 -inform DER -in "$_dl" -print_certs 2>/dev/null > "${_dl}.pem" \
       || "$OPENSSL" pkcs7 -inform PEM -in "$_dl" -print_certs 2>/dev/null > "${_dl}.pem"; then
        sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
            "${_dl}.pem" > "${CA_CACHE}/${_ih}.pem"
        rm -f "$_dl" "${_dl}.pem"
        if [ -s "${CA_CACHE}/${_ih}.pem" ]; then
            log "chain: issuer fetched via AIA and cached: ${_url}"
            printf '%s\n' "${CA_CACHE}/${_ih}.pem"
            return 0
        fi
    fi
    rm -f "$_dl" "${_dl}.pem"
    log "chain: AIA download is not readable as a certificate: ${_url}"
    return 1
}

# Complete the chain from $1 (appending at most 4 links) -> $2
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
    log "chain: no self-signed root reached after ${_depth} links"
    return 1
}

# SHA-256 fingerprint of the locally stored leaf certificate
local_fingerprint() {
    "$OPENSSL" x509 -in "$CHAIN_FILE" -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/^.*=//'
}

# SHA-256 fingerprint of the certificate served at a port
# $1 = port
served_fingerprint() {
    printf '' | "$OPENSSL" s_client -connect "${FQDN}:$1" \
        -servername "$FQDN" 2>/dev/null \
        | "$OPENSSL" x509 -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/^.*=//'
}

# Deploy into one database through nameserver routing.
# $1 = database name; uses $SQL_TMP
# -E 1: makes hdbsql abort on SQL errors and return a non-zero exit code
# (the default is: errors on stderr only, exit code 0!)
deploy_db() {
    "$HDBSQL" -U "$USTORE_KEY" -d "$1" -x -E 1 -I "$SQL_TMP" >> "$LOG_FILE" 2>&1
}

# --------------------------- Preconditions ----------------------------------
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

# Lock (mkdir is atomic and POSIX)
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "lock ${LOCK_DIR} exists, another run is active -- aborting"
    exit 2
fi
HAVE_LOCK="yes"

# Make sure the SAP environment is present: under cron or as a --reloadcmd
# there is no <sid>adm profile (no login shell sourcing), so hdbsql is not in
# PATH and SAPSYSTEMNAME is empty. The interactive .sapenv.sh CANNOT be sourced
# reliably here -- it calls "tset", which fails without a controlling terminal
# and takes the whole run down with it. Instead of sourcing, we set the two
# values we actually need: SAPSYSTEMNAME (from the instance path) and the HANA
# client PATH (the instance's exe directory).
if [ -z "${SAPSYSTEMNAME:-}" ]; then
    # /usr/sap/<SID>/HDB<nn> -> take the SID from the path
    for _d in /usr/sap/[A-Z][A-Z0-9][A-Z0-9]/HDB[0-9][0-9]; do
        [ -d "$_d" ] || continue
        SAPSYSTEMNAME=$(printf '%s' "$_d" | sed 's#/usr/sap/\([^/]*\)/.*#\1#')
        export SAPSYSTEMNAME
        break
    done
fi
if ! command -v "$HDBSQL" >/dev/null 2>&1; then
    # hdbsql lives in the instance's exe directory; locate it by glob
    for _exe in /usr/sap/"${SAPSYSTEMNAME:-*}"/HDB[0-9][0-9]/exe/hdbsql \
                /usr/sap/"${SAPSYSTEMNAME:-*}"/SYS/exe/hdb/hdbsql; do
        _cand=$(ls -1 $_exe 2>/dev/null | head -n1)
        if [ -n "$_cand" ] && [ -x "$_cand" ]; then
            PATH="$(dirname "$_cand"):$PATH"
            export PATH
            log "hdbsql found: ${_cand}"
            break
        fi
    done
fi

command -v "$HDBSQL"  >/dev/null 2>&1 || die "hdbsql not in PATH (instance exe directory not found -- set HDBSQL to the full path in this script)"
command -v "$OPENSSL" >/dev/null 2>&1 || die "openssl not in PATH"

# --------------------------- Automatic detection ----------------------------
# SID from the <sid>adm environment
if [ -z "$SID" ]; then
    SID="${SAPSYSTEMNAME:-}"
    [ -n "$SID" ] || die "cannot determine SID: SAPSYSTEMNAME is empty -- run as <sid>adm or set SID in this script"
fi

# FQDN from the system; sanity check: it has to contain a dot
if [ -z "$FQDN" ]; then
    FQDN=$(hostname -f 2>/dev/null)
    case "$FQDN" in
        *.*) ;;
        *) die "hostname -f does not return an FQDN ('${FQDN}') -- set FQDN in this script" ;;
    esac
fi

# Instance number from the instance directory
if [ -z "$INSTANCE" ]; then
    set -- /usr/sap/"$SID"/HDB[0-9][0-9]
    [ -d "$1" ] || die "no instance directory /usr/sap/${SID}/HDB<nn> found -- set INSTANCE in this script"
    [ $# -eq 1 ] || die "several instance directories found under /usr/sap/${SID} -- set INSTANCE in this script"
    INSTANCE="${1##*HDB}"
fi
SYSDB_PORT="3${INSTANCE}13"

# Certificate paths, unless overridden. As <sid>adm, $HOME is
# /usr/sap/<SID>/home -- the absolute form is used so the paths also work
# when the script is invoked with a different HOME.
[ -n "$KEY_FILE" ]   || KEY_FILE="/usr/sap/${SID}/home/certs/host.key"
[ -n "$CHAIN_FILE" ] || CHAIN_FILE="/usr/sap/${SID}/home/certs/host.fullchain.pem"

# Database list: SystemDB plus every tenant with its SQL port.
# Requires CATALOG READ for ACME_RENEW in the SystemDB.
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
        *) die "database auto-discovery failed (does the hdbuserstore key ${USTORE_KEY} exist? is CATALOG READ granted?) -- set DATABASES in this script" ;;
    esac
fi

log "context: SID=${SID} INSTANCE=${INSTANCE} FQDN=${FQDN} DATABASES=${DATABASES}"

[ -r "$CHAIN_FILE" ] || die "full chain file missing or unreadable: $CHAIN_FILE"
LOCAL_FP=$(local_fingerprint)
[ -n "$LOCAL_FP" ] || die "could not determine the fingerprint from $CHAIN_FILE"

# =============================================================================
# Mode: deploy
# =============================================================================
if [ "$MODE" = "deploy" ]; then
    [ -r "$KEY_FILE" ] || die "key file missing or unreadable: $KEY_FILE"

    # Sanity check: does the key match the certificate?
    PUB_CERT=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -pubkey 2>/dev/null)
    PUB_KEY=$("$OPENSSL" pkey -in "$KEY_FILE" -pubout 2>/dev/null)
    if [ -z "$PUB_CERT" ] || [ "$PUB_CERT" != "$PUB_KEY" ]; then
        die "key ${KEY_FILE} does not match certificate ${CHAIN_FILE}"
    fi

    log "deploy starting, certificate fingerprint: ${LOCAL_FP}"

    # Build the PEM for HANA: private key first, then the COMPLETE chain
    # (leaf + intermediates + root). The key is normalised with "openssl pkey"
    # (PKCS#8): acme.sh ECC keys carry a leading "EC PARAMETERS" block that the
    # HANA parser does not understand.
    # umask 077 is in effect, so mktemp files are readable by us only.
    PEM_TMP=$(mktemp "${STATE_DIR}/pem.XXXXXX") || die "mktemp failed"
    "$OPENSSL" pkey -in "$KEY_FILE" > "$PEM_TMP" 2>> "$LOG_FILE" \
        || die "key normalisation (openssl pkey) failed"

    CHAIN_WORK="${STATE_DIR}/chainwork.$$"
    if [ -n "$ROOT_CA_FILE" ]; then
        [ -r "$ROOT_CA_FILE" ] || die "ROOT_CA_FILE not readable: $ROOT_CA_FILE"
        cat "$CHAIN_FILE" "$ROOT_CA_FILE" > "$CHAIN_WORK" \
            || die "building the PEM (root CA override) failed"
    else
        complete_chain "$CHAIN_FILE" "$CHAIN_WORK" \
            || die "could not complete the certificate chain up to the root (trust store/AIA, see log) -- set ROOT_CA_FILE in this script"
    fi
    cat "$CHAIN_WORK" >> "$PEM_TMP" || die "building the PEM failed"

    # Build the SQL file (a PEM contains no single quotes, so the literal is safe)
    SQL_TMP=$(mktemp "${STATE_DIR}/sql.XXXXXX") || die "mktemp failed"
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
            log "${DB_NAME}: fingerprint unchanged, skipped"
            OK="${OK} ${DB_NAME}(skip)"
            continue
        fi

        if deploy_db "$DB_NAME"; then
            printf '%s' "$LOCAL_FP" > "$MARKER"
            log "${DB_NAME}: deploy ok"
            OK="${OK} ${DB_NAME}"
        else
            log "${DB_NAME}: deploy FAILED (see log)"
            FAILED="${FAILED} ${DB_NAME}"
        fi
    done

    rm -f "$PEM_TMP" "$SQL_TMP" "$CHAIN_WORK"
    PEM_TMP=""; SQL_TMP=""; CHAIN_WORK=""

    if [ -n "$FAILED" ]; then
        write_spool 2 "deploy failed for:${FAILED} | ok:${OK:- -}"
        log "deploy finished with errors:${FAILED}"
        exit 1
    fi
    log "deploy succeeded for all databases:${OK}"
fi

# =============================================================================
# Port verification (runs after deploy and in verify mode)
# Special case during initial setup: if a database's PSE is not on PURPOSE SSL
# yet (activation still pending), the port cannot serve the new certificate --
# that is "pending" (WARN, exit 0), not a failure.
# =============================================================================
V_OK=""
V_FAIL=""
V_PEND=""

for ENTRY in $DATABASES; do
    DB_NAME="${ENTRY%%:*}"
    PORT="${ENTRY#*:}"

    SERVED_FP=$(served_fingerprint "$PORT")
    if [ "$SERVED_FP" = "$LOCAL_FP" ] && [ -n "$SERVED_FP" ]; then
        log "${DB_NAME}: port ${PORT} serves the current certificate"
        V_OK="${V_OK} ${DB_NAME}"
        continue
    fi

    # The port does not serve the new certificate -- is the PSE active at all?
    PURPOSE=$("$HDBSQL" -U "$USTORE_KEY" -d "$DB_NAME" -x -a -j \
        "SELECT IFNULL(PURPOSE,'') FROM SYS.PSES WHERE NAME = '${PSE_NAME}'" \
        2>> "$LOG_FILE" | head -n1 | tr -d '"')
    if [ "$PURPOSE" != "SSL" ]; then
        log "${DB_NAME}: PSE ${PSE_NAME} is not PURPOSE SSL yet -- activation pending"
        V_PEND="${V_PEND} ${DB_NAME}"
    elif [ -z "$SERVED_FP" ]; then
        log "${DB_NAME}: port ${PORT} unreachable or not TLS"
        V_FAIL="${V_FAIL} ${DB_NAME}:${PORT}(unreachable)"
    else
        log "${DB_NAME}: port ${PORT} serves an OLD certificate (${SERVED_FP})"
        V_FAIL="${V_FAIL} ${DB_NAME}:${PORT}(stale)"
    fi
done

EXPIRY=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -enddate 2>/dev/null \
    | sed 's/^notAfter=//')

# Remaining lifetime as a Checkmk metric (seconds). The metric name matches the
# built-in certificate checks -- Checkmk only renders a Perf-O-Meter for that
# name. The WARN/CRIT decision is computed here rather than delegated to
# Checkmk; the thresholds in the perfdata are informational.
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
    DAYS_TXT=" ($((REMAIN / 86400)) days remaining)"
    [ "$REMAIN" -le "$WARN_S" ] && CERT_STATE=1
    [ "$REMAIN" -le "$CRIT_S" ] && CERT_STATE=2
fi

# Timestamp of the last successful deploy (mtime of the newest marker)
DEPLOY_TXT=""
LAST_MARKER=$(ls -t "${STATE_DIR}"/deployed.* 2>/dev/null | head -n1)
if [ -n "$LAST_MARKER" ]; then
    DEPLOY_TXT=" | last deploy: $(date -r "$LAST_MARKER" '+%Y-%m-%d %H:%M')"
fi

if [ -n "$V_FAIL" ]; then
    write_spool 2 "certificate not active on:${V_FAIL} | ok:${V_OK:- -} | expires: ${EXPIRY}${DAYS_TXT}" "$PERF"
    exit 1
fi

if [ -n "$V_PEND" ]; then
    write_spool 1 "deployed, activation pending (sap_hana_cert_setup.sh activate):${V_PEND} | ok:${V_OK:- -} | expires: ${EXPIRY}${DAYS_TXT}" "$PERF"
    log "verification: activation pending for:${V_PEND}"
    exit 0
fi

if [ "$CERT_STATE" -gt 0 ]; then
    write_spool "$CERT_STATE" "certificate active, but the remaining lifetime is below the threshold -- check the renewal chain! | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT} | databases:${V_OK}" "$PERF"
else
    write_spool 0 "certificate active on all databases:${V_OK} | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT}" "$PERF"
fi
log "verification ok:${V_OK}${DAYS_TXT}"
exit 0
