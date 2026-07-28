#!/bin/sh
# =============================================================================
# sap_hana_cockpit_cert_renew.sh
#
# Deploys ACME certificates (acme.sh) into the XSA platform router of a SAP
# HANA Cockpit installation (xs set-certificate) and restarts XSA so that the
# certificate becomes active. Afterwards it verifies the result with
# openssl s_client directly at the router port and writes a Checkmk spool file.
#
# SID, FQDN and instance number (and from those the API port 3<nn>30) are
# derived automatically; every value can be pinned in the configuration block
# below to override the automatic detection.
#
# CAUTION: "deploy" includes an XSA restart -- the cockpit UI is unavailable
# for a few minutes. Schedule the renewal accordingly (acme.sh cron at night).
#
# Modes:
#   sap_hana_cockpit_cert_renew.sh deploy   set certificate + XSA restart + verify
#   sap_hana_cockpit_cert_renew.sh verify   port verification and spool update only
#   sap_hana_cockpit_cert_renew.sh deploy --force
#                                           deploy even if the fingerprint is unchanged
#
# Location: this script is meant to live LOCALLY in the $HOME of the cockpit
# installation's <sid>adm ("$HOME"/sap_hana_cockpit_cert_renew.sh) rather than
# on a network share, so that the restart-critical deploy does not depend on a
# mount being available. After an update, copy it into place again:
#   install -m 755 /opt/sap-acme/sap_hana_cockpit_cert_renew.sh "$HOME"/
#
# Integration with acme.sh (run as the COCKPIT installation's <sid>adm):
#   "$HOME"/.acme.sh/acme.sh --install-cert -d "$(hostname -f)" \
#       --key-file       "$HOME/certs/host.key" \
#       --fullchain-file "$HOME/certs/host.fullchain.pem" \
#       --reloadcmd      "$HOME/sap_hana_cockpit_cert_renew.sh deploy"
#
# Cron (daily, keeps the Checkmk spool file fresh):
#   25 1 * * *  "$HOME"/sap_hana_cockpit_cert_renew.sh verify >/dev/null 2>&1
#
# Prerequisites (one-off):
#   - An XSA user (default acme_renew) with the role collection
#     XS_CONTROLLER_ADMIN, which is what set-certificate requires; see the
#     XSA_USER configuration block below for how to create it
#   - A password file (mode 600, owned by <sid>adm) holding one line, the
#     password only:
#       printf '%s\n' '<pw>' > ~/.xsa_cert_renew.pw && chmod 600 ~/.xsa_cert_renew.pw
#   - The XSA default domain has to match the certificate CN/SAN ("xs domains")
#
# Exit codes:
#   0 = ok, 1 = deploy or verification failed, 2 = precondition not met
# =============================================================================

set -u

# --------------------------- Configuration ----------------------------------
# Empty ("") = derive automatically. Set a value to override.
SID=""              # otherwise from $SAPSYSTEMNAME (<sid>adm environment)
FQDN=""             # otherwise from "hostname -f"
INSTANCE=""         # otherwise from /usr/sap/<SID>/HDB<nn>
KEY_FILE=""         # otherwise $HOME/certs/host.key
CHAIN_FILE=""       # otherwise $HOME/certs/host.fullchain.pem

# Optional root CA PEM as a MANUAL override for chain completion. Leave empty
# for automatic completion (system trust store, otherwise AIA download with a
# cache); if that fails, the original full chain is used, since the XSA router
# generally works without the root certificate in the blob.
ROOT_CA_FILE=""
XSA_API=""          # otherwise https://<FQDN>:3<nn>30
VERIFY_PORT=""      # otherwise 3<nn>30 (platform router / API endpoint)

# XSA access
# Dedicated technical user (create once as an XSA admin):
#   xs create-user acme_renew '<pw>' --no-password-change
#   xs assign-role-collection XS_CONTROLLER_ADMIN acme_renew
# Note the argument order of assign-role-collection: role collection first,
# then the user name.
XSA_USER="acme_renew"
XSA_PW_FILE="${HOME}/.xsa_cert_renew.pw"   # mode 600, one line: password of XSA_USER
XSA_ORG="orgname"                          # see "xs orgs"
XSA_SPACE="SAP"                            # see "xs spaces"

# How long to wait for the router after the XSA restart (seconds)
RESTART_TIMEOUT=900
POLL_INTERVAL=15

# Checkmk spool
SPOOL_DIR="/var/lib/check_mk_agent/spool"
SPOOL_MAX_AGE=90000                        # 25h -- "verify" runs daily
# Thresholds for the remaining lifetime (metric certificate_remaining_validity,
# in seconds).
CERT_WARN_DAYS=20
CERT_CRIT_DAYS=10

# Working directory for log, lock and deploy state
STATE_DIR="${HOME}/.sap_hana_cockpit_cert_renew"
LOG_FILE="${STATE_DIR}/renew.log"
LOCK_DIR="${STATE_DIR}/lock"
MARKER="${STATE_DIR}/deployed.fingerprint"

# xs and openssl binaries. Under cron they are located by glob in the instance
# and XSA directories (see below). If the glob does not find them, put the FULL
# path here (which xs / which openssl in the <sid>adm shell) -- that is the most
# robust option and skips the search entirely.
XS="xs"
OPENSSL="openssl"

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
    _spool_file="${SPOOL_DIR}/${SPOOL_MAX_AGE}_sap_hana_cockpit_cert_${_sid}"
    _spool_tmp="${_spool_file}.$$"
    {
        printf '<<<local:sep(0)>>>\n'
        printf '%s SAP_HANA_cockpit_cert_%s %s %s\n' "$1" "$_sid" "${3:--}" "$2"
    } > "$_spool_tmp" 2>/dev/null && mv "$_spool_tmp" "$_spool_file" 2>/dev/null \
        || log "WARNING: could not write spool file ${_spool_file}"
}

cleanup() {
    # do not leave a session open
    [ -n "${LOGGED_IN:-}" ] && "$XS" logout >> "$LOG_FILE" 2>&1
    [ -n "${CHAIN_WORK:-}" ] && rm -f "$CHAIN_WORK"
    [ -n "${KEY_WORK:-}" ] && { shred -u "$KEY_WORK" 2>/dev/null || rm -f "$KEY_WORK"; }
    rm -f "${STATE_DIR}/lastcert.$$" "${STATE_DIR}/aia_dl.$$" 2>/dev/null
    [ -n "${HAVE_LOCK:-}" ] && rmdir "$LOCK_DIR" 2>/dev/null
}

# ---- Automatic certificate chain completion ---------------------------------
# ACME full chains end at the intermediate, or at a cross-signed root. The
# missing links are resolved CA-agnostically: first from the system trust store
# (/etc/ssl/certs hash symlinks), otherwise downloaded via the AIA
# ("CA Issuers") URL and cached in ${STATE_DIR}/ca_cache.

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

    for _c in /etc/ssl/certs/"${_ih}".[0-9]*; do
        [ -r "$_c" ] || continue
        _subj=$("$OPENSSL" x509 -in "$_c" -noout -subject 2>/dev/null | sed 's/^subject=//')
        if [ "$_subj" = "$_want" ]; then
            log "chain: issuer found in system trust store: ${_c}"
            printf '%s\n' "$_c"
            return 0
        fi
    done

    if [ -r "${CA_CACHE}/${_ih}.pem" ]; then
        printf '%s\n' "${CA_CACHE}/${_ih}.pem"
        return 0
    fi

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

# SHA-256 fingerprint of the certificate served at the router port
served_fingerprint() {
    printf '' | "$OPENSSL" s_client -connect "${FQDN}:${VERIFY_PORT}" \
        -servername "$FQDN" 2>/dev/null \
        | "$OPENSSL" x509 -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/^.*=//'
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

# Make sure the SAP environment is present (under cron or as a --reloadcmd there
# is no <sid>adm profile). The interactive .sapenv.sh CANNOT be sourced reliably
# here -- it calls "tset", which fails without a controlling terminal and takes
# the whole run down with it. Instead of sourcing, we set what we need directly:
# SAPSYSTEMNAME (from the instance path) and the directories of xs and openssl
# (located by glob).
if [ -z "${SAPSYSTEMNAME:-}" ]; then
    for _d in /usr/sap/[A-Z][A-Z0-9][A-Z0-9]/HDB[0-9][0-9]; do
        [ -d "$_d" ] || continue
        SAPSYSTEMNAME=$(printf '%s' "$_d" | sed 's#/usr/sap/\([^/]*\)/.*#\1#')
        export SAPSYSTEMNAME
        break
    done
fi
if ! command -v "$XS" >/dev/null 2>&1; then
    # locate the XSA installation's xs CLI (instance bin or xs/bin)
    for _pat in /usr/sap/"${SAPSYSTEMNAME:-*}"/xs/bin/xs \
                /usr/sap/"${SAPSYSTEMNAME:-*}"/HDB[0-9][0-9]/exe/xscontroller/xs \
                /hana/shared/"${SAPSYSTEMNAME:-*}"/xs/bin/xs; do
        _cand=$(ls -1 $_pat 2>/dev/null | head -n1)
        if [ -n "$_cand" ] && [ -x "$_cand" ]; then
            PATH="$(dirname "$_cand"):$PATH"; export PATH
            log "xs found: ${_cand}"
            break
        fi
    done
fi
if ! command -v "$OPENSSL" >/dev/null 2>&1; then
    for _pat in /usr/sap/"${SAPSYSTEMNAME:-*}"/HDB[0-9][0-9]/exe/openssl \
                /usr/bin/openssl /bin/openssl; do
        _cand=$(ls -1 $_pat 2>/dev/null | head -n1)
        if [ -n "$_cand" ] && [ -x "$_cand" ]; then
            PATH="$(dirname "$_cand"):$PATH"; export PATH
            break
        fi
    done
fi

command -v "$OPENSSL" >/dev/null 2>&1 || die "openssl not in PATH (not found by glob -- set OPENSSL to the full path in this script)"

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

# Derived values, unless overridden
[ -n "$VERIFY_PORT" ] || VERIFY_PORT="3${INSTANCE}30"
[ -n "$XSA_API" ]     || XSA_API="https://${FQDN}:${VERIFY_PORT}"
[ -n "$KEY_FILE" ]    || KEY_FILE="${HOME}/certs/host.key"
[ -n "$CHAIN_FILE" ]  || CHAIN_FILE="${HOME}/certs/host.fullchain.pem"

log "context: SID=${SID} INSTANCE=${INSTANCE} FQDN=${FQDN} API=${XSA_API}"

[ -r "$CHAIN_FILE" ] || die "full chain file missing or unreadable: $CHAIN_FILE"
LOCAL_FP=$(local_fingerprint)
[ -n "$LOCAL_FP" ] || die "could not determine the fingerprint from $CHAIN_FILE"

# =============================================================================
# Mode: deploy
# =============================================================================
if [ "$MODE" = "deploy" ]; then
    command -v "$XS" >/dev/null 2>&1 || die "xs CLI not in PATH (run as the ${SID} <sid>adm, or set XS to the full path)"
    [ -r "$KEY_FILE" ] || die "key file missing or unreadable: $KEY_FILE"

    # Check the password file: present and not group- or world-readable
    [ -r "$XSA_PW_FILE" ] || die "password file missing: $XSA_PW_FILE"
    PW_PERM=$(ls -l "$XSA_PW_FILE" | cut -c5-10)
    case "$PW_PERM" in
        ------) ;;
        *) die "password file ${XSA_PW_FILE} must be mode 600" ;;
    esac

    # Sanity check: does the key match the certificate?
    PUB_CERT=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -pubkey 2>/dev/null)
    PUB_KEY=$("$OPENSSL" pkey -in "$KEY_FILE" -pubout 2>/dev/null)
    if [ -z "$PUB_CERT" ] || [ "$PUB_CERT" != "$PUB_KEY" ]; then
        die "key ${KEY_FILE} does not match certificate ${CHAIN_FILE}"
    fi

    # The key must not be encrypted (xs set-certificate rejects that)
    if grep -q 'ENCRYPTED' "$KEY_FILE"; then
        die "key ${KEY_FILE} is encrypted -- xs set-certificate needs an unencrypted PEM key"
    fi

    # Idempotence: only deploy when the certificate actually changed
    # (this avoids pointless XSA restarts)
    if [ "$FORCE" = "no" ] && [ -f "$MARKER" ] \
       && [ "$(cat "$MARKER")" = "$LOCAL_FP" ]; then
        log "fingerprint unchanged (${LOCAL_FP}), deploy skipped"
    else
        log "deploy starting, certificate fingerprint: ${LOCAL_FP}"

        # Complete the chain (best effort: the router usually works without the
        # root as well, so fall back to the original chain on failure)
        CHAIN_WORK="${STATE_DIR}/chainwork.$$"
        if [ -n "$ROOT_CA_FILE" ]; then
            [ -r "$ROOT_CA_FILE" ] || die "ROOT_CA_FILE not readable: $ROOT_CA_FILE"
            cat "$CHAIN_FILE" "$ROOT_CA_FILE" > "$CHAIN_WORK" \
                || die "building the chain (root CA override) failed"
        elif complete_chain "$CHAIN_FILE" "$CHAIN_WORK"; then
            :
        else
            log "WARNING: chain completion failed -- using the original full chain"
            cp "$CHAIN_FILE" "$CHAIN_WORK" || die "building the chain failed"
        fi

        # Login: the password is piped into "xs login --stdin" so that it does
        # NOT show up in the process list (ps). The --stdin flag is mandatory;
        # without it xs expects the password as a -p argument and aborts with
        # "Missing value for option 'PASSWORD'".
        if ! head -n1 "$XSA_PW_FILE" | "$XS" login -a "$XSA_API" -u "$XSA_USER" \
             -o "$XSA_ORG" -s "$XSA_SPACE" --stdin >> "$LOG_FILE" 2>&1; then
            write_spool 2 "xs login to ${XSA_API} failed"
            log "xs login failed"
            exit 1
        fi
        LOGGED_IN="yes"

        # Normalise the key to PKCS#8 PEM: acme.sh writes EC keys with a leading
        # "EC PARAMETERS" block, and traditional RSA/EC headers ("BEGIN RSA/EC
        # PRIVATE KEY") are not PKCS#8 either -- the XSA parser rejects both with
        # "FAILED to parse private key". "openssl pkey" produces
        # "BEGIN PRIVATE KEY" (PKCS#8), which xs set-certificate accepts.
        KEY_WORK="${STATE_DIR}/keywork.$$"
        "$OPENSSL" pkey -in "$KEY_FILE" > "$KEY_WORK" 2>> "$LOG_FILE" \
            || die "key normalisation (openssl pkey) failed"

        # This xs version uses the short options -k (key, unencrypted PKCS#8
        # PEM) and -c (certificate chain), not --key/--certificate.
        if ! "$XS" set-certificate "$FQDN" \
             -k "$KEY_WORK" \
             -c "$CHAIN_WORK" >> "$LOG_FILE" 2>&1; then
            write_spool 2 "xs set-certificate for ${FQDN} failed"
            log "xs set-certificate failed (is the domain correct? check 'xs domains')"
            exit 1
        fi
        log "set-certificate ok, restarting XSA"

        "$XS" logout >> "$LOG_FILE" 2>&1
        LOGGED_IN=""

        # Restart so that the platform router picks up the new certificate
        if ! XSA restart >> "$LOG_FILE" 2>&1; then
            write_spool 2 "XSA restart failed -- certificate was set but may not be active"
            log "XSA restart failed"
            exit 1
        fi

        # Wait until the router responds again and serves the new certificate
        ELAPSED=0
        while [ "$ELAPSED" -lt "$RESTART_TIMEOUT" ]; do
            SERVED_FP=$(served_fingerprint)
            [ "$SERVED_FP" = "$LOCAL_FP" ] && break
            sleep "$POLL_INTERVAL"
            ELAPSED=$((ELAPSED + POLL_INTERVAL))
        done

        printf '%s' "$LOCAL_FP" > "$MARKER"
        log "deploy finished (waited ${ELAPSED}s after the restart)"
    fi
fi

# =============================================================================
# Router port verification (runs after deploy and in verify mode)
# =============================================================================
EXPIRY=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -enddate 2>/dev/null \
    | sed 's/^notAfter=//')

# Remaining lifetime as a Checkmk metric (seconds). The metric name matches the
# built-in certificate checks -- Checkmk only renders a Perf-O-Meter for that
# name. The WARN/CRIT decision is computed here.
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

# Timestamp of the last successful deploy (mtime of the marker)
DEPLOY_TXT=""
if [ -f "$MARKER" ]; then
    DEPLOY_TXT=" | last deploy: $(date -r "$MARKER" '+%Y-%m-%d %H:%M')"
fi

SERVED_FP=$(served_fingerprint)
if [ -z "$SERVED_FP" ]; then
    write_spool 2 "router port ${VERIFY_PORT} unreachable or not TLS | expires (local file): ${EXPIRY}${DAYS_TXT}" "$PERF"
    log "verification: port ${VERIFY_PORT} unreachable"
    exit 1
elif [ "$SERVED_FP" != "$LOCAL_FP" ]; then
    write_spool 2 "router port ${VERIFY_PORT} serves an OLD certificate (${SERVED_FP}) | expected: ${LOCAL_FP}" "$PERF"
    log "verification: port ${VERIFY_PORT} serves an outdated certificate"
    exit 1
fi

if [ "$CERT_STATE" -gt 0 ]; then
    write_spool "$CERT_STATE" "certificate active, but the remaining lifetime is below the threshold -- check the renewal chain! | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT}" "$PERF"
else
    write_spool 0 "certificate active at router port ${VERIFY_PORT} | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT}" "$PERF"
fi
log "verification ok at port ${VERIFY_PORT}${DAYS_TXT}"
exit 0
