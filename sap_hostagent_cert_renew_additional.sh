#!/bin/bash
# =============================================================================
# sap_hostagent_cert_renew_additional.sh
#
# "additional": this script is NOT standalone, it is an add-on to the HANA ACME
# suite. It assumes that the acme.sh setup as <sid>adm is complete and that the
# certificate is present under /usr/sap/<SID>/home/certs/ (see the HANA
# documentation) -- it never requests a certificate from a CA itself.
#
# Imports the host certificate issued by acme.sh (as <sid>adm) into the
# SAPSSLS.pse of the SAP Host Agent (port 1129) and restarts the agent.
# It DELIBERATELY consumes the already installed certificate from
# /usr/sap/<SID>/home/certs/ -- no separate ACME account as root.
#
# Idempotent: import and restart happen only when the certificate fingerprint
# changed. It can therefore run safely from root's crontab every day and picks
# up renewals within 24 hours.
#
# Modes:
#   sap_hostagent_cert_renew_additional.sh deploy    import if the fingerprint changed
#   sap_hostagent_cert_renew_additional.sh deploy --force
#   sap_hostagent_cert_renew_additional.sh verify    port 1129 check and spool only
#
# root cron (daily; deploy is idempotent and includes the verification):
#   45 1 * * * /opt/sap-acme/sap_hostagent_cert_renew_additional.sh deploy >/dev/null 2>&1
#
# Must run as root (chown sapadm, saphostexec -restart).
# =============================================================================

set -u

# --------------------------- Configuration ----------------------------------
SEC=/usr/sap/hostctrl/exe/sec
EXE=/usr/sap/hostctrl/exe

# Certificate source: the files written by "acme.sh --install-cert" (as
# <sid>adm). Leave empty to detect them under /usr/sap/*/home/certs/.
KEY_FILE=""
CHAIN_FILE=""

# Optional manual root CA override (empty = automatic chain completion)
ROOT_CA_FILE=""

FQDN=""                                   # empty = hostname -f
HA_PORT=1129                              # HTTPS port of the Host Agent

MAILTO="sap-admins@example.com"
CMK_SPOOL=/var/lib/check_mk_agent/spool
CMK_MAX_AGE=90000                         # 25h -- the service goes stale if cron stops
CMK_SVC="SAP HostAgent Cert"
CERT_WARN_DAYS=20
CERT_CRIT_DAYS=10

RESTART_TIMEOUT=180
POLL_INTERVAL=5

STATE_DIR=/root/.sap_hostagent_cert_renew
LOG_FILE="$STATE_DIR/renew.log"
LOCK_DIR="$STATE_DIR/lock"
MARKER="$STATE_DIR/deployed.fingerprint"
CA_CACHE="$STATE_DIR/ca_cache"
OPENSSL=openssl

# --------------------------- Helper functions -------------------------------
log() { printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$$" "$1" >> "$LOG_FILE"; }

write_spool() {  # $1=state $2=message $3=perfdata (optional)
    [ -d "$CMK_SPOOL" ] || return 0
    local f="$CMK_SPOOL/${CMK_MAX_AGE}_sap_hostagent_cert" t
    t="$f.$$"
    {
        printf '<<<local:sep(0)>>>\n'
        printf '%s "%s" %s %s\n' "$1" "$CMK_SVC" "${3:--}" "$2"
    } > "$t" 2>/dev/null && mv "$t" "$f" 2>/dev/null \
        || log "WARNING: spool file $f is not writable"
}

send_mail() {  # $1=subject $2=body
    command -v mail >/dev/null 2>&1 || return 0
    printf '%s\n\nHost : %s\nTime : %s\nLog  : %s\n' \
        "$2" "$(hostname -f)" "$(date '+%F %T')" "$LOG_FILE" \
        | mail -s "[$(hostname -s)] $1" "$MAILTO" 2>/dev/null || true
}

die() {
    log "FATAL: $1"
    printf 'FATAL: %s\n' "$1" >&2
    write_spool 2 "certificate renewal FAILED: $1"
    send_mail "CRIT: SAP Host Agent certificate" "The renewal failed: $1"
    exit 2
}

cleanup() {
    [ -n "${TMP_P12:-}" ]   && shred -u "$TMP_P12"   2>/dev/null
    [ -n "${TMP_CHAIN:-}" ] && rm -f "$TMP_CHAIN"
    rm -f "$STATE_DIR/lastcert.$$" "$STATE_DIR/aia_dl.$$" 2>/dev/null
    [ -n "${HAVE_LOCK:-}" ] && rmdir "$LOCK_DIR" 2>/dev/null
}

served_fingerprint() {
    printf '' | "$OPENSSL" s_client -connect "${FQDN}:${HA_PORT}" \
        -servername "$FQDN" 2>/dev/null \
        | "$OPENSSL" x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//'
}

# ---- Chain completion (identical to the HANA suite) -------------------------
last_cert() {
    awk '/-----BEGIN CERTIFICATE-----/{buf=""; inb=1}
         inb{buf=buf $0 "\n"}
         /-----END CERTIFICATE-----/{inb=0; last=buf}
         END{printf "%s", last}' "$1"
}
is_self_signed() {
    [ "$("$OPENSSL" x509 -in "$1" -noout -subject_hash 2>/dev/null)" = \
      "$("$OPENSSL" x509 -in "$1" -noout -issuer_hash 2>/dev/null)" ]
}
fetch_issuer() {
    local ih want c subj url dl
    ih=$("$OPENSSL" x509 -in "$1" -noout -issuer_hash 2>/dev/null)
    want=$("$OPENSSL" x509 -in "$1" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    [ -n "$ih" ] || return 1
    for c in /etc/ssl/certs/"$ih".[0-9]*; do
        [ -r "$c" ] || continue
        subj=$("$OPENSSL" x509 -in "$c" -noout -subject 2>/dev/null | sed 's/^subject=//')
        [ "$subj" = "$want" ] && { log "chain: trust store hit: $c"; printf '%s\n' "$c"; return 0; }
    done
    [ -r "$CA_CACHE/$ih.pem" ] && { printf '%s\n' "$CA_CACHE/$ih.pem"; return 0; }
    url=$("$OPENSSL" x509 -in "$1" -noout -ext authorityInfoAccess 2>/dev/null \
        | sed -n 's/.*CA Issuers - URI://p' | head -n1)
    [ -n "$url" ] || { log "chain: no AIA URL (issuer: $want)"; return 1; }
    dl="$STATE_DIR/aia_dl.$$"
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 30 -o "$dl" "$url" 2>>"$LOG_FILE" || { rm -f "$dl"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 30 -O "$dl" "$url" 2>>"$LOG_FILE" || { rm -f "$dl"; return 1; }
    else
        return 1
    fi
    if "$OPENSSL" x509 -inform DER -in "$dl" 2>/dev/null > "$dl.pem" \
       || "$OPENSSL" x509 -inform PEM -in "$dl" 2>/dev/null > "$dl.pem" \
       || "$OPENSSL" pkcs7 -inform DER -in "$dl" -print_certs 2>/dev/null > "$dl.pem" \
       || "$OPENSSL" pkcs7 -inform PEM -in "$dl" -print_certs 2>/dev/null > "$dl.pem"; then
        sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$dl.pem" > "$CA_CACHE/$ih.pem"
        rm -f "$dl" "$dl.pem"
        [ -s "$CA_CACHE/$ih.pem" ] && { log "chain: fetched via AIA: $url"; printf '%s\n' "$CA_CACHE/$ih.pem"; return 0; }
    fi
    rm -f "$dl" "$dl.pem"
    return 1
}
complete_chain() {
    cp "$1" "$2" || return 1
    local depth=0 last="$STATE_DIR/lastcert.$$" iss
    while [ "$depth" -lt 4 ]; do
        last_cert "$2" > "$last"
        is_self_signed "$last" && { rm -f "$last"; return 0; }
        iss=$(fetch_issuer "$last") || { rm -f "$last"; return 1; }
        cat "$iss" >> "$2" || { rm -f "$last"; return 1; }
        depth=$((depth + 1))
    done
    rm -f "$last"
    return 1
}

# --------------------------- Preconditions ----------------------------------
MODE="${1:-}"
FORCE="no"
[ "${2:-}" = "--force" ] && FORCE="yes"
case "$MODE" in
    deploy|verify) ;;
    *) printf 'Usage: %s deploy [--force] | verify\n' "$0" >&2; exit 2 ;;
esac

[ "$(id -u)" = "0" ] || { printf 'Must run as root\n' >&2; exit 2; }
umask 077
mkdir -p "$STATE_DIR" "$CA_CACHE" || exit 2
trap cleanup EXIT INT TERM

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "lock $LOCK_DIR exists -- aborting"
    exit 2
fi
HAVE_LOCK="yes"

export SECUDIR="$SEC" LD_LIBRARY_PATH="$EXE"

if [ -z "$FQDN" ]; then
    FQDN=$(hostname -f 2>/dev/null)
    case "$FQDN" in *.*) ;; *) die "hostname -f does not return an FQDN ('$FQDN')";; esac
fi

# Locate the certificate source: the most recent install-cert location of any <sid>adm
if [ -z "$CHAIN_FILE" ]; then
    CHAIN_FILE=$(ls -t /usr/sap/[A-Z][A-Z0-9][A-Z0-9]/home/certs/host.fullchain.pem 2>/dev/null | head -n1)
    [ -n "$CHAIN_FILE" ] || die "no host.fullchain.pem found under /usr/sap/*/home/certs -- complete the HANA setup (acme.sh --install-cert) first"
    KEY_FILE="$(dirname "$CHAIN_FILE")/host.key"
fi
[ -r "$CHAIN_FILE" ] || die "full chain not readable: $CHAIN_FILE"
[ -r "$KEY_FILE" ]   || die "key not readable: $KEY_FILE"

LOCAL_FP=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')
[ -n "$LOCAL_FP" ] || die "cannot determine the fingerprint from $CHAIN_FILE"
log "context: FQDN=$FQDN source=$CHAIN_FILE FP=$LOCAL_FP"

# =============================================================================
# Mode: deploy (idempotent)
# =============================================================================
if [ "$MODE" = "deploy" ]; then
    if [ "$FORCE" = "no" ] && [ -f "$MARKER" ] && [ "$(cat "$MARKER")" = "$LOCAL_FP" ]; then
        log "fingerprint unchanged -- import skipped"
    else
        # Verify that the key matches the certificate
        [ "$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -pubkey 2>/dev/null)" = \
          "$("$OPENSSL" pkey -in "$KEY_FILE" -pubout 2>/dev/null)" ] \
            || die "key $KEY_FILE does not match certificate $CHAIN_FILE"

        TMP_CHAIN=$(mktemp "$STATE_DIR/chain.XXXXXX")
        if [ -n "$ROOT_CA_FILE" ]; then
            [ -r "$ROOT_CA_FILE" ] || die "ROOT_CA_FILE not readable: $ROOT_CA_FILE"
            cat "$CHAIN_FILE" "$ROOT_CA_FILE" > "$TMP_CHAIN"
        else
            complete_chain "$CHAIN_FILE" "$TMP_CHAIN" \
                || die "could not complete the chain up to the root -- set ROOT_CA_FILE"
        fi

        # Log the key type (useful when diagnosing CommonCryptoLib limits)
        KEY_TYPE=$("$OPENSSL" pkey -in "$KEY_FILE" -noout -text 2>/dev/null | head -1)
        log "key type: ${KEY_TYPE:-unknown}"

        # PKCS#12 with a random one-time password (valid for this process only).
        # IMPORTANT: request the legacy ciphers (3DES/SHA1) explicitly -- the
        # OpenSSL 3 default (AES/PBES2) is unreadable for older
        # CommonCryptoLib/sapgenpse builds and makes import_p12 fail.
        P12PW=$("$OPENSSL" rand -hex 24)
        # sapgenpse import_p12 silently appends ".p12" to a filename that does
        # not end in .p12 and then cannot find the file -- so the temporary name
        # has to carry the suffix.
        TMP_P12=$(mktemp "$STATE_DIR/p12.XXXXXX")
        mv "$TMP_P12" "$TMP_P12.p12"
        TMP_P12="$TMP_P12.p12"
        "$OPENSSL" pkcs12 -export \
            -inkey "$KEY_FILE" -in "$CHAIN_FILE" -certfile "$TMP_CHAIN" \
            -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
            -name saphostagent -passout pass:"$P12PW" -out "$TMP_P12" \
            2>>"$LOG_FILE" || die "PKCS#12 export failed"

        # Back up the existing PSE (import_p12 does not overwrite)
        if [ -f "$SEC/SAPSSLS.pse" ]; then
            cp -p "$SEC/SAPSSLS.pse" "$SEC/SAPSSLS.pse.$(date +%Y%m%d%H%M%S).bak"
            rm -f "$SEC/SAPSSLS.pse"
        fi
        rm -f "$SEC/cred_v2"

        "$EXE/sapgenpse" import_p12 -p "$SEC/SAPSSLS.pse" -x "" -z "$P12PW" "$TMP_P12" \
            >>"$LOG_FILE" 2>&1 || die "sapgenpse import_p12 failed (details: $LOG_FILE; most common causes: PKCS#12 cipher or an ECDSA key on an older CommonCryptoLib)"
        "$EXE/sapgenpse" seclogin -p "$SEC/SAPSSLS.pse" -x "" -O sapadm \
            >>"$LOG_FILE" 2>&1 || die "sapgenpse seclogin failed"

        chown sapadm:sapsys "$SEC/SAPSSLS.pse" "$SEC/cred_v2"
        chmod 600           "$SEC/SAPSSLS.pse" "$SEC/cred_v2"

        "$EXE/saphostexec" -restart >>"$LOG_FILE" 2>&1 || die "saphostexec -restart failed"

        # Wait until port 1129 serves the new certificate
        ELAPSED=0
        while [ "$ELAPSED" -lt "$RESTART_TIMEOUT" ]; do
            [ "$(served_fingerprint)" = "$LOCAL_FP" ] && break
            sleep "$POLL_INTERVAL"; ELAPSED=$((ELAPSED + POLL_INTERVAL))
        done

        printf '%s' "$LOCAL_FP" > "$MARKER"
        log "import and restart finished (waited ${ELAPSED}s)"

        # Backup rotation: keep the last five
        ls -t "$SEC"/SAPSSLS.pse.*.bak 2>/dev/null | tail -n +6 | xargs -r rm -f
    fi
fi

# =============================================================================
# Verification at port 1129 (after deploy and in verify mode)
# =============================================================================
EXPIRY=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
PERF="-"; DAYS_TXT=""; CERT_STATE=0
END_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
if [ -n "$END_EPOCH" ]; then
    REMAIN=$((END_EPOCH - $(date +%s))); [ "$REMAIN" -lt 0 ] && REMAIN=0
    WARN_S=$((CERT_WARN_DAYS * 86400)); CRIT_S=$((CERT_CRIT_DAYS * 86400))
    PERF="certificate_remaining_validity=$REMAIN;$WARN_S;$CRIT_S"
    DAYS_TXT=" ($((REMAIN / 86400)) days remaining)"
    [ "$REMAIN" -le "$WARN_S" ] && CERT_STATE=1
    [ "$REMAIN" -le "$CRIT_S" ] && CERT_STATE=2
fi
DEPLOY_TXT=""
[ -f "$MARKER" ] && DEPLOY_TXT=" | last deploy: $(date -r "$MARKER" '+%Y-%m-%d %H:%M')"

SERVED=$(served_fingerprint)
if [ -z "$SERVED" ]; then
    write_spool 2 "port $HA_PORT unreachable or not TLS | expires (local file): ${EXPIRY}${DAYS_TXT}" "$PERF"
    log "verification: port $HA_PORT unreachable"
    exit 1
elif [ "$SERVED" != "$LOCAL_FP" ]; then
    write_spool 2 "port $HA_PORT serves an OLD or foreign certificate ($SERVED)${DEPLOY_TXT}" "$PERF"
    log "verification: port $HA_PORT does not serve the expected certificate"
    exit 1
fi

if [ "$CERT_STATE" -gt 0 ]; then
    write_spool "$CERT_STATE" "certificate active, but the remaining lifetime is below the threshold -- check the renewal chain! | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT}" "$PERF"
else
    write_spool 0 "certificate active at port $HA_PORT | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT}" "$PERF"
fi
log "verification ok at port ${HA_PORT}${DAYS_TXT}"
exit 0
