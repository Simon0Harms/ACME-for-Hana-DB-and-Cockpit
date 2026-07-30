#!/bin/bash
# =============================================================================
# sap_hostagent_cert_renew_additional.sh
#
# "additional": Dieses Skript ist NICHT eigenstaendig lauffaehig, sondern ein
# Zusatzbaustein zur HANA-ACME-Suite. Es setzt voraus, dass die acme.sh-
# Einrichtung als <sid>adm abgeschlossen ist und das Zertifikat unter
# /usr/sap/<SID>/home/certs/ liegt (siehe README, Abschnitt 1) -- es stellt
# selbst KEINE Zertifikate aus.
#
# Importiert das per acme.sh (als <sid>adm) ausgestellte Host-Zertifikat in
# die SAPSSLS.pse des SAP Host Agent (Port 1129) und startet den Agent neu.
# Verwendet BEWUSST das bereits installierte Zertifikat aus
# /usr/sap/<SID>/home/certs/ -- KEIN eigener ACME-Account als root.
#
# Idempotent: Import + Restart nur, wenn sich der Zertifikats-Fingerprint
# geaendert hat. Kann damit gefahrlos taeglich per root-Cron laufen und
# nimmt Renewals binnen eines Tages automatisch auf.
#
# Aufrufmodi:
#   sap_hostagent_cert_renew_additional.sh deploy    Import bei geaendertem Fingerprint
#   sap_hostagent_cert_renew_additional.sh deploy --force
#   sap_hostagent_cert_renew_additional.sh verify    Nur Port-1129-Pruefung + Spool
#
# root-Cron (taeglich; deploy ist idempotent und schliesst verify ein):
#   45 6 * * * /opt/sap-acme/sap_hostagent_cert_renew_additional.sh deploy >/dev/null 2>&1
#
# Muss als root laufen (chown sapadm, saphostexec -restart).
# =============================================================================

set -u

# --------------------------- Konfiguration ----------------------------------
SEC=/usr/sap/hostctrl/exe/sec
EXE=/usr/sap/hostctrl/exe

# Zertifikatsquelle: die von "acme.sh --install-cert" (als <sid>adm) abgelegten
# Dateien. Leer lassen = automatische Ermittlung unter /usr/sap/*/home/certs/.
KEY_FILE=""
CHAIN_FILE=""

# Optionaler manueller Root-CA-Override (leer = automatische Vervollstaendigung)
ROOT_CA_FILE=""

FQDN=""                                   # leer = hostname -f
HA_PORT=1129                              # HTTPS-Port des Host Agent

MAILTO="sap-admins@example.com"
CMK_SPOOL=/var/lib/check_mk_agent/spool
CMK_MAX_AGE=90000                         # 25h -- Service wird stale, wenn der Cron ausfaellt
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
log() { printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$$" "$1" >> "$LOG_FILE"; }

write_spool() {  # $1=Status $2=Meldung $3=Perfdata (optional)
    [ -d "$CMK_SPOOL" ] || return 0
    local f="$CMK_SPOOL/${CMK_MAX_AGE}_sap_hostagent_cert" t
    t="$f.$$"
    {
        printf '<<<local:sep(0)>>>\n'
        printf '%s "%s" %s %s\n' "$1" "$CMK_SVC" "${3:--}" "$2"
    } > "$t" 2>/dev/null && mv "$t" "$f" 2>/dev/null \
        || log "WARNUNG: Spool-File $f nicht schreibbar"
}

send_mail() {  # $1=Subject $2=Body
    command -v mail >/dev/null 2>&1 || return 0
    printf '%s\n\nHost : %s\nZeit : %s\nLog  : %s\n' \
        "$2" "$(hostname -f)" "$(date '+%F %T')" "$LOG_FILE" \
        | mail -s "[$(hostname -s)] $1" "$MAILTO" 2>/dev/null || true
}

die() {
    log "FATAL: $1"
    printf 'FATAL: %s\n' "$1" >&2
    write_spool 2 "Zertifikatserneuerung FEHLGESCHLAGEN: $1"
    send_mail "CRIT: SAP Host Agent Zertifikat" "Die Erneuerung ist fehlgeschlagen: $1"
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

# ---- Kettenvervollstaendigung (identisch zur HANA-Suite) --------------------
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
        [ "$subj" = "$want" ] && { log "Kette: Truststore-Treffer: $c"; printf '%s\n' "$c"; return 0; }
    done
    [ -r "$CA_CACHE/$ih.pem" ] && { printf '%s\n' "$CA_CACHE/$ih.pem"; return 0; }
    url=$("$OPENSSL" x509 -in "$1" -noout -ext authorityInfoAccess 2>/dev/null \
        | sed -n 's/.*CA Issuers - URI://p' | head -n1)
    [ -n "$url" ] || { log "Kette: keine AIA-URL (issuer: $want)"; return 1; }
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
        [ -s "$CA_CACHE/$ih.pem" ] && { log "Kette: AIA geladen: $url"; printf '%s\n' "$CA_CACHE/$ih.pem"; return 0; }
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

# --------------------------- Vorbedingungen ---------------------------------
MODE="${1:-}"
FORCE="no"
[ "${2:-}" = "--force" ] && FORCE="yes"
case "$MODE" in
    deploy|verify) ;;
    *) printf 'Usage: %s deploy [--force] | verify\n' "$0" >&2; exit 2 ;;
esac

[ "$(id -u)" = "0" ] || { printf 'Muss als root laufen\n' >&2; exit 2; }
umask 077
mkdir -p "$STATE_DIR" "$CA_CACHE" || exit 2
trap cleanup EXIT INT TERM

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "Lock $LOCK_DIR existiert -- Abbruch"
    exit 2
fi
HAVE_LOCK="yes"

export SECUDIR="$SEC" LD_LIBRARY_PATH="$EXE"

if [ -z "$FQDN" ]; then
    FQDN=$(hostname -f 2>/dev/null)
    case "$FQDN" in *.*) ;; *) die "hostname -f liefert keinen FQDN ('$FQDN')";; esac
fi

# Zertifikatsquelle ermitteln: neueste install-cert-Ablage eines <sid>adm
if [ -z "$CHAIN_FILE" ]; then
    CHAIN_FILE=$(ls -t /usr/sap/[A-Z][A-Z0-9][A-Z0-9]/home/certs/host.fullchain.pem 2>/dev/null | head -n1)
    [ -n "$CHAIN_FILE" ] || die "Keine host.fullchain.pem unter /usr/sap/*/home/certs gefunden -- erst HANA-Einrichtung (acme.sh --install-cert) abschliessen"
    KEY_FILE="$(dirname "$CHAIN_FILE")/host.key"
fi
[ -r "$CHAIN_FILE" ] || die "Fullchain nicht lesbar: $CHAIN_FILE"
[ -r "$KEY_FILE" ]   || die "Key nicht lesbar: $KEY_FILE"

LOCAL_FP=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')
[ -n "$LOCAL_FP" ] || die "Fingerprint aus $CHAIN_FILE nicht ermittelbar"
log "Kontext: FQDN=$FQDN Quelle=$CHAIN_FILE FP=$LOCAL_FP"

# =============================================================================
# Modus: deploy (idempotent)
# =============================================================================
if [ "$MODE" = "deploy" ]; then
    if [ "$FORCE" = "no" ] && [ -f "$MARKER" ] && [ "$(cat "$MARKER")" = "$LOCAL_FP" ]; then
        log "Fingerprint unveraendert -- Import uebersprungen"
    else
        # Key/Cert-Match pruefen
        [ "$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -pubkey 2>/dev/null)" = \
          "$("$OPENSSL" pkey -in "$KEY_FILE" -pubout 2>/dev/null)" ] \
            || die "Key $KEY_FILE passt nicht zum Zertifikat $CHAIN_FILE"

        TMP_CHAIN=$(mktemp "$STATE_DIR/chain.XXXXXX")
        if [ -n "$ROOT_CA_FILE" ]; then
            [ -r "$ROOT_CA_FILE" ] || die "ROOT_CA_FILE nicht lesbar: $ROOT_CA_FILE"
            cat "$CHAIN_FILE" "$ROOT_CA_FILE" > "$TMP_CHAIN"
        else
            complete_chain "$CHAIN_FILE" "$TMP_CHAIN" \
                || die "Kette nicht bis zur Root vervollstaendigbar -- ROOT_CA_FILE setzen"
        fi

        # Key-Typ protokollieren (ECC-Keys deuten auf vergessenes
        # --keylength 2048 beim acme.sh-Issue hin)
        KEY_TYPE=$("$OPENSSL" pkey -in "$KEY_FILE" -noout -text 2>/dev/null | head -1)
        log "Key-Typ: ${KEY_TYPE:-unbekannt}"

        # PKCS#12 mit zufaelligem Einmal-Passwort (nur fuer diesen Prozess).
        # WICHTIG: explizit Legacy-Cipher (3DES/SHA1) -- der OpenSSL-3-Default
        # (AES/PBES2) ist fuer aeltere CommonCryptoLib/sapgenpse-Staende
        # unlesbar und laesst import_p12 fehlschlagen.
        P12PW=$("$OPENSSL" rand -hex 24)
        # sapgenpse import_p12 haengt an Dateinamen ohne .p12-Endung
        # stillschweigend ".p12" an und findet die Datei dann nicht --
        # der Temp-Name muss deshalb auf .p12 enden
        TMP_P12=$(mktemp "$STATE_DIR/p12.XXXXXX")
        mv "$TMP_P12" "$TMP_P12.p12"
        TMP_P12="$TMP_P12.p12"
        "$OPENSSL" pkcs12 -export \
            -inkey "$KEY_FILE" -in "$CHAIN_FILE" -certfile "$TMP_CHAIN" \
            -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
            -name saphostagent -passout pass:"$P12PW" -out "$TMP_P12" \
            2>>"$LOG_FILE" || die "PKCS#12-Export fehlgeschlagen"

        # Bestehende PSE sichern (import_p12 ueberschreibt nicht)
        if [ -f "$SEC/SAPSSLS.pse" ]; then
            cp -p "$SEC/SAPSSLS.pse" "$SEC/SAPSSLS.pse.$(date +%Y%m%d%H%M%S).bak"
            rm -f "$SEC/SAPSSLS.pse"
        fi
        rm -f "$SEC/cred_v2"

        "$EXE/sapgenpse" import_p12 -p "$SEC/SAPSSLS.pse" -x "" -z "$P12PW" "$TMP_P12" \
            >>"$LOG_FILE" 2>&1 || die "sapgenpse import_p12 fehlgeschlagen (Details: $LOG_FILE; haeufigste Ursachen: PKCS#12-Cipher oder ECC-Key)"
        "$EXE/sapgenpse" seclogin -p "$SEC/SAPSSLS.pse" -x "" -O sapadm \
            >>"$LOG_FILE" 2>&1 || die "sapgenpse seclogin fehlgeschlagen"

        chown sapadm:sapsys "$SEC/SAPSSLS.pse" "$SEC/cred_v2"
        chmod 600           "$SEC/SAPSSLS.pse" "$SEC/cred_v2"

        "$EXE/saphostexec" -restart >>"$LOG_FILE" 2>&1 || die "saphostexec -restart fehlgeschlagen"

        # Warten, bis Port 1129 das neue Zertifikat liefert
        ELAPSED=0
        while [ "$ELAPSED" -lt "$RESTART_TIMEOUT" ]; do
            [ "$(served_fingerprint)" = "$LOCAL_FP" ] && break
            sleep "$POLL_INTERVAL"; ELAPSED=$((ELAPSED + POLL_INTERVAL))
        done

        printf '%s' "$LOCAL_FP" > "$MARKER"
        log "Import + Restart abgeschlossen (Wartezeit: ${ELAPSED}s)"

        # Backup-Rotation: die letzten 5 behalten
        ls -t "$SEC"/SAPSSLS.pse.*.bak 2>/dev/null | tail -n +6 | xargs -r rm -f
    fi
fi

# =============================================================================
# Verifikation an Port 1129 (nach deploy und im Modus verify)
# =============================================================================
EXPIRY=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
PERF="-"; DAYS_TXT=""; CERT_STATE=0
END_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
if [ -n "$END_EPOCH" ]; then
    REMAIN=$((END_EPOCH - $(date +%s))); [ "$REMAIN" -lt 0 ] && REMAIN=0
    WARN_S=$((CERT_WARN_DAYS * 86400)); CRIT_S=$((CERT_CRIT_DAYS * 86400))
    PERF="certificate_remaining_validity=$REMAIN;$WARN_S;$CRIT_S"
    DAYS_TXT=" ($((REMAIN / 86400)) Tage verbleibend)"
    [ "$REMAIN" -le "$WARN_S" ] && CERT_STATE=1
    [ "$REMAIN" -le "$CRIT_S" ] && CERT_STATE=2
fi
DEPLOY_TXT=""
[ -f "$MARKER" ] && DEPLOY_TXT=" | letzter Deploy: $(date -r "$MARKER" '+%Y-%m-%d %H:%M')"

SERVED=$(served_fingerprint)
if [ -z "$SERVED" ]; then
    write_spool 2 "Port $HA_PORT nicht erreichbar oder kein TLS | expires (lokal): ${EXPIRY}${DAYS_TXT}" "$PERF"
    log "Verifikation: Port $HA_PORT nicht erreichbar"
    exit 1
elif [ "$SERVED" != "$LOCAL_FP" ]; then
    write_spool 2 "Port $HA_PORT liefert ALTES/FREMDES Zertifikat ($SERVED)${DEPLOY_TXT}" "$PERF"
    log "Verifikation: Port $HA_PORT liefert nicht das erwartete Zertifikat"
    exit 1
fi

if [ "$CERT_STATE" -gt 0 ]; then
    write_spool "$CERT_STATE" "Zertifikat aktiv, aber Restlaufzeit unterschreitet Schwellwert -- Renewal-Kette pruefen! | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT}" "$PERF"
else
    write_spool 0 "Zertifikat aktiv an Port $HA_PORT | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT}" "$PERF"
fi
log "Verifikation OK an Port ${HA_PORT}${DAYS_TXT}"
exit 0
