#!/bin/sh
# =============================================================================
# sap_hana_cockpit_cert_renew.sh
#
# Deployt ACME-Zertifikate (acme.sh) in den XSA Platform Router einer
# SAP-HANA-Cockpit-Installation (xs set-certificate) und startet XSA neu,
# damit das Zertifikat aktiv wird. Verifiziert anschliessend per
# openssl s_client direkt am Router-Port und schreibt ein
# CheckMK-Spool-File.
#
# SID, FQDN und Instanznummer (und damit der API-Port 3<nn>30) werden
# automatisch ermittelt; jede Groesse kann im Konfigurationsblock fest
# gesetzt werden, um die Ermittlung zu uebersteuern.
#
# ACHTUNG: "deploy" beinhaltet einen XSA-Neustart -- die Cockpit-Oberflaeche
# ist dabei einige Minuten nicht erreichbar. Renewal-Zeitpunkt entsprechend
# planen (acme.sh cronjob nachts).
#
# Aufrufmodi:
#   sap_hana_cockpit_cert_renew.sh deploy   Zertifikat setzen + XSA restart + verify
#   sap_hana_cockpit_cert_renew.sh verify   Nur Port-Verifikation + Spool-Update
#   sap_hana_cockpit_cert_renew.sh deploy --force
#                                           Deploy auch bei unveraendertem Fingerprint
#
# Ablage: Dieses Skript liegt LOKAL im $HOME des <sid>adm der Cockpit-
# Installation ("$HOME"/sap_hana_cockpit_cert_renew.sh), nicht auf dem
# NFS-Share -- so ist der (XSA-Neustart-kritische) Deploy vom NFS-Mount
# entkoppelt. Bei Updates aus /opt/sap-acme/ nach $HOME kopieren:
#   install -m 755 /opt/sap-acme/sap_hana_cockpit_cert_renew.sh "$HOME"/
#
# Integration mit acme.sh (als <sid>adm der COCKPIT-Installation):
#   "$HOME"/.acme.sh/acme.sh --install-cert -d "$(hostname -f)" \
#       --key-file       "$HOME/certs/host.key" \
#       --fullchain-file "$HOME/certs/host.fullchain.pem" \
#       --reloadcmd      "$HOME/sap_hana_cockpit_cert_renew.sh deploy"
#
# Cron (taeglich, haelt das CheckMK-Spool-File frisch):
#   25 1 * * *  "$HOME"/sap_hana_cockpit_cert_renew.sh verify >/dev/null 2>&1
#
# Voraussetzungen (einmalig):
#   - XSA-User acme_renew mit Rollcollection XS_CONTROLLER_ADMIN
#     (fuer set-certificate); Anlage siehe Konfigurationsblock XSA_USER
#   - Passwort-Datei (Mode 600, Owner <sid>adm), eine Zeile, nur das Passwort:
#       printf '%s\n' '<pw>' > ~/.xsa_cert_renew.pw && chmod 600 ~/.xsa_cert_renew.pw
#   - Die XSA-Default-Domain muss zum Zertifikats-CN/SAN passen ("xs domains")
#
# Exit-Codes:
#   0 = OK, 1 = Deploy/Verify fehlgeschlagen, 2 = Vorbedingung nicht erfuellt
# =============================================================================

set -u

# --------------------------- Konfiguration ----------------------------------
# Leer lassen ("") = automatische Ermittlung. Setzen = Uebersteuern.
SID=""              # sonst aus $SAPSYSTEMNAME (<sid>adm-Umgebung)
FQDN=""             # sonst aus "hostname -f"
INSTANCE=""         # sonst aus /usr/sap/<SID>/HDB<nn>
KEY_FILE=""         # sonst $HOME/certs/host.key
CHAIN_FILE=""       # sonst $HOME/certs/host.fullchain.pem

# Optional: Root-CA-PEM als MANUELLER Override fuer die Kettenvervollstaendigung.
# Leer lassen = automatische Vervollstaendigung (System-Truststore, sonst
# AIA-Download mit Cache); schlaegt sie fehl, wird die Original-Fullchain
# verwendet (der XSA-Router funktioniert i. d. R. auch ohne Root).
ROOT_CA_FILE=""
XSA_API=""          # sonst https://<FQDN>:3<nn>30
VERIFY_PORT=""      # sonst 3<nn>30 (Platform Router / API-Endpoint)

# XSA-Zugang
# Dedizierter technischer User (einmalig als XSA-Admin anlegen):
#   xs create-user acme_renew '<pw>' --no-password-change
#   xs assign-role-collection XS_CONTROLLER_ADMIN acme_renew
XSA_USER="acme_renew"
XSA_PW_FILE="${HOME}/.xsa_cert_renew.pw"   # Mode 600, eine Zeile: Passwort von XSA_USER
XSA_ORG="orgname"                          # siehe "xs orgs"
XSA_SPACE="SAP"                            # siehe "xs spaces"

# Wie lange nach dem XSA-Restart auf den Router warten (Sekunden)
RESTART_TIMEOUT=900
POLL_INTERVAL=15

# CheckMK-Spool
SPOOL_DIR="/var/lib/check_mk_agent/spool"
SPOOL_MAX_AGE=90000                        # 25h -- "verify" laeuft taeglich
# Schwellwerte fuer die Restlaufzeit (Metrik lifetime_remaining, Sekunden).
CERT_WARN_DAYS=20
CERT_CRIT_DAYS=10

# Arbeitsverzeichnis fuer Log, Lock und Deploy-State
STATE_DIR="${HOME}/.sap_hana_cockpit_cert_renew"
LOG_FILE="${STATE_DIR}/renew.log"
LOCK_DIR="${STATE_DIR}/lock"
MARKER="${STATE_DIR}/deployed.fingerprint"

# xs- und openssl-Binary. Werden unter Cron per Glob im Instanz-/XSA-
# Verzeichnis gesucht (siehe unten). Findet der Glob sie nicht, hier den
# VOLLEN Pfad eintragen (which xs / which openssl in der <sid>adm-Shell) --
# das ist der robusteste Weg und umgeht die Suche ganz.
XS="xs"
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
    _spool_file="${SPOOL_DIR}/${SPOOL_MAX_AGE}_sap_hana_cockpit_cert_${_sid}"
    _spool_tmp="${_spool_file}.$$"
    {
        printf '<<<local:sep(0)>>>\n'
        printf '%s SAP_HANA_cockpit_cert_%s %s %s\n' "$1" "$_sid" "${3:--}" "$2"
    } > "$_spool_tmp" 2>/dev/null && mv "$_spool_tmp" "$_spool_file" 2>/dev/null \
        || log "WARNUNG: Spool-File ${_spool_file} konnte nicht geschrieben werden"
}

cleanup() {
    # Session nicht offen liegen lassen
    [ -n "${LOGGED_IN:-}" ] && "$XS" logout >> "$LOG_FILE" 2>&1
    [ -n "${CHAIN_WORK:-}" ] && rm -f "$CHAIN_WORK"
    [ -n "${KEY_WORK:-}" ] && { shred -u "$KEY_WORK" 2>/dev/null || rm -f "$KEY_WORK"; }
    rm -f "${STATE_DIR}/lastcert.$$" "${STATE_DIR}/aia_dl.$$" 2>/dev/null
    [ -n "${HAVE_LOCK:-}" ] && rmdir "$LOCK_DIR" 2>/dev/null
}

# ---- Automatische Vervollstaendigung der Zertifikatskette -------------------
# ACME-Fullchains enden beim Intermediate bzw. bei cross-signierten Roots.
# Die fehlenden Glieder werden CA-unabhaengig ermittelt: zuerst aus dem
# System-Truststore (/etc/ssl/certs, Hash-Symlinks), sonst per AIA-URL
# ("CA Issuers") geladen und in ${STATE_DIR}/ca_cache gecacht.

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

    for _c in /etc/ssl/certs/"${_ih}".[0-9]*; do
        [ -r "$_c" ] || continue
        _subj=$("$OPENSSL" x509 -in "$_c" -noout -subject 2>/dev/null | sed 's/^subject=//')
        if [ "$_subj" = "$_want" ]; then
            log "Kette: Aussteller im System-Truststore gefunden: ${_c}"
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

# SHA256-Fingerprint des am Router-Port ausgelieferten Zertifikats
served_fingerprint() {
    printf '' | "$OPENSSL" s_client -connect "${FQDN}:${VERIFY_PORT}" \
        -servername "$FQDN" 2>/dev/null \
        | "$OPENSSL" x509 -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/^.*=//'
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

# SAP-Umgebung sicherstellen (unter Cron/reloadcmd fehlt das <sid>adm-Profil).
# Das interaktive .sapenv.sh laesst sich hier NICHT zuverlaessig sourcen --
# es ruft "tset" auf, das ohne Terminal abbricht und den ganzen Lauf killt.
# Statt zu sourcen, setzen wir die benoetigten Groessen direkt: SAPSYSTEMNAME
# (aus dem Instanzpfad) sowie die Verzeichnisse von xs und openssl (per Glob).
if [ -z "${SAPSYSTEMNAME:-}" ]; then
    for _d in /usr/sap/[A-Z][A-Z0-9][A-Z0-9]/HDB[0-9][0-9]; do
        [ -d "$_d" ] || continue
        SAPSYSTEMNAME=$(printf '%s' "$_d" | sed 's#/usr/sap/\([^/]*\)/.*#\1#')
        export SAPSYSTEMNAME
        break
    done
fi
if ! command -v "$XS" >/dev/null 2>&1; then
    # xs-CLI der XSA-Installation suchen (Instanz-bin bzw. xs/bin)
    for _pat in /usr/sap/"${SAPSYSTEMNAME:-*}"/xs/bin/xs \
                /usr/sap/"${SAPSYSTEMNAME:-*}"/HDB[0-9][0-9]/exe/xscontroller/xs \
                /hana/shared/"${SAPSYSTEMNAME:-*}"/xs/bin/xs; do
        _cand=$(ls -1 $_pat 2>/dev/null | head -n1)
        if [ -n "$_cand" ] && [ -x "$_cand" ]; then
            PATH="$(dirname "$_cand"):$PATH"; export PATH
            log "xs gefunden: ${_cand}"
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

command -v "$OPENSSL" >/dev/null 2>&1 || die "openssl nicht im PATH (SAP-Profil nicht gefunden/geladen -- im Cron '. \$HOME/.sapenv.sh;' voranstellen)"

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

# Abgeleitete Werte, falls nicht uebersteuert
[ -n "$VERIFY_PORT" ] || VERIFY_PORT="3${INSTANCE}30"
[ -n "$XSA_API" ]     || XSA_API="https://${FQDN}:${VERIFY_PORT}"
[ -n "$KEY_FILE" ]    || KEY_FILE="${HOME}/certs/host.key"
[ -n "$CHAIN_FILE" ]  || CHAIN_FILE="${HOME}/certs/host.fullchain.pem"

log "Kontext: SID=${SID} INSTANCE=${INSTANCE} FQDN=${FQDN} API=${XSA_API}"

[ -r "$CHAIN_FILE" ] || die "Fullchain-Datei fehlt/unlesbar: $CHAIN_FILE"
LOCAL_FP=$(local_fingerprint)
[ -n "$LOCAL_FP" ] || die "Konnte Fingerprint aus $CHAIN_FILE nicht ermitteln"

# =============================================================================
# Modus: deploy
# =============================================================================
if [ "$MODE" = "deploy" ]; then
    command -v "$XS" >/dev/null 2>&1 || die "xs-CLI nicht im PATH (als ${SID}-<sid>adm ausfuehren)"
    [ -r "$KEY_FILE" ] || die "Key-Datei fehlt/unlesbar: $KEY_FILE"

    # Passwort-Datei pruefen: vorhanden und nicht gruppen-/weltlesbar
    [ -r "$XSA_PW_FILE" ] || die "Passwort-Datei fehlt: $XSA_PW_FILE"
    PW_PERM=$(ls -l "$XSA_PW_FILE" | cut -c5-10)
    case "$PW_PERM" in
        ------) ;;
        *) die "Passwort-Datei ${XSA_PW_FILE} muss Mode 600 haben" ;;
    esac

    # Sanity-Check: passt der Key zum Zertifikat?
    PUB_CERT=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -pubkey 2>/dev/null)
    PUB_KEY=$("$OPENSSL" pkey -in "$KEY_FILE" -pubout 2>/dev/null)
    if [ -z "$PUB_CERT" ] || [ "$PUB_CERT" != "$PUB_KEY" ]; then
        die "Key ${KEY_FILE} passt nicht zum Zertifikat ${CHAIN_FILE}"
    fi

    # Key darf nicht verschluesselt sein (xs set-certificate lehnt das ab)
    if grep -q 'ENCRYPTED' "$KEY_FILE"; then
        die "Key ${KEY_FILE} ist verschluesselt -- xs set-certificate braucht unverschluesselten PEM-Key"
    fi

    # Idempotenz: nur deployen, wenn sich das Zertifikat geaendert hat
    # (erspart unnoetige XSA-Restarts)
    if [ "$FORCE" = "no" ] && [ -f "$MARKER" ] \
       && [ "$(cat "$MARKER")" = "$LOCAL_FP" ]; then
        log "Fingerprint unveraendert (${LOCAL_FP}), Deploy uebersprungen"
    else
        log "Deploy startet, Zertifikat-Fingerprint: ${LOCAL_FP}"

        # Kette vervollstaendigen (Best-Effort: der Router funktioniert i. d. R.
        # auch ohne Root, daher bei Fehlschlag Fallback auf die Original-Chain)
        CHAIN_WORK="${STATE_DIR}/chainwork.$$"
        if [ -n "$ROOT_CA_FILE" ]; then
            [ -r "$ROOT_CA_FILE" ] || die "ROOT_CA_FILE nicht lesbar: $ROOT_CA_FILE"
            cat "$CHAIN_FILE" "$ROOT_CA_FILE" > "$CHAIN_WORK" \
                || die "Kettenbau (Root-CA-Override) fehlgeschlagen"
        elif complete_chain "$CHAIN_FILE" "$CHAIN_WORK"; then
            :
        else
            log "WARNUNG: Kettenvervollstaendigung fehlgeschlagen -- verwende Original-Fullchain"
            cp "$CHAIN_FILE" "$CHAIN_WORK" || die "Kettenbau fehlgeschlagen"
        fi

        # Login: Passwort per stdin an "xs login --stdin" -- es taucht damit
        # NICHT in der Prozessliste (ps) auf. Das Flag --stdin ist zwingend,
        # sonst erwartet xs das Passwort als -p-Argument und bricht mit
        # "Missing value for option 'PASSWORD'" ab.
        if ! head -n1 "$XSA_PW_FILE" | "$XS" login -a "$XSA_API" -u "$XSA_USER" \
             -o "$XSA_ORG" -s "$XSA_SPACE" --stdin >> "$LOG_FILE" 2>&1; then
            write_spool 2 "xs login an ${XSA_API} fehlgeschlagen"
            log "xs login fehlgeschlagen"
            exit 1
        fi
        LOGGED_IN="yes"

        # Key nach PKCS8 PEM normalisieren: acme.sh liefert EC-Keys mit
        # vorangestelltem "EC PARAMETERS"-Block bzw. traditionelle RSA-/EC-
        # Header ("BEGIN RSA/EC PRIVATE KEY"), die der XSA-Parser mit
        # "FAILED to parse private key" ablehnt. "openssl pkey" erzeugt
        # daraus "BEGIN PRIVATE KEY" (PKCS8), das xs set-certificate versteht.
        KEY_WORK="${STATE_DIR}/keywork.$$"
        "$OPENSSL" pkey -in "$KEY_FILE" > "$KEY_WORK" 2>> "$LOG_FILE" \
            || die "Key-Normalisierung (openssl pkey) fehlgeschlagen"

        # Dieser xs-Stand nutzt die Kurzoptionen -k (Key, unverschluesselt,
        # PKCS8 PEM) und -c (Zertifikatskette), nicht --key/--certificate.
        if ! "$XS" set-certificate "$FQDN" \
             -k "$KEY_WORK" \
             -c "$CHAIN_WORK" >> "$LOG_FILE" 2>&1; then
            write_spool 2 "xs set-certificate fuer ${FQDN} fehlgeschlagen"
            log "xs set-certificate fehlgeschlagen (Domain korrekt? 'xs domains' pruefen)"
            exit 1
        fi
        log "set-certificate OK, starte XSA neu"

        "$XS" logout >> "$LOG_FILE" 2>&1
        LOGGED_IN=""

        # Restart, damit der Platform Router das neue Zertifikat laedt
        if ! XSA restart >> "$LOG_FILE" 2>&1; then
            write_spool 2 "XSA restart fehlgeschlagen -- Zertifikat gesetzt, aber evtl. nicht aktiv"
            log "XSA restart fehlgeschlagen"
            exit 1
        fi

        # Warten, bis der Router wieder antwortet und das neue Zertifikat liefert
        ELAPSED=0
        while [ "$ELAPSED" -lt "$RESTART_TIMEOUT" ]; do
            SERVED_FP=$(served_fingerprint)
            [ "$SERVED_FP" = "$LOCAL_FP" ] && break
            sleep "$POLL_INTERVAL"
            ELAPSED=$((ELAPSED + POLL_INTERVAL))
        done

        printf '%s' "$LOCAL_FP" > "$MARKER"
        log "Deploy abgeschlossen (Wartezeit nach Restart: ${ELAPSED}s)"
    fi
fi

# =============================================================================
# Verifikation am Router-Port (laeuft nach deploy und im Modus verify)
# =============================================================================
EXPIRY=$("$OPENSSL" x509 -in "$CHAIN_FILE" -noout -enddate 2>/dev/null \
    | sed 's/^notAfter=//')

# Restlaufzeit als CheckMK-Metrik (Sekunden). Metrikname wie bei den
# eingebauten Cert-Checks -- nur dafuer liefert CheckMK ein Perf-O-Meter.
# Die WARN/CRIT-Bewertung rechnet das Skript selbst.
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

# Zeitpunkt des letzten erfolgreichen Deploys (mtime des Markers)
DEPLOY_TXT=""
if [ -f "$MARKER" ]; then
    DEPLOY_TXT=" | letzter Deploy: $(date -r "$MARKER" '+%Y-%m-%d %H:%M')"
fi

SERVED_FP=$(served_fingerprint)
if [ -z "$SERVED_FP" ]; then
    write_spool 2 "Router-Port ${VERIFY_PORT} nicht erreichbar oder kein TLS | expires (lokal): ${EXPIRY}${DAYS_TXT}" "$PERF"
    log "Verifikation: Port ${VERIFY_PORT} nicht erreichbar"
    exit 1
elif [ "$SERVED_FP" != "$LOCAL_FP" ]; then
    write_spool 2 "Router-Port ${VERIFY_PORT} liefert ALTES Zertifikat (${SERVED_FP}) | erwartet: ${LOCAL_FP}" "$PERF"
    log "Verifikation: Port ${VERIFY_PORT} liefert veraltetes Zertifikat"
    exit 1
fi

if [ "$CERT_STATE" -gt 0 ]; then
    write_spool "$CERT_STATE" "Zertifikat aktiv, aber Restlaufzeit unterschreitet Schwellwert -- Renewal-Kette pruefen! | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT}" "$PERF"
else
    write_spool 0 "Zertifikat aktiv am Router-Port ${VERIFY_PORT} | expires: ${EXPIRY}${DAYS_TXT}${DEPLOY_TXT}" "$PERF"
fi
log "Verifikation OK am Port ${VERIFY_PORT}${DAYS_TXT}"
exit 0
