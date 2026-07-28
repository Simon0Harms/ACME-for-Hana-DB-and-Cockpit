# sap-acme-certs

Automated TLS certificate renewal for SAP HANA landscapes using [acme.sh](https://github.com/acmesh-official/acme.sh).

One certificate per host, issued once by any ACME CA, distributed to every TLS endpoint that needs it:

| Endpoint | Mechanism | Restart required? |
|---|---|---|
| HANA SQL/HTTP ports (SystemDB + all tenants) | in-database PSE, `ALTER PSE ... SET OWN CERTIFICATE` | no |
| SAP HANA Cockpit / XS Advanced router | `xs set-certificate` | yes, XSA restart |
| SAP Host Agent (port 1129) | file-based `SAPSSLS.pse`, `sapgenpse import_p12` | yes, short agent restart |

Every script verifies its work: after deploying, it opens a TLS connection to the port and compares the SHA-256 fingerprint of the served certificate against the local file. The result is published as a Checkmk local check, so a silently broken renewal chain becomes visible instead of expiring unnoticed.

## Why this exists

The usual advice for SAP TLS automation is "swap the file-based PSE and restart the database". That does not work for 60-day ACME renewal cycles. These scripts use the in-database PSE for HANA (effective immediately, no downtime) and accept a restart only where the product leaves no choice (XSA router, Host Agent).

The other half of the value is the list of SAP-specific traps in [SAP quirks](#sap-quirks-hard-won). Each one cost a debugging session; all of them are handled by the scripts now.

## Contents

```
scripts/
  sap_hana_cert_renew.sh                    # HANA in-database PSE, all databases
  sap_hana_cert_setup.sh                    # interactive first-time setup (user, PSE, trust anchor)
  sap_hana_cockpit_cert_renew.sh            # XSA platform router
  sap_hostagent_cert_renew_additional.sh    # SAP Host Agent (runs as root)
  hana_acme_setup.sql                       # manual equivalent of the setup script
docs/
  hana-database.md                          # HANA databases + Host Agent
  hana-cockpit.md                           # HANA Cockpit / XSA router
```

`_additional` in the Host Agent script name means: **not standalone**. It consumes the certificate that the `<sid>adm` ACME setup already produced; it never talks to a CA itself.

## Requirements

- SAP HANA 2.0 (MDC) for the in-database PSE path; XS Advanced for the cockpit path
- acme.sh installed and working as `<sid>adm` (no root required for issuance)
- `openssl` and, per use case, `hdbsql` or the `xs` CLI
- Checkmk agent with a writable spool directory (optional — without it you lose monitoring, not function)
- POSIX `sh`; the Host Agent script is Bash and expects Linux paths

Tested on SLES 15 with HANA 2.0 SPS07 and a CA requiring External Account Binding. Other distributions and CAs should work — the scripts avoid CA-specific logic — but have not been verified.

## Quick start (HANA databases)

Run as `<sid>adm`. Replace `/opt/sap-acme` with wherever you keep these scripts and `host.example.com` with your FQDN.

```sh
# 1. one-off: make the Checkmk spool writable for <sid>adm (as root)
chgrp sapsys /var/lib/check_mk_agent/spool && chmod g+ws /var/lib/check_mk_agent/spool

# 2. install acme.sh and register with your CA
git clone https://github.com/acmesh-official/acme.sh.git "$HOME"/.acme.sh
"$HOME"/.acme.sh/acme.sh --register-account \
    --server '<acme-directory-url>' \
    --accountemail 'sap-admins@example.com' \
    --eab-kid '<kid>' --eab-hmac-key '<hmac-key>'      # only for CAs requiring EAB

# 3. prepare every database (creates user, PSE, trust anchor, userstore key)
/opt/sap-acme/sap_hana_cert_setup.sh setup

# 4. issue and install — --install-cert triggers the first deploy via reloadcmd
"$HOME"/.acme.sh/acme.sh --issue --standalone \
    --server '<acme-directory-url>' -d host.example.com

mkdir -p "$HOME/certs"
"$HOME"/.acme.sh/acme.sh --install-cert -d host.example.com \
    --key-file       "$HOME/certs/host.key" \
    --fullchain-file "$HOME/certs/host.fullchain.pem" \
    --reloadcmd      "/opt/sap-acme/sap_hana_cert_renew.sh deploy"

# 5. activate the PSE (maintenance window: clients must trust the new chain)
/opt/sap-acme/sap_hana_cert_setup.sh activate

# 6. cron
crontab -e
```

```cron
5 1 * * *  "$HOME"/.acme.sh/acme.sh --cron --home "$HOME"/.acme.sh >/dev/null 2>&1
15 1 * * * /opt/sap-acme/sap_hana_cert_renew.sh verify >/dev/null 2>&1
```

Order matters: `setup` → issue/install → `activate`. Activating the PSE before the first deploy points new TLS connections at a PSE without a certificate.

Full walkthrough: [docs/hana-database.md](docs/hana-database.md) · Cockpit: [docs/hana-cockpit.md](docs/hana-cockpit.md)

## Modes

| Invocation | Effect |
|---|---|
| `deploy` | deploy if the fingerprint changed, then verify — this is what acme.sh calls as `--reloadcmd` |
| `deploy --force` | deploy regardless of the fingerprint marker (first run, repair) |
| `verify` | verify the port and update the monitoring spool file only |

Exit codes: `0` ok, `1` deploy or verification failed, `2` precondition not met (lock, missing files, discovery failure).

Everything is derived at runtime — SID from `$SAPSYSTEMNAME` or the instance path, FQDN from `hostname -f`, instance number from `/usr/sap/<SID>/HDB<nn>`, and the database list from `SYS_DATABASES.M_SERVICES`. New tenants are picked up automatically. Every value can be pinned in the configuration block at the top of each script, e.g. for virtual hostnames.

## Monitoring

Each script writes a Checkmk local check through a spool file with a 25-hour max age:

```
0 "SAP_HANA_cert_<SID>" certificate_remaining_validity=17189859;1728000;864000 \
  Certificate active on all databases: SB1 SYSTEMDB | expires: ... | last deploy: ...
```

Three failure modes are covered, deliberately:

**Wrong certificate served** → CRIT. The fingerprint comparison catches a renewal that produced a new local file but never reached the port — the failure mode that is otherwise invisible until expiry.

**Remaining lifetime below threshold** → WARN/CRIT (default 20/10 days). Since acme.sh renews after 60 days, crossing that line means at least one renewal cycle was lost. The alert arrives weeks before anything actually expires.

**The check itself stopped running** → stale, via the 25-hour spool max age. This is not decoration: the one real incident during development was a `--reloadcmd` that died before writing the spool file, and stale was the only signal that existed.

Use the metric name `certificate_remaining_validity` (seconds). Checkmk only renders a Perf-O-Meter for metric names it knows, and this is the one the built-in certificate checks use. A custom name gives you a graph but no Perf-O-Meter. The WARN/CRIT decision is computed in the script rather than delegated to Checkmk, so the semantics are visible in the code.

## Security notes

Private keys stay local. Key and full chain live under `$HOME/certs/` of the `<sid>adm`; only the scripts are shared. Do not place private keys on a network share.

If you distribute the scripts from a shared directory, treat it like a software distribution point: owner `root`, mode `755`, never group- or world-writable, exported read-only where possible. Anyone who can write there can run code as `<sid>adm` with certificate admin rights on every attached host.

The Host Agent script runs as root (it writes to `/usr/sap/hostctrl/exe/sec` and restarts the agent) and generates a random one-time password for the intermediate PKCS#12 file. The XSA script reads its password from a mode-600 file and passes it via stdin, so it never appears in the process list.

For XSA, create a dedicated technical user instead of using the platform admin:

```sh
xs create-user acme_renew '<pw>' --no-password-change
xs assign-role-collection XS_CONTROLLER_ADMIN acme_renew   # role collection first, then user
```

`XS_CONTROLLER_ADMIN` is the collection that covers `set-certificate`. It is narrower than the platform admin but still a full controller admin role — XSA does not ship a certificates-only role. Building one via the XS role builder is left as an exercise.

For HANA, the setup script creates a dedicated `ACME_RENEW` database user whose only meaningful privilege is `ALTER` on the certificate PSE.

## SAP quirks (hard-won)

Every item below is handled by the current scripts. If you are porting this logic elsewhere, this list is the reason the code is longer than you would expect.

**`ALTER PSE` fails with error 258, insufficient privilege.** System privileges are not enough; the user needs the object privilege `GRANT ALTER ON PSE <pse> TO <user>`. Also: `hdbsql` needs `-E 1`, otherwise it exits 0 even when the SQL failed.

**`ALTER PSE` fails with error 5645, incomplete certificate chain.** HANA wants the chain up to a self-signed root. ACME full chains end at the intermediate, and cross-signed roots never become self-signed. The scripts complete the chain CA-agnostically: system trust store first, then an AIA download of the issuer with a local cache.

**`SET PSE PURPOSE SSL` fails with error 5657, `sslclientpki = on`.** File-based X.509 client authentication blocks the in-database SSL PSE, and `sslclientpki=on` is the factory default in newer revisions. The setup script resolves the effective value across configuration layers, reports how many in-database X.509 providers exist, and offers the online correction. File-based mappings cannot be detected reliably — confirm only if you know nobody uses X.509 client logon.

**`sapgenpse import_p12` fails with `stat(...): No such file or directory`.** It silently appends `.p12` to a filename that lacks the suffix and then cannot find the file. `mktemp` templates end in random characters, so the temporary file must be renamed.

**`sapgenpse import_p12` rejects a PKCS#12 created by OpenSSL 3.** The modern default (AES-256/PBES2) is unreadable for older CommonCryptoLib. Export with `-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1`.

**`xs login` reports `Missing value for option 'PASSWORD'` although the password is piped in.** The `--stdin` flag is mandatory; without it, `xs` expects `-p`.

**`xs set-certificate` prints its usage instead of working.** Depending on the version it only accepts the short options `-k` and `-c`, not `--key`/`--certificate`.

**`xs set-certificate` fails with `FAILED to parse private key ... unencrypted PKCS8 PEM`.** acme.sh writes EC keys with a leading `EC PARAMETERS` block, and traditional RSA/EC headers are not PKCS#8 either. Normalize with `openssl pkey` before handing the key over. EC keys themselves are fine — supported algorithms are RSA and EC.

**A cron job or `--reloadcmd` dies immediately after sourcing the SAP profile.** `.sapenv.sh` is written for interactive logins and calls `tset`, which fails without a controlling terminal and takes the whole process with it. Neither `TERM=dumb` nor redirecting stdin is reliable. The scripts therefore do **not** source the profile: they derive `SAPSYSTEMNAME` from the instance path and locate `hdbsql`/`xs` by glob. Verify any change with the harshest environment available:

```sh
env -i HOME="$HOME" PATH=/usr/bin:/bin sh ./sap_hana_cert_renew.sh verify
```

This is the single most important test in the repository. An interactive run proves nothing about cron, because your terminal keeps `tset` happy.

## Contributing

Issues and pull requests welcome, particularly for other distributions, AIX, non-EAB CAs, and HANA revisions where the quirks above behave differently. Please keep the HANA and cockpit scripts POSIX `sh` — they run in environments without Bash guarantees.
