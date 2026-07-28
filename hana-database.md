# HANA databases (in-database PSE) and SAP Host Agent

Covers the SQL/HTTP interfaces of a HANA MDC installation — SystemDB and every tenant — plus the SAP Host Agent on port 1129 as an optional add-on. For the HANA Cockpit see [hana-cockpit.md](hana-cockpit.md).

Paths below use `/opt/sap-acme` for the script location and `host.example.com` for the FQDN. Adjust to your environment.

## How it works

### In-database PSE

The certificate is written into an in-database PSE via SQL (`ALTER PSE ... SET OWN CERTIFICATE`). The change takes effect for new connections **immediately, without a restart**. Because the SSL PSE exists per database, every database is served individually.

Connection model: a single `hdbuserstore` key (`ACME_RENEW`) against the SystemDB port `3<nn>13`; the target database is selected through nameserver routing (`hdbsql -d <DBNAME>`). This requires the `ACME_RENEW` user to exist in every database **with the same password**.

Only the client-facing SQL/HTTP interface is affected. Internal communication (inter-service, system replication) uses separate HANA-managed PSEs and is left untouched.

### SAP Host Agent (port 1129)

The Host Agent's HTTPS interface uses its own file-based PSE (`SAPSSLS.pse` in `/usr/sap/hostctrl/exe/sec`); without an import it serves a self-signed certificate. `sap_hostagent_cert_renew_additional.sh` deliberately does **not** maintain its own ACME account as root — it consumes the certificate the `<sid>adm` already installed under `/usr/sap/<SID>/home/certs/`, located by glob. One certificate, one renewal, several consumers.

The import runs through `openssl pkcs12` (random one-time password, legacy ciphers for older CommonCryptoLib) and `sapgenpse import_p12`/`seclogin`. The existing PSE is backed up first (last five kept), then `saphostexec -restart` runs and the script polls port 1129 until the new fingerprint appears.

Import and restart happen only when the fingerprint changed, so the script is safe to run daily from root's crontab and picks up renewals within 24 hours. It needs no `--reloadcmd` wiring.

If Checkmk or other tools query the Host Agent over HTTPS **with certificate validation**, they must trust the new chain after the switch — same as any HANA client.

### Verification

After every deploy, and daily in `verify` mode, the script opens a TLS connection with `openssl s_client` and compares the SHA-256 fingerprint served by each port against the local file. The result goes to a Checkmk local check via a spool file.

## Setup

Order matters: **a)** database side → **b)** issue and install → **c)** activate → **d)** cron. Then optionally **e)** Host Agent.

### a) Prepare the databases

```sh
/opt/sap-acme/sap_hana_cert_setup.sh setup
```

The script determines SID, instance and FQDN itself, lists all running databases through the SystemDB, and asks interactively for the SYSTEM password (per database if tenant passwords differ), the `ACME_RENEW` password (empty input generates a 24-character one), and optionally a root CA path. It then creates the user, grants (including `ALTER ON PSE`), the PSE and the trust anchor in every database, and writes the userstore key.

Everything is idempotent — rerun it after a failure or for a tenant that was started later, and only what is missing gets created. The SYSTEM password is used only during the run, through a temporary userstore key that is removed on exit.

If a certificate already exists under `$HOME/certs/`, the script offers to run `deploy --force` right away; otherwise it prints the acme.sh commands for step b.

**Manual alternative:** apply `hana_acme_setup.sql` per database with `hdbsql -I` (the SystemDB additionally needs `CATALOG READ`), then `hdbuserstore SET ACME_RENEW "<host>:3<nn>13" ACME_RENEW "<pw>"`. Details are in the SQL file's header.

### b) Issue and install the certificate

```sh
mkdir -p "$HOME/certs"

"$HOME"/.acme.sh/acme.sh --issue --standalone \
    --server '<acme-directory-url>' \
    -d host.example.com

"$HOME"/.acme.sh/acme.sh --install-cert -d host.example.com \
    --key-file       "$HOME/certs/host.key" \
    --fullchain-file "$HOME/certs/host.fullchain.pem" \
    --reloadcmd      "/opt/sap-acme/sap_hana_cert_renew.sh deploy"
```

`--install-cert` invokes the reload command once immediately and therefore **already deploys into all databases** — no separate `deploy --force` needed. Key and full chain live under `$HOME/certs/` (as `<sid>adm` that is `/usr/sap/<SID>/home/certs/`), locally rather than on a network share, because one of them is a private key. The Host Agent script (running as root, where `$HOME` is `/root`) finds this directory through the absolute path `/usr/sap/*/home/certs/`.

Multiple names go into additional `-d` arguments (or a comma-separated list). The first name is the primary one that acme.sh manages the certificate under and that you reference in `--install-cert`. Each name must be independently validatable.

**Key type:** acme.sh issues ECDSA by default, and current HANA revisions and CommonCryptoLib builds accept it. Add `--keylength 2048` for RSA (permanently: `DEFAULT_KEYLENGTH="2048"` in `~/.acme.sh/account.conf`). Note that acme.sh manages the RSA and ECC variants of the same hostname as **separate** objects — ECC commands need the `--ecc` flag, and a stale RSA entry will keep renewing in parallel until you `--remove` it. Before standardizing on ECC, test a real client connection from every application server type; older ODBC/SQLDBC builds, particularly on AIX, cannot do ECDSA.

**Challenge type:** `--standalone` needs port 80 reachable from the CA's validation network and usable by an unprivileged process (on SLES e.g. `sysctl net.ipv4.ip_unprivileged_port_start=80`, or a firewall redirect). For hosts that are not reachable from outside, use DNS-01 with the appropriate `--dns dns_*` hook instead.

The chosen method **and the server URL** are persisted per certificate in `~/.acme.sh/<fqdn>/<fqdn>.conf`, so `--cron` renewals reuse them. Worth checking after every issuance:

```sh
grep '^Le_API' ~/.acme.sh/host.example.com*/*.conf
```

An empty `Le_API` — easy to produce with an `--issue` that omitted `--server` — makes the renewal cron fall back to acme.sh's default CA and fail with `Cannot init API`. Remove such entries with `acme.sh --remove -d <fqdn>` (add `--ecc` for the ECC variant).

### c) Activate the PSE

Only **after** a successful deploy:

```sh
/opt/sap-acme/sap_hana_cert_setup.sh activate
```

For each database this runs `SET PSE <pse> PURPOSE SSL` after confirmation and immediately checks with `openssl s_client` whether the SQL port serves a certificate; if the check fails it stops before touching the next database. Databases whose PSE has no certificate yet are skipped, and the `sslclientpki` factory default is handled (see troubleshooting, error 5657).

> **Plan a maintenance window.** Clients using `sslValidateCertificate` — `hdbsql`, ODBC/JDBC, monitoring plugins — must trust the new CA chain, or you lock yourself out. Keep a second session open.

### d) Cron

In `<sid>adm`'s crontab, **not** root's:

```cron
15 1 * * * /opt/sap-acme/sap_hana_cert_renew.sh verify >/dev/null 2>&1
```

The daily `verify` keeps the Checkmk spool file fresh. Alerting happens through Checkmk, not through cron mail.

The script does not source `.sapenv.sh` (see the `tset` quirk in the main README) and derives its environment itself. Confirm that on your system with:

```sh
env -i HOME="$HOME" PATH=/usr/bin:/bin sh /opt/sap-acme/sap_hana_cert_renew.sh verify
tail -4 ~/.sap_hana_cert_renew/renew.log
```

The log must show a `context: SID=...` line and a successful verification. If it stops right after a profile line, the environment handling is broken for cron and the nightly renewal will fail silently.

### e) SAP Host Agent (optional)

Requires a)–c) to be complete. As **root**:

```sh
/opt/sap-acme/sap_hostagent_cert_renew_additional.sh deploy --force

openssl s_client -connect "$(hostname -f):1129" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

Then root's crontab — daily, idempotent:

```cron
45 1 * * * /opt/sap-acme/sap_hostagent_cert_renew_additional.sh deploy >/dev/null 2>&1
```

Logs and state live in `/root/.sap_hostagent_cert_renew/` (`renew.log`, fingerprint marker, lock, `ca_cache/`). Failures also send mail to the address configured at the top of the script. PSE backups (`SAPSSLS.pse.*.bak`) rotate to the last five.

## Operations

### Logs and state

Under `~/.sap_hana_cert_renew/` (database) and `/root/.sap_hostagent_cert_renew/` (Host Agent):

- `renew.log` — every run including the derived context (SID, instance, FQDN, database list)
- `deployed.<DBNAME>` / `deployed.fingerprint` — fingerprint of the last successfully deployed certificate (idempotence marker)
- `lock/` — lock directory; if a crash leaves it behind it blocks further runs and must be removed manually
- `ca_cache/` — issuer certificates fetched via AIA for chain completion

### Adding a tenant

1. Run `sap_hana_cert_setup.sh setup` again. It detects the new tenant automatically and leaves existing databases alone. Enter the **known** `ACME_RENEW` password rather than generating a new one, otherwise it diverges from the other databases.
2. If the offered deploy was skipped: `sap_hana_cert_renew.sh deploy --force`
3. `sap_hana_cert_setup.sh activate` — confirm only the new tenant; already active databases are detected and skipped.

No userstore entry is needed; auto-discovery finds the tenant on the next run.

### Rotating the ACME_RENEW password

Change it in every database and in the userstore, in this order: all tenants first (`ALTER USER ACME_RENEW PASSWORD ...`), then the SystemDB, then `hdbuserstore SET ACME_RENEW ...`. This keeps the failure window small and avoids locking the user through failed logons.

## Troubleshooting

| Symptom | Cause / action |
|---|---|
| `cannot determine SID: SAPSYSTEMNAME is empty` | Not running as `<sid>adm`, and the instance path glob found nothing; set `SID` in the configuration block |
| Service appears as `..._NA`, or `hdbsql not in PATH` | Environment derivation failed. Check that `/usr/sap/<SID>/HDB<nn>` exists and set `HDBSQL` to the full path if needed |
| Run stops right after a profile line in the log | The `tset` trap — see main README. Current versions do not source the profile at all; you are running an older copy |
| `hostname -f` does not return an FQDN | Fix DNS/`/etc/hosts`, or pin `FQDN` in the script |
| `database auto-discovery failed` | Userstore key missing, wrong password, or `CATALOG READ` missing in the SystemDB |
| `insufficient privilege` (258) on deploy | Missing object privilege: `GRANT ALTER ON PSE <pse> TO ACME_RENEW` per database; `setup` does this automatically, then `deploy --force` |
| `Incomplete certificate chain` (5645) on deploy | Chain completion failed (offline, no AIA URL — check `renew.log`). Point `ROOT_CA_FILE` at the matching root PEM |
| `PSE purpose blocked ... sslclientpki = on` (5657) on activate | Factory default blocks the in-database SSL PSE. `activate` detects it and offers the online correction on the SYSTEM layer. Confirm only if X.509 client logon is definitely unused. If a database is still skipped, check for a DATABASE-layer override in `M_INIFILE_CONTENTS` |
| Deploy ok, but the port serves the old certificate | PSE not yet on `PURPOSE SSL` (activate pending), or a different PSE is active (`SELECT * FROM SYS.PSES`) |
| A tenant is missing from the result | Stopped tenants do not appear in `M_SERVICES` and are skipped; the next deploy picks them up via the fingerprint comparison |
| Service stale in Checkmk | The daily `verify` is not running — check the crontab and `renew.log` |
| `WARNING: ... is not writable` in the log, no Checkmk service | Spool directory not writable for `<sid>adm`: `chgrp sapsys /var/lib/check_mk_agent/spool && chmod g+ws ...` |
| `lock ... exists, another run is active` | Parallel run, or a stale lock after a crash: `rmdir ~/.sap_hana_cert_renew/lock` |
| `413: last n passwords can not be reused` during setup | Password policy history. Only happens when setting a *previously used* password — if the entered one is already current, setup skips the `ALTER USER`. Choose a new password (then run `setup` for **all** databases) or move the user to a group with `last_used_passwords = 0` |
| Port 1129 serves a self-signed or old certificate | Host Agent import missing or outdated: as root, `sap_hostagent_cert_renew_additional.sh deploy --force`; details in `/root/.sap_hostagent_cert_renew/renew.log` |
| `import_p12` fails | Temporary file needs a `.p12` suffix (handled in current versions); otherwise legacy cipher issue (OpenSSL 3 default) or an ECDSA limit in an older CommonCryptoLib — update the Host Agent |
| `--reloadcmd` fails / script not found | If the scripts live on a network share, check the mount; acme.sh retries the reload on the next cron run |

## Scope

- **HANA Cockpit / XSA:** different mechanism, see [hana-cockpit.md](hana-cockpit.md).
- **AIX:** the Host Agent script is Bash and assumes Linux paths; it has not been tested on AIX.
- **`sapsrv.pse` (file-based):** deliberately unused — changes only take effect on database restart, which does not fit a 60-day cycle.
- **Internal HANA PSEs** (inter-service, system replication) are never touched.
