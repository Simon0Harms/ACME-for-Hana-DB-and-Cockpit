# SAP HANA Cockpit (XSA platform router)

Covers the TLS certificate of the XS Advanced platform router — the endpoint your browser talks to. For the HANA database interfaces and the SAP Host Agent see [hana-database.md](hana-database.md).

Paths below use `host.example.com` for the FQDN. The script is expected to live in the `<sid>adm` home directory (see [Where the script lives](#where-the-script-lives)).

## How it works

TLS for the cockpit UI is terminated by the XSA platform router, **not** by a database PSE. The certificate is applied with `xs set-certificate` and takes effect after an XSA restart.

> **The deploy restarts XSA.** The cockpit UI is unavailable for a few minutes. Schedule the acme.sh renewal cron at night.

The fingerprint comparison prevents pointless restarts: the certificate is only applied when it actually changed. After the restart the script polls the router port until the new certificate is served (up to 15 minutes by default).

The script uses the same acme.sh key and full chain as the rest of the landscape. The chain is completed up to a self-signed root before the import (system trust store, then AIA download with a cache); if that fails, the original full chain is used, since the router generally works without the root in the blob. `ROOT_CA_FILE` in the configuration block overrides the automatic path.

Everything else is derived at runtime: SID from `$SAPSYSTEMNAME` or the instance path, FQDN from `hostname -f`, instance number from `/usr/sap/<SID>/HDB<nn>` and from that the API and verification port `3<nn>30`.

### Where the script lives

Unlike the database scripts — which can be distributed centrally — the cockpit script is meant to sit **locally in the `<sid>adm` home directory** (`$HOME/sap_hana_cockpit_cert_renew.sh`). A cockpit installation is typically a single dedicated host, so central distribution buys nothing, and a local copy decouples the restart-critical deploy from the availability of a network mount.

The trade-off is manual maintenance: when you update the script, copy it into place again.

```sh
install -m 755 /path/to/repo/scripts/sap_hana_cockpit_cert_renew.sh "$HOME"/
```

Keep a note of which hosts hold local copies — these are exactly the ones forgotten during a future bug fix.

## Prerequisites

- acme.sh working as the cockpit's `<sid>adm`. If another SAP system on the same host already uses acme.sh under the same user, the certificate is already there and you can skip issuance.
- The `xs` CLI available, and `openssl`
- The XSA default domain must match the certificate CN/SAN (`xs domains`)
- Checkmk agent with a spool directory writable for `<sid>adm` (optional)

## Setup

### a) Create a dedicated XSA user

Rather than using the platform admin, create a technical user. As an XSA admin:

```sh
xs create-user acme_renew '<pw>' --no-password-change
xs assign-role-collection XS_CONTROLLER_ADMIN acme_renew
```

> Argument order for `assign-role-collection` is **role collection first, then user**.

`XS_CONTROLLER_ADMIN` is the collection that covers `set-certificate`. Verify before storing the password:

```sh
xs assigned-role-collections acme_renew          # must list XS_CONTROLLER_ADMIN
xs login -a https://host.example.com:3<nn>30 -u acme_renew -o <org> -s SAP
xs set-certificate <domain> -k /tmp/nonexistent.key -c /tmp/nonexistent.pem
```

The test call must fail on the **missing file**, not on missing authorization (`insufficient scope` / `forbidden`). Note that `XS_CONTROLLER_ADMIN` is narrower than the platform admin but still a full controller admin role — the user can also deploy and stop applications. XSA ships no certificates-only role collection.

### b) Store the password

As the cockpit's `<sid>adm`, the password of the user from step a:

```sh
printf '%s\n' '<pw>' > ~/.xsa_cert_renew.pw && chmod 600 ~/.xsa_cert_renew.pw
```

The script refuses to start if the file is not mode 600. The password is piped to `xs login --stdin` and never appears in the process list.

### c) Check the configuration

In the configuration block, set `XSA_USER` (default `acme_renew`) and `XSA_ORG` — `xs orgs` and `xs spaces` show the values. Verify with `xs domains` that the XSA default domain matches the certificate CN/SAN; otherwise `set-certificate` fails before every deploy.

If `xs` or `openssl` are not found by the built-in glob (check with `which xs`), pin `XS` and `OPENSSL` to their full paths in the same block. That is the most robust option and skips the search entirely.

### d) Issue and install the certificate

```sh
mkdir -p "$HOME/certs"

"$HOME"/.acme.sh/acme.sh --issue --standalone \
    --server '<acme-directory-url>' \
    -d host.example.com

"$HOME"/.acme.sh/acme.sh --install-cert -d host.example.com \
    --key-file       "$HOME/certs/host.key" \
    --fullchain-file "$HOME/certs/host.fullchain.pem" \
    --reloadcmd      "$HOME/sap_hana_cockpit_cert_renew.sh deploy"
```

`--install-cert` calls the reload command immediately, so the first deploy — **including the XSA restart** — happens right here. Key and full chain stay local under `$HOME/certs/`, never on a network share.

The certificate name (or a SAN) must match the XSA default domain. If the cockpit was installed with a short hostname rather than an FQDN, the certificate has to carry that name.

**Key type:** ECDSA works — the router accepts RSA and EC — but the key must be unencrypted PKCS#8 PEM. The script normalizes it with `openssl pkey` before handing it over, which is what makes acme.sh's default EC output usable.

### e) Verify the first deployment

If step d did not deploy, or to repeat it:

```sh
"$HOME"/sap_hana_cockpit_cert_renew.sh deploy --force
tail -f ~/.sap_hana_cockpit_cert_renew/renew.log
```

Then check the router port (insert your instance number):

```sh
openssl s_client -connect "$(hostname -f):3<nn>30" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

### f) Cron

In `<sid>adm`'s crontab, **not** root's:

```cron
5 1 * * *  "$HOME"/.acme.sh/acme.sh --cron --home "$HOME"/.acme.sh >/dev/null 2>&1
25 1 * * * "$HOME"/sap_hana_cockpit_cert_renew.sh verify >/dev/null 2>&1
```

The `verify` cron only checks the port and refreshes monitoring — **no restart**. The actual deploy runs through the acme.sh `--reloadcmd`, which is why that cron belongs at night.

Confirm the script survives a bare environment, because cron provides nothing:

```sh
env -i HOME="$HOME" PATH=/usr/bin:/bin sh "$HOME"/sap_hana_cockpit_cert_renew.sh verify
tail -4 ~/.sap_hana_cockpit_cert_renew/renew.log
```

A context line and a successful verification must appear. If the log stops after a profile line, see the `tset` quirk in the main README — the script is designed not to source `.sapenv.sh` for exactly this reason.

## Operations

| Invocation | Effect |
|---|---|
| `deploy` | apply the certificate if the fingerprint changed, restart XSA, verify; called by acme.sh as `--reloadcmd` |
| `deploy --force` | apply regardless of the fingerprint marker (first run, repair) |
| `verify` | router port verification and spool update only, **no restart** |

Exit codes: `0` ok, `1` deploy or verification failed, `2` precondition not met (lock, files, login).

State lives under `~/.sap_hana_cockpit_cert_renew/`: `renew.log`, `deployed.fingerprint` (the marker that prevents needless restarts), `lock/`, and `ca_cache/` for AIA-fetched issuer certificates.

Monitoring service: `SAP_HANA_cockpit_cert_<SID>`, with the metric `certificate_remaining_validity` and a 25-hour spool max age — see the monitoring section in the main README.

## Troubleshooting

| Symptom | Cause / action |
|---|---|
| SID cannot be determined | Not running as `<sid>adm` and the instance path glob found nothing; pin `SID` in the configuration block |
| `xs` or `openssl` not found | The glob missed them; set `XS`/`OPENSSL` to full paths (`which xs`) |
| Run stops right after a profile line | The `tset` trap — you are running an older copy that still sources `.sapenv.sh` |
| `xs login` reports `Missing value for option 'PASSWORD'` | The `--stdin` flag is missing — fixed in current versions |
| `xs login` fails otherwise | Wrong or missing `~/.xsa_cert_renew.pw` (mode 600), or `XSA_USER`/`XSA_ORG`/API port do not match (`xs orgs`, `xs spaces`) |
| `xs set-certificate` prints its usage | This version wants the short options `-k`/`-c`, not `--key`/`--certificate` |
| `FAILED to parse private key ... PKCS8` | Key is not unencrypted PKCS#8 (acme.sh EC keys carry an `EC PARAMETERS` block). Current versions normalize with `openssl pkey`; if you see this, the copy is outdated |
| `insufficient scope` / `forbidden` on set-certificate | `XS_CONTROLLER_ADMIN` not assigned: `xs assigned-role-collections acme_renew` |
| Domain argument rejected | Does not match the XSA default domain (`xs domains`) |
| Deploy ok, router still serves the old certificate | XSA restart incomplete or slower than `RESTART_TIMEOUT`; check `renew.log`, restart XSA manually if needed |
| Service stale in Checkmk | The daily `verify` is not running — check the crontab and `renew.log` |
| No Checkmk service at all | Spool directory not writable for `<sid>adm`: `chgrp sapsys /var/lib/check_mk_agent/spool && chmod g+ws ...` |
| `lock ... exists, another run is active` | Parallel run or stale lock: `rmdir ~/.sap_hana_cockpit_cert_renew/lock` |

## Scope

- The database interfaces and the Host Agent use different mechanisms — see [hana-database.md](hana-database.md).
- **XSA on production HANA systems:** if XS Advanced runs there too, its router follows exactly the same mechanism as described here.
- The certificate source (`$HOME/certs/`) and the acme.sh account can be shared with the database setup when cockpit and database run under the same `<sid>adm`.
