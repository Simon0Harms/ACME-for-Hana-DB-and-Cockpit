-- =============================================================================
-- hana_acme_setup.sql
--
-- One-off setup for sap_hana_cert_renew.sh.
-- Run this in EVERY database (SystemDB plus every tenant).
-- IMPORTANT: use THE SAME password in all databases -- the script relies on a
-- single hdbuserstore key with nameserver routing (-d).
--
--   hdbsql -u SYSTEM -n <host>:3<nn>13 -I hana_acme_setup.sql              (SystemDB)
--   hdbsql -u SYSTEM -n <host>:3<nn>13 -d <TENANT> -I hana_acme_setup.sql  (per tenant)
--
-- Afterwards, as <sid>adm, create ONE hdbuserstore key against the SystemDB:
--   hdbuserstore SET ACME_RENEW "<host>:3<nn>13" ACME_RENEW "<pw>"
--
-- -----------------------------------------------------------------------------
-- LICENSE
-- -----------------------------------------------------------------------------
-- GNU General Public License v3.0 or later. See the LICENSE file in the
-- repository root, or <https://www.gnu.org/licenses/gpl-3.0.html>.
--
-- SPDX-License-Identifier: GPL-3.0-or-later
--
-- This program comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
-- applicable law.
-- =============================================================================

-- 1) Technical user (replace the password, and keep it identical everywhere!)
CREATE USER ACME_RENEW PASSWORD "Change-Me-Now-1" NO FORCE_FIRST_PASSWORD_CHANGE;
ALTER USER ACME_RENEW DISABLE PASSWORD LIFETIME;

-- Minimum privileges for certificate and PSE management
GRANT CERTIFICATE ADMIN TO ACME_RENEW;
GRANT SSL ADMIN TO ACME_RENEW;

-- IN THE SYSTEMDB ONLY, additionally (needed for automatic tenant discovery
-- through SYS_DATABASES.M_SERVICES):
-- GRANT CATALOG READ TO ACME_RENEW;

-- 2) Create the PSE
CREATE PSE ACME_SSL;

-- Object privilege: CERTIFICATE ADMIN and SSL ADMIN are NOT sufficient to
-- modify a PSE owned by someone else -- without this GRANT, the deploy by
-- ACME_RENEW fails with "insufficient privilege" (error 258)
GRANT ALTER ON PSE ACME_SSL TO ACME_RENEW;

-- 3) Store the issuing PKI's root CA as a trust anchor
--    (one-off; renewals do not have to supply it again)
-- CREATE CERTIFICATE ORG_ROOT_CA FROM '-----BEGIN CERTIFICATE-----
-- ...paste the root CA PEM here...
-- -----END CERTIFICATE-----';
-- ALTER PSE ACME_SSL ADD CERTIFICATE ORG_ROOT_CA;

-- 4) Activate the PSE as the SSL PSE.
--    CAUTION: only run this AFTER the first successful deploy of your own
--    certificate (otherwise the active SSL PSE has no OWN CERTIFICATE).
--    So the order is:
--      a) this setup up to step 3
--      b) sap_hana_cert_renew.sh deploy --force
--      c) SET PSE ... PURPOSE SSL:
-- SET PSE ACME_SSL PURPOSE SSL;

-- Verification:
-- SELECT * FROM SYS.PSES;
-- SELECT * FROM SYS.PSE_CERTIFICATES;
