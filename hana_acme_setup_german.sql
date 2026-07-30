-- =============================================================================
-- hana_acme_setup.sql
--
-- Einmaliges Setup fuer sap_hana_cert_renew.sh.
-- In JEDER Datenbank ausfuehren (SystemDB + jeder Tenant).
-- WICHTIG: In allen Datenbanken DASSELBE Passwort verwenden -- das Skript
-- nutzt einen einzelnen hdbuserstore-Key mit Nameserver-Routing (-d).
--
--   hdbsql -u SYSTEM -n <host>:3<nn>13 -I hana_acme_setup.sql              (SystemDB)
--   hdbsql -u SYSTEM -n <host>:3<nn>13 -d <TENANT> -I hana_acme_setup.sql  (je Tenant)
--
-- Danach als <sid>adm EINEN hdbuserstore-Key gegen die SystemDB anlegen:
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

-- 1) Technischer User (Passwort ersetzen, ueberall identisch!)
CREATE USER ACME_RENEW PASSWORD "Change-Me-Now-1" NO FORCE_FIRST_PASSWORD_CHANGE;
ALTER USER ACME_RENEW DISABLE PASSWORD LIFETIME;

-- Minimalrechte fuer Zertifikats- und PSE-Verwaltung
GRANT CERTIFICATE ADMIN TO ACME_RENEW;
GRANT SSL ADMIN TO ACME_RENEW;

-- NUR IN DER SYSTEMDB zusaetzlich (fuer die automatische Tenant-Ermittlung
-- ueber SYS_DATABASES.M_SERVICES):
-- GRANT CATALOG READ TO ACME_RENEW;

-- 2) PSE anlegen
CREATE PSE ACME_SSL;

-- Objektprivileg: CERTIFICATE ADMIN/SSL ADMIN reichen NICHT, um eine fremde
-- PSE zu aendern -- ohne dieses GRANT scheitert das Deploy des ACME_RENEW
-- mit "insufficient privilege" (Fehler 258)
GRANT ALTER ON PSE ACME_SSL TO ACME_RENEW;

-- 3) Root-CA der ausstellenden PKI als Trust-Anker hinterlegen
--    (einmalig; muss bei Renewals NICHT erneut mitgeliefert werden)
-- CREATE CERTIFICATE ORG_ROOT_CA FROM '-----BEGIN CERTIFICATE-----
-- ...Root-CA-PEM hier einfuegen...
-- -----END CERTIFICATE-----';
-- ALTER PSE ACME_SSL ADD CERTIFICATE ORG_ROOT_CA;

-- 4) PSE als SSL-PSE aktivieren.
--    ACHTUNG: Erst NACH dem ersten erfolgreichen Deploy des eigenen
--    Zertifikats ausfuehren (sonst hat die aktive SSL-PSE kein
--    OWN CERTIFICATE). Reihenfolge also:
--      a) dieses Setup bis Schritt 3
--      b) sap_hana_cert_renew.sh deploy --force
--      c) SET PSE ... PURPOSE SSL:
-- SET PSE ACME_SSL PURPOSE SSL;

-- Kontrolle:
-- SELECT * FROM SYS.PSES;
-- SELECT * FROM SYS.PSE_CERTIFICATES;
