#!/usr/bin/env bash
# Bootstrap MariaDB for sqli.vulnlab.dev. Idempotent — safe to re-run.
#
# What it does (all gated on existence checks):
#   1. Creates /etc/vulnlab/sqli.env with a generated DB password (if absent).
#   2. Creates the vulnlab_sqli database (if absent).
#   3. Creates the vulnlab_sqli@localhost user with the env-file password
#      and grants SELECT/INSERT/DELETE on vulnlab_sqli.* only.
#   4. Applies apps/sqli/schema.sql (which itself uses CREATE IF NOT EXISTS
#      and REPLACE INTO for the seed rows).
#
# Run on the deploy host as the operator. Requires sudo for mariadb root
# socket auth and for writing /etc/vulnlab/.

set -euo pipefail

ENV_FILE="/etc/vulnlab/sqli.env"
DB_NAME="vulnlab_sqli"
DB_USER="vulnlab_sqli"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCHEMA_FILE="$REPO_ROOT/apps/sqli/schema.sql"

if [[ ! -f "$SCHEMA_FILE" ]]; then
    echo "schema not found at $SCHEMA_FILE" >&2
    exit 1
fi

# --- 1. env file -------------------------------------------------------------

sudo mkdir -p /etc/vulnlab
sudo chmod 755 /etc/vulnlab

if ! sudo test -f "$ENV_FILE"; then
    pw="$(openssl rand -hex 24)"
    printf 'VULNLAB_SQLI_DB_USER=%s\nVULNLAB_SQLI_DB_NAME=%s\nVULNLAB_SQLI_DB_PASSWORD=%s\n' \
        "$DB_USER" "$DB_NAME" "$pw" | sudo tee "$ENV_FILE" >/dev/null
    sudo chmod 600 "$ENV_FILE"
    echo "created $ENV_FILE"
else
    echo "$ENV_FILE already exists — keeping existing password"
fi

# Source the env into this shell. The file has KEY=val lines, no quoting.
DB_PASSWORD="$(sudo awk -F= '/^VULNLAB_SQLI_DB_PASSWORD=/{print substr($0, index($0,"=")+1); exit}' "$ENV_FILE")"
if [[ -z "${DB_PASSWORD:-}" ]]; then
    echo "could not read VULNLAB_SQLI_DB_PASSWORD from $ENV_FILE" >&2
    exit 1
fi

# --- 2 + 3. database and user ------------------------------------------------

# Single SQL session so we can use the password from the shell var safely.
# Pass the password via stdin so it doesn't appear in `ps`.
sudo mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
-- In case the user pre-existed with a different password, sync it:
ALTER USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
GRANT SELECT, INSERT, DELETE ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
SQL

# --- 4. schema + seed --------------------------------------------------------

sudo mysql "$DB_NAME" < "$SCHEMA_FILE"

# --- verify ------------------------------------------------------------------

echo "verifying..."
sudo mysql "$DB_NAME" -e "SELECT COUNT(*) AS users    FROM users;"
sudo mysql "$DB_NAME" -e "SELECT COUNT(*) AS products FROM products;"
sudo mysql "$DB_NAME" -e "SELECT COUNT(*) AS secrets  FROM secrets;"

echo "done. service can now read $ENV_FILE via EnvironmentFile=."
