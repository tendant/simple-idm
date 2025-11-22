#!/bin/bash
# cleanup-loadtest.sh - Clean up load test data from database

set -e

# Load .env file if it exists
ENV_FILE="${ENV_FILE:-cmd/quick/.env}"
if [ -f "$ENV_FILE" ]; then
    echo "Loading configuration from ${ENV_FILE}"
    export $(grep -v '^#' "$ENV_FILE" | xargs)
fi

# Configuration from environment variables
DB_HOST="${IDM_PG_HOST:-localhost}"
DB_PORT="${IDM_PG_PORT:-5432}"
DB_NAME="${IDM_PG_DATABASE:-idm_db}"
DB_USER="${IDM_PG_USER:-idm}"
DB_PASS="${IDM_PG_PASSWORD:-pwd}"
DB_SCHEMA="${IDM_PG_SCHEMA:-public}"

echo "Cleaning up load test data..."
echo "Database: ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME} (schema: ${DB_SCHEMA})"
echo

# Run cleanup
PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<EOF
-- Count before cleanup
SELECT 'Found ' || COUNT(*) || ' load test users' AS status
FROM ${DB_SCHEMA}.users WHERE email LIKE 'loadtest_%';

-- Delete user roles
DELETE FROM ${DB_SCHEMA}.user_roles WHERE user_id IN (
    SELECT id FROM ${DB_SCHEMA}.users WHERE email LIKE 'loadtest_%'
);

-- Delete users
DELETE FROM ${DB_SCHEMA}.users WHERE email LIKE 'loadtest_%';

-- Delete logins
DELETE FROM ${DB_SCHEMA}.logins
WHERE username LIKE 'user_%'
   OR username LIKE 'loadtest_%';

-- Count after cleanup
SELECT 'Cleanup complete' AS status;
EOF

echo
echo "✓ Load test data cleaned up successfully"
