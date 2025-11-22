#!/bin/bash
# test-api.sh - Rerunnable API test suite
# Uses .env file for configuration

set -e # Exit on error

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Load .env file if it exists
ENV_FILE="${ENV_FILE:-cmd/quick/.env}"
if [ -f "$ENV_FILE" ]; then
    echo -e "${BLUE}Loading configuration from ${ENV_FILE}${NC}"
    export $(grep -v '^#' "$ENV_FILE" | xargs)
fi

# Configuration from environment variables (with defaults)
BASE_URL="${BASE_URL:-http://localhost:4000}"
DB_HOST="${IDM_PG_HOST:-localhost}"
DB_PORT="${IDM_PG_PORT:-5432}"
DB_NAME="${IDM_PG_DATABASE:-idm_db}"
DB_USER="${IDM_PG_USER:-idm}"
DB_PASS="${IDM_PG_PASSWORD:-pwd}"
DB_SCHEMA="${IDM_PG_SCHEMA:-public}"

# Generate unique test ID
TEST_RUN_ID="test_$(date +%s)_$$"

echo -e "${BLUE}=== V2 API Test Suite ===${NC}"
echo "Run ID: ${TEST_RUN_ID}"
echo "Base URL: ${BASE_URL}"
echo "Database: ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME} (schema: ${DB_SCHEMA})"
echo

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Cleanup function
cleanup() {
    if [ "${SKIP_CLEANUP}" = "true" ]; then
        echo -e "\n${YELLOW}Skipping cleanup (SKIP_CLEANUP=true)${NC}"
        return
    fi

    echo -e "\n${YELLOW}Cleaning up test data...${NC}"

    PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -q <<EOF 2>/dev/null
DELETE FROM ${DB_SCHEMA}.user_roles WHERE user_id IN (
    SELECT id FROM ${DB_SCHEMA}.users WHERE email LIKE '%${TEST_RUN_ID}%'
);
DELETE FROM ${DB_SCHEMA}.users WHERE email LIKE '%${TEST_RUN_ID}%';
DELETE FROM ${DB_SCHEMA}.logins WHERE username LIKE '%${TEST_RUN_ID}%';
EOF

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Cleanup complete${NC}"
    else
        echo -e "${YELLOW}Warning: Cleanup may have failed${NC}"
    fi
}

# Register cleanup to run on exit
trap cleanup EXIT

# Test function
test_endpoint() {
    local name=$1
    local method=$2
    local path=$3
    local data=$4
    local expected_code=$5

    TESTS_RUN=$((TESTS_RUN + 1))

    echo -n "[$TESTS_RUN] Testing ${name}... "

    if [ -z "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "${method}" "${BASE_URL}${path}" 2>/dev/null)
    else
        response=$(curl -s -w "\n%{http_code}" -X "${method}" "${BASE_URL}${path}" \
            -H "Content-Type: application/json" \
            -d "${data}" 2>/dev/null)
    fi

    code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$code" -eq "$expected_code" ]; then
        echo -e "${GREEN}✓ PASS${NC} (HTTP $code)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        if [ "${VERBOSE}" = "true" ]; then
            echo "  Response: $body"
        fi
        return 0
    else
        echo -e "${RED}✗ FAIL${NC} (Expected $expected_code, got $code)"
        echo "  Response: $body"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Check if server is running
echo "Checking server availability..."
if ! curl -s "${BASE_URL}" > /dev/null 2>&1; then
    echo -e "${RED}Error: Server not running at ${BASE_URL}${NC}"
    echo "Start the server first with: cd cmd/quick && go run main.go"
    exit 1
fi
echo -e "${GREEN}Server is running${NC}"
echo

# Run tests
echo "Running tests..."
echo

# Test 1: Passwordless Signup
test_endpoint "Passwordless Signup" "POST" "/api/v2/auth/signup" \
    "{\"email\":\"passwordless_${TEST_RUN_ID}@example.com\"}" 201

# Test 2: Password-based Signup
test_endpoint "Password Signup" "POST" "/api/v2/auth/signup" \
    "{\"email\":\"withpwd_${TEST_RUN_ID}@example.com\",\"password\":\"Test12345\"}" 201

# Test 3: Login with correct password
test_endpoint "Login with correct password" "POST" "/api/v2/auth/login" \
    "{\"username\":\"withpwd_${TEST_RUN_ID}@example.com\",\"password\":\"Test12345\"}" 200

# Test 4: Login with wrong password (should fail)
test_endpoint "Login with wrong password" "POST" "/api/v2/auth/login" \
    "{\"username\":\"withpwd_${TEST_RUN_ID}@example.com\",\"password\":\"WrongPass\"}" 401 || true

# Test 5: Logout
test_endpoint "Logout" "POST" "/api/v2/auth/logout" "" 200

# Test 6: Magic Link Request
test_endpoint "Magic Link Request" "POST" "/api/v2/magic-links" \
    "{\"username\":\"withpwd_${TEST_RUN_ID}@example.com\"}" 200

# Test 7: Duplicate Email (should fail)
test_endpoint "Duplicate Email Should Fail" "POST" "/api/v2/auth/signup" \
    "{\"email\":\"withpwd_${TEST_RUN_ID}@example.com\"}" 409 || true

# Test 8: Signup with custom username
test_endpoint "Signup with custom username" "POST" "/api/v2/auth/signup" \
    "{\"email\":\"custom_${TEST_RUN_ID}@example.com\",\"username\":\"myuser_${TEST_RUN_ID}\",\"password\":\"Test12345\"}" 201

# Test 9: Refresh token endpoint
test_endpoint "Refresh token" "POST" "/api/v2/auth/refresh" "" 401 || true  # Should fail without token

# Summary
echo
echo -e "${BLUE}=== Test Summary ===${NC}"
echo "Total: ${TESTS_RUN}"
echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
if [ ${TESTS_FAILED} -gt 0 ]; then
    echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"
else
    echo -e "${GREEN}Failed: ${TESTS_FAILED}${NC}"
fi

if [ ${TESTS_FAILED} -eq 0 ]; then
    echo -e "\n${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed${NC}"
    exit 1
fi
