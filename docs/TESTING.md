# API Testing Guide

## Quick Start

### 1. Start the Server
```bash
cd cmd/quick
go run main.go
```

### 2. Run Tests
```bash
# From project root
./test-api.sh
```

## Configuration

The test script automatically loads configuration from `cmd/quick/.env`:

```bash
# Loaded automatically:
# - BASE_URL (default: http://localhost:4000)
# - IDM_PG_HOST, IDM_PG_PORT, etc.
# - All database connection details
```

### Override Configuration

```bash
# Use different .env file
ENV_FILE=cmd/quick/.env.test ./test-api.sh

# Override specific values
BASE_URL=http://localhost:8080 ./test-api.sh

# Skip cleanup (keep test data in database)
SKIP_CLEANUP=true ./test-api.sh

# Verbose output (show all responses)
VERBOSE=true ./test-api.sh
```

## Test Features

✅ **Rerunnable**: Uses unique test IDs for each run
✅ **Auto-cleanup**: Removes test data after completion
✅ **Configuration-driven**: No hardcoded values
✅ **Color-coded output**: Easy to read results
✅ **Server check**: Validates server is running before tests

## What Gets Tested

1. Passwordless signup (email only)
2. Password-based signup
3. Login with correct credentials
4. Login with wrong credentials (should fail)
5. Logout
6. Magic link request
7. Duplicate email handling (should fail)
8. Signup with custom username
9. Refresh token endpoint

## Example Output

```
Loading configuration from cmd/quick/.env
=== V2 API Test Suite ===
Run ID: test_1763792428_80155
Base URL: http://localhost:4000
Database: tripmemo@localhost:45432/tripmemo (schema: idm)

Checking server availability...
Server is running

Running tests...

[1] Testing Passwordless Signup... ✓ PASS (HTTP 201)
[2] Testing Password Signup... ✓ PASS (HTTP 201)
[3] Testing Login with correct password... ✓ PASS (HTTP 200)
...

=== Test Summary ===
Total: 9
Passed: 9
Failed: 0

✓ All tests passed!
```

## Integration with CI/CD

```bash
# In your CI pipeline
#!/bin/bash
set -e

# Start server in background
cd cmd/quick
go run main.go &
SERVER_PID=$!

# Wait for server to be ready
sleep 3

# Run tests
cd ../..
./test-api.sh

# Cleanup
kill $SERVER_PID
```

## Troubleshooting

### Server not running
```bash
Error: Server not running at http://localhost:4000
```
**Solution**: Start the server first: `cd cmd/quick && go run main.go`

### Database connection failed
```bash
Warning: Cleanup may have failed
```
**Solution**: Check database connection in `.env` file

### Port already in use
```bash
# Kill existing process
lsof -ti:4000 | xargs kill
```

## Advanced Usage

### Test specific environment
```bash
# Create test-specific .env
cp cmd/quick/.env cmd/quick/.env.test
# Edit cmd/quick/.env.test with test database

# Run with test config
ENV_FILE=cmd/quick/.env.test ./test-api.sh
```

### Keep test data for debugging
```bash
# Don't clean up after tests
SKIP_CLEANUP=true ./test-api.sh

# Then inspect the database
PGPASSWORD=pwd psql -h localhost -p 45432 -U tripmemo -d tripmemo \
  -c "SELECT email FROM idm.users WHERE email LIKE '%test_%';"
```

### Add custom tests

Edit `test-api.sh` and add new test cases:

```bash
# Add after existing tests
test_endpoint "Your Custom Test" "POST" "/api/v2/your/endpoint" \
    '{"data":"value"}' 200
```
