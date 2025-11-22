# Load Testing Guide

## Quick Start

### 1. Install k6
```bash
brew install k6
```

### 2. Run Load Test
```bash
# Basic load test (20 concurrent users for 3 minutes)
k6 run load-test.js

# Smoke test (quick validation with 5 users)
k6 run load-test.js --stage 30s:5

# Stress test (find breaking point)
k6 run load-test.js --stage 2m:50 --stage 5m:50 --stage 2m:100 --stage 5m:100

# Spike test (sudden traffic burst)
k6 run load-test.js --stage 10s:100 --stage 1m:100 --stage 10s:0

# Custom URL
BASE_URL=http://localhost:8080 k6 run load-test.js
```

## Test Scenarios

### Smoke Test (Quick Validation)
**Purpose**: Verify system works under minimal load
```bash
k6 run --vus 5 --duration 30s load-test.js
```
**Expected**: All requests succeed, ~100% success rate

### Load Test (Normal Traffic)
**Purpose**: Test system under expected load
```bash
k6 run --vus 20 --duration 5m load-test.js
```
**Expected**:
- Response time p95 < 500ms
- Error rate < 1%
- Stable throughout test

### Stress Test (Breaking Point)
**Purpose**: Find system limits
```bash
k6 run --stage 2m:50 --stage 5m:50 --stage 2m:100 --stage 3m:100 load-test.js
```
**Expected**:
- Identify max concurrent users
- See where response times degrade
- Observe system recovery

### Spike Test (Traffic Burst)
**Purpose**: Test sudden load increase
```bash
k6 run --stage 10s:100 --stage 1m:100 --stage 10s:0 load-test.js
```
**Expected**:
- System handles sudden spike
- Auto-scaling triggers (if configured)
- Quick recovery

## Understanding Results

### Sample Output
```
     ✓ signup status is 201
     ✓ signup has user_id
     ✓ login status is 200
     ✓ login has user data
     ✓ logout status is 200

     checks.........................: 100.00% ✓ 15000     ✗ 0
     data_received..................: 45 MB   150 kB/s
     data_sent......................: 15 MB   50 kB/s
     http_req_blocked...............: avg=1.2ms    min=0s     med=1ms    max=50ms   p(90)=2ms    p(95)=3ms
     http_req_connecting............: avg=800µs    min=0s     med=700µs  max=30ms   p(90)=1.5ms  p(95)=2ms
   ✓ http_req_duration..............: avg=120ms    min=50ms   med=100ms  max=500ms  p(90)=200ms  p(95)=250ms
     http_req_failed................: 0.00%   ✓ 0         ✗ 15000
     http_req_receiving.............: avg=500µs    min=100µs  med=400µs  max=10ms   p(90)=800µs  p(95)=1ms
     http_req_sending...............: avg=300µs    min=50µs   med=250µs  max=8ms    p(90)=500µs  p(95)=700µs
     http_req_tls_handshaking.......: avg=0s       min=0s     med=0s     max=0s     p(90)=0s     p(95)=0s
     http_req_waiting...............: avg=119ms    min=49ms   med=99ms   max=499ms  p(90)=199ms  p(95)=249ms
     http_reqs......................: 15000   50/s
     iteration_duration.............: avg=2.5s     min=2s     med=2.4s   max=3s     p(90)=2.8s   p(95)=2.9s
     iterations.....................: 5000    16.67/s
     login_duration.................: avg=120ms    min=50ms   med=100ms  max=500ms  p(90)=200ms  p(95)=250ms
     login_errors...................: 0       0/s
   ✓ success_rate...................: 100.00% ✓ 15000     ✗ 0
     signup_errors..................: 0       0/s
     vus............................: 20      min=0       max=20
     vus_max........................: 20      min=20      max=20
```

### Key Metrics Explained

**✅ Good Performance Indicators:**
- `http_req_duration` p95 < 500ms - 95% of requests complete quickly
- `http_req_failed` < 1% - Less than 1% errors
- `success_rate` > 95% - Most requests succeed
- `checks` 100% - All validation checks pass

**⚠️ Warning Signs:**
- `http_req_duration` p95 > 1s - Slow responses
- `http_req_failed` > 5% - High error rate
- `http_req_blocked` high - Connection issues
- Increasing trend over time - System degrading

**🚨 Critical Issues:**
- `http_req_failed` > 10% - System failing
- `http_req_duration` p95 > 5s - Severe slowness
- Checks failing - Functionality broken

## Cleanup After Load Test

Load tests create many test users. Clean them up:

```bash
# Delete all load test users
PGPASSWORD=pwd psql -h localhost -p 45432 -U tripmemo -d tripmemo <<EOF
DELETE FROM idm.user_roles WHERE user_id IN (
    SELECT id FROM idm.users WHERE email LIKE 'loadtest_%'
);
DELETE FROM idm.users WHERE email LIKE 'loadtest_%';
DELETE FROM idm.logins WHERE username LIKE 'user_%';
EOF
```

Or create a cleanup script:

```bash
#!/bin/bash
# cleanup-loadtest.sh

source cmd/quick/.env

PGPASSWORD=${IDM_PG_PASSWORD} psql \
  -h ${IDM_PG_HOST} \
  -p ${IDM_PG_PORT} \
  -U ${IDM_PG_USER} \
  -d ${IDM_PG_DATABASE} <<EOF

DELETE FROM ${IDM_PG_SCHEMA}.user_roles WHERE user_id IN (
    SELECT id FROM ${IDM_PG_SCHEMA}.users WHERE email LIKE 'loadtest_%'
);
DELETE FROM ${IDM_PG_SCHEMA}.users WHERE email LIKE 'loadtest_%';
DELETE FROM ${IDM_PG_SCHEMA}.logins WHERE username LIKE 'user_%';

SELECT 'Deleted ' || COUNT(*) || ' load test users'
FROM ${IDM_PG_SCHEMA}.users WHERE email LIKE 'loadtest_%';
EOF
```

## Alternative: Apache Bench (Simple)

For quick, simple load tests:

```bash
# Install (usually pre-installed on macOS)
brew install apr-util

# Test signup endpoint
ab -n 1000 -c 10 -p signup.json -T application/json \
  http://localhost:4000/api/v2/auth/signup

# Where signup.json contains:
# {"email":"ab_test@example.com","password":"Test123"}
```

**Limitations**:
- Can't create unique data per request
- All requests identical (will fail on duplicate emails)
- Less detailed metrics

## Alternative: wrk (Fast & Lightweight)

```bash
# Install
brew install wrk

# Basic test
wrk -t4 -c100 -d30s http://localhost:4000/api/v2/auth/logout

# With Lua script for POST requests
wrk -t4 -c100 -d30s -s signup.lua http://localhost:4000/api/v2/auth/signup
```

Create `signup.lua`:
```lua
wrk.method = "POST"
wrk.body   = '{"email":"wrk_test@example.com","password":"Test123"}'
wrk.headers["Content-Type"] = "application/json"
```

## Alternative: Vegeta (Go-based)

```bash
# Install
brew install vegeta

# Create targets file
echo "POST http://localhost:4000/api/v2/auth/logout" | \
  vegeta attack -duration=30s -rate=50 | \
  vegeta report
```

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Load Test

on:
  pull_request:
    branches: [main]

jobs:
  load-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Start server
        run: |
          cd cmd/quick
          go run main.go &
          sleep 5

      - name: Install k6
        run: |
          sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
          echo "deb https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
          sudo apt-get update
          sudo apt-get install k6

      - name: Run smoke test
        run: k6 run --stage 30s:5 load-test.js

      - name: Cleanup
        run: ./cleanup-loadtest.sh
```

## Best Practices

1. **Start Small**: Begin with smoke tests before stress tests
2. **Clean Data**: Always cleanup after load tests
3. **Monitor System**: Watch CPU, memory, database connections
4. **Realistic Scenarios**: Test actual user workflows
5. **Baseline**: Run tests regularly to track performance trends
6. **Isolate Environment**: Don't load test production!

## Troubleshooting

### High Error Rate
```
http_req_failed: 25%
```
**Check**:
- Database connection pool size
- Server logs for errors
- Resource limits (ulimit, file descriptors)

### Slow Response Times
```
http_req_duration p95: 5s
```
**Check**:
- Database query performance
- N+1 query issues
- Missing indexes
- Slow external API calls

### Connection Errors
```
http_req_blocked: avg=5s
```
**Check**:
- Max open connections
- System file descriptor limits
- Firewall/rate limiting
- DNS resolution issues

## Monitoring During Load Test

```bash
# Terminal 1: Run load test
k6 run load-test.js

# Terminal 2: Monitor server resources
watch -n 1 'ps aux | grep "go run"'

# Terminal 3: Monitor database
watch -n 1 'PGPASSWORD=pwd psql -h localhost -p 45432 -U tripmemo -d tripmemo \
  -c "SELECT count(*) FROM pg_stat_activity WHERE datname='\''tripmemo'\'';"'

# Terminal 4: Monitor server logs
tail -f /path/to/server.log
```
