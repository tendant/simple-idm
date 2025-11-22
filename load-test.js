import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const signupErrors = new Counter('signup_errors');
const loginErrors = new Counter('login_errors');
const successRate = new Rate('success_rate');
const loginDuration = new Trend('login_duration');

// Test configuration
export const options = {
  // Scenario 1: Smoke test (quick validation)
  // stages: [
  //   { duration: '30s', target: 5 },  // Ramp up to 5 users
  // ],

  // Scenario 2: Load test (sustained load)
  stages: [
    { duration: '1m', target: 20 },   // Ramp up to 20 users over 1 minute
    { duration: '3m', target: 20 },   // Stay at 20 users for 3 minutes
    { duration: '1m', target: 0 },    // Ramp down to 0 users
  ],

  // Scenario 3: Stress test (find breaking point)
  // stages: [
  //   { duration: '2m', target: 50 },   // Ramp up to 50 users
  //   { duration: '5m', target: 50 },   // Stay at 50 users
  //   { duration: '2m', target: 100 },  // Spike to 100 users
  //   { duration: '5m', target: 100 },  // Stay at 100 users
  //   { duration: '2m', target: 0 },    // Ramp down
  // ],

  // Scenario 4: Spike test (sudden traffic spike)
  // stages: [
  //   { duration: '10s', target: 100 }, // Sudden spike
  //   { duration: '1m', target: 100 },  // Maintain spike
  //   { duration: '10s', target: 0 },   // Quick ramp down
  // ],

  thresholds: {
    // 95% of requests should complete within 500ms
    http_req_duration: ['p(95)<500'],
    // 99% of requests should succeed
    http_req_failed: ['rate<0.01'],
    // Custom threshold for success rate
    success_rate: ['rate>0.95'],
  },
};

// Load configuration from environment
const BASE_URL = __ENV.BASE_URL || 'http://localhost:4000';

// Test data generator
function generateEmail() {
  return `loadtest_${__VU}_${__ITER}_${Date.now()}@example.com`;
}

function generateUsername() {
  return `user_${__VU}_${__ITER}`;
}

// Test scenario: Complete user flow
export default function () {
  const testEmail = generateEmail();
  const testUsername = generateUsername();
  const testPassword = 'LoadTest123';

  // 1. Test Signup
  const signupPayload = JSON.stringify({
    email: testEmail,
    username: testUsername,
    password: testPassword,
  });

  const signupParams = {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: 'Signup' },
  };

  const signupRes = http.post(
    `${BASE_URL}/api/v2/auth/signup`,
    signupPayload,
    signupParams
  );

  const signupSuccess = check(signupRes, {
    'signup status is 201': (r) => r.status === 201,
    'signup has user_id': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.user_id !== undefined;
      } catch (e) {
        return false;
      }
    },
  });

  if (!signupSuccess) {
    signupErrors.add(1);
  }
  successRate.add(signupSuccess);

  sleep(0.5); // Think time between requests

  // 2. Test Login
  const loginPayload = JSON.stringify({
    username: testUsername,
    password: testPassword,
  });

  const loginParams = {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: 'Login' },
  };

  const loginStart = Date.now();
  const loginRes = http.post(
    `${BASE_URL}/api/v2/auth/login`,
    loginPayload,
    loginParams
  );
  const loginEnd = Date.now();

  loginDuration.add(loginEnd - loginStart);

  const loginSuccess = check(loginRes, {
    'login status is 200': (r) => r.status === 200,
    'login has user data': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.status === 'success' && body.user !== undefined;
      } catch (e) {
        return false;
      }
    },
  });

  if (!loginSuccess) {
    loginErrors.add(1);
  }
  successRate.add(loginSuccess);

  sleep(0.5);

  // 3. Test Logout
  const logoutRes = http.post(
    `${BASE_URL}/api/v2/auth/logout`,
    null,
    { tags: { name: 'Logout' } }
  );

  const logoutSuccess = check(logoutRes, {
    'logout status is 200': (r) => r.status === 200,
  });

  successRate.add(logoutSuccess);

  sleep(1); // Think time before next iteration
}

// Lifecycle hooks
export function setup() {
  console.log(`Starting load test against ${BASE_URL}`);

  // Verify server is available
  const res = http.get(BASE_URL);
  if (res.status !== 200 && res.status !== 404) {
    throw new Error(`Server not responding at ${BASE_URL}`);
  }

  return { timestamp: Date.now() };
}

export function teardown(data) {
  console.log(`Load test completed. Started at ${new Date(data.timestamp)}`);

  // Note: You may want to cleanup test data from database
  // For now, test users will remain in the database
  console.log('Note: Test users remain in database. Clean up with:');
  console.log('  DELETE FROM idm.users WHERE email LIKE \'loadtest_%\';');
}
