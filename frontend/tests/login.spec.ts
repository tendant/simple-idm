import { test, expect } from '@playwright/test';

test.describe('Login Page', () => {
  test.beforeEach(async ({ page }) => {
    // Set up API mocking before navigating
    await page.route('**/auth/login', async (route) => {
      const requestData = JSON.parse(route.request().postData() || '{}');
      if (requestData.username === 'admin' && requestData.password === 'Password123!') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            id: '1',
            username: 'admin',
            email: 'admin@example.com',
            name: 'Admin User',
            roles: [{ id: '1', name: 'admin' }]
          })
        });
      } else if (requestData.username === 'user_with_2fa') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            status: '2fa_required',
            temp_token: 'temp_token_123',
            two_factor_methods: [
              {
                type: 'email',
                delivery_options: [
                  {
                    display_value: 'u***@example.com',
                    hashed_value: 'hashed_email_123'
                  }
                ]
              }
            ]
          })
        });
      } else {
        await route.fulfill({
          status: 401,
          contentType: 'text/plain',
          body: 'Invalid username or password'
        });
      }
    });
    
    // Navigate to the login page before each test
    await page.goto('/login');
  });

  test('should display login form', async ({ page }) => {
    // Verify login page elements are present
    await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
    await expect(page.getByLabel('Username')).toBeVisible();
    await expect(page.getByLabel('Password')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Forgot your password?' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Forgot your username?' })).toBeVisible();
  });

  test('should show error message with invalid credentials', async ({ page }) => {
    // Fill in invalid credentials
    await page.getByLabel('Username').fill('invalid_user');
    await page.getByLabel('Password').fill('invalid_password');
    
    // Submit the form
    await page.getByRole('button', { name: 'Sign in' }).click();
    
    // Check for error message
    await expect(page.getByText('Invalid username or password')).toBeVisible();
  });

  test('should redirect to users page after successful login', async ({ page }) => {
    // Mock the users list API response for the redirect
    await page.route('/idm/users', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: '1',
            username: 'admin',
            email: 'admin@example.com',
            name: 'Admin User',
            roles: [{ id: '1', name: 'admin' }]
          }
        ])
      });
    });
    
    // Fill in valid credentials
    await page.getByLabel('Username').fill('admin');
    await page.getByLabel('Password').fill('Password123!');
    
    // Submit the form
    await page.getByRole('button', { name: 'Sign in' }).click();
    
    // Check that we've been redirected to the users page
    await expect(page.url()).toContain('/users');
    await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible();
  });

  test('should redirect to two-factor verification when 2FA is required', async ({ page }) => {
    // Fill in credentials
    await page.getByLabel('Username').fill('user_with_2fa');
    await page.getByLabel('Password').fill('pwd');
    
    // Submit the form
    await page.getByRole('button', { name: 'Sign in' }).click();
    
    // Check that we've been redirected to the 2FA verification page
    await expect(page.url()).toContain('/two-factor-verification');
  });

  test('should navigate to forgot password page', async ({ page }) => {
    await page.getByRole('link', { name: 'Forgot your password?' }).click();
    await expect(page.url()).toContain('/password-reset-init');
  });

  test('should navigate to forgot username page', async ({ page }) => {
    await page.getByRole('link', { name: 'Forgot your username?' }).click();
    await expect(page.url()).toContain('/find-username');
  });
});
