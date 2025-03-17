import { test, expect } from '@playwright/test';

test.describe('Navigation Component', () => {
  test.beforeEach(async ({ page }) => {
    // Mock the authentication by setting localStorage
    await page.goto('/');
    await page.evaluate(() => {
      localStorage.setItem('user', JSON.stringify({
        id: '1',
        username: 'admin',
        email: 'admin@example.com',
        name: 'Admin User',
        roles: [{ id: '1', name: 'admin' }]
      }));
    });
    
    // Mock the users API response for the default page
    await page.route('/idm/users', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([])
      });
    });
    
    // Navigate to the users page to see the navigation
    await page.goto('/users');
  });

  test('should display all navigation links', async ({ page }) => {
    // Check for the app title
    await expect(page.getByText('Simple IDM')).toBeVisible();
    
    // Check for all navigation links
    await expect(page.getByRole('link', { name: 'Users' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Roles' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Logins' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Settings' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Logout' })).toBeVisible();
  });

  test('should navigate to Users page', async ({ page }) => {
    // Mock the users API response
    await page.route('/idm/users', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([])
      });
    });
    
    await page.getByRole('link', { name: 'Users' }).click();
    await expect(page.url()).toContain('/users');
  });

  test('should navigate to Roles page', async ({ page }) => {
    // Mock the roles API response
    await page.route('/idm/roles', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([])
      });
    });
    
    await page.getByRole('link', { name: 'Roles' }).click();
    await expect(page.url()).toContain('/roles');
  });

  test('should navigate to Logins page', async ({ page }) => {
    // Mock the logins API response
    await page.route('/idm/logins', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([])
      });
    });
    
    await page.getByRole('link', { name: 'Logins' }).click();
    await expect(page.url()).toContain('/logins');
  });

  test('should navigate to Settings page', async ({ page }) => {
    await page.getByRole('link', { name: 'Settings' }).click();
    await expect(page.url()).toContain('/settings');
  });

  test('should logout when clicking the logout button', async ({ page }) => {
    // Mock the logout API response
    await page.route('/auth/logout', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true })
      });
    });
    
    // Click the logout button
    await page.getByRole('button', { name: 'Logout' }).click();
    
    // Check that we've been redirected to the login page
    await expect(page.url()).toContain('/login');
    
    // Verify localStorage was cleared
    const user = await page.evaluate(() => localStorage.getItem('user'));
    expect(user).toBeNull();
  });

  test('should handle failed logout gracefully', async ({ page }) => {
    // Mock a failed logout API response
    await page.route('/auth/logout', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Logout failed' })
      });
    });
    
    // Spy on console.error
    const consoleErrorMessages: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrorMessages.push(msg.text());
      }
    });
    
    // Click the logout button
    await page.getByRole('button', { name: 'Logout' }).click();
    
    // Check that we're still on the same page (not redirected)
    await expect(page.url()).toContain('/users');
    
    // Verify an error was logged to the console
    expect(consoleErrorMessages.some(msg => msg.includes('Logout failed'))).toBeTruthy();
  });
});
