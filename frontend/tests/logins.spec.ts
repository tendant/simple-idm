import { test, expect } from '@playwright/test';

test.describe('Logins Page', () => {
  test.beforeEach(async ({ page }) => {
    // Go to the base URL first
    await page.goto('/');
    
    // Mock the authentication by setting localStorage
    await page.evaluate(() => {
      localStorage.setItem('user', JSON.stringify({
        id: '1',
        username: 'admin',
        email: 'admin@example.com',
        name: 'Admin User',
        roles: [{ id: '1', name: 'admin' }]
      }));
    });
    
    // Mock the logins API response
    await page.route('**/idm/logins', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: '1',
            username: 'admin',
            password_last_changed: '2025-01-15T10:30:00Z',
            status: 'Active',
            two_factor_enabled: true
          },
          {
            id: '2',
            username: 'user1',
            password_last_changed: '2025-02-20T14:45:00Z',
            status: 'Active',
            two_factor_enabled: false
          },
          {
            id: '3',
            username: 'user2',
            password_last_changed: null,
            status: 'Locked',
            two_factor_enabled: false
          }
        ])
      });
    });
    
    // Navigate to the logins page
    await page.goto('/logins');
  });

  test('should display logins table with correct data', async ({ page }) => {
    // Check page title
    await expect(page.getByRole('heading', { name: 'User Logins' })).toBeVisible();
    
    // Check table headers
    const headers = ['Username', 'Password Last Changed', 'Status'];
    for (const header of headers) {
      await expect(page.getByRole('columnheader', { name: header })).toBeVisible();
    }
    
    // Check login data is displayed correctly
    await expect(page.getByRole('cell', { name: 'admin' }).first()).toBeVisible();
    await expect(page.getByRole('cell', { name: /1\/15\/2025/ })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'Active' }).first()).toBeVisible();
    
    await expect(page.getByRole('cell', { name: 'user1' })).toBeVisible();
    await expect(page.getByRole('cell', { name: /2\/20\/2025/ })).toBeVisible();
    
    await expect(page.getByRole('cell', { name: 'user2' })).toBeVisible();
    await expect(page.getByRole('cell', { name: '-' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'Locked' })).toBeVisible();
  });

  test('should navigate to create login page', async ({ page }) => {
    await page.getByRole('button', { name: 'Add Login' }).click();
    await expect(page.url()).toContain('/logins/create');
  });

  test('should navigate to login detail page when clicking on username', async ({ page }) => {
    await page.getByRole('link', { name: 'admin' }).click();
    await expect(page.url()).toContain('/logins/1/detail');
  });

  test('should navigate to edit login page', async ({ page }) => {
    // Click the edit button for the first login
    await page.getByRole('button', { name: 'Edit' }).first().click();
    await expect(page.url()).toContain('/logins/1/edit');
  });

  test('should delete a login after confirmation', async ({ page }) => {
    // Mock the delete API response
    await page.route('**/idm/logins/2', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ success: true })
        });
      }
    });
    
    // Mock the window.confirm to return true
    page.on('dialog', dialog => dialog.accept());
    
    // Get the number of rows before deletion
    const rowsBeforeCount = await page.getByRole('row').count();
    
    // Click the delete button for the second login
    await page.getByRole('button', { name: 'Delete' }).nth(1).click();
    
    // Check that the login was removed from the table
    await expect(page.getByRole('row')).toHaveCount(rowsBeforeCount - 1);
    await expect(page.getByRole('cell', { name: 'user1' })).not.toBeVisible();
  });

  test('should show error when delete fails', async ({ page }) => {
    // Mock the delete API response to fail
    await page.route('**/idm/logins/2', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Failed to delete login' })
        });
      }
    });
    
    // Mock the window.confirm to return true
    page.on('dialog', dialog => dialog.accept());
    
    // Click the delete button for the second login
    await page.getByRole('button', { name: 'Delete' }).nth(1).click();
    
    // Check that an error message is displayed
    await expect(page.getByText('Failed to delete login')).toBeVisible();
  });

  test('should display empty state when no logins exist', async ({ page }) => {
    // Mock the logins API response with empty array
    await page.route('/idm/logins', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([])
      });
    });
    
    // Reload the page to get the new mocked data
    await page.reload();
    
    // Check for the empty state message
    await expect(page.getByText('No logins found')).toBeVisible();
  });
});
