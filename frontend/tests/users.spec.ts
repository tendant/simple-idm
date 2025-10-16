import { test, expect } from '@playwright/test';

test.describe('Users Page', () => {
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
    
    // Mock the users API response
    await page.route('**/api/idm/users', async (route) => {
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
          },
          {
            id: '2',
            username: 'user1',
            email: 'user1@example.com',
            name: 'Regular User',
            roles: [{ id: '2', name: 'user' }]
          },
          {
            id: '3',
            username: 'user2',
            email: 'user2@example.com',
            name: 'Another User',
            roles: [{ id: '2', name: 'user' }]
          }
        ])
      });
    });
    
    // Navigate to the users page
    await page.goto('/users');
  });

  test('should display users table with correct data', async ({ page }) => {
    // Check page title
    await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible();
    
    // Check table headers
    const headers = ['Name', 'Username', 'Email', 'Roles'];
    for (const header of headers) {
      await expect(page.getByRole('columnheader', { name: header })).toBeVisible();
    }
    
    // Check user data is displayed correctly
    await expect(page.getByRole('cell', { name: 'Admin User' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'admin' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'admin@example.com' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'admin' }).first()).toBeVisible();
    
    await expect(page.getByRole('cell', { name: 'Regular User' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'user1' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'user1@example.com' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'user' }).first()).toBeVisible();
  });

  test('should navigate to create user page', async ({ page }) => {
    await page.getByRole('button', { name: 'Add user' }).click();
    await expect(page.url()).toContain('/users/create');
  });

  test('should navigate to edit user page', async ({ page }) => {
    // Click the edit button for the first user
    await page.getByRole('button', { name: 'Edit' }).first().click();
    await expect(page.url()).toContain('/users/1/edit');
  });

  test('should delete a user after confirmation', async ({ page }) => {
    // Mock the delete API response
    await page.route('**/api/idm/users/2', async (route) => {
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
    
    // Click the delete button for the second user
    await page.getByRole('button', { name: 'Delete' }).nth(1).click();
    
    // Check that the user was removed from the table
    await expect(page.getByRole('row')).toHaveCount(rowsBeforeCount - 1);
    await expect(page.getByRole('cell', { name: 'Regular User' })).not.toBeVisible();
  });

  test('should show error when delete fails', async ({ page }) => {
    // Mock the delete API response to fail
    await page.route('**/api/idm/users/2', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Failed to delete user' })
        });
      }
    });
    
    // Mock the window.confirm to return true
    page.on('dialog', dialog => dialog.accept());
    
    // Click the delete button for the second user
    await page.getByRole('button', { name: 'Delete' }).nth(1).click();
    
    // Check that an error message is displayed
    await expect(page.getByText('Failed to delete user')).toBeVisible();
  });

  test('should cancel delete when user rejects confirmation', async ({ page }) => {
    // Mock the window.confirm to return false
    page.on('dialog', dialog => dialog.dismiss());
    
    // Get the number of rows before attempted deletion
    const rowsBeforeCount = await page.getByRole('row').count();
    
    // Click the delete button for the second user
    await page.getByRole('button', { name: 'Delete' }).nth(1).click();
    
    // Check that the number of rows hasn't changed
    await expect(page.getByRole('row')).toHaveCount(rowsBeforeCount);
    await expect(page.getByRole('cell', { name: 'Regular User' })).toBeVisible();
  });
});
