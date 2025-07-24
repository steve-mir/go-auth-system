import { test, expect } from '@playwright/test'

test.describe('Authentication', () => {
  test('should show login page when not authenticated', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveURL('/login')
    await expect(page.locator('h2')).toContainText('Admin Dashboard')
    await expect(page.locator('input[type="email"]')).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()
  })

  test('should show validation errors for invalid login', async ({ page }) => {
    await page.goto('/login')
    
    // Try to submit empty form
    await page.click('button[type="submit"]')
    await expect(page.locator('text=Email is required')).toBeVisible()
    await expect(page.locator('text=Password is required')).toBeVisible()

    // Try invalid email
    await page.fill('input[type="email"]', 'invalid-email')
    await page.click('button[type="submit"]')
    await expect(page.locator('text=Invalid email address')).toBeVisible()

    // Try short password
    await page.fill('input[type="email"]', 'admin@example.com')
    await page.fill('input[type="password"]', '123')
    await page.click('button[type="submit"]')
    await expect(page.locator('text=Password must be at least 6 characters')).toBeVisible()
  })

  test('should toggle password visibility', async ({ page }) => {
    await page.goto('/login')
    
    const passwordInput = page.locator('input[type="password"]')
    const toggleButton = page.locator('button:has-text("")').last() // Eye icon button
    
    await expect(passwordInput).toHaveAttribute('type', 'password')
    await toggleButton.click()
    await expect(passwordInput).toHaveAttribute('type', 'text')
    await toggleButton.click()
    await expect(passwordInput).toHaveAttribute('type', 'password')
  })

  test('should login with valid credentials', async ({ page }) => {
    // Mock successful login API response
    await page.route('/api/v1/auth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            token: 'mock-jwt-token'
          }
        })
      })
    })

    await page.goto('/login')
    await page.fill('input[type="email"]', 'admin@example.com')
    await page.fill('input[type="password"]', 'password123')
    await page.click('button[type="submit"]')

    // Should redirect to dashboard
    await expect(page).toHaveURL('/dashboard')
  })

  test('should handle login API error', async ({ page }) => {
    // Mock failed login API response
    await page.route('/api/v1/auth/login', async (route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({
          error: {
            message: 'Invalid credentials'
          }
        })
      })
    })

    await page.goto('/login')
    await page.fill('input[type="email"]', 'admin@example.com')
    await page.fill('input[type="password"]', 'wrongpassword')
    await page.click('button[type="submit"]')

    // Should show error message
    await expect(page.locator('text=Invalid credentials')).toBeVisible()
    await expect(page).toHaveURL('/login')
  })

  test('should logout successfully', async ({ page }) => {
    // Mock login
    await page.addInitScript(() => {
      localStorage.setItem('admin_token', 'mock-jwt-token')
    })

    // Mock logout API response
    await page.route('/api/v1/auth/logout', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Logged out successfully' })
      })
    })

    await page.goto('/dashboard')
    await page.click('button:has-text("Sign out")')

    // Should redirect to login
    await expect(page).toHaveURL('/login')
  })
})