import { test, expect } from '@playwright/test'

test.describe('Navigation', () => {
  test.beforeEach(async ({ page }) => {
    // Mock authentication
    await page.addInitScript(() => {
      localStorage.setItem('admin_token', 'mock-jwt-token')
    })

    // Mock basic API responses
    await page.route('/api/v1/admin/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: {} })
      })
    })
  })

  test('should navigate between pages using sidebar', async ({ page }) => {
    await page.goto('/dashboard')

    // Test navigation to Users page
    await page.click('text=Users')
    await expect(page).toHaveURL('/users')
    await expect(page.locator('h1')).toContainText('User Management')

    // Test navigation to Roles page
    await page.click('text=Roles')
    await expect(page).toHaveURL('/roles')
    await expect(page.locator('h1')).toContainText('Role Management')

    // Test navigation to Sessions page
    await page.click('text=Sessions')
    await expect(page).toHaveURL('/sessions')
    await expect(page.locator('h1')).toContainText('Active Sessions')

    // Test navigation to Audit Logs page
    await page.click('text=Audit Logs')
    await expect(page).toHaveURL('/audit-logs')
    await expect(page.locator('h1')).toContainText('Audit Logs')

    // Test navigation to System Health page
    await page.click('text=System Health')
    await expect(page).toHaveURL('/system-health')
    await expect(page.locator('h1')).toContainText('System Health')

    // Test navigation to Configuration page
    await page.click('text=Configuration')
    await expect(page).toHaveURL('/configuration')
    await expect(page.locator('h1')).toContainText('Configuration')

    // Test navigation to Alerts page
    await page.click('text=Alerts')
    await expect(page).toHaveURL('/alerts')
    await expect(page.locator('h1')).toContainText('System Alerts')

    // Test navigation to Notifications page
    await page.click('text=Notifications')
    await expect(page).toHaveURL('/notifications')
    await expect(page.locator('h1')).toContainText('Notification Settings')

    // Test navigation back to Dashboard
    await page.click('text=Dashboard')
    await expect(page).toHaveURL('/dashboard')
    await expect(page.locator('h1')).toContainText('Dashboard')
  })

  test('should highlight active navigation item', async ({ page }) => {
    await page.goto('/dashboard')

    // Dashboard should be active
    const dashboardLink = page.locator('a[href="/dashboard"]')
    await expect(dashboardLink).toHaveClass(/bg-primary-100/)

    // Navigate to Users and check active state
    await page.click('text=Users')
    const usersLink = page.locator('a[href="/users"]')
    await expect(usersLink).toHaveClass(/bg-primary-100/)
    await expect(dashboardLink).not.toHaveClass(/bg-primary-100/)
  })

  test('should work on mobile with hamburger menu', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 })
    await page.goto('/dashboard')

    // Sidebar should be hidden on mobile
    await expect(page.locator('nav').first()).not.toBeVisible()

    // Click hamburger menu
    await page.click('button[aria-label="Open menu"], button:has-text("☰"), svg[data-testid="menu"]')

    // Sidebar should be visible
    await expect(page.locator('nav').first()).toBeVisible()

    // Navigate to Users
    await page.click('text=Users')
    await expect(page).toHaveURL('/users')

    // Sidebar should close after navigation
    await expect(page.locator('nav').first()).not.toBeVisible()
  })

  test('should show system status indicator in header', async ({ page }) => {
    // Mock healthy system
    await page.route('/api/v1/admin/system/health', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            status: 'healthy',
            components: {},
            timestamp: new Date().toISOString()
          }
        })
      })
    })

    await page.goto('/dashboard')

    // Should show green status indicator
    const statusIndicator = page.locator('.bg-green-500').first()
    await expect(statusIndicator).toBeVisible()
  })

  test('should show alert count in navigation', async ({ page }) => {
    // Mock alerts with active alerts
    await page.route('/api/v1/admin/alerts', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            alerts: [
              {
                id: '1',
                severity: 'high',
                is_active: true,
                is_resolved: false
              },
              {
                id: '2',
                severity: 'medium',
                is_active: true,
                is_resolved: false
              }
            ]
          }
        })
      })
    })

    await page.goto('/dashboard')

    // Should show alert count badge
    const alertsLink = page.locator('a:has-text("Alerts")')
    await expect(alertsLink.locator('text=2')).toBeVisible()
  })

  test('should redirect to dashboard from root path', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveURL('/dashboard')
  })

  test('should redirect unknown paths to dashboard', async ({ page }) => {
    await page.goto('/unknown-path')
    await expect(page).toHaveURL('/dashboard')
  })

  test('should maintain navigation state on page refresh', async ({ page }) => {
    await page.goto('/users')
    await page.reload()
    
    await expect(page).toHaveURL('/users')
    await expect(page.locator('h1')).toContainText('User Management')
    
    const usersLink = page.locator('a[href="/users"]')
    await expect(usersLink).toHaveClass(/bg-primary-100/)
  })
})