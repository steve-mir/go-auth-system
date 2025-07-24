import { test, expect } from '@playwright/test'

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Mock authentication
    await page.addInitScript(() => {
      localStorage.setItem('admin_token', 'mock-jwt-token')
    })

    // Mock API responses
    await page.route('/api/v1/admin/system/metrics', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            requests: {
              total: 10000,
              success_rate: 0.99,
              avg_latency: '45ms',
              p95_latency: '120ms',
              p99_latency: '250ms',
              error_rate: 0.01
            },
            authentication: {
              total_logins: 5000,
              failed_logins: 50,
              success_rate: 0.99,
              active_sessions: 150,
              mfa_usage: 0.75
            },
            users: {
              total_users: 1000,
              active_users: 800,
              verified_users: 950,
              locked_accounts: 5,
              new_users_24h: 25,
              new_users_7d: 180
            },
            tokens: {
              issued_tokens: 15000,
              active_tokens: 500,
              expired_tokens: 14000,
              blacklisted_tokens: 500,
              refresh_rate: 0.1
            },
            database: {
              active_connections: 10,
              idle_connections: 5,
              max_connections: 100,
              avg_query_time: '2.5ms',
              slow_queries: 2,
              error_rate: 0.001
            },
            cache: {
              hit_rate: 0.95,
              miss_rate: 0.05,
              memory_usage: '256MB',
              key_count: 50000,
              eviction_count: 100
            },
            security: {
              rate_limit_hits: 100,
              blocked_requests: 25,
              suspicious_activity: 5,
              failed_auth_attempts: 50
            },
            timestamp: new Date().toISOString()
          }
        })
      })
    })

    await page.route('/api/v1/admin/users/stats', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            total_users: 1000,
            active_users: 800,
            verified_users: 950,
            locked_accounts: 5,
            users_by_role: {
              admin: 5,
              user: 980,
              moderator: 15
            },
            registration_trend: [
              { date: '2024-01-01', count: 10 },
              { date: '2024-01-02', count: 15 },
              { date: '2024-01-03', count: 12 },
              { date: '2024-01-04', count: 18 },
              { date: '2024-01-05', count: 20 }
            ],
            login_trend: [
              { date: '2024-01-01', count: 100 },
              { date: '2024-01-02', count: 120 },
              { date: '2024-01-03', count: 110 },
              { date: '2024-01-04', count: 130 },
              { date: '2024-01-05', count: 140 }
            ]
          }
        })
      })
    })

    await page.route('/api/v1/admin/alerts', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            alerts: [
              {
                id: '1',
                type: 'system',
                severity: 'high',
                title: 'High CPU Usage',
                message: 'CPU usage is above 80%',
                source: 'monitoring',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                is_active: true,
                is_resolved: false
              }
            ]
          }
        })
      })
    })

    await page.route('/api/v1/admin/system/health', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            status: 'healthy',
            components: {
              database: {
                status: 'healthy',
                last_checked: new Date().toISOString()
              },
              cache: {
                status: 'healthy',
                last_checked: new Date().toISOString()
              },
              auth: {
                status: 'healthy',
                last_checked: new Date().toISOString()
              }
            },
            timestamp: new Date().toISOString()
          }
        })
      })
    })
  })

  test('should display dashboard with key metrics', async ({ page }) => {
    await page.goto('/dashboard')

    // Check page title
    await expect(page.locator('h1')).toContainText('Dashboard')

    // Check key metrics cards
    await expect(page.locator('text=Total Users')).toBeVisible()
    await expect(page.locator('text=1,000')).toBeVisible()
    await expect(page.locator('text=Active Sessions')).toBeVisible()
    await expect(page.locator('text=150')).toBeVisible()
    await expect(page.locator('text=Avg Response Time')).toBeVisible()
    await expect(page.locator('text=45ms')).toBeVisible()
    await expect(page.locator('text=Active Alerts')).toBeVisible()
  })

  test('should display charts', async ({ page }) => {
    await page.goto('/dashboard')

    // Check for chart containers
    await expect(page.locator('text=User Registration Trend')).toBeVisible()
    await expect(page.locator('text=Login Activity')).toBeVisible()
    await expect(page.locator('.recharts-wrapper')).toHaveCount(3) // Registration, Login, and Pie chart
  })

  test('should show system status', async ({ page }) => {
    await page.goto('/dashboard')

    // Check system status section
    await expect(page.locator('text=System Status')).toBeVisible()
    await expect(page.locator('text=Database')).toBeVisible()
    await expect(page.locator('text=Cache')).toBeVisible()
    await expect(page.locator('text=Auth Service')).toBeVisible()
    await expect(page.locator('text=Healthy')).toHaveCount(3)
  })

  test('should display performance metrics', async ({ page }) => {
    await page.goto('/dashboard')

    // Check performance section
    await expect(page.locator('text=Performance')).toBeVisible()
    await expect(page.locator('text=Cache Hit Rate')).toBeVisible()
    await expect(page.locator('text=95.0%')).toBeVisible()
    await expect(page.locator('text=DB Connections')).toBeVisible()
  })

  test('should show critical alerts banner', async ({ page }) => {
    // Mock critical alert
    await page.route('/api/v1/admin/alerts', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            alerts: [
              {
                id: '1',
                type: 'system',
                severity: 'critical',
                title: 'Database Connection Failed',
                message: 'Unable to connect to primary database',
                source: 'database',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                is_active: true,
                is_resolved: false
              }
            ]
          }
        })
      })
    })

    await page.goto('/dashboard')

    // Should show critical alert banner
    await expect(page.locator('text=1 Critical Alert')).toBeVisible()
    await expect(page.locator('text=Database Connection Failed')).toBeVisible()
  })

  test('should update metrics in real-time', async ({ page }) => {
    await page.goto('/dashboard')

    // Initial load
    await expect(page.locator('text=1,000')).toBeVisible()

    // Mock updated metrics
    await page.route('/api/v1/admin/system/metrics', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            users: {
              total_users: 1001, // Updated value
              active_users: 801,
              verified_users: 951,
              locked_accounts: 5,
              new_users_24h: 26,
              new_users_7d: 181
            },
            // ... other metrics remain the same
            timestamp: new Date().toISOString()
          }
        })
      })
    })

    // Wait for auto-refresh (30 seconds in real app, but we can trigger manually)
    await page.waitForTimeout(1000)
    await page.reload()

    // Should show updated value
    await expect(page.locator('text=1,001')).toBeVisible()
  })
})