import { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Users,
  Shield,
  Activity,
  FileText,
  Settings,
  AlertTriangle,
  Bell,
  LogOut,
  Menu,
  X,
  Heart,
} from 'lucide-react'
import { useQuery } from 'react-query'
import { systemApi, alertsApi } from '@/lib/api'
import { cn } from '@/lib/utils'
import toast from 'react-hot-toast'

interface LayoutProps {
  children: React.ReactNode
  onLogout: () => void
}

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Users', href: '/users', icon: Users },
  { name: 'Roles', href: '/roles', icon: Shield },
  { name: 'Sessions', href: '/sessions', icon: Activity },
  { name: 'Audit Logs', href: '/audit-logs', icon: FileText },
  { name: 'System Health', href: '/system-health', icon: Heart },
  { name: 'Configuration', href: '/configuration', icon: Settings },
  { name: 'Alerts', href: '/alerts', icon: AlertTriangle },
  { name: 'Notifications', href: '/notifications', icon: Bell },
]

export default function Layout({ children, onLogout }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const location = useLocation()

  // Get system health for status indicator
  const { data: systemHealth } = useQuery(
    'system-health',
    systemApi.getHealth,
    {
      refetchInterval: 30000, // Refetch every 30 seconds
      onError: () => {
        // Don't show error toast for health checks
      },
    }
  )

  // Get active alerts count
  const { data: alerts } = useQuery('active-alerts', alertsApi.getActive, {
    refetchInterval: 60000, // Refetch every minute
    onError: () => {
      // Don't show error toast for alerts
    },
  })

  const activeAlertsCount = alerts?.filter((alert) => alert.is_active && !alert.is_resolved).length || 0

  const handleLogout = async () => {
    try {
      // Call logout API
      await fetch('/api/v1/auth/logout', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('admin_token')}`,
        },
      })
    } catch (error) {
      // Ignore logout API errors
    } finally {
      localStorage.removeItem('admin_token')
      onLogout()
      toast.success('Logged out successfully')
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Mobile sidebar */}
      <div className={cn(
        'fixed inset-0 z-50 lg:hidden',
        sidebarOpen ? 'block' : 'hidden'
      )}>
        <div className="fixed inset-0 bg-gray-600 bg-opacity-75" onClick={() => setSidebarOpen(false)} />
        <div className="fixed inset-y-0 left-0 flex w-64 flex-col bg-white shadow-xl">
          <div className="flex h-16 items-center justify-between px-4">
            <h1 className="text-xl font-semibold text-gray-900">Admin Dashboard</h1>
            <button
              onClick={() => setSidebarOpen(false)}
              className="text-gray-400 hover:text-gray-600"
            >
              <X className="h-6 w-6" />
            </button>
          </div>
          <nav className="flex-1 space-y-1 px-2 py-4">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href
              const Icon = item.icon
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  onClick={() => setSidebarOpen(false)}
                  className={cn(
                    'group flex items-center px-2 py-2 text-sm font-medium rounded-md',
                    isActive
                      ? 'bg-primary-100 text-primary-700'
                      : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                  )}
                >
                  <Icon className="mr-3 h-5 w-5 flex-shrink-0" />
                  {item.name}
                  {item.name === 'Alerts' && activeAlertsCount > 0 && (
                    <span className="ml-auto inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                      {activeAlertsCount}
                    </span>
                  )}
                </Link>
              )
            })}
          </nav>
          <div className="border-t border-gray-200 p-4">
            <button
              onClick={handleLogout}
              className="group flex w-full items-center px-2 py-2 text-sm font-medium text-gray-600 rounded-md hover:bg-gray-50 hover:text-gray-900"
            >
              <LogOut className="mr-3 h-5 w-5 flex-shrink-0" />
              Sign out
            </button>
          </div>
        </div>
      </div>

      {/* Desktop sidebar */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:flex lg:w-64 lg:flex-col">
        <div className="flex flex-col flex-grow bg-white border-r border-gray-200">
          <div className="flex items-center h-16 px-4 border-b border-gray-200">
            <h1 className="text-xl font-semibold text-gray-900">Admin Dashboard</h1>
            {systemHealth && (
              <div className="ml-auto">
                <div
                  className={cn(
                    'w-3 h-3 rounded-full',
                    systemHealth.status === 'healthy' ? 'bg-green-500' : 'bg-red-500'
                  )}
                  title={`System Status: ${systemHealth.status}`}
                />
              </div>
            )}
          </div>
          <nav className="flex-1 space-y-1 px-2 py-4">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href
              const Icon = item.icon
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={cn(
                    'group flex items-center px-2 py-2 text-sm font-medium rounded-md',
                    isActive
                      ? 'bg-primary-100 text-primary-700'
                      : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                  )}
                >
                  <Icon className="mr-3 h-5 w-5 flex-shrink-0" />
                  {item.name}
                  {item.name === 'Alerts' && activeAlertsCount > 0 && (
                    <span className="ml-auto inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                      {activeAlertsCount}
                    </span>
                  )}
                </Link>
              )
            })}
          </nav>
          <div className="border-t border-gray-200 p-4">
            <button
              onClick={handleLogout}
              className="group flex w-full items-center px-2 py-2 text-sm font-medium text-gray-600 rounded-md hover:bg-gray-50 hover:text-gray-900"
            >
              <LogOut className="mr-3 h-5 w-5 flex-shrink-0" />
              Sign out
            </button>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top bar */}
        <div className="sticky top-0 z-40 flex h-16 bg-white border-b border-gray-200 lg:hidden">
          <button
            onClick={() => setSidebarOpen(true)}
            className="px-4 text-gray-500 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary-500 lg:hidden"
          >
            <Menu className="h-6 w-6" />
          </button>
          <div className="flex flex-1 justify-between px-4">
            <div className="flex flex-1">
              <h1 className="text-xl font-semibold text-gray-900 self-center">Admin Dashboard</h1>
            </div>
            <div className="ml-4 flex items-center md:ml-6">
              {systemHealth && (
                <div
                  className={cn(
                    'w-3 h-3 rounded-full mr-4',
                    systemHealth.status === 'healthy' ? 'bg-green-500' : 'bg-red-500'
                  )}
                  title={`System Status: ${systemHealth.status}`}
                />
              )}
            </div>
          </div>
        </div>

        {/* Page content */}
        <main className="flex-1">
          <div className="py-6">
            <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
              {children}
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}