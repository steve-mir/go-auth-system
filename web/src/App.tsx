import { Routes, Route, Navigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import Layout from '@/components/Layout'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'
import Users from '@/pages/Users'
import Roles from '@/pages/Roles'
import Sessions from '@/pages/Sessions'
import AuditLogs from '@/pages/AuditLogs'
import SystemHealth from '@/pages/SystemHealth'
import Configuration from '@/pages/Configuration'
import Alerts from '@/pages/Alerts'
import NotificationSettings from '@/pages/NotificationSettings'

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null)

  useEffect(() => {
    // Check if user is authenticated
    const token = localStorage.getItem('admin_token')
    setIsAuthenticated(!!token)
  }, [])

  // Show loading while checking authentication
  if (isAuthenticated === null) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="loading-spinner"></div>
      </div>
    )
  }

  // If not authenticated, show login page
  if (!isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<Login onLogin={() => setIsAuthenticated(true)} />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  // If authenticated, show main app
  return (
    <Layout onLogout={() => setIsAuthenticated(false)}>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/users" element={<Users />} />
        <Route path="/roles" element={<Roles />} />
        <Route path="/sessions" element={<Sessions />} />
        <Route path="/audit-logs" element={<AuditLogs />} />
        <Route path="/system-health" element={<SystemHealth />} />
        <Route path="/configuration" element={<Configuration />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/notifications" element={<NotificationSettings />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  )
}

export default App