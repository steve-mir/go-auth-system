import { useQuery } from 'react-query'
import {
  Users,
  Shield,
  Activity,
  AlertTriangle,
  TrendingUp,
  Database,
  Zap,
  Clock,
} from 'lucide-react'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts'
import { systemApi, userApi, alertsApi } from '@/lib/api'
import { formatNumber, formatPercentage, formatBytes, getStatusColor } from '@/lib/utils'

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6']

export default function Dashboard() {
  const { data: systemMetrics, isLoading: metricsLoading } = useQuery(
    'system-metrics',
    systemApi.getMetrics,
    {
      refetchInterval: 30000, // Refetch every 30 seconds
    }
  )

  const { data: userStats, isLoading: userStatsLoading } = useQuery(
    'user-stats',
    userApi.getStats,
    {
      refetchInterval: 60000, // Refetch every minute
    }
  )

  const { data: alerts } = useQuery('active-alerts', alertsApi.getActive, {
    refetchInterval: 60000,
  })

  const activeAlerts = alerts?.filter((alert) => alert.is_active && !alert.is_resolved) || []
  const criticalAlerts = activeAlerts.filter((alert) => alert.severity === 'critical')

  // Prepare chart data
  const registrationTrendData = userStats?.registration_trend?.map((point) => ({
    date: new Date(point.date).toLocaleDateString(),
    registrations: point.count,
  })) || []

  const loginTrendData = userStats?.login_trend?.map((point) => ({
    date: new Date(point.date).toLocaleDateString(),
    logins: point.count,
  })) || []

  const roleDistributionData = userStats?.users_by_role
    ? Object.entries(userStats.users_by_role).map(([role, count]) => ({
        name: role,
        value: count,
      }))
    : []

  const performanceData = systemMetrics
    ? [
        {
          name: 'Requests',
          total: systemMetrics.requests.total,
          success: Math.round(systemMetrics.requests.total * systemMetrics.requests.success_rate),
          errors: Math.round(systemMetrics.requests.total * systemMetrics.requests.error_rate),
        },
      ]
    : []

  if (metricsLoading || userStatsLoading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/4 mb-6"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="card p-6">
                <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                <div className="h-8 bg-gray-200 rounded w-1/2"></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <div className="text-sm text-gray-500">
          Last updated: {new Date().toLocaleTimeString()}
        </div>
      </div>

      {/* Critical Alerts Banner */}
      {criticalAlerts.length > 0 && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="h-5 w-5 text-red-600 mr-2" />
            <h3 className="text-sm font-medium text-red-800">
              {criticalAlerts.length} Critical Alert{criticalAlerts.length > 1 ? 's' : ''}
            </h3>
          </div>
          <div className="mt-2 text-sm text-red-700">
            {criticalAlerts.slice(0, 3).map((alert) => (
              <div key={alert.id}>{alert.title}</div>
            ))}
            {criticalAlerts.length > 3 && (
              <div>And {criticalAlerts.length - 3} more...</div>
            )}
          </div>
        </div>
      )}

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Users className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Total Users</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatNumber(systemMetrics?.users.total_users || 0)}
              </p>
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
            <span className="text-green-600">
              +{formatNumber(systemMetrics?.users.new_users_24h || 0)} today
            </span>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg">
              <Activity className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Active Sessions</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatNumber(systemMetrics?.authentication.active_sessions || 0)}
              </p>
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <span className="text-gray-600">
              Success Rate: {formatPercentage(systemMetrics?.authentication.success_rate || 0)}
            </span>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Clock className="h-6 w-6 text-yellow-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Avg Response Time</p>
              <p className="text-2xl font-bold text-gray-900">
                {systemMetrics?.requests.avg_latency || 'N/A'}
              </p>
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <span className="text-gray-600">
              P95: {systemMetrics?.requests.p95_latency || 'N/A'}
            </span>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Active Alerts</p>
              <p className="text-2xl font-bold text-gray-900">
                {activeAlerts.length}
              </p>
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <span className="text-red-600">
              {criticalAlerts.length} critical
            </span>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* User Registration Trend */}
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">User Registration Trend</h3>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={registrationTrendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Area
                  type="monotone"
                  dataKey="registrations"
                  stroke="#3b82f6"
                  fill="#3b82f6"
                  fillOpacity={0.1}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Login Activity */}
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Login Activity</h3>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={loginTrendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="logins"
                  stroke="#10b981"
                  strokeWidth={2}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* System Status and Role Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* System Components Status */}
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">System Status</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <Database className="h-4 w-4 text-gray-400 mr-2" />
                <span className="text-sm text-gray-600">Database</span>
              </div>
              <span className={`badge ${getStatusColor('healthy')}`}>
                Healthy
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <Zap className="h-4 w-4 text-gray-400 mr-2" />
                <span className="text-sm text-gray-600">Cache</span>
              </div>
              <span className={`badge ${getStatusColor('healthy')}`}>
                Healthy
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <Shield className="h-4 w-4 text-gray-400 mr-2" />
                <span className="text-sm text-gray-600">Auth Service</span>
              </div>
              <span className={`badge ${getStatusColor('healthy')}`}>
                Healthy
              </span>
            </div>
          </div>
        </div>

        {/* Role Distribution */}
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">User Roles</h3>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={roleDistributionData}
                  cx="50%"
                  cy="50%"
                  innerRadius={40}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {roleDistributionData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 space-y-2">
            {roleDistributionData.map((entry, index) => (
              <div key={entry.name} className="flex items-center justify-between text-sm">
                <div className="flex items-center">
                  <div
                    className="w-3 h-3 rounded-full mr-2"
                    style={{ backgroundColor: COLORS[index % COLORS.length] }}
                  />
                  <span className="text-gray-600">{entry.name}</span>
                </div>
                <span className="font-medium">{formatNumber(entry.value)}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Performance Metrics */}
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Performance</h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-600">Cache Hit Rate</span>
                <span className="font-medium">
                  {formatPercentage(systemMetrics?.cache.hit_rate || 0)}
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-green-500 h-2 rounded-full"
                  style={{ width: `${(systemMetrics?.cache.hit_rate || 0) * 100}%` }}
                />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-600">Memory Usage</span>
                <span className="font-medium">
                  {formatBytes(systemMetrics?.database.active_connections || 0)}
                </span>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-600">DB Connections</span>
                <span className="font-medium">
                  {systemMetrics?.database.active_connections || 0} / {systemMetrics?.database.max_connections || 0}
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full"
                  style={{
                    width: `${
                      systemMetrics?.database.max_connections
                        ? (systemMetrics.database.active_connections / systemMetrics.database.max_connections) * 100
                        : 0
                    }%`,
                  }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}