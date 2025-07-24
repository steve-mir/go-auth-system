import { useQuery } from 'react-query'
import {
  Database,
  Zap,
  Server,
  Shield,
  Activity,
  AlertCircle,
  CheckCircle,
  Clock,
} from 'lucide-react'
import { systemApi } from '@/lib/api'
import { formatBytes, formatPercentage, formatRelativeTime, getStatusColor, cn } from '@/lib/utils'

export default function SystemHealth() {
  const { data: systemHealth, isLoading: healthLoading } = useQuery(
    'system-health',
    systemApi.getHealth,
    {
      refetchInterval: 10000, // Refetch every 10 seconds
    }
  )

  const { data: systemInfo, isLoading: infoLoading } = useQuery(
    'system-info',
    systemApi.getInfo
  )

  const { data: systemMetrics, isLoading: metricsLoading } = useQuery(
    'system-metrics',
    systemApi.getMetrics,
    {
      refetchInterval: 30000, // Refetch every 30 seconds
    }
  )

  if (healthLoading || infoLoading || metricsLoading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/4 mb-6"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="card p-6">
                <div className="h-4 bg-gray-200 rounded w-3/4 mb-4"></div>
                <div className="space-y-2">
                  {[...Array(3)].map((_, j) => (
                    <div key={j} className="h-3 bg-gray-200 rounded"></div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    )
  }

  const components = systemHealth?.components || {}
  const healthyComponents = Object.values(components).filter(c => c.status === 'healthy').length
  const totalComponents = Object.keys(components).length
  const overallHealthy = healthyComponents === totalComponents

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">System Health</h1>
        <div className="flex items-center gap-2">
          <div
            className={cn(
              'w-3 h-3 rounded-full',
              overallHealthy ? 'bg-green-500' : 'bg-red-500'
            )}
          />
          <span className="text-sm font-medium text-gray-700">
            {overallHealthy ? 'All Systems Operational' : 'System Issues Detected'}
          </span>
        </div>
      </div>

      {/* Overall Status */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-medium text-gray-900">System Overview</h2>
          <div className="text-sm text-gray-500">
            Last updated: {systemHealth ? formatRelativeTime(systemHealth.timestamp) : 'N/A'}
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900">{healthyComponents}/{totalComponents}</div>
            <div className="text-sm text-gray-600">Components Healthy</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900">
              {systemInfo?.runtime.uptime || 'N/A'}
            </div>
            <div className="text-sm text-gray-600">Uptime</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900">
              {systemInfo?.runtime.go_routines || 0}
            </div>
            <div className="text-sm text-gray-600">Go Routines</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900">
              {systemInfo?.runtime.cpu_usage ? `${systemInfo.runtime.cpu_usage.toFixed(1)}%` : 'N/A'}
            </div>
            <div className="text-sm text-gray-600">CPU Usage</div>
          </div>
        </div>
      </div>

      {/* Component Health */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {Object.entries(components).map(([name, component]) => {
          const isHealthy = component.status === 'healthy'
          const Icon = name === 'database' ? Database :
                     name === 'cache' ? Zap :
                     name === 'auth' ? Shield :
                     Server

          return (
            <div key={name} className="card p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center">
                  <div className={cn(
                    'p-2 rounded-lg',
                    isHealthy ? 'bg-green-100' : 'bg-red-100'
                  )}>
                    <Icon className={cn(
                      'h-5 w-5',
                      isHealthy ? 'text-green-600' : 'text-red-600'
                    )} />
                  </div>
                  <div className="ml-3">
                    <h3 className="text-lg font-medium text-gray-900 capitalize">{name}</h3>
                    <p className="text-sm text-gray-500">
                      Last checked: {formatRelativeTime(component.last_checked)}
                    </p>
                  </div>
                </div>
                <div className="flex items-center">
                  {isHealthy ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-red-500" />
                  )}
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Status</span>
                  <span className={`badge ${getStatusColor(component.status)}`}>
                    {component.status}
                  </span>
                </div>

                {component.message && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-600">Message</span>
                    <span className="text-sm text-gray-900">{component.message}</span>
                  </div>
                )}

                {component.metrics && Object.keys(component.metrics).length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Metrics</h4>
                    <div className="space-y-1">
                      {Object.entries(component.metrics).map(([key, value]) => (
                        <div key={key} className="flex items-center justify-between text-sm">
                          <span className="text-gray-600 capitalize">{key.replace(/_/g, ' ')}</span>
                          <span className="text-gray-900 font-mono">
                            {typeof value === 'number' && key.includes('bytes') 
                              ? formatBytes(value)
                              : typeof value === 'number' && key.includes('rate')
                              ? formatPercentage(value)
                              : String(value)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Performance Metrics */}
      {systemMetrics && (
        <div className="card p-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Performance Metrics</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <h3 className="text-sm font-medium text-gray-900 mb-3">Database</h3>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Active Connections</span>
                  <span className="font-mono">{systemMetrics.database.active_connections}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Idle Connections</span>
                  <span className="font-mono">{systemMetrics.database.idle_connections}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Avg Query Time</span>
                  <span className="font-mono">{systemMetrics.database.avg_query_time}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Error Rate</span>
                  <span className="font-mono">{formatPercentage(systemMetrics.database.error_rate)}</span>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-900 mb-3">Cache</h3>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Hit Rate</span>
                  <span className="font-mono">{formatPercentage(systemMetrics.cache.hit_rate)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Miss Rate</span>
                  <span className="font-mono">{formatPercentage(systemMetrics.cache.miss_rate)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Memory Usage</span>
                  <span className="font-mono">{systemMetrics.cache.memory_usage}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Key Count</span>
                  <span className="font-mono">{systemMetrics.cache.key_count.toLocaleString()}</span>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-900 mb-3">Security</h3>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Rate Limit Hits</span>
                  <span className="font-mono">{systemMetrics.security.rate_limit_hits.toLocaleString()}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Blocked Requests</span>
                  <span className="font-mono">{systemMetrics.security.blocked_requests.toLocaleString()}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Suspicious Activity</span>
                  <span className="font-mono">{systemMetrics.security.suspicious_activity.toLocaleString()}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Failed Auth Attempts</span>
                  <span className="font-mono">{systemMetrics.security.failed_auth_attempts.toLocaleString()}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* System Information */}
      {systemInfo && (
        <div className="card p-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">System Information</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="text-sm font-medium text-gray-900 mb-3">Build Information</h3>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Version</span>
                  <span className="font-mono">{systemInfo.version}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Go Version</span>
                  <span className="font-mono">{systemInfo.build.go_version}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Build Time</span>
                  <span className="font-mono">{formatRelativeTime(systemInfo.build.build_time)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Git Commit</span>
                  <span className="font-mono">{systemInfo.build.git_commit.slice(0, 8)}</span>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-900 mb-3">Runtime Information</h3>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Environment</span>
                  <span className="font-mono">{systemInfo.runtime.environment}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Start Time</span>
                  <span className="font-mono">{formatRelativeTime(systemInfo.runtime.start_time)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Memory Allocated</span>
                  <span className="font-mono">{formatBytes(systemInfo.runtime.memory_usage.allocated)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">GC Runs</span>
                  <span className="font-mono">{systemInfo.runtime.memory_usage.num_gc}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}