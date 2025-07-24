import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { useForm } from 'react-hook-form'
import {
  AlertTriangle,
  Plus,
  X,
  CheckCircle,
  Clock,
  Filter,
  Search,
  MoreHorizontal,
} from 'lucide-react'
import { alertsApi } from '@/lib/api'
import { formatRelativeTime, getSeverityColor, cn } from '@/lib/utils'
import toast from 'react-hot-toast'
import type { Alert, CreateAlertRequest } from '@/types/api'

interface AlertForm {
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  message: string
  source: string
}

export default function Alerts() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [selectedSeverity, setSelectedSeverity] = useState<string>('')
  const [searchTerm, setSearchTerm] = useState('')
  const [showResolved, setShowResolved] = useState(false)
  const queryClient = useQueryClient()

  const { data: alerts = [], isLoading } = useQuery('active-alerts', alertsApi.getActive, {
    refetchInterval: 30000, // Refetch every 30 seconds for real-time updates
  })

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<AlertForm>()

  const createMutation = useMutation(alertsApi.create, {
    onSuccess: () => {
      toast.success('Alert created successfully')
      setShowCreateModal(false)
      reset()
      queryClient.invalidateQueries('active-alerts')
    },
    onError: () => {
      toast.error('Failed to create alert')
    },
  })

  const updateMutation = useMutation(
    ({ alertId, data }: { alertId: string; data: any }) =>
      alertsApi.update(alertId, data),
    {
      onSuccess: () => {
        toast.success('Alert updated successfully')
        queryClient.invalidateQueries('active-alerts')
      },
      onError: () => {
        toast.error('Failed to update alert')
      },
    }
  )

  const deleteMutation = useMutation(alertsApi.delete, {
    onSuccess: () => {
      toast.success('Alert deleted successfully')
      queryClient.invalidateQueries('active-alerts')
    },
    onError: () => {
      toast.error('Failed to delete alert')
    },
  })

  // Real-time notifications for new critical alerts
  useEffect(() => {
    const criticalAlerts = alerts.filter(
      (alert) => alert.severity === 'critical' && alert.is_active && !alert.is_resolved
    )
    
    criticalAlerts.forEach((alert) => {
      const alertTime = new Date(alert.created_at).getTime()
      const now = Date.now()
      const fiveMinutesAgo = now - 5 * 60 * 1000
      
      // Show notification for alerts created in the last 5 minutes
      if (alertTime > fiveMinutesAgo) {
        toast.error(`Critical Alert: ${alert.title}`, {
          duration: 10000,
          icon: '🚨',
        })
      }
    })
  }, [alerts])

  const onSubmit = (data: AlertForm) => {
    createMutation.mutate(data)
  }

  const handleResolveAlert = (alertId: string) => {
    updateMutation.mutate({
      alertId,
      data: { is_resolved: true },
    })
  }

  const handleDeleteAlert = (alertId: string) => {
    if (confirm('Are you sure you want to delete this alert?')) {
      deleteMutation.mutate(alertId)
    }
  }

  // Filter alerts
  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch = 
      alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.source.toLowerCase().includes(searchTerm.toLowerCase())
    
    const matchesSeverity = !selectedSeverity || alert.severity === selectedSeverity
    const matchesResolved = showResolved || !alert.is_resolved
    
    return matchesSearch && matchesSeverity && matchesResolved
  })

  // Group alerts by severity
  const alertsBySeverity = {
    critical: filteredAlerts.filter((a) => a.severity === 'critical'),
    high: filteredAlerts.filter((a) => a.severity === 'high'),
    medium: filteredAlerts.filter((a) => a.severity === 'medium'),
    low: filteredAlerts.filter((a) => a.severity === 'low'),
  }

  const severityStats = {
    critical: alerts.filter((a) => a.severity === 'critical' && a.is_active && !a.is_resolved).length,
    high: alerts.filter((a) => a.severity === 'high' && a.is_active && !a.is_resolved).length,
    medium: alerts.filter((a) => a.severity === 'medium' && a.is_active && !a.is_resolved).length,
    low: alerts.filter((a) => a.severity === 'low' && a.is_active && !a.is_resolved).length,
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">System Alerts</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-primary"
        >
          <Plus className="h-4 w-4 mr-2" />
          Create Alert
        </button>
      </div>

      {/* Alert Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Critical</p>
              <p className="text-2xl font-bold text-red-600">{severityStats.critical}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-orange-100 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-orange-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">High</p>
              <p className="text-2xl font-bold text-orange-600">{severityStats.high}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-yellow-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Medium</p>
              <p className="text-2xl font-bold text-yellow-600">{severityStats.medium}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Low</p>
              <p className="text-2xl font-bold text-blue-600">{severityStats.low}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-6">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search alerts..."
                className="input pl-10"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
          <select
            className="input"
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <div className="flex items-center">
            <input
              type="checkbox"
              id="showResolved"
              checked={showResolved}
              onChange={(e) => setShowResolved(e.target.checked)}
              className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
            />
            <label htmlFor="showResolved" className="ml-2 text-sm text-gray-700">
              Show resolved
            </label>
          </div>
        </div>
      </div>

      {/* Alerts List */}
      <div className="space-y-4">
        {Object.entries(alertsBySeverity).map(([severity, severityAlerts]) => {
          if (severityAlerts.length === 0) return null

          return (
            <div key={severity} className="space-y-2">
              <h3 className="text-lg font-medium text-gray-900 capitalize">
                {severity} Alerts ({severityAlerts.length})
              </h3>
              {severityAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className={cn(
                    'card p-4 border-l-4',
                    alert.severity === 'critical' && 'border-l-red-500',
                    alert.severity === 'high' && 'border-l-orange-500',
                    alert.severity === 'medium' && 'border-l-yellow-500',
                    alert.severity === 'low' && 'border-l-blue-500',
                    alert.is_resolved && 'opacity-60'
                  )}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={`badge ${getSeverityColor(alert.severity)}`}>
                          {alert.severity.toUpperCase()}
                        </span>
                        <span className="text-sm text-gray-500">{alert.source}</span>
                        {alert.is_resolved && (
                          <span className="badge-success">Resolved</span>
                        )}
                      </div>
                      <h4 className="text-lg font-medium text-gray-900 mb-1">
                        {alert.title}
                      </h4>
                      <p className="text-gray-600 mb-2">{alert.message}</p>
                      <div className="flex items-center gap-4 text-sm text-gray-500">
                        <div className="flex items-center">
                          <Clock className="h-4 w-4 mr-1" />
                          Created {formatRelativeTime(alert.created_at)}
                        </div>
                        {alert.resolved_at && (
                          <div className="flex items-center">
                            <CheckCircle className="h-4 w-4 mr-1" />
                            Resolved {formatRelativeTime(alert.resolved_at)}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 ml-4">
                      {!alert.is_resolved && (
                        <button
                          onClick={() => handleResolveAlert(alert.id)}
                          className="text-green-600 hover:text-green-700"
                          title="Resolve alert"
                        >
                          <CheckCircle className="h-4 w-4" />
                        </button>
                      )}
                      <button
                        onClick={() => handleDeleteAlert(alert.id)}
                        className="text-red-600 hover:text-red-700"
                        title="Delete alert"
                      >
                        <X className="h-4 w-4" />
                      </button>
                      <button className="text-gray-400 hover:text-gray-600">
                        <MoreHorizontal className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )
        })}

        {filteredAlerts.length === 0 && (
          <div className="text-center py-12">
            <AlertTriangle className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No alerts found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {searchTerm || selectedSeverity
                ? 'Try adjusting your search criteria.'
                : 'No alerts match the current filters.'}
            </p>
          </div>
        )}
      </div>

      {/* Create Alert Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" />
            <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <form onSubmit={handleSubmit(onSubmit)}>
                <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-medium text-gray-900">Create New Alert</h3>
                    <button
                      type="button"
                      onClick={() => setShowCreateModal(false)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <X className="h-5 w-5" />
                    </button>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <label className="label">Alert Type</label>
                      <input
                        {...register('type', { required: 'Type is required' })}
                        type="text"
                        className="input mt-1"
                        placeholder="e.g., system, security, performance"
                      />
                      {errors.type && (
                        <p className="mt-1 text-sm text-red-600">{errors.type.message}</p>
                      )}
                    </div>
                    <div>
                      <label className="label">Severity</label>
                      <select
                        {...register('severity', { required: 'Severity is required' })}
                        className="input mt-1"
                      >
                        <option value="">Select severity...</option>
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                      </select>
                      {errors.severity && (
                        <p className="mt-1 text-sm text-red-600">{errors.severity.message}</p>
                      )}
                    </div>
                    <div>
                      <label className="label">Title</label>
                      <input
                        {...register('title', { required: 'Title is required' })}
                        type="text"
                        className="input mt-1"
                        placeholder="Brief alert title"
                      />
                      {errors.title && (
                        <p className="mt-1 text-sm text-red-600">{errors.title.message}</p>
                      )}
                    </div>
                    <div>
                      <label className="label">Message</label>
                      <textarea
                        {...register('message', { required: 'Message is required' })}
                        rows={3}
                        className="input mt-1"
                        placeholder="Detailed alert description"
                      />
                      {errors.message && (
                        <p className="mt-1 text-sm text-red-600">{errors.message.message}</p>
                      )}
                    </div>
                    <div>
                      <label className="label">Source</label>
                      <input
                        {...register('source', { required: 'Source is required' })}
                        type="text"
                        className="input mt-1"
                        placeholder="e.g., auth-service, database, monitoring"
                      />
                      {errors.source && (
                        <p className="mt-1 text-sm text-red-600">{errors.source.message}</p>
                      )}
                    </div>
                  </div>
                </div>
                <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                  <button
                    type="submit"
                    disabled={createMutation.isLoading}
                    className="btn-primary sm:ml-3"
                  >
                    {createMutation.isLoading ? 'Creating...' : 'Create Alert'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="btn-secondary mt-3 sm:mt-0"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}