import { useState } from 'react'
import { useQuery } from 'react-query'
import { Search, Filter, Download, Calendar } from 'lucide-react'
import { auditApi } from '@/lib/api'
import { formatDate, formatRelativeTime } from '@/lib/utils'

export default function AuditLogs() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedAction, setSelectedAction] = useState('')
  const [page, setPage] = useState(1)
  const [limit] = useState(20)

  const { data: auditData, isLoading } = useQuery(
    ['audit-logs', page, limit, searchTerm, selectedAction],
    () =>
      auditApi.getLogs({
        page,
        limit,
        action: selectedAction,
        sort_by: 'timestamp',
        sort_order: 'desc',
      }),
    {
      keepPreviousData: true,
    }
  )

  const actions = [
    'user.login',
    'user.logout',
    'user.register',
    'user.update',
    'user.delete',
    'role.assign',
    'role.remove',
    'config.update',
    'alert.create',
    'alert.resolve',
  ]

  const getActionColor = (action: string) => {
    if (action.includes('delete') || action.includes('remove')) return 'badge-danger'
    if (action.includes('create') || action.includes('register')) return 'badge-success'
    if (action.includes('update') || action.includes('assign')) return 'badge-warning'
    return 'badge-info'
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Audit Logs</h1>
        <button className="btn-secondary">
          <Download className="h-4 w-4 mr-2" />
          Export
        </button>
      </div>

      {/* Filters */}
      <div className="card p-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search logs..."
              className="input pl-10"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <select
            className="input"
            value={selectedAction}
            onChange={(e) => setSelectedAction(e.target.value)}
          >
            <option value="">All Actions</option>
            {actions.map((action) => (
              <option key={action} value={action}>
                {action}
              </option>
            ))}
          </select>
          <button className="btn-secondary">
            <Calendar className="h-4 w-4 mr-2" />
            Date Range
          </button>
        </div>
      </div>

      {/* Audit Logs Table */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="p-6">
            <div className="animate-pulse space-y-4">
              {[...Array(10)].map((_, i) => (
                <div key={i} className="h-12 bg-gray-200 rounded"></div>
              ))}
            </div>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table">
                <thead className="table-header">
                  <tr>
                    <th className="table-head">Timestamp</th>
                    <th className="table-head">Action</th>
                    <th className="table-head">User</th>
                    <th className="table-head">Resource</th>
                    <th className="table-head">IP Address</th>
                    <th className="table-head">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {auditData?.data.map((log) => (
                    <tr key={log.id} className="table-row">
                      <td className="table-cell">
                        <div>
                          <div className="text-sm font-medium text-gray-900">
                            {formatDate(log.timestamp, 'MMM d, HH:mm:ss')}
                          </div>
                          <div className="text-xs text-gray-500">
                            {formatRelativeTime(log.timestamp)}
                          </div>
                        </div>
                      </td>
                      <td className="table-cell">
                        <span className={`badge ${getActionColor(log.action)}`}>
                          {log.action}
                        </span>
                      </td>
                      <td className="table-cell">
                        <div className="text-sm text-gray-900">
                          {log.user_id ? log.user_id.slice(0, 8) + '...' : 'System'}
                        </div>
                      </td>
                      <td className="table-cell">
                        <div>
                          {log.resource_type && (
                            <div className="text-sm text-gray-900">{log.resource_type}</div>
                          )}
                          {log.resource_id && (
                            <div className="text-xs text-gray-500">
                              {log.resource_id.slice(0, 12)}...
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="table-cell">
                        <div className="text-sm text-gray-900">
                          {log.ip_address || 'N/A'}
                        </div>
                      </td>
                      <td className="table-cell">
                        <div className="text-sm text-gray-600">
                          {log.metadata && Object.keys(log.metadata).length > 0 ? (
                            <details className="cursor-pointer">
                              <summary className="text-blue-600 hover:text-blue-700">
                                View metadata
                              </summary>
                              <pre className="mt-2 text-xs bg-gray-50 p-2 rounded overflow-x-auto">
                                {JSON.stringify(log.metadata, null, 2)}
                              </pre>
                            </details>
                          ) : (
                            'No additional data'
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {auditData && auditData.pagination.total_pages > 1 && (
              <div className="px-6 py-4 border-t border-gray-200">
                <div className="flex items-center justify-between">
                  <div className="text-sm text-gray-700">
                    Showing {(page - 1) * limit + 1} to{' '}
                    {Math.min(page * limit, auditData.pagination.total)} of{' '}
                    {auditData.pagination.total} logs
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setPage(page - 1)}
                      disabled={!auditData.pagination.has_prev}
                      className="btn-secondary btn-sm disabled:opacity-50"
                    >
                      Previous
                    </button>
                    <span className="text-sm text-gray-700">
                      Page {page} of {auditData.pagination.total_pages}
                    </span>
                    <button
                      onClick={() => setPage(page + 1)}
                      disabled={!auditData.pagination.has_next}
                      className="btn-secondary btn-sm disabled:opacity-50"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </div>
            )}

            {auditData?.data.length === 0 && (
              <div className="text-center py-12">
                <Search className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-2 text-sm font-medium text-gray-900">No audit logs found</h3>
                <p className="mt-1 text-sm text-gray-500">
                  {searchTerm || selectedAction
                    ? 'Try adjusting your search criteria.'
                    : 'No audit logs match the current filters.'}
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}