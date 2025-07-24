import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import {
  Search,
  Filter,
  Trash2,
  Monitor,
  Smartphone,
  Globe,
  Clock,
  MapPin,
} from 'lucide-react'
import { userApi } from '@/lib/api'
import { formatRelativeTime, formatDate, cn } from '@/lib/utils'
import toast from 'react-hot-toast'

export default function Sessions() {
  const [searchTerm, setSearchTerm] = useState('')
  const [page, setPage] = useState(1)
  const [limit] = useState(20)
  const queryClient = useQueryClient()

  const { data: sessionsData, isLoading } = useQuery(
    ['user-sessions', page, limit, searchTerm],
    () =>
      userApi.getSessions({
        page,
        limit,
        user_id: searchTerm,
        sort_by: 'last_used',
        sort_order: 'desc',
      }),
    {
      keepPreviousData: true,
    }
  )

  const deleteSessionMutation = useMutation(userApi.deleteSession, {
    onSuccess: () => {
      toast.success('Session terminated successfully')
      queryClient.invalidateQueries('user-sessions')
    },
    onError: () => {
      toast.error('Failed to terminate session')
    },
  })

  const handleDeleteSession = (sessionId: string) => {
    if (confirm('Are you sure you want to terminate this session?')) {
      deleteSessionMutation.mutate(sessionId)
    }
  }

  const getDeviceIcon = (userAgent: string) => {
    if (userAgent.toLowerCase().includes('mobile')) {
      return <Smartphone className="h-4 w-4" />
    }
    return <Monitor className="h-4 w-4" />
  }

  const getBrowserInfo = (userAgent: string) => {
    if (userAgent.includes('Chrome')) return 'Chrome'
    if (userAgent.includes('Firefox')) return 'Firefox'
    if (userAgent.includes('Safari')) return 'Safari'
    if (userAgent.includes('Edge')) return 'Edge'
    return 'Unknown'
  }

  const getLocationInfo = (ipAddress: string) => {
    // In a real app, you'd use a geolocation service
    // This is just for demo purposes
    const locations = [
      'New York, US',
      'London, UK',
      'Tokyo, JP',
      'Sydney, AU',
      'Berlin, DE',
    ]
    return locations[Math.floor(Math.random() * locations.length)]
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Active Sessions</h1>
      </div>

      {/* Search and Filters */}
      <div className="card p-6">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search by user ID or email..."
                className="input pl-10"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
          <button className="btn-secondary">
            <Filter className="h-4 w-4 mr-2" />
            Filters
          </button>
        </div>
      </div>

      {/* Sessions Table */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="p-6">
            <div className="animate-pulse space-y-4">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-16 bg-gray-200 rounded"></div>
              ))}
            </div>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table">
                <thead className="table-header">
                  <tr>
                    <th className="table-head">User</th>
                    <th className="table-head">Device & Browser</th>
                    <th className="table-head">Location</th>
                    <th className="table-head">Session Info</th>
                    <th className="table-head">Last Activity</th>
                    <th className="table-head">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sessionsData?.data.map((session) => (
                    <tr key={session.session_id} className="table-row">
                      <td className="table-cell">
                        <div>
                          <div className="font-medium text-gray-900">
                            {session.user_email}
                          </div>
                          <div className="text-sm text-gray-500">
                            ID: {session.user_id.slice(0, 8)}...
                          </div>
                        </div>
                      </td>
                      <td className="table-cell">
                        <div className="flex items-center gap-2">
                          {getDeviceIcon(session.user_agent)}
                          <div>
                            <div className="text-sm font-medium text-gray-900">
                              {getBrowserInfo(session.user_agent)}
                            </div>
                            <div className="text-xs text-gray-500">
                              {session.user_agent.length > 30
                                ? session.user_agent.slice(0, 30) + '...'
                                : session.user_agent}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="table-cell">
                        <div className="flex items-center gap-1">
                          <MapPin className="h-3 w-3 text-gray-400" />
                          <div>
                            <div className="text-sm text-gray-900">
                              {getLocationInfo(session.ip_address)}
                            </div>
                            <div className="text-xs text-gray-500">
                              {session.ip_address}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="table-cell">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <span
                              className={cn(
                                'badge',
                                session.is_active ? 'badge-success' : 'badge-danger'
                              )}
                            >
                              {session.is_active ? 'Active' : 'Inactive'}
                            </span>
                            <span className="badge-info">{session.token_type}</span>
                          </div>
                          <div className="text-xs text-gray-500">
                            Created: {formatDate(session.created_at, 'MMM d, HH:mm')}
                          </div>
                          <div className="text-xs text-gray-500">
                            Expires: {formatDate(session.expires_at, 'MMM d, HH:mm')}
                          </div>
                        </div>
                      </td>
                      <td className="table-cell">
                        <div className="flex items-center gap-1">
                          <Clock className="h-3 w-3 text-gray-400" />
                          <span className="text-sm text-gray-900">
                            {formatRelativeTime(session.last_used)}
                          </span>
                        </div>
                      </td>
                      <td className="table-cell">
                        <button
                          onClick={() => handleDeleteSession(session.session_id)}
                          className="text-red-600 hover:text-red-700"
                          title="Terminate session"
                          disabled={deleteSessionMutation.isLoading}
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {sessionsData && sessionsData.pagination.total_pages > 1 && (
              <div className="px-6 py-4 border-t border-gray-200">
                <div className="flex items-center justify-between">
                  <div className="text-sm text-gray-700">
                    Showing {(page - 1) * limit + 1} to{' '}
                    {Math.min(page * limit, sessionsData.pagination.total)} of{' '}
                    {sessionsData.pagination.total} sessions
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setPage(page - 1)}
                      disabled={!sessionsData.pagination.has_prev}
                      className="btn-secondary btn-sm disabled:opacity-50"
                    >
                      Previous
                    </button>
                    <span className="text-sm text-gray-700">
                      Page {page} of {sessionsData.pagination.total_pages}
                    </span>
                    <button
                      onClick={() => setPage(page + 1)}
                      disabled={!sessionsData.pagination.has_next}
                      className="btn-secondary btn-sm disabled:opacity-50"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </div>
            )}

            {sessionsData?.data.length === 0 && (
              <div className="text-center py-12">
                <Monitor className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-2 text-sm font-medium text-gray-900">No sessions found</h3>
                <p className="mt-1 text-sm text-gray-500">
                  {searchTerm
                    ? 'Try adjusting your search criteria.'
                    : 'No active sessions at the moment.'}
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}