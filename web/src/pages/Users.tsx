import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import {
  Search,
  Filter,
  MoreHorizontal,
  UserCheck,
  UserX,
  Mail,
  Phone,
  Trash2,
  Shield,
  ShieldOff,
} from 'lucide-react'
import { userApi } from '@/lib/api'
import { formatNumber, formatRelativeTime, cn } from '@/lib/utils'
import toast from 'react-hot-toast'

interface User {
  id: string
  email: string
  username?: string
  first_name?: string
  last_name?: string
  email_verified: boolean
  phone_verified: boolean
  account_locked: boolean
  failed_login_attempts: number
  last_login_at?: string
  created_at: string
  roles: string[]
}

export default function Users() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedUsers, setSelectedUsers] = useState<string[]>([])
  const [bulkAction, setBulkAction] = useState('')
  const [showBulkModal, setShowBulkModal] = useState(false)
  const queryClient = useQueryClient()

  const { data: userStats, isLoading: statsLoading } = useQuery(
    'user-stats',
    userApi.getStats
  )

  // Mock users data - in real app this would come from API
  const users: User[] = [
    {
      id: '1',
      email: 'admin@example.com',
      username: 'admin',
      first_name: 'Admin',
      last_name: 'User',
      email_verified: true,
      phone_verified: false,
      account_locked: false,
      failed_login_attempts: 0,
      last_login_at: '2024-01-15T10:30:00Z',
      created_at: '2024-01-01T00:00:00Z',
      roles: ['admin', 'user'],
    },
    {
      id: '2',
      email: 'user@example.com',
      username: 'user1',
      first_name: 'John',
      last_name: 'Doe',
      email_verified: true,
      phone_verified: true,
      account_locked: false,
      failed_login_attempts: 0,
      last_login_at: '2024-01-14T15:45:00Z',
      created_at: '2024-01-02T00:00:00Z',
      roles: ['user'],
    },
    {
      id: '3',
      email: 'locked@example.com',
      username: 'locked_user',
      first_name: 'Jane',
      last_name: 'Smith',
      email_verified: false,
      phone_verified: false,
      account_locked: true,
      failed_login_attempts: 5,
      created_at: '2024-01-03T00:00:00Z',
      roles: ['user'],
    },
  ]

  const bulkActionMutation = useMutation(userApi.bulkActions, {
    onSuccess: (result) => {
      toast.success(`Bulk action completed: ${result.success}/${result.total} successful`)
      setSelectedUsers([])
      setShowBulkModal(false)
      queryClient.invalidateQueries('user-stats')
    },
    onError: () => {
      toast.error('Bulk action failed')
    },
  })

  const handleSelectAll = () => {
    if (selectedUsers.length === users.length) {
      setSelectedUsers([])
    } else {
      setSelectedUsers(users.map((user) => user.id))
    }
  }

  const handleSelectUser = (userId: string) => {
    setSelectedUsers((prev) =>
      prev.includes(userId)
        ? prev.filter((id) => id !== userId)
        : [...prev, userId]
    )
  }

  const handleBulkAction = () => {
    if (!bulkAction || selectedUsers.length === 0) return

    bulkActionMutation.mutate({
      user_ids: selectedUsers,
      action: bulkAction as any,
      reason: 'Admin bulk action',
    })
  }

  const filteredUsers = users.filter((user) =>
    user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.username?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    `${user.first_name} ${user.last_name}`.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">User Management</h1>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <UserCheck className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Total Users</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatNumber(userStats?.total_users || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg">
              <UserCheck className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Active Users</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatNumber(userStats?.active_users || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Mail className="h-6 w-6 text-yellow-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Verified Users</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatNumber(userStats?.verified_users || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <UserX className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Locked Accounts</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatNumber(userStats?.locked_accounts || 0)}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="card p-6">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search users by email, username, or name..."
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

        {/* Bulk Actions */}
        {selectedUsers.length > 0 && (
          <div className="mt-4 p-4 bg-blue-50 rounded-lg">
            <div className="flex items-center justify-between">
              <span className="text-sm text-blue-700">
                {selectedUsers.length} user{selectedUsers.length > 1 ? 's' : ''} selected
              </span>
              <div className="flex items-center gap-2">
                <select
                  className="input text-sm"
                  value={bulkAction}
                  onChange={(e) => setBulkAction(e.target.value)}
                >
                  <option value="">Select action...</option>
                  <option value="lock">Lock accounts</option>
                  <option value="unlock">Unlock accounts</option>
                  <option value="verify_email">Verify email</option>
                  <option value="enable_mfa">Enable MFA</option>
                  <option value="disable_mfa">Disable MFA</option>
                </select>
                <button
                  className="btn-primary btn-sm"
                  onClick={handleBulkAction}
                  disabled={!bulkAction || bulkActionMutation.isLoading}
                >
                  {bulkActionMutation.isLoading ? 'Processing...' : 'Apply'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Users Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table">
            <thead className="table-header">
              <tr>
                <th className="table-head">
                  <input
                    type="checkbox"
                    checked={selectedUsers.length === users.length}
                    onChange={handleSelectAll}
                    className="rounded border-gray-300"
                  />
                </th>
                <th className="table-head">User</th>
                <th className="table-head">Status</th>
                <th className="table-head">Roles</th>
                <th className="table-head">Last Login</th>
                <th className="table-head">Created</th>
                <th className="table-head">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((user) => (
                <tr key={user.id} className="table-row">
                  <td className="table-cell">
                    <input
                      type="checkbox"
                      checked={selectedUsers.includes(user.id)}
                      onChange={() => handleSelectUser(user.id)}
                      className="rounded border-gray-300"
                    />
                  </td>
                  <td className="table-cell">
                    <div>
                      <div className="font-medium text-gray-900">
                        {user.first_name && user.last_name
                          ? `${user.first_name} ${user.last_name}`
                          : user.username || 'N/A'}
                      </div>
                      <div className="text-sm text-gray-500">{user.email}</div>
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2">
                        {user.account_locked ? (
                          <span className="badge-danger">Locked</span>
                        ) : (
                          <span className="badge-success">Active</span>
                        )}
                      </div>
                      <div className="flex items-center gap-1 text-xs">
                        {user.email_verified ? (
                          <Mail className="h-3 w-3 text-green-500" title="Email verified" />
                        ) : (
                          <Mail className="h-3 w-3 text-gray-400" title="Email not verified" />
                        )}
                        {user.phone_verified ? (
                          <Phone className="h-3 w-3 text-green-500" title="Phone verified" />
                        ) : (
                          <Phone className="h-3 w-3 text-gray-400" title="Phone not verified" />
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className="flex flex-wrap gap-1">
                      {user.roles.map((role) => (
                        <span key={role} className="badge-info">
                          {role}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className="text-sm text-gray-900">
                      {user.last_login_at
                        ? formatRelativeTime(user.last_login_at)
                        : 'Never'}
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className="text-sm text-gray-900">
                      {formatRelativeTime(user.created_at)}
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className="flex items-center gap-2">
                      {user.account_locked ? (
                        <button
                          className="text-green-600 hover:text-green-700"
                          title="Unlock account"
                        >
                          <UserCheck className="h-4 w-4" />
                        </button>
                      ) : (
                        <button
                          className="text-yellow-600 hover:text-yellow-700"
                          title="Lock account"
                        >
                          <UserX className="h-4 w-4" />
                        </button>
                      )}
                      <button
                        className="text-blue-600 hover:text-blue-700"
                        title="Manage MFA"
                      >
                        <Shield className="h-4 w-4" />
                      </button>
                      <button
                        className="text-red-600 hover:text-red-700"
                        title="Delete user"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                      <button className="text-gray-400 hover:text-gray-600">
                        <MoreHorizontal className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredUsers.length === 0 && (
          <div className="text-center py-12">
            <UserX className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No users found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {searchTerm ? 'Try adjusting your search criteria.' : 'No users match the current filters.'}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}