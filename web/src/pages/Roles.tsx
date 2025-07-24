import { useState } from 'react'
import { useQuery } from 'react-query'
import { Shield, Users, Plus, Edit, Trash2 } from 'lucide-react'
import { roleApi } from '@/lib/api'
import { formatNumber } from '@/lib/utils'

export default function Roles() {
  const [showCreateModal, setShowCreateModal] = useState(false)

  const { data: roleStats, isLoading } = useQuery('role-stats', roleApi.getStats)

  // Mock roles data - in real app this would come from API
  const roles = [
    {
      id: '1',
      name: 'admin',
      description: 'Full system administrator access',
      permissions: ['read', 'write', 'delete', 'admin'],
      user_count: 5,
      created_at: '2024-01-01T00:00:00Z',
    },
    {
      id: '2',
      name: 'user',
      description: 'Standard user access',
      permissions: ['read'],
      user_count: 150,
      created_at: '2024-01-01T00:00:00Z',
    },
    {
      id: '3',
      name: 'moderator',
      description: 'Content moderation access',
      permissions: ['read', 'write'],
      user_count: 12,
      created_at: '2024-01-01T00:00:00Z',
    },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Role Management</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-primary"
        >
          <Plus className="h-4 w-4 mr-2" />
          Create Role
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Shield className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Total Roles</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatNumber(roleStats?.total_roles || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg">
              <Users className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Most Used Role</p>
              <p className="text-lg font-bold text-gray-900">
                {roleStats?.role_usage
                  ? Object.entries(roleStats.role_usage).sort(([,a], [,b]) => b - a)[0]?.[0] || 'N/A'
                  : 'N/A'}
              </p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-purple-100 rounded-lg">
              <Shield className="h-6 w-6 text-purple-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Permissions</p>
              <p className="text-2xl font-bold text-gray-900">
                {roleStats?.permission_usage
                  ? Object.keys(roleStats.permission_usage).length
                  : 0}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Roles Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {roles.map((role) => (
          <div key={role.id} className="card p-6">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <Shield className="h-5 w-5 text-blue-600" />
                </div>
                <div className="ml-3">
                  <h3 className="text-lg font-medium text-gray-900">{role.name}</h3>
                  <p className="text-sm text-gray-500">{role.user_count} users</p>
                </div>
              </div>
              <div className="flex items-center gap-1">
                <button className="text-gray-400 hover:text-gray-600">
                  <Edit className="h-4 w-4" />
                </button>
                <button className="text-red-400 hover:text-red-600">
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
            
            <p className="text-sm text-gray-600 mb-4">{role.description}</p>
            
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-2">Permissions</h4>
              <div className="flex flex-wrap gap-1">
                {role.permissions.map((permission) => (
                  <span key={permission} className="badge-info">
                    {permission}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}