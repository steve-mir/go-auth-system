import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { useForm } from 'react-hook-form'
import { Save, RefreshCw, AlertCircle, CheckCircle } from 'lucide-react'
import { configApi } from '@/lib/api'
import { cn } from '@/lib/utils'
import toast from 'react-hot-toast'

interface ConfigForm {
  server: {
    host: string
    port: number
    environment: string
  }
  security: {
    password_hash: {
      algorithm: string
    }
    token: {
      type: string
      access_ttl: string
      refresh_ttl: string
    }
    rate_limit: {
      enabled: boolean
      requests_per_minute: number
      burst_size: number
      window_size: string
    }
  }
  features: {
    mfa_enabled: boolean
    social_auth: boolean
    enterprise_sso: boolean
    admin_dashboard: boolean
    audit_logging: boolean
  }
}

export default function Configuration() {
  const [activeTab, setActiveTab] = useState('server')
  const queryClient = useQueryClient()

  const { data: config, isLoading } = useQuery('configuration', configApi.get)

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isDirty },
    watch,
  } = useForm<ConfigForm>({
    defaultValues: config,
  })

  // Reset form when config data loads
  React.useEffect(() => {
    if (config) {
      reset(config)
    }
  }, [config, reset])

  const updateMutation = useMutation(configApi.update, {
    onSuccess: () => {
      toast.success('Configuration updated successfully')
      queryClient.invalidateQueries('configuration')
    },
    onError: () => {
      toast.error('Failed to update configuration')
    },
  })

  const reloadMutation = useMutation(configApi.reload, {
    onSuccess: () => {
      toast.success('Configuration reloaded successfully')
      queryClient.invalidateQueries('configuration')
    },
    onError: () => {
      toast.error('Failed to reload configuration')
    },
  })

  const onSubmit = (data: ConfigForm) => {
    updateMutation.mutate(data)
  }

  const handleReload = () => {
    reloadMutation.mutate()
  }

  const tabs = [
    { id: 'server', name: 'Server', icon: '🖥️' },
    { id: 'security', name: 'Security', icon: '🔒' },
    { id: 'features', name: 'Features', icon: '⚡' },
  ]

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/4 mb-6"></div>
          <div className="card p-6">
            <div className="h-4 bg-gray-200 rounded w-3/4 mb-4"></div>
            <div className="space-y-3">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-10 bg-gray-200 rounded"></div>
              ))}
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Configuration</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={handleReload}
            disabled={reloadMutation.isLoading}
            className="btn-secondary"
          >
            <RefreshCw className={cn('h-4 w-4 mr-2', reloadMutation.isLoading && 'animate-spin')} />
            Reload Config
          </button>
        </div>
      </div>

      {/* Configuration Status */}
      <div className="card p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <CheckCircle className="h-5 w-5 text-green-500 mr-2" />
            <span className="text-sm font-medium text-gray-900">Configuration Status</span>
          </div>
          <div className="flex items-center gap-4 text-sm text-gray-600">
            <span>Environment: {config?.server.environment}</span>
            <span>Last Updated: {new Date().toLocaleString()}</span>
          </div>
        </div>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* Tabs */}
        <div className="card">
          <div className="border-b border-gray-200">
            <nav className="-mb-px flex space-x-8 px-6">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    'py-4 px-1 border-b-2 font-medium text-sm',
                    activeTab === tab.id
                      ? 'border-primary-500 text-primary-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  )}
                >
                  <span className="mr-2">{tab.icon}</span>
                  {tab.name}
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            {/* Server Configuration */}
            {activeTab === 'server' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Server Settings</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="label">Host</label>
                      <input
                        {...register('server.host', {
                          required: 'Host is required',
                        })}
                        type="text"
                        className="input mt-1"
                        placeholder="0.0.0.0"
                      />
                      {errors.server?.host && (
                        <p className="mt-1 text-sm text-red-600">{errors.server.host.message}</p>
                      )}
                    </div>
                    <div>
                      <label className="label">Port</label>
                      <input
                        {...register('server.port', {
                          required: 'Port is required',
                          min: { value: 1, message: 'Port must be greater than 0' },
                          max: { value: 65535, message: 'Port must be less than 65536' },
                        })}
                        type="number"
                        className="input mt-1"
                        placeholder="8080"
                      />
                      {errors.server?.port && (
                        <p className="mt-1 text-sm text-red-600">{errors.server.port.message}</p>
                      )}
                    </div>
                    <div>
                      <label className="label">Environment</label>
                      <select
                        {...register('server.environment', {
                          required: 'Environment is required',
                        })}
                        className="input mt-1"
                      >
                        <option value="development">Development</option>
                        <option value="staging">Staging</option>
                        <option value="production">Production</option>
                      </select>
                      {errors.server?.environment && (
                        <p className="mt-1 text-sm text-red-600">{errors.server.environment.message}</p>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Security Configuration */}
            {activeTab === 'security' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Password Hashing</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="label">Algorithm</label>
                      <select
                        {...register('security.password_hash.algorithm', {
                          required: 'Algorithm is required',
                        })}
                        className="input mt-1"
                      >
                        <option value="argon2">Argon2</option>
                        <option value="bcrypt">bcrypt</option>
                      </select>
                      {errors.security?.password_hash?.algorithm && (
                        <p className="mt-1 text-sm text-red-600">
                          {errors.security.password_hash.algorithm.message}
                        </p>
                      )}
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Token Configuration</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div>
                      <label className="label">Token Type</label>
                      <select
                        {...register('security.token.type', {
                          required: 'Token type is required',
                        })}
                        className="input mt-1"
                      >
                        <option value="jwt">JWT</option>
                        <option value="paseto">Paseto</option>
                      </select>
                      {errors.security?.token?.type && (
                        <p className="mt-1 text-sm text-red-600">{errors.security.token.type.message}</p>
                      )}
                    </div>
                    <div>
                      <label className="label">Access Token TTL</label>
                      <input
                        {...register('security.token.access_ttl', {
                          required: 'Access TTL is required',
                        })}
                        type="text"
                        className="input mt-1"
                        placeholder="15m"
                      />
                      {errors.security?.token?.access_ttl && (
                        <p className="mt-1 text-sm text-red-600">{errors.security.token.access_ttl.message}</p>
                      )}
                    </div>
                    <div>
                      <label className="label">Refresh Token TTL</label>
                      <input
                        {...register('security.token.refresh_ttl', {
                          required: 'Refresh TTL is required',
                        })}
                        type="text"
                        className="input mt-1"
                        placeholder="7d"
                      />
                      {errors.security?.token?.refresh_ttl && (
                        <p className="mt-1 text-sm text-red-600">{errors.security.token.refresh_ttl.message}</p>
                      )}
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Rate Limiting</h3>
                  <div className="space-y-4">
                    <div className="flex items-center">
                      <input
                        {...register('security.rate_limit.enabled')}
                        type="checkbox"
                        className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                      />
                      <label className="ml-2 text-sm text-gray-700">Enable rate limiting</label>
                    </div>
                    {watch('security.rate_limit.enabled') && (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div>
                          <label className="label">Requests per Minute</label>
                          <input
                            {...register('security.rate_limit.requests_per_minute', {
                              min: { value: 1, message: 'Must be at least 1' },
                            })}
                            type="number"
                            className="input mt-1"
                            placeholder="100"
                          />
                        </div>
                        <div>
                          <label className="label">Burst Size</label>
                          <input
                            {...register('security.rate_limit.burst_size', {
                              min: { value: 1, message: 'Must be at least 1' },
                            })}
                            type="number"
                            className="input mt-1"
                            placeholder="10"
                          />
                        </div>
                        <div>
                          <label className="label">Window Size</label>
                          <input
                            {...register('security.rate_limit.window_size')}
                            type="text"
                            className="input mt-1"
                            placeholder="1m"
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Features Configuration */}
            {activeTab === 'features' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 mb-4">Feature Flags</h3>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div>
                        <h4 className="text-sm font-medium text-gray-900">Multi-Factor Authentication</h4>
                        <p className="text-sm text-gray-500">Enable MFA support for enhanced security</p>
                      </div>
                      <input
                        {...register('features.mfa_enabled')}
                        type="checkbox"
                        className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                      />
                    </div>
                    <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div>
                        <h4 className="text-sm font-medium text-gray-900">Social Authentication</h4>
                        <p className="text-sm text-gray-500">Allow login with social media accounts</p>
                      </div>
                      <input
                        {...register('features.social_auth')}
                        type="checkbox"
                        className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                      />
                    </div>
                    <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div>
                        <h4 className="text-sm font-medium text-gray-900">Enterprise SSO</h4>
                        <p className="text-sm text-gray-500">Enable SAML, OIDC, and LDAP integration</p>
                      </div>
                      <input
                        {...register('features.enterprise_sso')}
                        type="checkbox"
                        className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                      />
                    </div>
                    <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div>
                        <h4 className="text-sm font-medium text-gray-900">Admin Dashboard</h4>
                        <p className="text-sm text-gray-500">Enable this admin dashboard interface</p>
                      </div>
                      <input
                        {...register('features.admin_dashboard')}
                        type="checkbox"
                        className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                      />
                    </div>
                    <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div>
                        <h4 className="text-sm font-medium text-gray-900">Audit Logging</h4>
                        <p className="text-sm text-gray-500">Log all authentication and admin actions</p>
                      </div>
                      <input
                        {...register('features.audit_logging')}
                        type="checkbox"
                        className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                      />
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Save Button */}
        {isDirty && (
          <div className="sticky bottom-0 bg-white border-t border-gray-200 px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center text-sm text-amber-600">
                <AlertCircle className="h-4 w-4 mr-2" />
                You have unsaved changes
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => reset(config)}
                  className="btn-secondary"
                >
                  Reset
                </button>
                <button
                  type="submit"
                  disabled={updateMutation.isLoading}
                  className="btn-primary"
                >
                  <Save className="h-4 w-4 mr-2" />
                  {updateMutation.isLoading ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </div>
          </div>
        )}
      </form>
    </div>
  )
}