import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { useForm } from 'react-hook-form'
import { Save, Mail, MessageSquare, Phone, Bell } from 'lucide-react'
import { notificationsApi } from '@/lib/api'
import toast from 'react-hot-toast'

interface NotificationForm {
  email_enabled: boolean
  email_recipients: string[]
  slack_enabled: boolean
  slack_webhook: string
  sms_enabled: boolean
  sms_recipients: string[]
  thresholds: {
    failed_login_rate: number
    error_rate: number
    response_time_ms: number
    database_connections: number
    memory_usage_percent: number
    cpu_usage_percent: number
  }
}

export default function NotificationSettings() {
  const [emailRecipient, setEmailRecipient] = useState('')
  const [smsRecipient, setSmsRecipient] = useState('')
  const queryClient = useQueryClient()

  const { data: settings, isLoading } = useQuery(
    'notification-settings',
    notificationsApi.getSettings
  )

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    formState: { errors, isDirty },
  } = useForm<NotificationForm>({
    defaultValues: settings,
  })

  // Reset form when settings data loads
  React.useEffect(() => {
    if (settings) {
      setValue('email_enabled', settings.email_enabled)
      setValue('email_recipients', settings.email_recipients)
      setValue('slack_enabled', settings.slack_enabled)
      setValue('slack_webhook', settings.slack_webhook || '')
      setValue('sms_enabled', settings.sms_enabled)
      setValue('sms_recipients', settings.sms_recipients)
      setValue('thresholds', settings.thresholds)
    }
  }, [settings, setValue])

  const updateMutation = useMutation(notificationsApi.updateSettings, {
    onSuccess: () => {
      toast.success('Notification settings updated successfully')
      queryClient.invalidateQueries('notification-settings')
    },
    onError: () => {
      toast.error('Failed to update notification settings')
    },
  })

  const onSubmit = (data: NotificationForm) => {
    updateMutation.mutate(data)
  }

  const addEmailRecipient = () => {
    if (emailRecipient && emailRecipient.includes('@')) {
      const currentRecipients = watch('email_recipients') || []
      if (!currentRecipients.includes(emailRecipient)) {
        setValue('email_recipients', [...currentRecipients, emailRecipient])
        setEmailRecipient('')
      }
    }
  }

  const removeEmailRecipient = (email: string) => {
    const currentRecipients = watch('email_recipients') || []
    setValue('email_recipients', currentRecipients.filter(r => r !== email))
  }

  const addSmsRecipient = () => {
    if (smsRecipient) {
      const currentRecipients = watch('sms_recipients') || []
      if (!currentRecipients.includes(smsRecipient)) {
        setValue('sms_recipients', [...currentRecipients, smsRecipient])
        setSmsRecipient('')
      }
    }
  }

  const removeSmsRecipient = (phone: string) => {
    const currentRecipients = watch('sms_recipients') || []
    setValue('sms_recipients', currentRecipients.filter(r => r !== phone))
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/4 mb-6"></div>
          <div className="card p-6">
            <div className="space-y-4">
              {[...Array(6)].map((_, i) => (
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
        <h1 className="text-2xl font-bold text-gray-900">Notification Settings</h1>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* Email Notifications */}
        <div className="card p-6">
          <div className="flex items-center mb-4">
            <Mail className="h-5 w-5 text-blue-600 mr-2" />
            <h2 className="text-lg font-medium text-gray-900">Email Notifications</h2>
          </div>
          
          <div className="space-y-4">
            <div className="flex items-center">
              <input
                {...register('email_enabled')}
                type="checkbox"
                className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
              />
              <label className="ml-2 text-sm text-gray-700">Enable email notifications</label>
            </div>

            {watch('email_enabled') && (
              <div>
                <label className="label">Email Recipients</label>
                <div className="flex gap-2 mt-1">
                  <input
                    type="email"
                    className="input flex-1"
                    placeholder="Enter email address"
                    value={emailRecipient}
                    onChange={(e) => setEmailRecipient(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addEmailRecipient())}
                  />
                  <button
                    type="button"
                    onClick={addEmailRecipient}
                    className="btn-secondary"
                  >
                    Add
                  </button>
                </div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {(watch('email_recipients') || []).map((email) => (
                    <span
                      key={email}
                      className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                    >
                      {email}
                      <button
                        type="button"
                        onClick={() => removeEmailRecipient(email)}
                        className="ml-1 text-blue-600 hover:text-blue-800"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Slack Notifications */}
        <div className="card p-6">
          <div className="flex items-center mb-4">
            <MessageSquare className="h-5 w-5 text-green-600 mr-2" />
            <h2 className="text-lg font-medium text-gray-900">Slack Notifications</h2>
          </div>
          
          <div className="space-y-4">
            <div className="flex items-center">
              <input
                {...register('slack_enabled')}
                type="checkbox"
                className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
              />
              <label className="ml-2 text-sm text-gray-700">Enable Slack notifications</label>
            </div>

            {watch('slack_enabled') && (
              <div>
                <label className="label">Slack Webhook URL</label>
                <input
                  {...register('slack_webhook', {
                    required: watch('slack_enabled') ? 'Webhook URL is required' : false,
                  })}
                  type="url"
                  className="input mt-1"
                  placeholder="https://hooks.slack.com/services/..."
                />
                {errors.slack_webhook && (
                  <p className="mt-1 text-sm text-red-600">{errors.slack_webhook.message}</p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* SMS Notifications */}
        <div className="card p-6">
          <div className="flex items-center mb-4">
            <Phone className="h-5 w-5 text-purple-600 mr-2" />
            <h2 className="text-lg font-medium text-gray-900">SMS Notifications</h2>
          </div>
          
          <div className="space-y-4">
            <div className="flex items-center">
              <input
                {...register('sms_enabled')}
                type="checkbox"
                className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
              />
              <label className="ml-2 text-sm text-gray-700">Enable SMS notifications</label>
            </div>

            {watch('sms_enabled') && (
              <div>
                <label className="label">SMS Recipients</label>
                <div className="flex gap-2 mt-1">
                  <input
                    type="tel"
                    className="input flex-1"
                    placeholder="Enter phone number"
                    value={smsRecipient}
                    onChange={(e) => setSmsRecipient(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addSmsRecipient())}
                  />
                  <button
                    type="button"
                    onClick={addSmsRecipient}
                    className="btn-secondary"
                  >
                    Add
                  </button>
                </div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {(watch('sms_recipients') || []).map((phone) => (
                    <span
                      key={phone}
                      className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800"
                    >
                      {phone}
                      <button
                        type="button"
                        onClick={() => removeSmsRecipient(phone)}
                        className="ml-1 text-purple-600 hover:text-purple-800"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Alert Thresholds */}
        <div className="card p-6">
          <div className="flex items-center mb-4">
            <Bell className="h-5 w-5 text-orange-600 mr-2" />
            <h2 className="text-lg font-medium text-gray-900">Alert Thresholds</h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="label">Failed Login Rate (%)</label>
              <input
                {...register('thresholds.failed_login_rate', {
                  min: { value: 0, message: 'Must be at least 0' },
                  max: { value: 100, message: 'Must be at most 100' },
                })}
                type="number"
                step="0.1"
                className="input mt-1"
                placeholder="5.0"
              />
              {errors.thresholds?.failed_login_rate && (
                <p className="mt-1 text-sm text-red-600">{errors.thresholds.failed_login_rate.message}</p>
              )}
            </div>

            <div>
              <label className="label">Error Rate (%)</label>
              <input
                {...register('thresholds.error_rate', {
                  min: { value: 0, message: 'Must be at least 0' },
                  max: { value: 100, message: 'Must be at most 100' },
                })}
                type="number"
                step="0.1"
                className="input mt-1"
                placeholder="1.0"
              />
              {errors.thresholds?.error_rate && (
                <p className="mt-1 text-sm text-red-600">{errors.thresholds.error_rate.message}</p>
              )}
            </div>

            <div>
              <label className="label">Response Time (ms)</label>
              <input
                {...register('thresholds.response_time_ms', {
                  min: { value: 0, message: 'Must be at least 0' },
                })}
                type="number"
                className="input mt-1"
                placeholder="1000"
              />
              {errors.thresholds?.response_time_ms && (
                <p className="mt-1 text-sm text-red-600">{errors.thresholds.response_time_ms.message}</p>
              )}
            </div>

            <div>
              <label className="label">Database Connections</label>
              <input
                {...register('thresholds.database_connections', {
                  min: { value: 0, message: 'Must be at least 0' },
                })}
                type="number"
                className="input mt-1"
                placeholder="80"
              />
              {errors.thresholds?.database_connections && (
                <p className="mt-1 text-sm text-red-600">{errors.thresholds.database_connections.message}</p>
              )}
            </div>

            <div>
              <label className="label">Memory Usage (%)</label>
              <input
                {...register('thresholds.memory_usage_percent', {
                  min: { value: 0, message: 'Must be at least 0' },
                  max: { value: 100, message: 'Must be at most 100' },
                })}
                type="number"
                step="0.1"
                className="input mt-1"
                placeholder="85.0"
              />
              {errors.thresholds?.memory_usage_percent && (
                <p className="mt-1 text-sm text-red-600">{errors.thresholds.memory_usage_percent.message}</p>
              )}
            </div>

            <div>
              <label className="label">CPU Usage (%)</label>
              <input
                {...register('thresholds.cpu_usage_percent', {
                  min: { value: 0, message: 'Must be at least 0' },
                  max: { value: 100, message: 'Must be at most 100' },
                })}
                type="number"
                step="0.1"
                className="input mt-1"
                placeholder="80.0"
              />
              {errors.thresholds?.cpu_usage_percent && (
                <p className="mt-1 text-sm text-red-600">{errors.thresholds.cpu_usage_percent.message}</p>
              )}
            </div>
          </div>
        </div>

        {/* Save Button */}
        {isDirty && (
          <div className="sticky bottom-0 bg-white border-t border-gray-200 px-6 py-4">
            <div className="flex items-center justify-end">
              <button
                type="submit"
                disabled={updateMutation.isLoading}
                className="btn-primary"
              >
                <Save className="h-4 w-4 mr-2" />
                {updateMutation.isLoading ? 'Saving...' : 'Save Settings'}
              </button>
            </div>
          </div>
        )}
      </form>
    </div>
  )
}