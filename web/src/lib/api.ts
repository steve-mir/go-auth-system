import axios, { AxiosResponse } from 'axios'
import toast from 'react-hot-toast'
import type {
  ApiResponse,
  PaginatedResponse,
  SystemInfo,
  SystemHealth,
  SystemMetrics,
  UserStats,
  UserSession,
  BulkUserActionRequest,
  BulkActionResult,
  RoleStats,
  BulkRoleAssignRequest,
  AuditLog,
  AuditEvent,
  ConfigurationResponse,
  UpdateConfigurationRequest,
  Alert,
  CreateAlertRequest,
  UpdateAlertRequest,
  NotificationSettings,
  UpdateNotificationSettingsRequest,
  PaginationInfo,
} from '@/types/api'

// Create axios instance with default config
const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor for auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('admin_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('admin_token')
      window.location.href = '/login'
    } else if (error.response?.status >= 500) {
      toast.error('Server error occurred. Please try again.')
    } else if (error.response?.data?.error?.message) {
      toast.error(error.response.data.error.message)
    } else {
      toast.error('An unexpected error occurred')
    }
    return Promise.reject(error)
  }
)

// Helper function to extract data from API response
const extractData = <T>(response: AxiosResponse<ApiResponse<T>>): T => {
  return response.data.data
}

const extractPaginatedData = <T>(
  response: AxiosResponse<PaginatedResponse<T>>
): { data: T[]; pagination: PaginationInfo } => {
  return {
    data: response.data.data,
    pagination: response.data.pagination,
  }
}

// System API
export const systemApi = {
  getInfo: (): Promise<SystemInfo> =>
    api.get<ApiResponse<SystemInfo>>('/admin/system/info').then(extractData),

  getHealth: (): Promise<SystemHealth> =>
    api.get<ApiResponse<SystemHealth>>('/admin/system/health').then(extractData),

  getMetrics: (): Promise<SystemMetrics> =>
    api.get<ApiResponse<SystemMetrics>>('/admin/system/metrics').then(extractData),
}

// User Management API
export const userApi = {
  getStats: (): Promise<UserStats> =>
    api.get<ApiResponse<UserStats>>('/admin/users/stats').then(extractData),

  getSessions: (params?: {
    page?: number
    limit?: number
    user_id?: string
    sort_by?: string
    sort_order?: 'asc' | 'desc'
  }): Promise<{ data: UserSession[]; pagination: PaginationInfo }> =>
    api
      .get<PaginatedResponse<UserSession>>('/admin/users/sessions', { params })
      .then(extractPaginatedData),

  deleteSession: (sessionId: string): Promise<void> =>
    api.delete(`/admin/users/sessions/${sessionId}`).then(() => {}),

  bulkActions: (request: BulkUserActionRequest): Promise<BulkActionResult> =>
    api
      .post<ApiResponse<BulkActionResult>>('/admin/users/bulk-actions', request)
      .then(extractData),
}

// Role Management API
export const roleApi = {
  getStats: (): Promise<RoleStats> =>
    api.get<ApiResponse<RoleStats>>('/admin/roles/stats').then(extractData),

  bulkAssign: (request: BulkRoleAssignRequest): Promise<BulkActionResult> =>
    api
      .post<ApiResponse<BulkActionResult>>('/admin/roles/bulk-assign', request)
      .then(extractData),
}

// Audit API
export const auditApi = {
  getLogs: (params?: {
    page?: number
    limit?: number
    user_id?: string
    action?: string
    resource_type?: string
    start_time?: string
    end_time?: string
    sort_by?: string
    sort_order?: 'asc' | 'desc'
  }): Promise<{ data: AuditLog[]; pagination: PaginationInfo }> =>
    api
      .get<PaginatedResponse<AuditLog>>('/admin/audit/logs', { params })
      .then(extractPaginatedData),

  getEvents: (params?: {
    page?: number
    limit?: number
    event_type?: string
    sort_by?: string
    sort_order?: 'asc' | 'desc'
  }): Promise<{ data: AuditEvent[]; pagination: PaginationInfo }> =>
    api
      .get<PaginatedResponse<AuditEvent>>('/admin/audit/events', { params })
      .then(extractPaginatedData),
}

// Configuration API
export const configApi = {
  get: (): Promise<ConfigurationResponse> =>
    api.get<ApiResponse<ConfigurationResponse>>('/admin/config').then(extractData),

  update: (request: UpdateConfigurationRequest): Promise<void> =>
    api.put('/admin/config', request).then(() => {}),

  reload: (): Promise<void> =>
    api.post('/admin/config/reload').then(() => {}),
}

// Alerts API
export const alertsApi = {
  getActive: (): Promise<Alert[]> =>
    api
      .get<ApiResponse<{ alerts: Alert[] }>>('/admin/alerts')
      .then((response) => response.data.data.alerts),

  create: (request: CreateAlertRequest): Promise<Alert> =>
    api.post<ApiResponse<Alert>>('/admin/alerts', request).then(extractData),

  update: (alertId: string, request: UpdateAlertRequest): Promise<Alert> =>
    api
      .put<ApiResponse<Alert>>(`/admin/alerts/${alertId}`, request)
      .then(extractData),

  delete: (alertId: string): Promise<void> =>
    api.delete(`/admin/alerts/${alertId}`).then(() => {}),
}

// Notifications API
export const notificationsApi = {
  getSettings: (): Promise<NotificationSettings> =>
    api
      .get<ApiResponse<NotificationSettings>>('/admin/notifications/settings')
      .then(extractData),

  updateSettings: (request: UpdateNotificationSettingsRequest): Promise<void> =>
    api.put('/admin/notifications/settings', request).then(() => {}),
}

// Auth API (for admin login)
export const authApi = {
  login: (email: string, password: string): Promise<{ token: string }> =>
    api
      .post<ApiResponse<{ token: string }>>('/auth/login', { email, password })
      .then(extractData),

  logout: (): Promise<void> =>
    api.post('/auth/logout').then(() => {
      localStorage.removeItem('admin_token')
    }),
}

export default api