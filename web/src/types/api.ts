// API Response Types based on backend admin service interface

export interface ApiResponse<T> {
  data: T
  message?: string
  timestamp: string
}

export interface PaginatedResponse<T> {
  data: T[]
  pagination: PaginationInfo
}

export interface PaginationInfo {
  page: number
  limit: number
  total: number
  total_pages: number
  has_next: boolean
  has_prev: boolean
}

// System Information
export interface SystemInfo {
  service: string
  version: string
  build: BuildInfo
  runtime: RuntimeInfo
  features: Record<string, any>
  timestamp: string
}

export interface BuildInfo {
  go_version: string
  build_time: string
  git_commit: string
  git_branch: string
  build_user: string
  build_host: string
}

export interface RuntimeInfo {
  uptime: string
  start_time: string
  go_routines: number
  memory_usage: MemoryInfo
  cpu_usage: number
  environment: string
}

export interface MemoryInfo {
  allocated: number
  total_alloc: number
  system_memory: number
  num_gc: number
  heap_objects: number
}

// System Health
export interface SystemHealth {
  status: string
  components: Record<string, ComponentHealth>
  timestamp: string
}

export interface ComponentHealth {
  status: string
  message?: string
  last_checked: string
  metrics?: Record<string, any>
}

// System Metrics
export interface SystemMetrics {
  requests: RequestMetrics
  authentication: AuthMetrics
  users: UserMetrics
  tokens: TokenMetrics
  database: DatabaseMetrics
  cache: CacheMetrics
  security: SecurityMetrics
  timestamp: string
}

export interface RequestMetrics {
  total: number
  success_rate: number
  avg_latency: string
  p95_latency: string
  p99_latency: string
  error_rate: number
}

export interface AuthMetrics {
  total_logins: number
  failed_logins: number
  success_rate: number
  active_sessions: number
  mfa_usage: number
}

export interface UserMetrics {
  total_users: number
  active_users: number
  verified_users: number
  locked_accounts: number
  new_users_24h: number
  new_users_7d: number
}

export interface TokenMetrics {
  issued_tokens: number
  active_tokens: number
  expired_tokens: number
  blacklisted_tokens: number
  refresh_rate: number
}

export interface DatabaseMetrics {
  active_connections: number
  idle_connections: number
  max_connections: number
  avg_query_time: string
  slow_queries: number
  error_rate: number
}

export interface CacheMetrics {
  hit_rate: number
  miss_rate: number
  memory_usage: string
  key_count: number
  eviction_count: number
}

export interface SecurityMetrics {
  rate_limit_hits: number
  blocked_requests: number
  suspicious_activity: number
  failed_auth_attempts: number
}

// User Management
export interface UserStats {
  total_users: number
  active_users: number
  verified_users: number
  locked_accounts: number
  users_by_role: Record<string, number>
  registration_trend: RegistrationTrendPoint[]
  login_trend: LoginTrendPoint[]
}

export interface RegistrationTrendPoint {
  date: string
  count: number
}

export interface LoginTrendPoint {
  date: string
  count: number
}

export interface UserSession {
  session_id: string
  user_id: string
  user_email: string
  ip_address: string
  user_agent: string
  created_at: string
  last_used: string
  expires_at: string
  token_type: string
  is_active: boolean
}

export interface BulkUserActionRequest {
  user_ids: string[]
  action: 'lock' | 'unlock' | 'verify_email' | 'verify_phone' | 'delete' | 'enable_mfa' | 'disable_mfa'
  reason?: string
}

export interface BulkActionResult {
  action: string
  total: number
  success: number
  failed: number
  errors?: string[]
  details?: ActionDetail[]
}

export interface ActionDetail {
  user_id: string
  success: boolean
  error?: string
}

// Role Management
export interface RoleStats {
  total_roles: number
  role_usage: Record<string, number>
  permission_usage: Record<string, number>
}

export interface BulkRoleAssignRequest {
  user_ids: string[]
  role_id: string
  action: 'assign' | 'remove'
  reason?: string
}

// Audit Logs
export interface AuditLog {
  id: string
  user_id?: string
  action: string
  resource_type?: string
  resource_id?: string
  ip_address?: string
  user_agent?: string
  metadata?: Record<string, any>
  timestamp: string
}

export interface AuditEvent {
  event_type: string
  count: number
  last_seen: string
}

// Configuration
export interface ConfigurationResponse {
  server: ServerConfig
  security: SecurityConfig
  features: FeaturesConfig
}

export interface ServerConfig {
  host: string
  port: number
  environment: string
}

export interface SecurityConfig {
  password_hash: PasswordHashConfig
  token: TokenConfig
  rate_limit: RateLimitConfig
}

export interface PasswordHashConfig {
  algorithm: string
}

export interface TokenConfig {
  type: string
  access_ttl: string
  refresh_ttl: string
}

export interface RateLimitConfig {
  enabled: boolean
  requests_per_minute: number
  burst_size: number
  window_size: string
}

export interface FeaturesConfig {
  mfa_enabled: boolean
  social_auth: boolean
  enterprise_sso: boolean
  admin_dashboard: boolean
  audit_logging: boolean
}

export interface UpdateConfigurationRequest {
  server?: Partial<ServerConfig>
  security?: Partial<SecurityConfig>
  features?: Partial<FeaturesConfig>
}

// Alerts
export interface Alert {
  id: string
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  message: string
  source: string
  metadata?: Record<string, any>
  created_at: string
  updated_at: string
  resolved_at?: string
  is_active: boolean
  is_resolved: boolean
}

export interface CreateAlertRequest {
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  message: string
  source: string
  metadata?: Record<string, any>
}

export interface UpdateAlertRequest {
  severity?: 'low' | 'medium' | 'high' | 'critical'
  title?: string
  message?: string
  metadata?: Record<string, any>
  is_resolved?: boolean
}

// Notifications
export interface NotificationSettings {
  email_enabled: boolean
  email_recipients: string[]
  slack_enabled: boolean
  slack_webhook?: string
  sms_enabled: boolean
  sms_recipients: string[]
  thresholds: NotificationThresholds
}

export interface NotificationThresholds {
  failed_login_rate: number
  error_rate: number
  response_time_ms: number
  database_connections: number
  memory_usage_percent: number
  cpu_usage_percent: number
}

export interface UpdateNotificationSettingsRequest {
  email_enabled?: boolean
  email_recipients?: string[]
  slack_enabled?: boolean
  slack_webhook?: string
  sms_enabled?: boolean
  sms_recipients?: string[]
  thresholds?: Partial<NotificationThresholds>
}