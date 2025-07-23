package rest

// import (
// 	"net/http"
// 	"time"

// 	"github.com/gin-gonic/gin"
// 	"github.com/google/uuid"
// 	"github.com/steve-mir/go-auth-system/internal/service/admin"
// )

// // setupAdminRoutes configures admin-specific routes
// func (s *Server) setupAdminRoutes(group *gin.RouterGroup) {
// 	// System information and health
// 	group.GET("/system/info", s.getSystemInfoHandler)
// 	group.GET("/system/health", s.getSystemHealthHandler)
// 	group.GET("/system/metrics", s.getSystemMetricsHandler)

// 	// User management (extended admin functions)
// 	userGroup := group.Group("/users")
// 	{
// 		userGroup.GET("/stats", s.getUserStatsHandler)
// 		userGroup.POST("/bulk-actions", s.bulkUserActionsHandler)
// 		userGroup.GET("/sessions", s.getAllUserSessionsHandler)
// 		userGroup.DELETE("/sessions/:session_id", s.deleteUserSessionHandler)
// 	}

// 	// Role management (extended admin functions)
// 	roleGroup := group.Group("/roles")
// 	{
// 		roleGroup.GET("/stats", s.getRoleStatsHandler)
// 		roleGroup.POST("/bulk-assign", s.bulkRoleAssignHandler)
// 	}

// 	// Audit and logging
// 	auditGroup := group.Group("/audit")
// 	{
// 		auditGroup.GET("/logs", s.getAuditLogsHandler)
// 		auditGroup.GET("/events", s.getAuditEventsHandler)
// 	}

// 	// Configuration management
// 	configGroup := group.Group("/config")
// 	{
// 		configGroup.GET("", s.getConfigHandler)
// 		configGroup.PUT("", s.updateConfigHandler)
// 		configGroup.POST("/reload", s.reloadConfigHandler)
// 	}

// 	// Alerts and notifications
// 	alertGroup := group.Group("/alerts")
// 	{
// 		alertGroup.GET("", s.getActiveAlertsHandler)
// 		alertGroup.POST("", s.createAlertHandler)
// 		alertGroup.PUT("/:alert_id", s.updateAlertHandler)
// 		alertGroup.DELETE("/:alert_id", s.deleteAlertHandler)
// 	}

// 	// Notification settings
// 	notificationGroup := group.Group("/notifications")
// 	{
// 		notificationGroup.GET("/settings", s.getNotificationSettingsHandler)
// 		notificationGroup.PUT("/settings", s.updateNotificationSettingsHandler)
// 	}
// }

// // System information handlers

// // getSystemInfoHandler returns system information
// func (s *Server) getSystemInfoHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	info, err := s.adminService.GetSystemInfo(c.Request.Context())
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, info)
// }

// // getSystemHealthHandler returns detailed system health information
// func (s *Server) getSystemHealthHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	health, err := s.adminService.GetSystemHealth(c.Request.Context())
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, health)
// }

// // getSystemMetricsHandler returns system metrics
// func (s *Server) getSystemMetricsHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	metrics, err := s.adminService.GetSystemMetrics(c.Request.Context())
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, metrics)
// }

// // User management handlers

// // getUserStatsHandler returns user statistics
// func (s *Server) getUserStatsHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	stats, err := s.adminService.GetUserStats(c.Request.Context())
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, stats)
// }

// // bulkUserActionsHandler handles bulk user actions
// func (s *Server) bulkUserActionsHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	var req admin.BulkUserActionRequest
// 	if !s.bindAndValidate(c, &req) {
// 		return
// 	}

// 	result, err := s.adminService.BulkUserActions(c.Request.Context(), &req)
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, result)
// }

// // getAllUserSessionsHandler returns all active user sessions
// func (s *Server) getAllUserSessionsHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	page, limit, valid := s.GetPaginationParams(c)
// 	if !valid {
// 		return
// 	}

// 	// Get additional query parameters
// 	userID := c.Query("user_id")
// 	sortBy := c.Query("sort_by")
// 	sortOrder := c.Query("sort_order")

// 	req := &admin.GetSessionsRequest{
// 		Page:      page,
// 		Limit:     limit,
// 		UserID:    userID,
// 		SortBy:    sortBy,
// 		SortOrder: sortOrder,
// 	}

// 	response, err := s.adminService.GetAllUserSessions(c.Request.Context(), req)
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.paginatedResponse(c, http.StatusOK, response.Sessions, s.convertPaginationInfo(&response.Pagination))
// }

// // deleteUserSessionHandler deletes a specific user session
// func (s *Server) deleteUserSessionHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	sessionIDStr, valid := s.parseUUIDParam(c, "session_id")
// 	if !valid {
// 		return
// 	}

// 	sessionID, err := uuid.Parse(sessionIDStr)
// 	if err != nil {
// 		s.badRequestResponse(c, "Invalid session ID format", nil)
// 		return
// 	}

// 	if err := s.adminService.DeleteUserSession(c.Request.Context(), sessionID); err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, gin.H{
// 		"message": "Session deleted successfully",
// 	})
// }

// // Role management handlers

// // getRoleStatsHandler returns role statistics
// func (s *Server) getRoleStatsHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	stats, err := s.adminService.GetRoleStats(c.Request.Context())
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, stats)
// }

// // bulkRoleAssignHandler handles bulk role assignments
// func (s *Server) bulkRoleAssignHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	var req admin.BulkRoleAssignRequest
// 	if !s.bindAndValidate(c, &req) {
// 		return
// 	}

// 	result, err := s.adminService.BulkRoleAssign(c.Request.Context(), &req)
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, result)
// }

// // Audit handlers

// // getAuditLogsHandler returns audit logs
// func (s *Server) getAuditLogsHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	page, limit, valid := s.GetPaginationParams(c)
// 	if !valid {
// 		return
// 	}

// 	// Parse query parameters
// 	userID := c.Query("user_id")
// 	action := c.Query("action")
// 	resourceType := c.Query("resource_type")
// 	sortBy := c.Query("sort_by")
// 	sortOrder := c.Query("sort_order")

// 	// Parse time range if provided
// 	var startTime, endTime time.Time
// 	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
// 		if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
// 			startTime = t
// 		}
// 	}
// 	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
// 		if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
// 			endTime = t
// 		}
// 	}

// 	req := &admin.GetAuditLogsRequest{
// 		Page:         page,
// 		Limit:        limit,
// 		UserID:       userID,
// 		Action:       action,
// 		ResourceType: resourceType,
// 		StartTime:    startTime,
// 		EndTime:      endTime,
// 		SortBy:       sortBy,
// 		SortOrder:    sortOrder,
// 	}

// 	response, err := s.adminService.GetAuditLogs(c.Request.Context(), req)
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.paginatedResponse(c, http.StatusOK, response.Logs, s.convertPaginationInfo(&response.Pagination))
// }

// // getAuditEventsHandler returns audit events with filtering
// func (s *Server) getAuditEventsHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	page, limit, valid := s.GetPaginationParams(c)
// 	if !valid {
// 		return
// 	}

// 	eventType := c.Query("event_type")
// 	sortBy := c.Query("sort_by")
// 	sortOrder := c.Query("sort_order")

// 	req := &admin.GetAuditEventsRequest{
// 		Page:      page,
// 		Limit:     limit,
// 		EventType: eventType,
// 		SortBy:    sortBy,
// 		SortOrder: sortOrder,
// 	}

// 	response, err := s.adminService.GetAuditEvents(c.Request.Context(), req)
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.paginatedResponse(c, http.StatusOK, response.Events, s.convertPaginationInfo(&response.Pagination))
// }

// // Configuration handlers

// // getConfigHandler returns current configuration
// func (s *Server) getConfigHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	config, err := s.adminService.GetConfiguration(c.Request.Context())
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, config)
// }

// // updateConfigHandler updates configuration
// func (s *Server) updateConfigHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	var req admin.UpdateConfigurationRequest
// 	if !s.bindAndValidate(c, &req) {
// 		return
// 	}

// 	if err := s.adminService.UpdateConfiguration(c.Request.Context(), &req); err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, gin.H{
// 		"message":   "Configuration updated successfully",
// 		"timestamp": time.Now(),
// 	})
// }

// // reloadConfigHandler reloads configuration
// func (s *Server) reloadConfigHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	if err := s.adminService.ReloadConfiguration(c.Request.Context()); err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, gin.H{
// 		"message":   "Configuration reloaded successfully",
// 		"timestamp": time.Now(),
// 	})
// }

// // Alert handlers

// // getActiveAlertsHandler returns active alerts
// func (s *Server) getActiveAlertsHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	response, err := s.adminService.GetActiveAlerts(c.Request.Context())
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, response)
// }

// // createAlertHandler creates a new alert
// func (s *Server) createAlertHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	var req admin.CreateAlertRequest
// 	if !s.bindAndValidate(c, &req) {
// 		return
// 	}

// 	alert, err := s.adminService.CreateAlert(c.Request.Context(), &req)
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusCreated, alert)
// }

// // updateAlertHandler updates an existing alert
// func (s *Server) updateAlertHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	alertIDStr, valid := s.parseUUIDParam(c, "alert_id")
// 	if !valid {
// 		return
// 	}

// 	alertID, err := uuid.Parse(alertIDStr)
// 	if err != nil {
// 		s.badRequestResponse(c, "Invalid alert ID format", nil)
// 		return
// 	}

// 	var req admin.UpdateAlertRequest
// 	if !s.bindAndValidate(c, &req) {
// 		return
// 	}

// 	alert, err := s.adminService.UpdateAlert(c.Request.Context(), alertID, &req)
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, alert)
// }

// // deleteAlertHandler deletes an alert
// func (s *Server) deleteAlertHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	alertIDStr, valid := s.parseUUIDParam(c, "alert_id")
// 	if !valid {
// 		return
// 	}

// 	alertID, err := uuid.Parse(alertIDStr)
// 	if err != nil {
// 		s.badRequestResponse(c, "Invalid alert ID format", nil)
// 		return
// 	}

// 	if err := s.adminService.DeleteAlert(c.Request.Context(), alertID); err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, gin.H{
// 		"message": "Alert deleted successfully",
// 	})
// }

// // Notification handlers

// // getNotificationSettingsHandler returns notification settings
// func (s *Server) getNotificationSettingsHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	settings, err := s.adminService.GetNotificationSettings(c.Request.Context())
// 	if err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, settings)
// }

// // updateNotificationSettingsHandler updates notification settings
// func (s *Server) updateNotificationSettingsHandler(c *gin.Context) {
// 	if s.adminService == nil {
// 		s.internalServerErrorResponse(c, "Admin service not available")
// 		return
// 	}

// 	var req admin.UpdateNotificationSettingsRequest
// 	if !s.bindAndValidate(c, &req) {
// 		return
// 	}

// 	if err := s.adminService.UpdateNotificationSettings(c.Request.Context(), &req); err != nil {
// 		s.handleServiceError(c, err)
// 		return
// 	}

// 	s.successResponse(c, http.StatusOK, gin.H{
// 		"message":   "Notification settings updated successfully",
// 		"timestamp": time.Now(),
// 	})
// }

// // Helper method to convert admin.PaginationInfo to response.PaginationMeta
// func (s *Server) convertPaginationInfo(info *admin.PaginationInfo) *PaginationMeta {
// 	return &PaginationMeta{
// 		Page:       info.Page,
// 		Limit:      info.Limit,
// 		Total:      info.Total,
// 		TotalPages: info.TotalPages,
// 		HasNext:    info.HasNext,
// 		HasPrev:    info.HasPrev,
// 	}
// }
