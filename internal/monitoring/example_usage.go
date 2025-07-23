package monitoring

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

// ExampleUsage demonstrates how to use the enhanced monitoring system
func ExampleUsage() {
	// 1. Create monitoring service with full configuration
	config := Config{
		Enabled: true,
		Prometheus: PrometheusConfig{
			Enabled: true,
			Path:    "/metrics",
			Port:    9090,
		},
		Logging: LoggerConfig{
			Level:             LogLevelInfo,
			Format:            LogFormatJSON,
			Output:            "stdout",
			EnableTracing:     true,
			EnableCorrelation: true,
			ServiceName:       "auth-service",
			ServiceVersion:    "1.0.0",
		},
		ErrorTracker: ErrorTrackerConfig{
			Enabled:          true,
			MaxErrors:        10000,
			RetentionPeriod:  7 * 24 * time.Hour,
			AlertingEnabled:  true,
			AlertBuffer:      1000,
			DefaultSeverity:  SeverityMedium,
			EnableStackTrace: true,
			EnableGrouping:   true,
		},
		Aggregator: LogAggregatorConfig{
			Enabled:           true,
			MaxEntries:        100000,
			RetentionPeriod:   24 * time.Hour,
			AggregationLevels: []string{"minute", "hour", "day"},
			PatternDetection:  true,
			MetricsEnabled:    true,
		},
		Tracing: TracingConfig{
			Enabled:        true,
			ServiceName:    "auth-service",
			ServiceVersion: "1.0.0",
			SampleRate:     0.1,
		},
	}

	service, err := NewService(config)
	if err != nil {
		panic(fmt.Sprintf("Failed to create monitoring service: %v", err))
	}

	// 2. Set up HTTP server with monitoring middleware
	router := gin.New()

	// Add monitoring middleware in the correct order
	router.Use(RequestIDMiddleware())
	router.Use(TraceIDMiddleware())
	router.Use(service.CorrelationMiddleware())
	router.Use(service.TracingMiddleware())
	router.Use(service.ErrorTrackingMiddleware())
	router.Use(service.LogAggregationMiddleware())
	router.Use(service.HTTPMiddleware())

	// 3. Example API endpoint with comprehensive monitoring
	router.POST("/api/v1/auth/login", func(c *gin.Context) {
		ctx := c.Request.Context()

		// Start a trace for the login operation
		trace, ctx := service.StartTrace(ctx, "user_login")
		defer func() {
			service.FinishTrace(ctx, trace, nil)
		}()

		// Add trace tags
		service.AddTraceTag(ctx, "endpoint", "/api/v1/auth/login")
		service.AddTraceTag(ctx, "method", "POST")

		// Simulate authentication logic with error tracking
		err := authenticateUser(ctx, service, "user@example.com", "password123")
		if err != nil {
			// Track the error
			errorID := service.TrackError(ctx, err, CategoryAuth, "authenticate_user", "auth_service")

			// Add additional context to the error
			service.AddErrorContext(errorID, "email", "user@example.com")
			service.AddErrorContext(errorID, "attempt_time", time.Now())

			c.JSON(401, gin.H{"error": "Authentication failed"})
			return
		}

		// Record successful authentication
		service.RecordAuthEvent(ctx, "login", "user-123", true, 150*time.Millisecond, map[string]interface{}{
			"method": "password",
			"ip":     c.ClientIP(),
		})

		c.JSON(200, gin.H{"message": "Login successful"})
	})

	// 4. Example database operation with monitoring
	router.GET("/api/v1/users/:id", func(c *gin.Context) {
		ctx := c.Request.Context()
		userID := c.Param("id")

		// Start trace for database operation
		trace, ctx := service.StartTrace(ctx, "get_user")
		service.AddTraceTag(ctx, "user_id", userID)

		// Simulate database query with monitoring
		start := time.Now()
		user, err := getUserFromDatabase(ctx, service, userID)
		duration := time.Since(start)

		// Record database metrics
		service.RecordDatabaseEvent(ctx, "SELECT", "users", duration, err)

		if err != nil {
			// Track database error
			errorID := service.TrackError(ctx, err, CategoryDatabase, "get_user", "postgres")
			service.AddErrorContext(errorID, "user_id", userID)
			service.AddErrorContext(errorID, "query_duration", duration)

			service.FinishTrace(ctx, trace, err)
			c.JSON(500, gin.H{"error": "Database error"})
			return
		}

		service.FinishTrace(ctx, trace, nil)
		c.JSON(200, user)
	})

	// 5. Admin endpoints for monitoring data
	adminGroup := router.Group("/admin")
	{
		// Get error statistics
		adminGroup.GET("/errors", func(c *gin.Context) {
			category := c.Query("category")
			severity := c.Query("severity")

			var cat ErrorCategory
			if category != "" {
				cat = ErrorCategory(category)
			}

			var sev ErrorSeverity
			if severity != "" {
				sev = ErrorSeverity(severity)
			}

			errors := service.GetErrors(cat, sev, nil)
			c.JSON(200, errors)
		})

		// Get log statistics
		adminGroup.GET("/logs/stats", func(c *gin.Context) {
			start := time.Now().Add(-24 * time.Hour)
			end := time.Now()

			stats := service.GetLogStatistics(start, end)
			c.JSON(200, stats)
		})

		// Search logs
		adminGroup.GET("/logs/search", func(c *gin.Context) {
			query := LogSearchQuery{
				Level:     c.Query("level"),
				EventType: c.Query("event_type"),
				Component: c.Query("component"),
				Message:   c.Query("message"),
				UserID:    c.Query("user_id"),
				Limit:     10,
			}

			results := service.SearchLogs(query)
			c.JSON(200, results)
		})

		// Get log patterns
		adminGroup.GET("/logs/patterns", func(c *gin.Context) {
			eventType := c.Query("event_type")
			component := c.Query("component")

			patterns := service.GetLogPatterns(eventType, component)
			c.JSON(200, patterns)
		})

		// Get alerts
		adminGroup.GET("/alerts", func(c *gin.Context) {
			alerts := service.GetAlerts(nil)
			c.JSON(200, alerts)
		})

		// Resolve error
		adminGroup.POST("/errors/:id/resolve", func(c *gin.Context) {
			errorID := c.Param("id")
			resolvedBy := c.GetHeader("X-User-ID")

			service.ResolveError(errorID, resolvedBy)
			c.JSON(200, gin.H{"message": "Error resolved"})
		})

		// Export metrics
		adminGroup.GET("/metrics/export", func(c *gin.Context) {
			format := c.DefaultQuery("format", "json")

			data, err := service.ExportLogMetrics(format)
			if err != nil {
				c.JSON(400, gin.H{"error": err.Error()})
				return
			}

			c.Data(200, "application/json", data)
		})
	}

	// 6. Start alert monitoring in background
	go monitorAlerts(service)

	// 7. Start metrics collection
	ctx := context.Background()
	service.StartCollection(ctx, 30*time.Second)

	fmt.Println("Monitoring system initialized with full observability features")
	fmt.Println("- Distributed tracing enabled")
	fmt.Println("- Error tracking and alerting enabled")
	fmt.Println("- Log aggregation and pattern detection enabled")
	fmt.Println("- Prometheus metrics available at /metrics")
	fmt.Println("- Admin monitoring endpoints available at /admin/*")
}

// authenticateUser simulates user authentication with error scenarios
func authenticateUser(ctx context.Context, service *Service, email, password string) error {
	// Start a sub-trace for authentication
	trace, ctx := service.StartTrace(ctx, "validate_credentials")
	defer service.FinishTrace(ctx, trace, nil)

	service.AddTraceTag(ctx, "email", email)

	// Simulate different error scenarios
	switch email {
	case "blocked@example.com":
		err := errors.New("account is blocked")
		service.TrackError(ctx, err, CategorySecurity, "validate_credentials", "auth_service")
		return err
	case "notfound@example.com":
		err := errors.New("user not found")
		service.TrackError(ctx, err, CategoryAuth, "validate_credentials", "auth_service")
		return err
	case "invalid@example.com":
		err := errors.New("invalid password")
		service.TrackError(ctx, err, CategoryAuth, "validate_credentials", "auth_service")
		return err
	}

	// Simulate successful authentication
	return nil
}

// getUserFromDatabase simulates database operations with error scenarios
func getUserFromDatabase(ctx context.Context, service *Service, userID string) (map[string]interface{}, error) {
	// Start a sub-trace for database operation
	trace, ctx := service.StartTrace(ctx, "db_query_user")
	defer func() {
		service.FinishTrace(ctx, trace, nil)
	}()

	service.AddTraceTag(ctx, "table", "users")
	service.AddTraceTag(ctx, "operation", "SELECT")

	// Simulate different database scenarios
	switch userID {
	case "timeout":
		err := errors.New("database connection timeout")
		service.TrackError(ctx, err, CategoryDatabase, "db_query_user", "postgres")
		return nil, err
	case "deadlock":
		err := errors.New("database deadlock detected")
		service.TrackError(ctx, err, CategoryDatabase, "db_query_user", "postgres")
		return nil, err
	case "notfound":
		err := errors.New("user not found")
		return nil, err
	}

	// Simulate successful database query
	user := map[string]interface{}{
		"id":    userID,
		"email": "user@example.com",
		"name":  "John Doe",
	}

	return user, nil
}

// monitorAlerts demonstrates how to handle alerts in real-time
func monitorAlerts(service *Service) {
	alertChan := service.GetAlertChannel()
	if alertChan == nil {
		return
	}

	for alert := range alertChan {
		fmt.Printf("🚨 ALERT: %s - %s\n", alert.RuleName, alert.Message)
		fmt.Printf("   Severity: %s\n", alert.Severity)
		fmt.Printf("   Error Count: %d in %v\n", alert.ErrorCount, alert.TimeWindow)
		fmt.Printf("   Timestamp: %s\n", alert.Timestamp.Format(time.RFC3339))

		// Here you would typically:
		// 1. Send notifications (email, Slack, PagerDuty, etc.)
		// 2. Create tickets in your issue tracking system
		// 3. Trigger automated remediation actions
		// 4. Log to external alerting systems

		// Example: Send to external alerting system
		sendToExternalAlerting(alert)
	}
}

// sendToExternalAlerting simulates sending alerts to external systems
func sendToExternalAlerting(alert *Alert) {
	// This would integrate with your alerting infrastructure
	fmt.Printf("📧 Sending alert to external system: %s\n", alert.ID)

	// Example integrations:
	// - Send to Slack webhook
	// - Send to PagerDuty
	// - Send email notification
	// - Create Jira ticket
	// - Send to monitoring dashboard
}

// ExampleCustomErrorTracking demonstrates custom error tracking patterns
func ExampleCustomErrorTracking(service *Service) {
	ctx := context.Background()

	// 1. Track business logic errors
	businessErr := errors.New("insufficient funds for transaction")
	errorID := service.TrackError(ctx, businessErr, CategoryValidation, "process_payment", "payment_service")

	// Add business context
	service.AddErrorContext(errorID, "user_id", "user-123")
	service.AddErrorContext(errorID, "transaction_amount", 1500.00)
	service.AddErrorContext(errorID, "account_balance", 750.00)

	// 2. Track integration errors
	integrationErr := errors.New("third-party API rate limit exceeded")
	errorID2 := service.TrackError(ctx, integrationErr, CategoryExternal, "call_payment_api", "stripe_integration")

	service.AddErrorContext(errorID2, "api_endpoint", "/v1/charges")
	service.AddErrorContext(errorID2, "rate_limit", "100/hour")
	service.AddErrorContext(errorID2, "retry_after", "3600")

	// 3. Track security events
	securityErr := errors.New("suspicious login pattern detected")
	errorID3 := service.TrackError(ctx, securityErr, CategorySecurity, "analyze_login_pattern", "security_service")

	service.AddErrorContext(errorID3, "ip_address", "192.168.1.100")
	service.AddErrorContext(errorID3, "failed_attempts", 5)
	service.AddErrorContext(errorID3, "time_window", "5 minutes")
}

// ExampleDistributedTracing demonstrates distributed tracing across services
func ExampleDistributedTracing(service *Service) {
	ctx := context.Background()

	// 1. Start main operation trace
	mainTrace, ctx := service.StartTrace(ctx, "user_registration")
	service.AddTraceTag(ctx, "service", "auth-service")
	service.AddTraceTag(ctx, "version", "1.0.0")

	// 2. Trace validation step
	validationTrace, ctx := service.StartTrace(ctx, "validate_user_data")
	service.AddTraceTag(ctx, "validation_type", "email_and_password")

	// Simulate validation work
	time.Sleep(50 * time.Millisecond)
	service.FinishTrace(ctx, validationTrace, nil)

	// 3. Trace database operations
	dbTrace, ctx := service.StartTrace(ctx, "create_user_record")
	service.AddTraceTag(ctx, "database", "postgresql")
	service.AddTraceTag(ctx, "table", "users")

	// Simulate database work
	time.Sleep(100 * time.Millisecond)
	service.FinishTrace(ctx, dbTrace, nil)

	// 4. Trace external service call
	emailTrace, ctx := service.StartTrace(ctx, "send_welcome_email")
	service.AddTraceTag(ctx, "email_service", "sendgrid")
	service.AddTraceTag(ctx, "template", "welcome_template")

	// Simulate email service call
	time.Sleep(200 * time.Millisecond)
	service.FinishTrace(ctx, emailTrace, nil)

	// 5. Finish main trace
	service.FinishTrace(ctx, mainTrace, nil)

	fmt.Println("Distributed trace completed with multiple spans")
}

// ExampleLogAggregationQueries demonstrates log querying capabilities
func ExampleLogAggregationQueries(service *Service) {
	// 1. Search for authentication failures
	authFailures := service.SearchLogs(LogSearchQuery{
		EventType: "auth",
		Level:     "error",
		Message:   "failed",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Limit:     100,
	})

	fmt.Printf("Found %d authentication failures in the last hour\n", len(authFailures))

	// 2. Get database performance metrics
	dbMetrics := service.GetLogMetrics("database", "postgres", AggregationMinute,
		time.Now().Add(-1*time.Hour), time.Now())

	fmt.Printf("Database metrics for the last hour: %d data points\n", len(dbMetrics))

	// 3. Analyze error patterns
	errorPatterns := service.GetLogPatterns("error", "")
	fmt.Printf("Detected %d error patterns\n", len(errorPatterns))

	for _, pattern := range errorPatterns {
		fmt.Printf("- Pattern: %s, Frequency: %.2f/min, Severity: %s\n",
			pattern.Pattern, pattern.Frequency, pattern.Severity)
	}

	// 4. Get system statistics
	stats := service.GetLogStatistics(time.Now().Add(-24*time.Hour), time.Now())
	fmt.Printf("System statistics for the last 24 hours:\n")
	fmt.Printf("- Total entries: %d\n", stats.TotalEntries)
	fmt.Printf("- Error rate: %.2f%%\n", stats.ErrorRate)
	fmt.Printf("- Average duration: %.2fms\n", stats.AvgDuration)
}
