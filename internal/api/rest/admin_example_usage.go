package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
)

// AdminAPIExamples demonstrates how to use the admin API endpoints
type AdminAPIExamples struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewAdminAPIExamples creates a new admin API examples instance
func NewAdminAPIExamples(baseURL, token string) *AdminAPIExamples {
	return &AdminAPIExamples{
		baseURL: baseURL,
		token:   token,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// makeRequest makes an authenticated HTTP request
func (a *AdminAPIExamples) makeRequest(method, endpoint string, body interface{}) (*http.Response, error) {
	var reqBody *bytes.Buffer
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	var req *http.Request
	var err error
	if reqBody != nil {
		req, err = http.NewRequest(method, a.baseURL+endpoint, reqBody)
	} else {
		req, err = http.NewRequest(method, a.baseURL+endpoint, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return a.client.Do(req)
}

// GetSystemInfo demonstrates getting system information
func (a *AdminAPIExamples) GetSystemInfo(ctx context.Context) (*interfaces.SystemInfo, error) {
	resp, err := a.makeRequest("GET", "/api/v1/admin/system/info", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success bool                   `json:"success"`
		Data    *interfaces.SystemInfo `json:"data"`
		Error   map[string]interface{} `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API error: %v", response.Error)
	}

	return response.Data, nil
}

// GetSystemHealth demonstrates getting system health status
func (a *AdminAPIExamples) GetSystemHealth(ctx context.Context) (*interfaces.SystemHealth, error) {
	resp, err := a.makeRequest("GET", "/api/v1/admin/system/health", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success bool                     `json:"success"`
		Data    *interfaces.SystemHealth `json:"data"`
		Error   map[string]interface{}   `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API error: %v", response.Error)
	}

	return response.Data, nil
}

// GetSystemMetrics demonstrates getting system metrics
func (a *AdminAPIExamples) GetSystemMetrics(ctx context.Context) (*interfaces.SystemMetrics, error) {
	resp, err := a.makeRequest("GET", "/api/v1/admin/system/metrics", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success bool                      `json:"success"`
		Data    *interfaces.SystemMetrics `json:"data"`
		Error   map[string]interface{}    `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API error: %v", response.Error)
	}

	return response.Data, nil
}

// BulkUserActions demonstrates performing bulk actions on users
func (a *AdminAPIExamples) BulkUserActions(ctx context.Context, userIDs []uuid.UUID, action, reason string) (*interfaces.BulkActionResult, error) {
	requestBody := interfaces.BulkUserActionRequest{
		UserIDs: userIDs,
		Action:  action,
		Reason:  reason,
	}

	resp, err := a.makeRequest("POST", "/api/v1/admin/users/bulk-actions", requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success bool                         `json:"success"`
		Data    *interfaces.BulkActionResult `json:"data"`
		Error   map[string]interface{}       `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API error: %v", response.Error)
	}

	return response.Data, nil
}

// GetAllUserSessions demonstrates getting all user sessions with pagination
func (a *AdminAPIExamples) GetAllUserSessions(ctx context.Context, page, limit int, userID string) (*interfaces.GetSessionsResponse, error) {
	endpoint := fmt.Sprintf("/api/v1/admin/users/sessions?page=%d&limit=%d", page, limit)
	if userID != "" {
		endpoint += "&user_id=" + userID
	}

	resp, err := a.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success    bool                     `json:"success"`
		Data       []interfaces.UserSession `json:"data"`
		Pagination *PaginationInfo          `json:"pagination"`
		Error      map[string]interface{}   `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API error: %v", response.Error)
	}

	return &interfaces.GetSessionsResponse{
		Sessions: response.Data,
		Pagination: interfaces.PaginationInfo{
			Page:       response.Pagination.Page,
			Limit:      response.Pagination.Limit,
			Total:      response.Pagination.Total,
			TotalPages: response.Pagination.TotalPages,
			HasNext:    response.Pagination.HasNext,
			HasPrev:    response.Pagination.HasPrev,
		},
	}, nil
}

// DeleteUserSession demonstrates deleting a user session
func (a *AdminAPIExamples) DeleteUserSession(ctx context.Context, sessionID uuid.UUID) error {
	endpoint := fmt.Sprintf("/api/v1/admin/users/sessions/%s", sessionID.String())

	resp, err := a.makeRequest("DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success bool                   `json:"success"`
		Data    map[string]interface{} `json:"data"`
		Error   map[string]interface{} `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("API error: %v", response.Error)
	}

	return nil
}

// CreateAlert demonstrates creating a new alert
func (a *AdminAPIExamples) CreateAlert(ctx context.Context, alertType, severity, title, message, source string) (*interfaces.Alert, error) {
	requestBody := interfaces.CreateAlertRequest{
		Type:     alertType,
		Severity: severity,
		Title:    title,
		Message:  message,
		Source:   source,
	}

	resp, err := a.makeRequest("POST", "/api/v1/admin/alerts", requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success bool                   `json:"success"`
		Data    *interfaces.Alert      `json:"data"`
		Error   map[string]interface{} `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API error: %v", response.Error)
	}

	return response.Data, nil
}

// GetActiveAlerts demonstrates getting active alerts
func (a *AdminAPIExamples) GetActiveAlerts(ctx context.Context) (*interfaces.AlertsResponse, error) {
	resp, err := a.makeRequest("GET", "/api/v1/admin/alerts", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success bool                       `json:"success"`
		Data    *interfaces.AlertsResponse `json:"data"`
		Error   map[string]interface{}     `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API error: %v", response.Error)
	}

	return response.Data, nil
}

// UpdateAlert demonstrates updating an existing alert
func (a *AdminAPIExamples) UpdateAlert(ctx context.Context, alertID uuid.UUID, severity, title, message *string, isResolved *bool) (*interfaces.Alert, error) {
	requestBody := interfaces.UpdateAlertRequest{
		Severity:   severity,
		Title:      title,
		Message:    message,
		IsResolved: isResolved,
	}

	endpoint := fmt.Sprintf("/api/v1/admin/alerts/%s", alertID.String())

	resp, err := a.makeRequest("PUT", endpoint, requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success bool                   `json:"success"`
		Data    *interfaces.Alert      `json:"data"`
		Error   map[string]interface{} `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API error: %v", response.Error)
	}

	return response.Data, nil
}

// GetNotificationSettings demonstrates getting notification settings
func (a *AdminAPIExamples) GetNotificationSettings(ctx context.Context) (*interfaces.NotificationSettings, error) {
	resp, err := a.makeRequest("GET", "/api/v1/admin/notifications/settings", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success bool                             `json:"success"`
		Data    *interfaces.NotificationSettings `json:"data"`
		Error   map[string]interface{}           `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API error: %v", response.Error)
	}

	return response.Data, nil
}

// UpdateNotificationSettings demonstrates updating notification settings
func (a *AdminAPIExamples) UpdateNotificationSettings(ctx context.Context, settings *interfaces.UpdateNotificationSettingsRequest) error {
	resp, err := a.makeRequest("PUT", "/api/v1/admin/notifications/settings", settings)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Success bool                   `json:"success"`
		Data    map[string]interface{} `json:"data"`
		Error   map[string]interface{} `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("API error: %v", response.Error)
	}

	return nil
}

// ExampleUsage demonstrates how to use the admin API
func ExampleUsage() {
	// Initialize the admin API client
	adminAPI := NewAdminAPIExamples("http://localhost:8080", "your-admin-jwt-token")
	ctx := context.Background()

	// Get system information
	fmt.Println("=== Getting System Information ===")
	systemInfo, err := adminAPI.GetSystemInfo(ctx)
	if err != nil {
		fmt.Printf("Error getting system info: %v\n", err)
	} else {
		fmt.Printf("Service: %s, Version: %s\n", systemInfo.Service, systemInfo.Version)
		fmt.Printf("Uptime: %v\n", systemInfo.Runtime.Uptime)
	}

	// Get system health
	fmt.Println("\n=== Getting System Health ===")
	systemHealth, err := adminAPI.GetSystemHealth(ctx)
	if err != nil {
		fmt.Printf("Error getting system health: %v\n", err)
	} else {
		fmt.Printf("Overall Status: %s\n", systemHealth.Status)
		for component, health := range systemHealth.Components {
			fmt.Printf("  %s: %s - %s\n", component, health.Status, health.Message)
		}
	}

	// Perform bulk user actions
	fmt.Println("\n=== Performing Bulk User Actions ===")
	userIDs := []uuid.UUID{uuid.New(), uuid.New()}
	bulkResult, err := adminAPI.BulkUserActions(ctx, userIDs, "lock", "Security violation detected")
	if err != nil {
		fmt.Printf("Error performing bulk actions: %v\n", err)
	} else {
		fmt.Printf("Action: %s, Total: %d, Success: %d, Failed: %d\n",
			bulkResult.Action, bulkResult.Total, bulkResult.Success, bulkResult.Failed)
	}

	// Get user sessions
	fmt.Println("\n=== Getting User Sessions ===")
	sessions, err := adminAPI.GetAllUserSessions(ctx, 1, 10, "")
	if err != nil {
		fmt.Printf("Error getting sessions: %v\n", err)
	} else {
		fmt.Printf("Found %d sessions (Page %d of %d)\n",
			len(sessions.Sessions), sessions.Pagination.Page, sessions.Pagination.TotalPages)
		for _, session := range sessions.Sessions {
			fmt.Printf("  Session %s: User %s from %s\n",
				session.SessionID, session.UserEmail, session.IPAddress)
		}
	}

	// Create an alert
	fmt.Println("\n=== Creating Alert ===")
	alert, err := adminAPI.CreateAlert(ctx, "security", "high", "Test Alert", "This is a test alert", "admin_api_example")
	if err != nil {
		fmt.Printf("Error creating alert: %v\n", err)
	} else {
		fmt.Printf("Created alert: %s (ID: %s)\n", alert.Title, alert.ID)
	}

	// Get active alerts
	fmt.Println("\n=== Getting Active Alerts ===")
	alerts, err := adminAPI.GetActiveAlerts(ctx)
	if err != nil {
		fmt.Printf("Error getting alerts: %v\n", err)
	} else {
		fmt.Printf("Found %d active alerts\n", alerts.Total)
		for _, alert := range alerts.Alerts {
			fmt.Printf("  %s: %s (%s)\n", alert.Severity, alert.Title, alert.Type)
		}
	}

	// Get notification settings
	fmt.Println("\n=== Getting Notification Settings ===")
	notificationSettings, err := adminAPI.GetNotificationSettings(ctx)
	if err != nil {
		fmt.Printf("Error getting notification settings: %v\n", err)
	} else {
		fmt.Printf("Email enabled: %v, Recipients: %v\n",
			notificationSettings.EmailEnabled, notificationSettings.EmailRecipients)
		fmt.Printf("Slack enabled: %v, SMS enabled: %v\n",
			notificationSettings.SlackEnabled, notificationSettings.SMSEnabled)
	}
}
